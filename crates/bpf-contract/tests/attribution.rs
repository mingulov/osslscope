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
fn role_table_census_is_exactly_seventy_seven() {
    // Stage-1 grows the Phase-1 twenty-nine with exactly one role: 161,
    // the query-observation role (TYPED_QUERY_ROLES, never public). T2 S1a
    // adds the seven digest copied roles 309-315 (op 1), T2 S2a adds the
    // eight cipher copied roles 316-323 (op 2), T2 S3a adds the
    // twenty-three signature copied roles 324-346 (op 12), and T2 S4a adds
    // the nine KEM copied roles 347-355 (newctx / freectx / dupctx +
    // encapsulate / decapsulate / auth-encapsulate /
    // auth-decapsulate verbs, op 14; params 8-11 stay unmapped). The
    // copied probes hold out of firemap/pin and the load roots until the
    // R5 revision lands, so the roles admit in the contract but the BPF
    // dispatch enumeration never fires them. Any other addition or
    // removal still fails here.
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
            161, 258, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313,
            314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
            331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347,
            348, 349, 350, 351, 352, 353, 354, 355,
        ]
    );
    for id in [
        0, 1, 12, 48, 49, 127, 128, 129, 132, 156, 160, 176, 256, 257, 260, 356, 511,
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
#[test]
fn code_role_identity_binds_inode_offset_and_cookie_epoch() {
    // I1 two-phase-binding pin (replaces the inode-only key pin): the key
    // scopes by (process, image, epoch 0, inode, file offset, kind 5,
    // packed pair) and selects one row per (file, offset, op, fun);
    // the consuming kernel join binds it to the firing cookie's live
    // registration/source epoch (native-proven: the join takes the
    // cookie and checks SOURCE_READY/guards before consulting the
    // row). The kernel `code_role_key` wrapper and `publish_code_role`
    // delegate to these exact constructors, so any rekey, offset drop
    // or position drift fails here. No VA/cookie dependence is
    // structural in either constructor: both take neither (see their
    // signatures), so a caller cannot smuggle either in.
    let key = code_role_key(0x1111, 0x2222, 0x3333, 0x1b4, 5, 4);
    assert_eq!(key.process_incarnation, 0x1111);
    assert_eq!(key.image_epoch, 0x2222);
    assert_eq!(key.relation_epoch, 0);
    assert_eq!(
        key.primary_handle, 0x3333,
        "primary is the inode scope, not a cookie"
    );
    assert_eq!(
        key.secondary_handle, 0x1b4,
        "secondary is the exact file offset"
    );
    assert_eq!(key.kind, REL_CODE_ROLE);
    assert_eq!(
        key.operation,
        code_role_pair(5, 4),
        "operation carries the packed pair, not the bare op"
    );
    assert_eq!(code_role_pair(5, 4), 0x0005_0004);
    // Composition: inode, offset, function and operation each select a
    // distinct row, and the epoch stays 0 across all of them.
    let others = [
        code_role_key(0x1111, 0x2222, 0x4444, 0x1b4, 5, 4),
        code_role_key(0x1111, 0x2222, 0x3333, 0x2c8, 5, 4),
        code_role_key(0x1111, 0x2222, 0x3333, 0x1b4, 6, 4),
        code_role_key(0x1111, 0x2222, 0x3333, 0x1b4, 5, 3),
    ];
    assert_ne!(others[0].primary_handle, key.primary_handle);
    assert_ne!(others[1].secondary_handle, key.secondary_handle);
    assert_ne!(others[2].operation, key.operation);
    assert_ne!(others[3].operation, key.operation);
    // The packed pair is injective over the code_shape domain: all
    // eleven gated (op, fun) pairs encode distinctly.
    let mut pairs = Vec::new();
    for (operation, function) in [
        (3, 1),
        (4, 1),
        (3, 2),
        (4, 2),
        (3, 3),
        (4, 3),
        (3, 4),
        (3, 5),
        (4, 5),
        (3, 6),
        (4, 4),
    ] {
        pairs.push(code_role_pair(function, operation));
    }
    pairs.sort_unstable();
    pairs.dedup();
    assert_eq!(pairs.len(), 11, "every gated pair encodes distinctly");
    for other in &others {
        assert_eq!(other.relation_epoch, 0);
        assert_eq!(other.kind, REL_CODE_ROLE);
        assert_eq!(other.process_incarnation, 0x1111);
        assert_eq!(other.image_epoch, 0x2222);
    }
    // Value identity: every position locked, offset at data[3).
    let value = code_role_data(4, 5, 5, 0x1b4, 0x77, 0x99);
    assert_eq!(
        value,
        [4, 5, 5, 0x1b4, 0x77, 0, 0x99, 0, 0, 0],
        "data is [op, fun, shape, offset, occurrence, 0, seq, 0, 0, 0]"
    );
    // Substitution killer: same key scope, different observed offsets
    // are distinct identities — query-for-A never equals staged-B.
    let same_key_other_offset = code_role_data(4, 5, 5, 0x2c8, 0x77, 0x99);
    assert_ne!(same_key_other_offset[3], value[3]);
    assert_eq!(same_key_other_offset[0], value[0]);
    assert_eq!(same_key_other_offset[1], value[1]);
}
#[test]
fn code_role_key_disambiguates_same_function_callbacks_by_file_offset() {
    // U5K regression pin (§25.4): two distinct callbacks in one file
    // sharing (inode, function, op) but advertised at different file
    // offsets must publish distinct CODE_ROLE rows. The pre-fix key
    // carried no offset slot, so both publications derived the same
    // key and the second refused with LOSS_MAP (54 attempts -> 6 rows
    // + 48 refused attempts on the U5 workload). RED pre-fix: the two
    // constructor calls below stand for the two offsets (0x1b4,
    // 0x2c8), which the old signature could not express.
    let first = code_role_key(0x1111, 0x2222, 0x3333, 0x1b4, 5, 4);
    let second = code_role_key(0x1111, 0x2222, 0x3333, 0x2c8, 5, 4);
    assert_ne!(
        (
            second.primary_handle,
            second.secondary_handle,
            second.operation
        ),
        (
            first.primary_handle,
            first.secondary_handle,
            first.operation
        ),
        "same (inode, function, op) at two file offsets must key distinct rows"
    );
    // And the identical callback re-advertised keys the same row, so
    // dedup adoption (not a second mint) covers true re-publication.
    let repeat = code_role_key(0x1111, 0x2222, 0x3333, 0x1b4, 5, 4);
    assert_eq!(
        (
            repeat.primary_handle,
            repeat.secondary_handle,
            repeat.operation
        ),
        (
            first.primary_handle,
            first.secondary_handle,
            first.operation
        ),
        "same (file, offset, op, fun) must key the same row"
    );
}

// Independent SHA-256 known answers. Digest literals were generated with
// Python hashlib.sha256. Padding literals use standard SHA padding of the
// 56-byte protocol header plus each name length; they include the zero-filled
// remainder of the full 192-byte scratch buffer. No production helper builds
// either expected digest or expected padding.
fn kat_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn kat_object(profile: usize) -> [u8; 32] {
    core::array::from_fn(|i| match profile {
        0 => i as u8,
        1 => (7 * i + 3) as u8,
        2 => 0,
        _ => panic!("unknown object fixture"),
    })
}

fn kat_scratch() -> [[u8; 192]; 4] {
    [
        [0; 192],
        [0xa5; 192],
        [0x5a; 192],
        core::array::from_fn(|i| (13 * i + 7) as u8),
    ]
}

fn protocol_scratch(op: u32, object: &[u8; 32], name: &[u8]) -> [u8; 192] {
    let mut expected = b"ossl-code-req-v1".to_vec();
    expected.extend_from_slice(object);
    expected.extend_from_slice(&op.to_le_bytes());
    expected.extend_from_slice(&(name.len() as u32).to_le_bytes());
    expected.extend_from_slice(name);
    expected.extend_from_slice(&kat_hex(PROTOCOL_PADDING[name.len() - 1]));
    expected.try_into().unwrap()
}

fn check_protocol_kat(id: &str, op: u32, object: [u8; 32], name: &[u8], digest: &str) {
    let expected: [u8; 32] = kat_hex(digest).try_into().unwrap();
    let expected_scratch = protocol_scratch(op, &object, name);
    let mut raw = [0; 128];
    raw[..name.len()].copy_from_slice(name);
    assert!(
        exact_name_canonical(&raw, name.len() as u32),
        "{id}: canonical"
    );
    for domain in [1, 9, u64::MAX] {
        let key = ExactNameKey::from_read(domain, op, &raw, name.len() as i64 + 1)
            .unwrap_or_else(|| panic!("{id}: constructor"));
        assert_eq!(key.object_domain, domain, "{id}: domain");
        assert_eq!(key.operation, op, "{id}: family");
        assert_eq!(key.name_length, name.len() as u32, "{id}: length");
        assert_eq!(key.name, raw, "{id}: exact name");
        assert_eq!(
            selector_digest(&object, &key),
            Some(expected),
            "{id}: keyed digest"
        );
        for (profile, mut scratch) in kat_scratch().into_iter().enumerate() {
            assert_eq!(
                selector_digest_into(&object, &key, &mut scratch),
                Some(expected),
                "{id}: into digest, domain {domain}, scratch {profile}"
            );
            assert_eq!(
                scratch, expected_scratch,
                "{id}: into scratch, domain {domain}, scratch {profile}"
            );
        }
    }
    for (profile, mut scratch) in kat_scratch().into_iter().enumerate() {
        assert_eq!(
            selector_digest_parts(op, name.len() as u32, &raw, &object, &mut scratch),
            Some(expected),
            "{id}: parts digest, scratch {profile}"
        );
        assert_eq!(
            scratch, expected_scratch,
            "{id}: parts scratch, scratch {profile}"
        );
    }
}

#[test]
fn selector_sha256_independent_all_lengths_and_spellings() {
    let mut cases = 0;
    for (table, answers) in LENGTH_DIGESTS.iter().enumerate() {
        let op = 3 + (table / 2) as u32;
        let profile = table % 2;
        for (offset, digest) in answers.iter().enumerate() {
            let length = offset + 1;
            let name = vec![if profile == 0 { b'Z' } else { 0xff }; length];
            check_protocol_kat(
                &format!("length/op{op}/profile{profile}/{length}"),
                op,
                kat_object(profile),
                &name,
                digest,
            );
            cases += 1;
        }
    }
    for (index, (op, profile, name, digest)) in EXTRA_DIGESTS.iter().enumerate() {
        check_protocol_kat(
            &format!("extra/{index}/op{op}"),
            *op,
            kat_object(*profile),
            &kat_hex(name),
            digest,
        );
        cases += 1;
    }
    assert_eq!(cases, 546);
    println!("{cases} independent protocol cases; domains 1/9/MAX; four full scratch profiles");
}

#[test]
fn sha256_block_independent_padded_messages() {
    for (id, padded, digest) in BLOCK_DIGESTS {
        let padded = kat_hex(padded);
        assert_eq!(padded.len() % 64, 0, "{id}: complete blocks");
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut scalar = 0;
        for block in padded.chunks_exact(64) {
            scalar = sha256_block(&mut state, block.try_into().unwrap());
            assert_eq!(scalar, u64::from(state[0]), "{id}: scalar return");
        }
        let expected = kat_hex(digest);
        let expected_words: Vec<_> = expected
            .chunks_exact(4)
            .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(state.as_slice(), expected_words, "{id}: final state");
        assert_eq!(scalar, u64::from(expected_words[0]), "{id}: final scalar");
        let actual: Vec<_> = state.into_iter().flat_map(u32::to_be_bytes).collect();
        assert_eq!(actual, expected, "{id}: final digest");
    }
    assert_eq!(BLOCK_DIGESTS.len(), 24);
    println!("24 independent generic SHA messages; final state, digest and scalar return");
}

struct NameLayerCase {
    id: String,
    op: u32,
    length: u32,
    raw: [u8; 128],
    result: i64,
    domain: u64,
    canonical: bool,
    // Constructor success carries independently specified normalized bytes.
    normalized: Option<Vec<u8>>,
    direct_digest: Option<&'static str>,
    parts_digest: Option<&'static str>,
    normalized_digest: Option<&'static str>,
}

fn check_name_layers(case: NameLayerCase) {
    let id = &case.id;
    let object = kat_object(0);
    assert_eq!(
        exact_name_canonical(&case.raw, case.length),
        case.canonical,
        "{id}: canonical"
    );
    let constructed = ExactNameKey::from_read(case.domain, case.op, &case.raw, case.result);
    assert_eq!(
        constructed.is_some(),
        case.normalized.is_some(),
        "{id}: constructor"
    );
    if let (Some(key), Some(name)) = (constructed, case.normalized) {
        assert_eq!(key.object_domain, case.domain, "{id}: constructor domain");
        assert_eq!(key.operation, case.op, "{id}: constructor family");
        assert_eq!(
            key.name_length as usize,
            name.len(),
            "{id}: constructor length"
        );
        let mut expected_name = [0; 128];
        expected_name[..name.len()].copy_from_slice(&name);
        assert_eq!(key.name, expected_name, "{id}: normalized tail");
        let expected = case
            .normalized_digest
            .map(|hex| <[u8; 32]>::try_from(kat_hex(hex)).unwrap());
        assert_eq!(
            selector_digest(&object, &key),
            expected,
            "{id}: normalized digest"
        );
    }
    let direct = ExactNameKey {
        object_domain: case.domain,
        operation: case.op,
        name_length: case.length,
        name: case.raw,
    };
    let direct_expected = case
        .direct_digest
        .map(|hex| <[u8; 32]>::try_from(kat_hex(hex)).unwrap());
    let parts_expected = case
        .parts_digest
        .map(|hex| <[u8; 32]>::try_from(kat_hex(hex)).unwrap());
    assert_eq!(
        selector_digest(&object, &direct),
        direct_expected,
        "{id}: direct digest"
    );
    for (profile, initial) in kat_scratch().into_iter().enumerate() {
        let mut scratch = initial;
        assert_eq!(
            selector_digest_into(&object, &direct, &mut scratch),
            direct_expected,
            "{id}: into digest, scratch {profile}"
        );
        if direct_expected.is_some() {
            assert_eq!(
                scratch,
                protocol_scratch(case.op, &object, &case.raw[..case.length as usize]),
                "{id}: successful into scratch {profile}"
            );
        }
        scratch = initial;
        assert_eq!(
            selector_digest_parts(case.op, case.length, &case.raw, &object, &mut scratch),
            parts_expected,
            "{id}: parts digest, scratch {profile}"
        );
        if parts_expected.is_some() {
            assert_eq!(
                scratch,
                protocol_scratch(case.op, &object, &case.raw[..case.length as usize]),
                "{id}: successful parts scratch {profile}"
            );
        }
        // Failure scratch is unspecified; do not constrain its contents.
    }
}

#[test]
fn selector_sha256_rejection_and_constructor_layers() {
    let mut cases = 0;
    for op in [3, 4] {
        let refused = |id: String, length, raw, result| NameLayerCase {
            id,
            op,
            length,
            raw,
            result,
            domain: 1,
            canonical: false,
            normalized: None,
            direct_digest: None,
            parts_digest: None,
            normalized_digest: None,
        };
        check_name_layers(refused(format!("empty/{op}"), 0, [0; 128], 1));
        cases += 1;
        for length in [127, 128, 129, u32::MAX] {
            let mut raw = [b'A'; 128];
            if length == 127 {
                raw[127] = 0;
            }
            check_name_layers(refused(
                format!("overlength/{op}/{length}"),
                length,
                raw,
                i64::from(length) + 1,
            ));
            cases += 1;
        }
        for length in [1usize, 63, 64, 126] {
            let mut positions = vec![0, length / 2, length - 1];
            positions.sort_unstable();
            positions.dedup();
            for position in positions {
                let mut raw = [0; 128];
                raw[..length].fill(b'A');
                raw[position] = 0;
                check_name_layers(refused(
                    format!("interior/{op}/{length}/{position}"),
                    length as u32,
                    raw,
                    length as i64 + 1,
                ));
                cases += 1;
            }
            let mut positions = vec![length, length + 1, 127];
            positions.sort_unstable();
            positions.dedup();
            for position in positions {
                let mut raw = [0; 128];
                raw[..length].fill(b'A');
                raw[position] = b'B';
                let mut case = refused(
                    format!("tail/{op}/{length}/{position}"),
                    length as u32,
                    raw,
                    length as i64 + 1,
                );
                if position > length {
                    case.normalized = Some(vec![b'A'; length]);
                    case.normalized_digest = Some(normalized_answer(op, length));
                }
                check_name_layers(case);
                cases += 1;
            }
        }
        let mut raw = [0; 128];
        raw[0] = b'A';
        let answer = normalized_answer(op, 1);
        check_name_layers(NameLayerCase {
            id: format!("domain-zero/{op}"),
            op,
            length: 1,
            raw,
            result: 2,
            domain: 0,
            canonical: true,
            normalized: Some(vec![b'A']),
            direct_digest: None,
            parts_digest: Some(answer),
            normalized_digest: None,
        });
        cases += 1;
        for result in [-14, -1, 0, 1, 128, 129] {
            check_name_layers(NameLayerCase {
                id: format!("helper/{op}/{result}"),
                op,
                length: 1,
                raw,
                result,
                domain: 1,
                canonical: true,
                normalized: None,
                direct_digest: Some(answer),
                parts_digest: Some(answer),
                normalized_digest: None,
            });
            cases += 1;
        }
    }
    for op in [0, 1, 2, 5, u32::MAX] {
        let mut raw = [0; 128];
        raw[0] = b'A';
        check_name_layers(NameLayerCase {
            id: format!("family/{op}"),
            op,
            length: 1,
            raw,
            result: 2,
            domain: 1,
            canonical: true,
            normalized: None,
            direct_digest: None,
            parts_digest: None,
            normalized_digest: None,
        });
        cases += 1;
    }
    assert_eq!(cases, 71);
    println!(
        "{cases} independent rejection/layer cases; failure scratch intentionally unspecified"
    );
}

const LENGTH_DIGESTS: [[&str; 126]; 4] = [
    [
        "7ce27deaa1d5b29ed0930dd81a91dfb693a67183a64041129f9f7c0741182560",
        "3d6794eb7a8c78b2d43d144517ddf694a1ce539324bc5e88387f7b0d3a97c0e9",
        "ccec47b7fe8097ecf06f52707073910a3f928562ac7d5bb6acd00d16022d5236",
        "28eb0adf3d072da787f1faf79e8f0dc55ab51dcaa1888feedfa0f97ea2a612ff",
        "ba060ee0b6b98a1ef32792a13a3e18ca97d460ab467fc8bd3070d348c39cb3ab",
        "d7bee5440df760652514b0af8c3a3ff3b61b07017f1c536a14537ef78cd92349",
        "95aeebba284d9c5777552301388cc151482e8430d0630ed9e0a3e7638ba6621b",
        "f0efc17db624ac12d2907bedf605eebf9297ecdb83416802bf6789396607b509",
        "fbcd881f5d55bb3ae103b0d1b0da06bc5af6015288ea230c136ac656a48366de",
        "02af97f9ff34898ef1146f0c1f0ab1273f05814aaa65bd5e5f65a4c2535feca8",
        "45924c9432450ba067e78e8c74e69856f334301e4d6fde145cc2cc88f323c9ef",
        "40daa434a1f70f20d8ea0589db5cbfc473d19809ad1e3ad29eb6e1b7951581d8",
        "b24abed40edb24caf4db0d8596ff8b0e3e6ad41629e320ef58b1c3949f8a29a9",
        "93fb99abe534fd53623d35395fa955fc1f61799f88eec962d087438f798fd561",
        "3126212d335e2baa75dbb616026591959a25f88c650090240cfeaa6e6b9382ec",
        "e821cf62ec573be78ff6485630c56b9aa4877b82bbd82a4f8bdfe79e5204a585",
        "83d225c6fdf6bdcddf40e2f1e7216619203443f417a78cbe4517c7ff5d85dfcc",
        "8bddb406f7b6194dfae193fe8571681972806ed7fb4fde98ca05649e0f76ebb7",
        "bf7efd626a14232b02dcc060c9e32618e6faede6fa1d2b4b157430651a64cc2d",
        "290168699c654a1a73c5303209f6cc590a24d0b8a984cf4e02ed68add4b50c93",
        "eb578bd33d6b54eb3f05394b7b0def72dd55b7fb79aca388cd1906b80a5341c3",
        "c941096f865f487e251ed40737bac8d9b39a47d56183d8b6685387422d998fee",
        "6732081b4823813f3b44f2875af9164d2560daa4ddad7f2c6f88b5249fe7f00e",
        "5c986cef6e2eb8bbe6456a9558e3938574e4a090cbaf9759e2052b19c3c683e5",
        "7bbecf2358bd5ee9d3d561d645581cf5237b367abe20205bdd1dc1a172e28479",
        "dc968d93b3b05ce9e5468344afe7244d03eea7e792b860b853b8850b05831bc0",
        "3152ba6e403b3016d10dc972401d8b9561195a65bddf5948291d79fccba753bf",
        "d986610e4c329072b534cd979745431fdd0c26165df9007bd4211b754f2d20f0",
        "627ac8a85117a1f7b919899da98be6712fe845f13419d9159ad2bedfd834c370",
        "04cbe1017602f19d292c79408ad39689c1d142a0cd7b65749d06d99bbf8452fe",
        "642b3eb2dabc658466eea47223f690fb711264d4bca07af3a5aaa07b3c56b79d",
        "ee684e89dcc6825182c11dc4ffd5a61923cf958f014befc3930be55cb117cd74",
        "7a7cca256b1f622d6f69422702f6c151f7ec2ba57ed353d0f5371cdc6e55f702",
        "a7d619d721ff88db97a25ce35cb3b5f21c955e882c654faadc2e290d0e50107c",
        "10922eb2b874b2343f8f53a1cdeec899209bae8a5d6993a05581542f5e507e94",
        "a0f9c5c9d68515938f09c31cf091ab81da0a226e0f07066f1293b4cb8bac0bbe",
        "81cc84953a0bdac75b9523f46bff45dc21c04d62a0ea43b5f9eb72eea8acd482",
        "5050058d5312526b34440c8d33c04f5c35f4db57e8b7ace3cd61a653b41f9cb8",
        "412c4983b3f97b53757c9d71e07769a3a9b8bb34c8deba0a246a31464dc9ac90",
        "9f27ea9664037dbc9bc0b08dbfb73c920f0635d6747e45a151aa1d0cc0d23b2f",
        "173675d4d5381d7cd4e3abbc34f5d69cd70668034141ce413da30b2653ebf5e3",
        "1031018e1b4e8aec4861abf6bf9509a923ce8d89a1067baa9152ac1f8beb1d7d",
        "fa804e9ca74debf1f13a5a6826b949a72054d2c949ad6c9c8a78e84763b36902",
        "97a4112dc892e88f5381c93f9e2b75bfda8f1d4259e7bed8f98842641f9dad71",
        "a94fd4a828e7cd961f33d826ca38576ece3edd348f845c2ffb5bc4171ee943b9",
        "b7654f4b36e5bfbf913cb4e1a9aa69487495b982b61e1161be93b5f0ca45599a",
        "ca63dfed752b1cf0c9f5e422ab71cdf90af644f280b8f5a45d2da4deda1b969c",
        "55fa82df338998e0efb29581e19a03783960db134ae15eb37a9ee299a166d9cb",
        "5385399c93b4fbc39f9adde948cff5c519b8fd8a7a405513774de2f2aaed1eb7",
        "c90ce02cffe9507acc481dc6637a09227c0718de9b65de20aa30f296da6296e5",
        "c16e8da2482817beb47775be9e5e15763ae14815e284942b9869f2b1f19fc579",
        "cf93d9341e0fb6ae01db8ea5a3dd649bf855730873a7d455283c58b5bf935681",
        "6763ae27261726521a981212ae3d4ae9f1d1003663dbe0720e633ceba55f92fe",
        "514e6262e144e6f11bd94a208ee6dac0419d0585872c19176aedcef7e8b664c4",
        "78cab4c68ff955bb682c82d2fa8e5b9ffb583ab506b82de911ee6badc21d8bb2",
        "63eb18f9c989a006147aa7b961b5677a5868bdfea6f721a4a2c0d8719fcc450f",
        "4ed5214af7bef2a6c3aacbc6c68c5970e0f6cc4f89d4af1423c2bc5f8e5218ad",
        "f93b8315e416451539a3b67ba0bcfb31a504a684b5374bbbddc7a60131c58894",
        "59aee5c6288c6d068860652094b42c821274de42a7ae6df83ed2bb7a8b39db32",
        "71e47963af2327cafbd02bd2cef09fa4d6dc252a52047cdced4375a2e1c1de66",
        "ae1b3a56a2d216dbf02e00035f8914adb41e29f3ead5d4f852761f9b96cd4a6d",
        "782492659b7c7da13d427ea1f5625195dc6c876694d5009d001d80607fb8dbb9",
        "fe3b2f8563b6cde460abc680898597e10935a083b0d7704a5ba72d4c5ba8a998",
        "d31e76b988bd0efe6a3541313ab9556550e79bf72b931ba9d29e0501cf724519",
        "4742fe4138ea94ec80d19d9fde44fa4c3fe63d940152d16132c948d16d2ca4f1",
        "ff6e99cde28c21ce8a5b0c46bf1af923a354715409731c6f6100b0a17456ce3f",
        "85cba90f9411f52dfb461fdec558aa5927f3301359ce8918e610907e36df9fb5",
        "2b594de1f18f22e9aa52a8913784dbd26d61ce59ef487b7e30eaf816800ee09b",
        "0de0cbfe52b421243c9f941ed77bc76cfda2f53c8a4b24cdad16ce4d8f75c792",
        "3be6acf48aeb8e87b44a3e7d52daa6aadef98d4f3b68f5314cacb92879e66d97",
        "eb67123810c0f6b0db94991694893304d316114283b2d1ddc02496c387fe58f7",
        "d0855dd531de3fc665cddab2861679901ef6d84fa455e1a42384b1aea7fb4634",
        "4c1f0da23b840bc896caada0946ad1724fe2365a418f544bf5a98585cdc3df89",
        "9803ab0b80b27cd9f2411ee928d0074251ec8a7a92e2e37c09f1e49dc2c2a39b",
        "b8cad499421abc3dce12059d1326d5d989cb35c1f36571cb7beacd1703886d98",
        "9d69d0912324f29eb185fa6e62b5e8c074103bf2886619f0435d1d27028588e7",
        "e0bcbe350cf5111f6e6799e1481b08e8b16e1042943f2aac05f8eb9cb4570356",
        "f5f461e8e04e601cb947f99005ee5797dd2e438b48c35b77b053064be2c594cf",
        "e057a4db1f9b6c329425844631d564465e4e0d70858538a197c3d52cb761c934",
        "5d21903117057d1a3a096d8661c376d7035e2ffe67c4001a0a92395fe2836636",
        "3b7cbb9cf0c2e600594a63bc2720b5e891abddc07d70344fe32a9e8c1e4f980f",
        "efe7ef196461c729e837bc46499e760199528ea5acd134a085ad5a926714c3f8",
        "ac6118416aef9f7768f2fd6786e3d7ad84edd01c18a40f8053a703a284ad2d8c",
        "d3c23dcb078b584ef13722c80eed4846c8ab3b2616ca74da464007f19c880901",
        "937fc031debad67de05f5eb1098d535617d4e62d23a7fdd0bb7af629640114a3",
        "800eadc71888680dc741c83ef5df39760e537221df6b943a4d069ded23549c09",
        "6aebf06ecb2ffe0f788d099be676e1e3c4702af1ccf783900f62f8aea1579a00",
        "639a8ae85ad990af71535afcaf8c782c4a52679d2b7cfae3dfa4f80593065d49",
        "420e9b966296b41493ad4408778017bc1281ae50f471f53ffb893bb3cd99e3e4",
        "5d8e1be98fef5edc98c66b9810b26d4db8ee547a994c26f7edbb437c4c0fccc6",
        "f2e89defbff8b420f222f4c2e33b5207a135d790d530c45d29ae689957ed8531",
        "e6b8a894c4fb44fbbd45beb5048b95ab2ff68c9f6b9a7d06a6fe1302b1684765",
        "1d9507bcbfeec4c212a4f7a546bbddedc473664c6839ccf8ecacdb002c02a0bc",
        "cb9f07433f69da160fff88d3ced4a1ee11ab86fae89ccdd69e5ccba7356d6c97",
        "8031bf9d5e9ea31fb02e75cf70bf42bfd95fb74397b69196c3a61bf17eb3a35a",
        "08234ccd5250e46ea42d721a48aba010eccbb1b636a2da67d19e7794396f08b9",
        "b26d8b3f05e098fcfe57f171f374cee6aba178863f2d1c00e92e88b556cf1d41",
        "b923b2357771a3de970a84606183cb0ef7c1e9fe1a047d3e344af4ebfb84c1b0",
        "a12db64e02cc0506db0d47c1a788b1c18aaef921c1b30aa436d5befd8404c91e",
        "bc57e3bb0ed8a0987273513e88c20053a386b977181e8a2368a18799f2812b1e",
        "47565c80f70ff041d41ab2eb327d09357991a66aa05ebe46045d5f185bca6310",
        "cf383dcce21427e08cf4ab71ad326d3a1645154986eb01de376fff60be4d953b",
        "2d32db54c593552b21574fe547bb4e17d330274dd203a864620d45a60fa51f8e",
        "5c0bc8e92e09139fa066a5b058c886a710d9ce2370dc933d60848c519b784d1f",
        "3fce6b0cac4306c3ee449cc8ffab6a43c12b5469cbef9b34ec289d2a454ca9ed",
        "a8015a7bcc0b9bfc7053b1778e04301f322758c6142c26273be3e48afd12c854",
        "8663f1897c4c5efc38f39c96c1d0326a600433ed71cb0ecb42972f7937cbeea4",
        "a8e7bdf12ed76718204158330ac39648e0d00778347685b2061d45d81c759a51",
        "1294ebef7baa62324050de97234bdd4efb2f919b4d7835ce848bdabae9de6855",
        "2c21da7a23ae63b1003267c9d0344f8a66a9a6eb0c7a1aaf116dd273c186beb9",
        "8b899cc884bfefa3484b2bdab47b2f7f9c22368d7d0c17f8fb5b6a6aff1f7744",
        "dd612d0bfe6f5b5798b598866bb058de28c4cca35bb3f285e079dc79bb18210f",
        "1fbbf869415ffa226f67cfca1cd0f8e782e5036f12f0320cdc6aa369968af3d0",
        "3573fb0f6bcbb8dec7e670f6155f8b8f6bd65f322f18f3585fbc83b358431f23",
        "293149548a3b3561fb984c88a7b7a0c318ce86be8f6edad65060131b75433f9f",
        "d3ea570c9d0a70a2db691ccef76055e87a1b20dc20ee58c4a7c096699865f4ed",
        "1da49d43f1bfc0ebd480edff7b814c71f79ffdd3e6695385880a7311a5adb5f1",
        "f7796d17ee4a14bf3d5d99961cd1e66b7468079dfba45c58abb305ce56c74ad3",
        "d150c1e85e98e5585c019fe779c6320fa0f0cef4f463a14433ee5fef28383bcc",
        "26df3e9481c10d5bc5a5001a6cdd2f7d6d58cb3e3b3bd98c54bd86064de32e75",
        "a9ae7340cb349f3835e17055d7ed260492db40dd22652cada679562bc72560aa",
        "70adc4266e097ad644570ade2e452c870d66abbd94810a7c31123cd479d6319e",
        "55ab854fad031338e74f972601445e6510122cb7c97a6d98d4893d9eb8e174d7",
        "c6530c4221e9ad0297af2f23aa12cabccc94d1dc5b569ee216a6c5bbbdd89d0d",
        "7a37c7346de08a4062c3208f769a6ece62edf75c477012871f1ea8fc835becfd",
        "84c764603236968a37aed686bfcc7f5341d5d0458076bac8330a4e33df6f69e1",
    ],
    [
        "85298cddbc7b8f914cf86f3df8568073cf182c8b4a7e5012025a9a6002ddf447",
        "d4b4ce2194f1b3be56d8102c5b81ea13fc71a75137a49f2df9273d26ccf10f0f",
        "315cc4aff0d1c2415562efc0faf0b67493aee3def7ffcb20331da723e5dbe3e2",
        "56d543f310e53aea9b12528d94a3998ff592abe83f9ef27eee2392114f9955fe",
        "f83cab57acb8d9903f6a894f98b1572ee0a4ffc003cdbf77c10fd20af14d6874",
        "4e0baceefed86d5221268c5dfc8a27425ae09107ec75bc38ed99e006a8e9371d",
        "b1bb031d143f8913254471f984e12345b618ac8125893f6d4c18458db43017b7",
        "de3fdfed063acc4eddbd4145427eb66b7b44efd7775f8aca91f8912fcfb21491",
        "ec32047c124ebddcfaa7744cc9b5321be8ea8decc569080366129ccb74e457e8",
        "12aa0edb7827099a7b3e1ae08648f10007b28f1341fdde3e62cb94b535256d17",
        "82b0890dea8f4c5a8cca80e362a2d42dd01c8dc11ba5cb9e8b8b1d527dce03c1",
        "df9011e041ad0b8f587078a0172a548efd943833ae795fe47dece92b63858bba",
        "20192d79113eae6778fb6cfb3967c0fd477425fb8dc6580469c577ccd7afa593",
        "878a292c36a328cd6d588163f6187935321ac630cd49f8bcc7f0765f59e30ccf",
        "be522a760dfdbb785270a09bc63c26b36a760c469ad327dbb053d9f040aec181",
        "a8d81834b5bc8c58c9c161cc7b66349e23f4bfb520c117745a9e43fd00821afa",
        "f5c277fc1cae2af49c59ba32beeefbf1b420fb19939ece01c7e89442ce7b1b4d",
        "91874ea629325362632551951de547a75003a79c57d8fd2a1850e20782edd84f",
        "aa0fc435bc47575245d35131c0a05b2c4007292fa628a7c999b5cd1b836bdf5f",
        "0033b96cbd1f73fd59d72544c05c0ed96968c184132718d307ecd011636f55bc",
        "8be9a30e14aff631359c0a3ed0d1d14c6b7edf1c4af4590477c00c31261b0335",
        "5c93ca575ed09ade2f51dfeb45c3a8b40a5e66075a3a68f54a51e025bb1df701",
        "621bf92fcf868e32edcf50fa894bfead89d5e11ae317697cadbfa7bd1cd1b8b2",
        "9e623c38068484ae3391683fd25a9aa4c1cb1f7e34f8303d69f8c79fbb063534",
        "c46ef56461384f52128d7ca45652a8fdccc0881714ff16cb03012bdce7c4b77e",
        "46dba57d5a6dec35fcc08a7c728e27445df4eb47865166848abcab09de8e2a8e",
        "5cccb50b9d92480571970c9c0e07cf7accb64f07505caad50b3ab64de1b9a0ac",
        "6fefb2bc8f7415ba72f660776f7385ae2ce13a26ebfc0d1cfbe211d1109da279",
        "1a527b205c2bf961167fa13849c789968795c58b573a825dad08dbd316f23cfa",
        "5e4d1505fc544b52f5905858d52a1e674bd9538b934eb239c922a07d42adcb5f",
        "49a2a3aa10b6eb9a557c9a581c83fe05d06b8e803362c4208e877fb5cebfa54f",
        "dc467a5283b3f1b4738b433702280b05115ae250bd47764f8740246361efd88b",
        "e90c18d1022444261ddf4139282a8a223f0ade00ac03d06bbbc23f94db4bb582",
        "d7371d3559f0075dccb90ef41487b9d8eb18291f47c6a3224ed43893c6da15e1",
        "cf3741136314a49f989756f1a1e2c55bfe0ed50a569083cdf9563a6ef6243932",
        "4a0b02044f07a251f732281a87f6fc3e4cb7e01db30602a432570932b287d32d",
        "07d9ab2ae86297456dcf56bc8a449b11fa20ca327fb5f1a6292a12b6ca795553",
        "0ca9c00eb76788c38b974a904b9950315f4a5f0000d5dcb37ff717e195a65711",
        "8267baeba919453fd90ba8b7ecdf793c7bb861b03bf45ba63144de3ef8d018aa",
        "d7db6436ac0d3bb3228bc04cd0dd24699d2468868bae3d9ee7e8244658a89ff7",
        "6d2a9fc27ec61d69ecb391d4eaee4cacee2b39d31dfee5ec8b217a71ecb7cfa7",
        "b368f63ed6929ba6ea47e60b0f2bd8b0746a10304b7bdf5f0d29027f030a7183",
        "3a0e7e487bdeb53419132cf107195ea9b7aec8ba617a5fcba36aebe7d7412396",
        "6e79eab933fd5b51a9984381f63b9224c32725288c7af8f84050c0f798b01974",
        "263ffd5731ba2c1ebb2083cda567e1b708025e8fe08b0d602381b79e18b47d79",
        "fd06dac43ba413ff65f06aafadd56cf335241f347b85d88bebdd1fd9d32a83d0",
        "2a0523cfd24eedb79d5dffad864c380b3c9c174641df72ea7d6b5f6f71dc8d1b",
        "f63b45f08a5dc5fe01c4e304c7ef2c53727e91e8357aa354a900e5b8e28a64b0",
        "63c095c0e45f3dc14b50a0f199545f3727065a82096c27fe976762dd2c7ea1c3",
        "532307a496115267b4a4a3c1442ed317a898a9693841c81b52fcd8d0206e8c3c",
        "fd3351411195a2c63658e2666fcb747f0085c746521e8ee3fdab2f1039ba79ce",
        "7326c1ef93e2711d9266c8d37e40559da8a8b137a320242992ce2cc0c8a14436",
        "b3fa747810dd2171dcaaeb9f4420b05b9d2ea6e523997e769a64f855f2d3120f",
        "cc85bdcc55c62f11d69528457762813f1c53bea4f20885276876d7ce0c03d3fb",
        "6977a18fcbffe92522b41acc65941b8fd309100fafe4ec2532ca0cea1ba01704",
        "f1dedc84ae1686f984a237dc519f13b79c0928c44550c83f96f227bce3ece8a8",
        "b3f36716c9b015288c5bf9aede5465ab789499f16dd7f8f896520b027ec2969b",
        "24a869e4ff9ef36625a9fb28a66f9d49b7f8ed58073a67e033997877621bdc7c",
        "6f9bb24f57071b6743f573b0a07aaf73608c84331b92003e387ad61e8c0ccb9c",
        "c77853e20fb4d5590d95b820408d0409b46871b2f970efcc19340a4b05ae828d",
        "1c30e85ab498511aafcd115d60ec84e25ffd81b45bc1ee5245fe4dca47be77fc",
        "799fc8dc04f3d1ab5ab528ba97ef2fea30f9159e3ae6610c90370fd08cdb58f1",
        "b0fb506246f19967d78a62ac4dee17a31e467829e84dcacd98ad0eca328d0e07",
        "820094803314b620f8dc1f4b1156f91763ef78ba00862592bf22999546c4942c",
        "e1cf0cf1c61d0a851e5643118882208396f306e7bdebac463e74ebe51037d53b",
        "8e23d0dd45f3062740c98ec55a2d6385368328d126d348f7fee03623cd98dc24",
        "0f516d314f7a8f00e7c32b7fbac5513086c2aef7cf88e06261343021a2cebb0c",
        "8b99321e3b13b5278343055a66e0038d6a6b718731de78752ea1727b4ac40332",
        "cc9c7aa8a9d89339b79593ca1ce18bd735b0340f96376be0292c6cd6f4398914",
        "49520b07e45a6af4c84b7e390822f1ce6bb1721c603b6eba96610147f28955d3",
        "40d3e03a6d2e77ef9ee26a9ab713f6d728dc1acb5adc5e2398ea7b3323bdba6d",
        "b16296364436362dd2c0a1d05a7e35af33bcdaed2d267b5a64a927ec27dad7ec",
        "0ac37dfe312b70c7e34b594f1c4a4378046a89a3be21159b5103b594f95c8e97",
        "ea2a8bb0e1ec85341939750485de89094d1aab22b59c5451e1418112871b5299",
        "1eb99f40865e808186028d7f24c752bc3ccf502fd226d7df59d69957cca1340b",
        "2538d93cab1e48945be14368b68ef51a9f76707cf8ce792fd100c4becb0e1b96",
        "cc092058e222c569a983ea5ada562517e4ae01641a980561ea72c1ccc42f3765",
        "184f5b829c26cc9606b913121ef0ecaa2fc25213ff7019e519f24df1e46c568d",
        "98b4284bc0d3a35ba8d4d0cb2a63cb21be6777910cf5a54f281a4696adb8ab91",
        "f532b8369e9a4c5c80f8ef9ca3b4e8c9d4ef7d37cd1b3c9b86ac4b69e3011c50",
        "da1470f004af5feefe0a77d45415804f0b3815352ea3f814d7ee2d9b63f70027",
        "f83691799a98221b231334687b478a908f7c606fbc4d1fa0040cb0eb6b9776b7",
        "b92fd335d5aba1b907d3cee723ce6ea31f359aef413ece3d99a1c73b3ed57211",
        "dce1f60445d60484cba9580d66fb3a0225e2f860c7dce22ce15216fd4a4a6bf8",
        "4c8cb28617ec841d8cecbca14c0b2508cfff7b8c9a2a3473fab0f7c1136bef54",
        "43c632243f5caa7555546a2fe75c9004a65a686ef71396dc11d260be945a1c4f",
        "7828d7462e6f15a178327e54cf4aed870e2d6060b823990506e2c62ec0aaddfa",
        "8917b01a5d1de0a7301c04b754b4b1d4411624a64fae19214b79f7bee49df394",
        "13f0421aefed65c7b74c6c06df7acfaa3da8c6ad6403d2c65b02a1b90ffeefd7",
        "9ff31b422579a309357bc83c9a133e1dd0d400154cca4d6c94920339c6608d66",
        "a8b2472fd64f9dcbd983b7e570bfbe3f2ce6486cc67da748d66d008cf6525aa4",
        "e4709d4f0be103b437f8a7738387955113bcc3fbd38337b6d644e7a84ed87646",
        "f844e646f42c7d2fb6420c504ba30f39586f082d39b9bad3b873bda4359fe06f",
        "6a1227f3c20bce319f94b2677b74030bb77b994a6ac99b101abcd724e08328fa",
        "168e765ff8e9d9322af9daebf3fb15b477551faa4ad7faf569162608fac25f8e",
        "286148e19489facc53748738c3c916f65abeaef9207c26dc94838140dce02e03",
        "478dec7cec62a7c93c71869d82a26e6a5633d1e79a4921cf438d57470f41f97f",
        "f4df9e14de2a8ecfc8326ccf9b563c3a34c423d8bd22955441d9dccfece057b8",
        "f15cb08299d6330a55bb076e481b6d342995d8a65d7047a2813d00f2fd12186e",
        "1b3783079799a0ead3fc81093c9d2f1efdd2ac321e7ea0206d324933ccefbd4d",
        "dc80b4727134eb174edf5381518fc51fc3c9f8ea9a3aa32ce2ad95ae0ca883a3",
        "0f74e2b207d443c0e75eb28ce163cb087a192fe80eae8e690d1dbf14aec00dff",
        "73daff43a2aee3801d66a42b7ccfde357be4958f6215b154ea939aaca44db144",
        "d51fafae9cbd1028ff1d1af25d124bda9051cdc82f014925a52534573d9d28d5",
        "26e97af019df93520e02342d0b95144b9594865d79489410ffb1d64eebbdacca",
        "41a10c179794e886635ad5216558047baccd29a11f8084d87284262fdc7ca97c",
        "d14bd2a6987ae3f17c842c4d0058c2816bce53a46fd97f9cf5e0ec7baba56bb3",
        "04d8b951b63891c9831cf5cae15ffdf81747afc41874dad0ac182d315fbc06f0",
        "fe67585568da7249030d1e36bdc68352534a6a81528deceafe8ea1c2ab04fbde",
        "087a1e14449c6e1531ddd577050dbd41b63ab9678778e087c2abcd1ccc43495d",
        "7b82924ea73042ca83f028ffbaf5db83bf58b1ad4f0d09f716d61473556b36d8",
        "8c23cfada463843ec2d7db63fa4182d4995a5bfc3617cb4d77963d3193ec88d7",
        "58de8b74082fda055b6219a04b2b347ff086979eb6bc18bf41c0e87330aa652c",
        "56f431b870f45820ebe8cb552dfc10418b9c20740a138c243d14ffec422a3d06",
        "36724feceda8e3aaa3040a663199eff1361af3fe9c6a52461b5ba595b63f839b",
        "7333252a50e947bbd2ea49f3b9a03358ebbde8398a368706b985961a2afede53",
        "1fa6ba84c5813d88ecfaaaa4f7b6975c17cf076b071308c5eacc074614eb536d",
        "c2bbe899466a16cf755af6f106d469aaf720cfe3ad6c4386f1fe04c220d21cc7",
        "112f47508b9c825a10693ac1c7c58c607201a42c99b4d444c1b4f089d1bcd971",
        "dc8a59de22f2434bfcf52f96ec6c1cb93b946f096e6cd04bd93a0465e665207b",
        "75184569485590fcd6cde0c8e231eb2436661800350740bfa698fa0b45a79621",
        "91a9dab8da1b9cee0ebd3964197fe7c5f729ee2031b08a61ebd24dea61a1fdfa",
        "0f9f290720abbe586e9f20cde42a7e75b3daee6eac3a9f887b3419e9a4d82a60",
        "d49d7ad589c58a07f62d25e94765f69d9053ea16a85fa9803bc6a8b37b4c164d",
        "5899d0172d13e8088729d39333db532a2d2eba72c9aaaf66c9f7d00740af82c3",
        "57200b2f1c72b15f2e29ffe452f9406d455cc5188fe14451aa76b94e36e7e5fc",
    ],
    [
        "5b38a8adbdf6f5b8de79774c43fca8d2323e5ce208cd2cf65c49a13a1dc26c0d",
        "9bd8c432e648e20cc141e4035be7cc660746679928151905349958dc777321a1",
        "9ff7feec5637ca3e589779e0c8fb61608fe48637696c39daf90409846e4d6d1e",
        "87a0b20dd671c6800ff1de3858ae8541b68b3e8b8a429fd6e309d4454681c660",
        "756759560d96382790766249480dded1e125b892bc7841e5d2a8ab9748730e10",
        "6dc8be28b4693ff7b7d022c55a6a4a20fa6fd59bfba021660b78abf7206af660",
        "9849b66145a2c6b746c2ec223867f871c5ee0a2dec12f48b2b93f746111b0495",
        "1117e6644c114b83880e0c3fc4b9995ae1209051cecc2946d15cee8e2dafedad",
        "be3c6d944d4290e27ab651f380144738e182f1ff4c73c8a87082637b431a2268",
        "19057b78634e4d9ca892dc035829d0ad4620a794a07d78419f5ae8be8b780866",
        "1d011319dac1b03ca1b82350a373a5e94d7deaa8914fd27e3fdd3cde622b4dc3",
        "4774bebb579204ce048c73f211dc1b199c615945beeeb5608a6728456ce7a8bb",
        "fb6a1035cd4176294f8a2bab9097f1e6fe2a753a73dbb3c386135146bec7d47e",
        "b4191b32dbc120d98324519478441a870b59b29c46504bfa54086217a251fc9c",
        "c0dc3760050aef12f8914a5b85a3186f255a1c899b617ac34dbe49e6d8d0665c",
        "a33a1d19a0b09f9383f7d98e068e6924dfe3307dc57beb2014168f331280cedc",
        "49930c2da51e439719c6e9d459551779486feaaaf78baa6146b4b8c49cd96d56",
        "48890473e70eb8e311f859e3c4186e5a01424dfb461fada1d9e2fa382be1e6aa",
        "1ff74fd12782e3d3ddf2cc771e76f52d087d15bf29fd334a1ae32a0f29da44df",
        "879890b31bb643882fa9e35b95824389b3cc95f96b9aa24c463be5c76f2b8b19",
        "d25f340377324e13038150443d9d5dedc3605a8fb69eca8ac5023171c6126672",
        "391bfae1cd8aa052ff0aead2bcaee5343116af0df40a7cd8ffebb7866056360b",
        "16dbc31f5d4466850c811c86880695de5361ff9c663f1cc8ae8feed2573edfbb",
        "62c441a427d8b0dfee58b715eb360a1d02b53a36e5fba461aef145ac4651db29",
        "9dd33891ea463d57fcc22dc930f43cc00b465ee61d877171516a2016a79093b7",
        "a0ec4c5542d175b6c13640d1fc222061764a36a1be37da9a5872893429ba041e",
        "25941070cc54d1e831900e224ef0fc46fba8fbb66e7c0a4e98fa0eb86531d12d",
        "4412eed7cd358f1d34a0ee08add04883d8b2e6b4843c3581b6db860aa773c26c",
        "e53b4170b9657793ae500176b0381cab68d6e344f5f6d95b39c926cf9c1da8a1",
        "eef44f2175a5deea1db6150bd19f8576d6e6860d77207382d250786bfa83b863",
        "c2942c4cc59189f476d5bc22a856fa042e7496a5fb642e80bc782cb790e1a81a",
        "9dc2082887cd9debebe78215988bf23f2ccb6d58e9b6863d3f1cfb19fd28b305",
        "b1a793a9cf39e71b599a817369b8abbdc3a8d6ef76611e2dea792f1a07e9f706",
        "80d63d6021f025bfbbc5a63d133e749422b0a464feb0235ac0f130ad55684029",
        "3580a42a6ad2c103c85106c6b4f91de1dcacf4a55f1da45316b0a246af51ed6e",
        "f525b8ca9de6ee12c9691cf8c7c45d8bc3e4e48e600e8f3c4a346bb0975087fa",
        "1ce3977669094bad378918ba01a1a6be4359b41a6c45bb8ce60fc85a042ae58d",
        "e4660bc5966225981a90c9a6422b4f99a6160f1f4c8e99657200ab1cce31f09a",
        "f22428014c529a139b4291588e6a4164ca2f75ea45722fbfc40c44e412b39707",
        "d88101fe8e83ea7a81ac9fbc2ac8dafe3cf5df2d1187eaede228f53db1607331",
        "a0aa2b9e85018737e4182449809227eb817b0555a1be0de5a30b46cc1c76ff2f",
        "5f3d5f4eb4fb6e1c94b99907b2fb39c991d768c86c04631b253dd804bfe5e1da",
        "be01091f1dcd9f531f633dbd3df75215ce3574fd814dd64e8def3d875cff2f92",
        "fde49b43e27c0f6e2d1038e0f660f7d1772bba4fee530ac29ed9fc33c63d9038",
        "bade3528172d778525ac9011dbf64147dadbcede21621e3fc9df6cc231f33909",
        "5d33c39408d5448383ff08ae55aa8e51469dce33439de6419f1f99cf2433fea4",
        "ef43bf80896fd82a1d3911a698e43e3829b769c89d38a0afe0bc6bbde4e96826",
        "3ce429978264c02424b3fbacf680cc13fe0dda4c18e33f16a45b64a781447b0a",
        "99ea7dd37951febeb4a91aa19cfaa670ea4e2851b89c012816630529ef7b8d16",
        "088974b78e91e1f78ec011500f612e689520bde589d6e68cd54ac4cd8ebfa1d7",
        "4540cf0faae4d519bea53ac0a2a8dcb2e4e9f715099461a7548408ffa12a57f9",
        "80949a14e1c249721a3f494a73f0e06209fb020ab854bbe5a056e0e1672da29e",
        "bc124755475676fb45c739b89c488f84a2521cb91de361684d0722e23b3dba9c",
        "e6da090250c2688c3dc4ac6b9f37af7606868c27dde1afd5689a0fbdc10d6c61",
        "883e97b7aebbe8323072316d47daf1c64fb68032e66d7f7ac4ec75a99bd6c40c",
        "e83bd8e2d601932f91ba269538fbf00f267db31b6c803f5817511fa8c75844d9",
        "139f09e219a572ec67efd70f289ca7ff2afbcba4c104ab861df4fd495c9b6768",
        "4cde83a09c458903e990c69ed744ac8e04727fc5bf89480668550bfc1e6c6127",
        "bb33ce772446ec7c820b0f492f1f66ade2e9c95eeefbd5b460a7d5a1803543ad",
        "3e4fb6454b8b569d816217b78f0f891f2f5e5f12306dca9519bf36a38eddde44",
        "0487a315c2418e2b38557bdda0e084d0be0e9759505d648879393d24609ebc5f",
        "ae9ec0e0f36b889bed0bc57817cd080e55756b7b080650058d63866e4494f040",
        "d7dd80f4f96825f735c03a834b0ad7891b4ac3c60e76c016e865c8be86568687",
        "c6bc2014eb275628d47e543f38925362445376bbae209fc6223efe62e719ee66",
        "9b9de42c18624079d90d54f4af6c037beafed1b6b62c90380a0550ecb09acbf4",
        "cbecf2426ad1181c3e6507f2213f4a7fd6082e91231cf1ca708562b561e3f5ba",
        "8eeee9f0001b614ab6170c8211febf0dcd2d60ab0defa9d3b915fc762f5718af",
        "52eb688540ccccb4111484b1e26f2f1a5246058a7b6c11a7e933a560beb1d457",
        "f075fb0609336c447df344b8ef995c8344ff7cc58f3c8713db7038208b4f142f",
        "468486a1d328f707f0d8cfb8dd2d7f711745c6770d94ed48d831fbdd3a079964",
        "52e13d45044454040528adb294a17135b6a7bf9002c7c19e3e4035e06c8bcd3b",
        "1c274606a9c3a72851ad07c5002d4ee0625a304c1e2274e9a383e211674bf77d",
        "03431d5047da36acd08b85cd08745ab4e17a8f137f2f7bd782b399aa75f3913b",
        "4afadc6e8d27ab957730e9289664f1853dd405c86eae8c1663c0216101ffe18f",
        "d3fee618e5f00f86454c3ee401888b950ceec2d62138df71a81bd0915a70d3c9",
        "d94f64119b75bf45ceea5cf998665c294ca3edb38cdc90c26ddf3af56ac67200",
        "4215c7c6dcfd307f167d7e19e9e5eca041a66d13bbd4f667d32e56db83718d9b",
        "4e22eb752a99bb2094d85deb855d996b7d53852eff9eda5498f5f2b2d4717d01",
        "b495f5830fe7b5d3903d05a00de689987d3d225ee22d642ed64c3ad03db62fac",
        "cb78255832810b9e10f558b00db087322a0c22f578bfc64f3288e10ca7475ea1",
        "61b4b0be70fc2176f9c65588479d282f2adab11fc6514fabb8289100d3f77174",
        "a13626bd551d488c48f9ab9cb3e73c073aaa7ab66c628b431646414b42f6938d",
        "4d3f757a0cd9984dceae55a8c8c4d26e8ae278f05ad1c676c4b398c95b594bee",
        "b9f64d9736f89dbd9ca3c782690b828c4648770f857f81d26b89f4cb99f11a27",
        "8e80cccf072076f5f848d469d7b772dc954ad16bff3ed7fdb3929813a1020c27",
        "0db257e47d52b414b8f1ab1dfa60bfaa54bc5506d7f5979c3661b8bb4d76f5c9",
        "f651a4c4ce4eaf9bee0d20d74c9c3f7d198a93e032258fd3d1554bbd6f3db27a",
        "040ee3c8a75061c1dbfbd1f5fe3ed6076da36f73f84fb2df2b5f2b8fa774d650",
        "9b93507a45f54faa5f9aa69b127aa0fd5e158f50526839bf3ce6cd2aaec28430",
        "09d45c0f65aea313087ba93d8c917c6de14356c7d808532fec7456de25766043",
        "f5475be2a6b80800e4827fedb4717c011397837238e198f5917d0a818ef96aca",
        "e74c3350fbc7208a7d981a59270bc2fd2f1aee8105554bf3c5d98c4ee12a099c",
        "826cd053c07611d5b49b6fea493796a136da193b908d3b9dd240b3b91de141da",
        "809edc12650106c35c435fc4389b08bad491f1850fdaecd4ae468f9266c9fddf",
        "b8e69b220d9953c8492f3c719a03da987d6831c4e25d0564dcfc17b10911eb36",
        "3602221023cc9f8603a979bb19d4f634e24d71ef9d1f27e689fb3ef08848c4f7",
        "cbb984623d5474dc93c819397a539d9c09d22ed9e56706ff9d90b28065716628",
        "a3267da02f4263184802f8a8d507bee610968b0f0611b546faebb15442e5d757",
        "da930fb4fcf24f2eb62f4cabea6ebca22059c389013187012bf71713f77c231a",
        "06021330fc92f207fcc2a1f49fd4cc2a1a4f40dcbf7bb0819d49312be7cbaa20",
        "a1de9fa365f86e14b4e031797d3ce6bd68f9a5aeb67051b70f2b48e5090c1327",
        "bf3196af890306b0e3fb51c6555975747f35e44d2cf3b7190a2186ab4cbd8bd8",
        "14bbe25e7d1b86733acb9e69af68868b785ff111aa3c4d8b9a446eff9b74950e",
        "774dea91a3a72bd480a3767794bb3a4c8b9eda92296a7012e488289c9bd9a946",
        "ed98cf4d9d1a20942be4d5d39c1ad5eaf0bb28ada1c976d13aa22282a076f0d0",
        "cb54fd3bfcc59d06bbd499d6f30353f5132010a7aa5c76a6a8bf1950a8331c30",
        "17e7a178cc80c077fd80c97335d7481ce7cac551707a82f09b35146b1c23faa4",
        "1d9ccb8893931a28ed8163363893ab66dd002b4f475634ec77b0c7f987b7d55c",
        "dcb0be52ab617607e0edfdb01fba52674612b7197583475db413c874130e02b9",
        "90687505b70162c6b4861103872ce30d82c37eb7bd8b6dc4b772b4eb42e6041a",
        "5734f76c2599ea155c77d4c35b4f91b2f7fb5bca35a8f22008c57e78f399becd",
        "7037c78388df51e155bce6a8c37efd52322c330bf94dea1c7ca019b42a03e7c2",
        "60660cd299755935b40553141d82609037e6cda2e74b9e1abad179af017096c4",
        "e335225a60cd97dbd6c4f7ddb87428e6f00a6a17bea4c3ba97b868654a15e4c9",
        "339cd5be25f3842ae02ca03752cc9f69198c73ffab73c77654bd6717c73e2200",
        "20c3d9a80f83cc502046af185c9014d1e3ec7154547653695d6d70990ade74b6",
        "d3ccaba0ba38656fd9babe3c96f4d594e89f235ced6419732e09ffda8ffc821b",
        "7a2d1d305d6e6f10faaa34dd0d8a5b7b2a972980e881cd3e2f5ce5f7be9048f7",
        "679de3db8282748f2a31fdcea8b9491b5bc727b98e819db8e6fa7fd89bc3f208",
        "4fd938899a40e0d7297ea832f5783b4ff40524fc8b5b1bd762122387fb77c527",
        "f65a62088c779b316286272b9b2c5ee7f423a647611dd8150a0927cd232646a5",
        "315ded2201d8b7ce5904bebe836d3aca42a510d9dfc1884176899224180f195e",
        "b693070a819c7159993b16a8205ffc2d579d0758bd10dbf29fdaf324cacb0ff6",
        "7c1447ad6c706bea9d20a31fbfbf4c7710404a879139f8ba6ee9321f410d2e6b",
        "6c14cb73ff30e0e1451d94a38717a0be6271cd1558ffc891ef3ca5fa5f2b6263",
        "b513e088c7705263f5248f337fa19621a400840f7ea9a51d94be285d92de5a04",
    ],
    [
        "ac2f7178c5132eb2a486487efe8fe1b208213d4c84c944ff1b4844f040bf26f1",
        "92659c6233fc00a589106c05a8ba04a8c1766a2aa037750e73dfd89d336262a7",
        "15f223d508f83c4f7e5d259c1f0e16d3e1f386684839dd63ccd160ca6d0ee4fc",
        "cf0123abe72b8b21c98e18ae915976b1bc82f8f737c873b5d5cd78a14e6022b8",
        "94c4318f4a5946fc6b641f83edd0de93bf0d09f267269ca80c0771ed4df7e7b2",
        "5f064db0777eef60efb6e78691d2552eacadb6208fe4c895d14e4e7cd2425653",
        "5b4add9194b78036b06e8e433b248501b6c2eca948b63f3a5424767998cc0091",
        "d6717445bb52396a2cc63b13f4d1db11dc98656ea06f0e5e339b22351ac92960",
        "fe065d2c4235a4ff6f0596488777b0a3ebe0065774ab2af0aa88a79104c67593",
        "2654fb81a91f714b5484470859a2c8cff60b8944c419e47bcd4ab58f04fe0058",
        "0136f1775a6521cfc566525a186a2f20aba492c9861e04a9cd51920b0ecd8e24",
        "f5399d47bceb33be55ffda94417e45f99001300cf35d748e5e1544eae9343c59",
        "1b12cba9ccca1153feab3e7b3e72cf045d985b8822609f9d3a78a061b779b0f6",
        "6bfe9cdb51f3993f9fab78075a29b3f3945ac24de531ff880c19c42a8241e0e1",
        "4b39794feb7dab373d183ebe1447991726df3beef7ce23c85a54f154a4a16799",
        "ddadab3635fb51dfd8d59162bfda80dbba8f19d81e9a3a10002af4b24b4cafdf",
        "3b73b6a8ff54824d0909aea32c9d979a091be269e44d373b8f34cc3b70b4e66a",
        "6ce0a5a6902d4ff1bafe2e2c27a72842432e091c1da3142c83a631cf6a9d7000",
        "85f47b3a6f61adf3e9d8c0c024500c8c40fbb64bc8cc941d9512c9453329df0f",
        "4298a48638c4eb95e01ac05d9e410270475801e90a491942d42692e98feb60e9",
        "f94b6125ac089a248b64f587407bfc3564bdd0abf6d9c496b3904af560452774",
        "8b7082dba552f27f30797942b961363f76e34ea36d3b0e038aa2a08476e3ad46",
        "1cf68bdda1f1a9eaa2571f2c12fd25782e36b79af424e6e3f58d44458e6a78d9",
        "f42bed0e60f9e555382cf2dc6a7158ab9ffdeb5acbe1994030e4a95633a479ca",
        "2bbb67af7dc91ae10157516d959b0fd98f3f38c5ad17ff921c9c992f19928d89",
        "7bf1bd973e7901807b511252c05c4d149568d954fb61419c418d4c5c46380da2",
        "5ce1e4e01fd0d2dcb9e1dbf5d58023cb75a20814aaee184aab67bb972d617c16",
        "0bed7a3362690b0183310f0be99c8029415a6b869041b3c47f82921c5cf97add",
        "11fd6f3bc2412d066e762669e57a72bab3de43f1d6e1a870bab788840e341e46",
        "ef22784e21b6034a1ace90b5500a13eef5759aff98ad259c0d6d9adf8e8bc2b7",
        "6e8121c244c252679fd4eb0a677e03d4967fefc7b957bfeeba5b31b4ebf9ad51",
        "4ace1fe15a80053ab6e03cf40255b023c625b56f7ae69114fa7b7edb86c2e730",
        "14ef8efa562f61662b731d76aa1c35495951fb8554e1e200b40623ae845a3ffb",
        "e0eb29a2e8b601600512c26d12aa2d27f19bc9203dc122e59f4f42a538bc5414",
        "aff8ac032ad20729b19b07d3d757dcff7b87e728ae0d87620d5b026fb26ad87a",
        "b8c4db8acc24209502487aa2da5cd0fafdc27dedfc17f4d915076b98b9e5595d",
        "13c48e16daa0d6fce087dc833fb3d0584a7b7e5da4d1874bd71c7a92d03950a8",
        "ee56937afe2b8c7f418bab1741d01ad0689dc1b7fd6e786830a37de95485dfac",
        "8bf57233ad329ae6a98fd7a8106fd1908e24807cf86c830a9ef36d229e00b3a0",
        "5f2092e86dc9d37e1e2d60d326736e4a59d563d1d69815e052f8f113975ec21c",
        "eeb60352a2790497b548517c3923e00f29052c6a9cff0b1d22f815f519a5bfc4",
        "3d3c651abe782b8d098e28e04a2ac0c6ea92d849b0847df89071b8d42e2dbd0e",
        "776909ed1dbc7ab32809a9b027e3d7b21bcd315e1c7cc5f2af4dead96349c1ba",
        "4f2341c7edfb2c4548b7c9d5cd55c9488e20d8f266e562eef9ca85f4139443d9",
        "7301aa40e986d0bf7f67279c05bdcd981f9c781571e59a6fe34a84810434616a",
        "58954a7868f761b2b9384f0992860aa9d42c1c09c4033df7a65bc128621bb90d",
        "87daaa41de88b972c37b564a0d59d43a01f2bea984ed067bef446efa0420f845",
        "44d129f2920784cd52de4b57b251642b7fdfa9bbc92e4774565324b1bde4fadc",
        "e97c8eeeab83a542b2f88de2fb53fae31188f72b732b24f04ca4ecebcba4bc5f",
        "c365331e727f0c73d53dabd4da7d3c273be04ca8697c6f17a12bbe9429874200",
        "c4330f35410b95e218cb7a5b545f7df4cb870e7dde499ebfda0c7719ca7f3c6f",
        "fd894bcfa8d74f39c321f2e0310c3ebee15fd1204b3e0baaedb728f21eab620a",
        "560a249638083f1f104380ee2fd70aa79f462b2af53733f4789ba1fad27314c1",
        "e97afc303a58e929fcc2a18bb546b4ebad7753d49045dda964ccc8057344bf7e",
        "de9f6043b199cedc0eca985d2a787c3867351c2731689b6e3964746c0214e84a",
        "028ff27b597629b3f55918805ae106b6d6528eecdf372c55a43616920665488c",
        "9826a80707d9e4d784d5a0fdddc5214086f92d8a9b6f44bf45aa3c6cab40fde4",
        "5a9aa8cfb393519692e1e0d4bd77c01bd2776d8c34840db103780a51ba0635bb",
        "438a0a20240d082a81bfc069eac70142a0d7ab20ddb05042401af70ca56b18f3",
        "f268f9257aca6e1d29ab7ebc8f84a144a524acc24cf84f532639ea75977e4f0b",
        "187a895608075ba9dfc5b0c9c62b5390ada8cb1f99c9ed76c6d98434d5bf3962",
        "46763533081f443bad38669e9c60430d9de1b1429a768810e1dc7bb7a9a8421a",
        "009cd79e5dc7d89cf00903746263221cfbbada3983b9aac75e9ed020b4c749d1",
        "8477bdaecef3f1746f8ffe97111883590a7ee822b164e92d0e4b4d314e75390e",
        "8f2bdf7b94d44c19a7b15980d95378f4d2e0ece271200688a03fdb2119a15f03",
        "604b6386c31586685d08ee3b945b5af81b3522131c37e48b918e604675f0b86b",
        "4afd1b3f9495fe5f4718758096354364c9e22dc4c14ee7f0305ebd14f69de2e4",
        "bc073479b638edd6f374238ab32c4183cf7b2803e148a5570c4a068654a7c530",
        "a2abf1a55aeb006b7e31264b91fd455ef4f0abdf369bfce71d6ff9925466e8d8",
        "d57c8eb856b287b8999bf91857dffceac9794393d7bcdde1b774adbe5ad54a32",
        "838d8d1b9be62925b374867e75ce78d8dccb2351bfffb11381e2b3946957e413",
        "4c82c8f76a3c7177ba3f52ad4f1843a783c5d309c9e1443dbd96963b322e9c11",
        "2ba300b669dc181183edd8f4d15fc7c43c60b5d15d991194996eb8d1a45c1037",
        "6821c164b4a836193da948f23e274eeae2b2589cf45c50971b76ee4d96a3df98",
        "08e79c067fb1ea31cee9a09452c0638cd9a96ab3401584f1272649c7c09bd234",
        "bf87b92418b7226ec82880b1956cd14d6bbb68985c3d5e759efa65e876733d56",
        "f336e56373ec2c0dc30fd29002c508a11db63135137e69f47d9d134ec2880c2d",
        "5724af140fc8185fabe1d178673bb09add588d5c19101c8a29082c5acf079073",
        "2619274acf7a2a17a797fea112c7d300873b240d8efb39e4d73927f31fe38114",
        "8456823be11dbb38597f4373d5a30a198a1ca33f1095172aa392d59c647258ca",
        "790de62fdb4d2073588a15b788c649e49c46da88af1c84b82497a5079df02bbd",
        "4e8a8a080c6e662bd6b5f1e808df67948d17b93c54840e180883489117b4e1f5",
        "2109aff12230689e66733239a3622921e049eab316a02288860d522171406e0f",
        "4f1b0420e182b91045c261dd36903491aef3cac2432a95f7500fb16e6eb31fc1",
        "23e039ac94d6d5f3ab3989d309ba737817067d1ac0191696bf7902f01961afe4",
        "b671d7b589de867a6b839faa200f6027673398d30c6998cba64f3d91989603c6",
        "266410ccb67db057bbed4a89c60eafe03d0652c3ff7c1da92758f2edc95fc6dd",
        "36f02f11dd66dd94b8b86d029bc60bd2124143fc0be554ab0d960f10dd8b0c79",
        "0ff036dde2a692ffa1c5d36595abfcad7d81d8d959cafec5773647e9b7c8f578",
        "860d3e283b799ee45c64e9490927572b1f66da844b138c12c36a3309d0f441c0",
        "44f454958fcbb23df6252909cfc7a071c2502134ae6afeaf952f56e7332ab11d",
        "d8a934c65a6225ade02fce4d5c999db94660584a4b036c5bc6cff230e7b65adf",
        "254e6001170ced318cb74245b21f7d33d09d9ab719db32884559da18f97036dd",
        "7917cedf72d842952aaadaa21a7e561d32b4a1f47e27062d9feef022d0ec09d0",
        "7fd407d05ad6a6b5a07f90e455251346c5cef1a1ad40734e0085ffb9c83faf48",
        "8091e712c8dd0a877f839f733e8b2d39fb5eba569a7d3ef877a26f804b5d6ec0",
        "1f51db21c224ef91943e1fe84475ac76b55db93b3fb869f91d82346a38895ec7",
        "6fb5367e66ad082bb359ecf1aa82b5b280f19e5a267029eeb78246023eb8797b",
        "e888d4061b57422bb3a1b4b142988016940099a2284ad97d1792d8e656ee3b5f",
        "d75099802400d6b6733e0fc74fbb23eee81a2eb4d7413a3e64ee99ff7230e64d",
        "58d3ec5757d9863e27ca54a8ba4cf2ed5f517fddbc54bc05c5161e1992581521",
        "1ee71805e677743c5c3a6cafa57869797ea61e4e144cb1762d60d71b55d3eac6",
        "3859e62cd1c10168044f56569cdd63e107c2558fab84fb782be02ae20e61ea70",
        "5179ce8d36e89cd2e477ff2dbfd4ebc11607d7daffa2c8ade899c922577f2a56",
        "1e851c29387e0d159f5753cdb8dba8040ccba66e178b3052f70be0ea587920b0",
        "65e8e2d86e437b38f96311b7019571077f0835483578646574ce3d58e99aa7b6",
        "1851e4ee98024053015524ff552bf0710689cd7e07f2f53f4cf211ac24f501c8",
        "967c5d4b4bdeeed71b61f49d8ac4d2be5a16009d146f2a5e9108f55c23c788c0",
        "ebbdc7e4be75aa2ed695f6eb2cae902ac82687920b3ce2211dfe1c84739cfff1",
        "0840a19372d374d7b8fafb8cb5963a4dc081aaf797286de1b918308efa3e4d10",
        "ad8e64447b6aafc0c8b8318ec5cb5698e71d97272560b7355bcb7e685217cf09",
        "ca3228b24863eea76afa1e687ee497cd127422a0d08c4568ed05cdd708fc7a9e",
        "df80c194010a7125b617f2f79143679bd7cd6c9c9869fbb59a2f41437352bac7",
        "5dcc5d17e07740f45d919c0d39438df68be88c26f176096f511c5aaf8fe6ee92",
        "970828147ca8eb5493c084aff3de4416c329e6ef300ab20c1f9405552799fc3b",
        "0a9de03d94874eaf3aab21de9d7e1058d2468b9361e9c086d9d6ead412d11160",
        "84cec6f28a4ec733b6befa2174c0db4996426d6a3f3d16f59e96a41cb7cd6541",
        "78dc578457a2c8cb7ff9ef567dc2113afa0118c6f69a21f9ae3326192a9445bf",
        "6f970894be93f9e1e47f7cec4abed36b20f12daf02072d0a9b69b188098ab6dd",
        "71494af4f04b9d418bb56ded69413b8f4eaeca85be88a21abade472da53c65e5",
        "34af8cf21d9d62cd231377b020f8b391981e978d0155ca608f10b670853cf1bc",
        "99aa444f961bed421f077a1a3150d903bd0d17f7616c516a120162eb47bb536a",
        "4bb57e56590854bdc341a12d6f3c6bb9d0bc27a07af9a575a5b5d76aba1d1db7",
        "f1def212fa6a8a3bafa9f538572af6a5b7a41a02aa4e0da147b302f87e22f370",
        "44176905421f295876f03ab1fd2eb1fa6ff10a6295c457ac9dfd23cf69eaad10",
        "d2b8c517001ac3c78b1201d11b99892cd0f1fa7fe584e5b2c5e2d9058316c421",
    ],
];

const EXTRA_DIGESTS: &[(u32, usize, &str, &str)] = &[
    (3, 0, "14", "b7025a8ef91d279596417318fc2006ab943766f323055dfc14424140135dc7c8"),
    (3, 0, "86cf1962abf43e", "c1ee92b9ff72c7ec6cd74bf7140f80d594639bc020c1980e2073a84d53fc945b"),
    (3, 0, "99e22c75be08519a", "821603bccea1ad64b3981140d02f64a4929479291f61c51c436f670ac03b373e"),
    (3, 0, "1a63acf53f88d11b64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468f", "e4414d2b939d2c8e4d0b5cd5da095938e9c5b38aafddd3be5b994f2c8952bd41"),
    (3, 0, "2d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb", "dd9ece257d413f9f31890ffe1f5b00b34061818efa79d739093035b241b1f842"),
    (3, 0, "b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972", "950ae333571b78bfa3d048f4487cd3d65b2514ecdc690e56eb36150bf5637fa0"),
    (3, 0, "c50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6ef3982cb155ea7f03a83cc165fa8f13b84cd1760a9f23c85ce", "f10697bf48f43e90f8b288a29f80eec3a5ccc3209c7044b6aa849c210b3a0f74"),
    (3, 0, "d8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972bb054e97e02a73bc064f98e12b", "c6410ec6fc816f4544fdd80f3d88317e192f9bce917f3c2edc9e49a8629a6fe8"),
    (3, 0, "de2871ba044d96df2972bb054e97e02a73bc064f98e12b74bd075099e22c75be08519ae32d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6", "369699bf35bbad5e5a51c9c24894fe42dbe13d0a51091043a65e6a0ba016e5e8"),
    (3, 0, "f13b84cd1760a9f23c85ce1861aaf33d86cf1962abf43e87d01a63acf53f88d11b64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b903", "29320fa3fb33d3f5bef0c2d288580b65aa41ebe72ad36f20d667d947810c3d8a"),
    (3, 0, "519ae32d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6ef3982cb155ea7f03a83cc165fa8f13b84cd1760a9f23c85ce1861aaf33d86cf1962abf43e87d0", "82fed516d1e580c188d96ec6c550afda7f39b6ed4ecf14a8ac5a813d1fabf44d"),
    (3, 0, "64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972bb054e97e02a73bc064f98e12b74bd075099e22c75be08519ae32d", "ffd61c3482c37d8b93289b3a416c06dc2d81b19cad18d3a4202957019f663ce1"),
    (3, 1, "484d4143", "1d234776c32243fe2b21b1e8b9629c725766e1bf92762bb1873d857075f6bbf9"),
    (3, 1, "686d6163", "02212f33dad0d5fcc707b39e2fb0c90765397d096aaba6c4d79af93b13a99946"),
    (3, 1, "484b4446", "623aed33156ffc8d9abd99757895515617bb0e8ce38e093c87e324100104ff12"),
    (3, 1, "50424b444632", "5b7bc752a2424c02f5b0719870a91d02260b9db9913018f975ec085f4444c441"),
    (3, 1, "544c53312d505246", "a30cc53989091cd59bb6fca737473061df36c36572fa27b8e2f6ed9dad62186d"),
    (3, 1, "582d554e524547495354455245442d414c494153", "a24b9b87b5802f3a3c129b69010e93768d328320071d796820f1042b0ad93d44"),
    (3, 2, "41", "6ae531fe619c1f6083eb3a4b677de2d598091e64afd6ff35b4ad1a2d1e8af7d5"),
    (4, 0, "14", "5cd29976da3fcac5bc48856f00ba87911d9f80e621cd02937c4afabf053b3577"),
    (4, 0, "86cf1962abf43e", "05b884715e0cf476b16bfeb43bda135aa6fa9eb7b1655e7c474c820f57fec56b"),
    (4, 0, "99e22c75be08519a", "d0756f9ac5b6685946a74a3ce31299a4d629a0149b328e8dfe32f98ebe83df6b"),
    (4, 0, "1a63acf53f88d11b64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468f", "e395a393dc21a6bc87ed2a7c66c6bbb6a659cbb686f483826862d861c2841ca7"),
    (4, 0, "2d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb", "fc86dffa32033949d9acb24c139f81e8fb4846d249ae664652ab461cb1f4826c"),
    (4, 0, "b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972", "155ab1fd4f3eab758f055c97dac1cbce931a48f9a46ff101614a4fe822d9c0c0"),
    (4, 0, "c50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6ef3982cb155ea7f03a83cc165fa8f13b84cd1760a9f23c85ce", "6e1a6cb4f063eda05e0a46049c0a878facc4f897bcdbab91e195967154aa9ffb"),
    (4, 0, "d8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972bb054e97e02a73bc064f98e12b", "05a1b7fc0db02798f495709c52126de8f101ff703161e35151ec820b313497a0"),
    (4, 0, "de2871ba044d96df2972bb054e97e02a73bc064f98e12b74bd075099e22c75be08519ae32d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6", "d39ebb142771279ef24c8e23891ee996383b980e77051875c8eae093949dda62"),
    (4, 0, "f13b84cd1760a9f23c85ce1861aaf33d86cf1962abf43e87d01a63acf53f88d11b64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b903", "ce6d747ff9e0e008112391afb044d7ee79d5705745ba9b1a72d860b4ead6689f"),
    (4, 0, "519ae32d76bf09529be42e77c00a539ce52f78c10b549de63079c20c559ee7317ac30d569fe8327bc40e57a0e9337cc50f58a1ea347dc61059a2eb357ec7115aa3ec367fc8125ba4ed3780c9135ca5ee3881ca145da6ef3982cb155ea7f03a83cc165fa8f13b84cd1760a9f23c85ce1861aaf33d86cf1962abf43e87d0", "62f0048ff61f74c97366d30597ec2317c5e458fa9365fd9f07252d78a12ceb2e"),
    (4, 0, "64adf64089d21c65aef7418ad31d66aff8428bd41e67b0f9438cd51f68b1fa448dd62069b2fb458ed7216ab3fc468fd8226bb4fd4790d9236cb5fe4891da246db6ff4992db256eb7014a93dc266fb8024b94dd2770b9034c95de2871ba044d96df2972bb054e97e02a73bc064f98e12b74bd075099e22c75be08519ae32d", "44951f715127a0024b0e48ee6b56348a70d1538565d2fec012e4d5d213bf0fee"),
    (4, 1, "484d4143", "37dea155c3c810f4a5a76c2ca80dddced8d209429e4f3d4a6f994132c1b26b2d"),
    (4, 1, "686d6163", "0a8e9c96b81a5c28ef8b387d56d43ef31d0eb115b1ffbb9fb2788e96f2c1043a"),
    (4, 1, "484b4446", "0fd316a3ae38d3cf9e924c0c7092dce9ab60e1dff25d0671e66e868337229c2a"),
    (4, 1, "50424b444632", "cf9d3a8a951b55ea3ebff5dfc3b603bade4af5eac6fc0b4f45bd0548c277bfc4"),
    (4, 1, "544c53312d505246", "b617fc63c36369f07e7d05455657d6dce2390592ae6db6446007654d8f1e6f9a"),
    (4, 1, "582d554e524547495354455245442d414c494153", "18380f137aa062a21079c04a951277e2cadf301ba352133af05df7dadb2033dc"),
    (4, 2, "41", "f955bdc4075f76f78f2597d13f485d4d4642224daaaedd80e232d3ad10a8aedb"),
    (3, 0, "41", "4a7fe4ee4e979c69089a90ec9c8028f6e99478ee70a022e5554eb85918efd2fa"),
    (3, 1, "41", "ba5d5456d03f8f14d2a51ecd325f50841046e97f851c99ea0001a34ffdbb0717"),
    (4, 0, "41", "218bb890a3c4348f7f22a084c50b5e55ca742d1fe9830e1c89cf45ce6d94ccbe"),
    (4, 1, "41", "33e83f49cc3eacd27b34281c9f0037373c5655775c59a690c23daf6d6079076a"),
];

const PROTOCOL_PADDING: [&str; 126] = [
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000021000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000021800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000023000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000023800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000029000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000029800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000002a800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000002b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000002b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000002c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000000000002d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000000000002d800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000002e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000000000000002e800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000000002f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000002f800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000030800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000000000031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000000000031800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000000000032800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000033800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000000000034800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000035000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000000000035800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000036800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000000000037000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000000000037800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000000000000038800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000000000000039000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000039800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000003a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "80000000000000000003a800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "800000000000000003b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000003b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c0",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c8",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d0",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d8",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e0",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e8",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f0",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f8",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000408",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000418",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000420",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000428",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000430",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000438",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000440",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000448",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000450",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000458",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000460",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000468",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000470",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000478",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000488",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000490",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000498",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000000000004a0",
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000004a8",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000004b0",
    "80000000000000000000000000000000000000000000000000000000000000000000000000000004b8",
    "800000000000000000000000000000000000000000000000000000000000000000000000000004c0",
    "8000000000000000000000000000000000000000000000000000000000000000000000000004c8",
    "80000000000000000000000000000000000000000000000000000000000000000000000004d0",
    "800000000000000000000000000000000000000000000000000000000000000000000004d8",
    "8000000000000000000000000000000000000000000000000000000000000000000004e0",
    "80000000000000000000000000000000000000000000000000000000000000000004e8",
    "800000000000000000000000000000000000000000000000000000000000000004f0",
    "8000000000000000000000000000000000000000000000000000000000000004f8",
    "8000000000000000000000000000000000000000000000000000000000000500",
    "80000000000000000000000000000000000000000000000000000000000508",
    "800000000000000000000000000000000000000000000000000000000510",
    "8000000000000000000000000000000000000000000000000000000518",
    "80000000000000000000000000000000000000000000000000000520",
    "800000000000000000000000000000000000000000000000000528",
    "8000000000000000000000000000000000000000000000000530",
    "80000000000000000000000000000000000000000000000538",
    "800000000000000000000000000000000000000000000540",
    "8000000000000000000000000000000000000000000548",
    "80000000000000000000000000000000000000000550",
    "800000000000000000000000000000000000000558",
    "8000000000000000000000000000000000000560",
    "80000000000000000000000000000000000568",
    "800000000000000000000000000000000570",
    "8000000000000000000000000000000578",
    "80000000000000000000000000000580",
    "800000000000000000000000000588",
    "8000000000000000000000000590",
    "80000000000000000000000598",
    "8000000000000000000005a0",
    "80000000000000000005a8",
    "800000000000000005b0",
];

const BLOCK_DIGESTS: &[(&str, &str, &str)] = &[
    ("empty", "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("standard-56", "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ("pattern-1", "03800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008", "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
    ("pattern-54", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef001122334455667788800000000000000001b0", "b049958c18299b973766328ea0198d5a131af151d2e799f2a646ebd5de3604ba"),
    ("pattern-55", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef001122334455667788998000000000000001b8", "c40dbcd18dfdb34a5c52a791f09286986b5e9d61f867278c03adda227684e897"),
    ("pattern-56", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aa8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0", "ca6c4804e2170c368f94d2da606adf4552eb0b1d35bc2ad1dc12887627a028eb"),
    ("pattern-57", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabb80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c8", "6f622dcd0a7f01cc588f376ac71fd2d8e787dba4b101d0006a9c512212ecbe7c"),
    ("pattern-63", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f8", "7f963102afccacb03458e0e3ee8f51a234359aed99cb7ebfd33d5e47a095fcba"),
    ("pattern-64", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff10213280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200", "30a1b375b49e0f1d5e00b6868bbfd471cbe5387806456cc11fd153c689bfe747"),
    ("pattern-65", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff10213243800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000208", "ce4c5c9097270aaca5630ec6ca4b48c145a1bb24462589a0ec3f69cd5c9b2a5c"),
    ("pattern-118", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8800000000000000003b0", "bc384892aa3110c9c1e1f244c6467117a6baf9fc127d10d9d44276b64dea70d6"),
    ("pattern-119", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d98000000000000003b8", "c9b7b15a882bf470dc6a27daf5486f9222f0ec5193069462d1ae5d729bbcc3eb"),
    ("pattern-120", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9ea8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c0", "53416ddca73fa04063bbedf24baf10637cde9f47c447586231115c0cc944645d"),
    ("pattern-121", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c8", "27c26ee2bb5a45641e7c37e4a827a76e8e1cfd7707094c1ec5b8764f58895144"),
    ("pattern-127", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f506180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f8", "fc7d260501b641289fe7df7d943df65d93c782f2f3a1e2a4e69c6f763d88f8c5"),
    ("pattern-128", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f50617280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400", "5a878aab98a988c5479b48c00d8e2bef988c946dc648583ffe7ac598d76bacd5"),
    ("pattern-129", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f50617283800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000408", "a1253e220a0a60177ba22d6f1ae079f6b8f0b8fa598b0adc1390b0d7c81756fa"),
    ("pattern-183", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708198000000000000005b8", "c811264154c59ad24eaab7c4b4bcfa9bc563f3b442fc9fad11b855848348caff"),
    ("pattern-184", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708192a8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c0", "1ec3d3c38c1d9a7110a15d474aeea1359f21d0486abdd109ceb2a55b73289431"),
    ("pattern-191", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f8", "02c0eb8838f712b321b6030f3a70c3c5d99e368429e08475daefa8c3a9b6b5eb"),
    ("pattern-192", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600", "3c3600235e8c21518005ab6af104890ff3848d0debadb72f07a3b29823aaa623"),
    ("pattern-255", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b2c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748596a7b8c9daebfd0e180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f8", "d990656c560f084c02cff84fb818505172b37d27a9c5c5531c26dc453199df82"),
    ("pattern-256", "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b2c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748596a7b8c9daebfd0e1f280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800", "a15c31ac66d64c42626322653083309abb46d605813c04494a1835c6d9170c76"),
];

fn normalized_answer(op: u32, length: usize) -> &'static str {
    match (op, length) {
        (3, 1) => "4a7fe4ee4e979c69089a90ec9c8028f6e99478ee70a022e5554eb85918efd2fa",
        (3, 63) => "31ad57f6cf71d4e8c8812242a8b1787b3f74818002230a99a53ba82f897875f1",
        (3, 64) => "c64a1b33acbebb8e57a8b423d8f4e44dc7736b1d61fc547aa032317113449fbb",
        (3, 126) => "3617d0f3caf768178329cdcf62fffeb209d5f56cadb23ebd83fb708bb7fda8e3",
        (4, 1) => "218bb890a3c4348f7f22a084c50b5e55ca742d1fe9830e1c89cf45ce6d94ccbe",
        (4, 63) => "79fd82ce5ac85db43bb435fffeb7248ad51a285bc6db57e7672b9a97e8881bd6",
        (4, 64) => "0796d9bd3aa287e3d4dddfb1407a8242b6756f5767f2096aa856e42a43419138",
        (4, 126) => "43f4fe7f6dcfc5fa9843e104414ec15adcdbe15f58f5a51860671320a1bcc4ec",
        _ => panic!("unknown normalized-name fixture"),
    }
}
