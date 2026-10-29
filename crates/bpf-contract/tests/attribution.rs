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
