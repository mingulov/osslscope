// SPDX-License-Identifier: GPL-3.0-or-later
// Complete bound-selector publication through the actual prepare/commit bodies.
// Expected SHA256 values are independent known answers for the documented
// encoding and a retained object hash of 32 bytes with value 0x11.
fn bound_publication(family: u32, name: &[u8], digest: [u8; 32]) {
    reset(family);
    assert_eq!(core::mem::size_of::<RelValue>(), 256);
    assert_eq!(core::mem::offset_of!(RelValue, tail), 128);
    let request_key = global_key(82, REL_REQUEST_NAME, family);
    let mut request = REL.peek(request_key).unwrap();
    request.data[1] = name.len() as u64;
    request.tail.fill(0);
    request.tail[..name.len()].copy_from_slice(name);
    REL.set(request_key, request);
    let tx = prepare(family, 21, 0x2000, 0x2200, 91, false);
    let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
    let root = resolve_target(77).unwrap();
    phase("bind");
    assert!(bind_prepare(
        control,
        tx.frame,
        (77u64 << 32) | 78,
        &mut Target {
            entry_seq: root.entry_seq,
            ..target()
        },
        tx.owner
    ));
    let staged = bytes(&ITER_SLOT.peek(0).unwrap().staging);
    assert_eq!(
        &staged[144..176],
        &digest,
        "independent staged digest known answer"
    );
    if name.len() == 126 {
        assert_eq!(
            &staged[120..128],
            &[b'A'; 8],
            "legal long name leaves nonzero prepublication scratch"
        );
    }
    assert_eq!(
        ITER_SLOT.peek(1).unwrap().staging,
        [0xa5a5_a5a5_a5a5_a5a5; 32]
    );
    assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1008);
    phase("commit");
    assert_eq!(
        commit_publish(
            control,
            tx.frame,
            (77u64 << 32) | 78,
            &mut Target {
                entry_seq: root.entry_seq,
                ..target()
            },
            tx.owner
        ),
        OUT_OK
    );
    phase("release");
    release_frame(&tx.key);
    assert!(BIND_PENDING.peek(tx.key).is_none());
    assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
    assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 16);
    assert_owner(&tx, family, 1001, 16, 1006, 1007);

    let actual = REL
        .peek(global_key(1005, REL_OBJECT_SELECTOR, family))
        .unwrap();
    let mut expected = blank_rel();
    expected.witness_id = 1005;
    expected.parent_id = 82;
    expected.evidence_epoch = 13;
    expected.born_ns = 900;
    expected.state = REL_WITNESS;
    expected.data[..5].copy_from_slice(&[61, u64::from(family), 82, 1006, 1007]);
    expected.tail[..32].copy_from_slice(&digest);
    let dictionary = SELECTOR_DICT
        .peek(SelectorDictionaryKey {
            session_id: 1,
            selector_id: 1006,
        })
        .unwrap();
    let expected_dictionary = SelectorDictionaryValue {
        object_id: 61,
        operation: family,
        encoding: 2,
        digest,
        dictionary_epoch: 1007,
        reserved: 0,
    };
    let indexed = DIGEST_INDEX.peek(DigestKey {
        code_object_id: 61,
        operation: family,
        reserved: 0,
        digest,
    });
    let mut malformed = [0; 32];
    malformed[..24].copy_from_slice(&digest[8..]);
    assert_ne!(malformed, digest);
    let malformed_absent = DIGEST_INDEX
        .peek(DigestKey {
            code_object_id: 61,
            operation: family,
            reserved: 0,
            digest: malformed,
        })
        .is_none();
    // Full byte comparisons include every unused data/tail word and reserved
    // dictionary byte, independently of values read from the produced rows.
    assert_eq!(
        (
            bytes(&actual),
            bytes(&dictionary),
            indexed,
            malformed_absent
        ),
        (
            bytes(&expected),
            bytes(&expected_dictionary),
            Some(1005),
            true
        ),
        "complete bound publication including unused zeros and exact digest identity"
    );
    trace();
}
mod bound_controls {
    use super::*;
    #[test]
    fn mac_known_answer() {
        bound_publication(
            3,
            b"HMAC",
            [
                142, 134, 183, 246, 168, 91, 30, 97, 83, 216, 151, 117, 135, 216, 235, 201, 49, 54,
                10, 71, 68, 97, 37, 90, 118, 96, 81, 102, 234, 96, 176, 236,
            ],
        );
    }
    #[test]
    fn kdf_known_answer() {
        bound_publication(
            4,
            b"HKDF",
            [
                35, 151, 77, 204, 138, 45, 8, 219, 62, 152, 220, 104, 245, 27, 155, 45, 246, 117,
                244, 222, 114, 50, 215, 218, 209, 100, 185, 46, 130, 122, 108, 45,
            ],
        );
    }
    #[test]
    fn long_name_clears_unused_words() {
        bound_publication(
            3,
            &[b'A'; 126],
            [
                39, 44, 183, 165, 157, 9, 160, 115, 100, 90, 179, 98, 105, 241, 84, 211, 69, 55,
                132, 145, 90, 179, 7, 199, 167, 38, 68, 239, 224, 98, 118, 104,
            ],
        );
    }
}
