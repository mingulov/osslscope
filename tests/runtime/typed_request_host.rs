// SPDX-License-Identifier: GPL-3.0-or-later
// Appended with the production fetch/request definitions to the bind fixture.
// A fresh request rewrites one slot from exact key to REL value and back. The
// exact key and published request must agree after both typed views are used.
struct RetProbeContext(u64);
impl RetProbeContext {
    fn ret(&self) -> u64 {
        notice(format!("return operand={}", self.0));
        self.0
    }
}
fn request_rebuild(family: u32) {
    reset(family);
    let name = if family == 3 { b"HMAC" } else { b"HKDF" };
    let mut frame: BindPendingValue = unsafe { core::mem::zeroed() };
    frame.api_role = if family == 3 { 130 } else { 131 };
    frame.occurrence_id = 91;
    frame.entry_handle = 0x7000;
    frame.name_state = NAME_COMPLETE;
    frame.name_length = 4;
    frame.name[..4].copy_from_slice(name);
    let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
    phase("fetch-request");
    fetch_return(
        &RetProbeContext(0x2000),
        control,
        &mut frame,
        (77u64 << 32) | 78,
        &mut target(),
    );

    let mut key = ExactNameKey {
        object_domain: 0,
        operation: family,
        name_length: 4,
        name: [0; 128],
    };
    key.name[..4].copy_from_slice(name);
    assert_eq!(
        EXACT_NAME.peek(key),
        Some(1001),
        "rebuilt full exact-name key"
    );
    let mut request = blank_rel();
    request.witness_id = 1001;
    request.born_ns = 900;
    request.state = REL_WITNESS;
    request.data[..2].copy_from_slice(&[u64::from(family), 4]);
    request.tail[..4].copy_from_slice(name);
    assert_eq!(
        bytes(
            &REL.peek(global_key(1001, REL_REQUEST_NAME, family))
                .unwrap()
        ),
        bytes(&request),
        "complete immutable request after key rebuild"
    );
    let mut method = blank_rel();
    method.witness_id = 1002;
    method.parent_id = 1001;
    method.evidence_epoch = 13;
    method.born_ns = 900;
    method.state = REL_WITNESS;
    method.data[..2].copy_from_slice(&[0x7000, 13]);
    let method_key = rel_key(13, 0x2000, 0, REL_METHOD, family);
    assert_eq!(
        bytes(&REL.peek(method_key).unwrap()),
        bytes(&method),
        "complete METHOD reference"
    );

    // An identical refetch adopts the rebuilt key without another ID/charge.
    phase("refetch-request");
    fetch_return(
        &RetProbeContext(0x2000),
        control,
        &mut frame,
        (77u64 << 32) | 78,
        &mut target(),
    );
    assert_eq!(bytes(&REL.peek(method_key).unwrap()), bytes(&method));
    assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1003);
    let state = ATTR_STATE.peek(0).unwrap();
    assert_eq!(
        (
            state.relationship_claims,
            state.pending_claims,
            state.published_sequence
        ),
        (4, 2, 15)
    );
    assert_eq!(
        ITER_SLOT.peek(1).unwrap().staging,
        [0xa5a5_a5a5_a5a5_a5a5; 32]
    );
    trace();
}
mod request_controls {
    use super::*;
    #[test]
    fn rebuild_mac_request_key() {
        request_rebuild(3);
    }
    #[test]
    fn rebuild_kdf_request_key() {
        request_rebuild(4);
    }
}
