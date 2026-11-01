// SPDX-License-Identifier: GPL-3.0-or-later
// Additional controls over complete production return/publication bodies.
// Observer hooks schedule external transitions; they never choose a production
// result. Backing and the owner oracle are shared with typed_bind_host.rs.
struct Hook {
    point: String,
    remaining: usize,
    action: Box<dyn FnOnce()>,
}
#[derive(Default)]
struct Script {
    cpu: u32,
    hooks: Vec<Hook>,
    inside: bool,
    denied: Vec<CellKey>,
    closed: bool,
    words: BTreeMap<(u64, usize), u64>,
    resolutions: Vec<(u64, bool, [u64; 5])>,
    cleanup_targets: Vec<[u64; 5]>,
    dispatch_targets: Vec<[u64; 5]>,
    plans: Vec<(u32, usize, u64)>,
    query: Vec<(u64, u64, u64, u64)>,
}
thread_local! { static SCRIPT: RefCell<Script> = RefCell::new(Script::default()); }
fn script<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    SCRIPT.with(|s| f(&mut s.borrow_mut()))
}
fn reset_script() {
    script(|s| *s = Script::default());
}
fn notice(point: String) {
    edit(|s| record(s, format!("observe {point}")));
    let action = script(|s| {
        if s.inside {
            return None;
        }
        let mut ready = None;
        for (index, hook) in s.hooks.iter_mut().enumerate() {
            if hook.point == point {
                hook.remaining -= 1;
                if hook.remaining == 0 {
                    assert!(ready.is_none(), "one external action per boundary");
                    ready = Some(index);
                }
            }
        }
        ready.map(|index| {
            s.inside = true;
            s.hooks.remove(index).action
        })
    });
    if let Some(action) = action {
        // Neither RefCell borrow survives into production/competitor work.
        action();
        script(|s| s.inside = false);
    }
}
fn hook(point: impl Into<String>, nth: usize, action: impl FnOnce() + 'static) {
    assert!(nth > 0);
    script(|s| {
        s.hooks.push(Hook {
            point: point.into(),
            remaining: nth,
            action: Box::new(action),
        })
    });
}
fn observed<R>(name: &'static str, body: impl FnOnce() -> R) -> R {
    edit(|s| s.scopes.push(name));
    notice(format!("enter {name}"));
    let result = body();
    notice(format!("exit {name}"));
    assert_eq!(edit(|s| s.scopes.pop()), Some(name));
    result
}
fn on_cpu<R>(cpu: u32, body: impl FnOnce() -> R) -> R {
    let previous = script(|s| {
        let previous = s.cpu;
        s.cpu = cpu;
        previous
    });
    notice(format!("cpu enter={cpu}"));
    let result = body();
    notice(format!("cpu exit={cpu}"));
    script(|s| s.cpu = previous);
    result
}
fn initialize_cpu_slots() {
    for cell in 0..2 {
        ITER_SLOT.set(
            cell,
            SourceSlot {
                slot: 0,
                staging: [0xa5a5_a5a5_a5a5_a5a5; 32],
            },
        );
    }
}
fn point<K>(operation: &str, map: &str, key: &K) -> String {
    format!("{operation}:{map}:{:?}", bytes(key))
}
fn take_insert_failure(map: &'static str, key: &[u8]) -> bool {
    script(
        |s| match s.denied.iter().position(|(m, k)| *m == map && k == key) {
            Some(index) => {
                s.denied.remove(index);
                true
            }
            None => false,
        },
    )
}
fn deny<K>(map: &'static str, key: K) {
    script(|s| s.denied.push((map, bytes(&key))));
}
fn coords(target: &Target) -> [u64; 5] {
    [
        target.process,
        target.image,
        target.relation,
        target.loss_epoch,
        target.entry_seq,
    ]
}
fn resolve_inner(tgid: u32, entry_seq: u64, out: &mut Target) -> bool {
    notice(format!("resolve before E={entry_seq}"));
    let result = actual_resolve_inner(tgid, entry_seq, out);
    script(|s| s.resolutions.push((entry_seq, result, coords(out))));
    notice(format!("resolve after E={entry_seq} success={result}"));
    result
}
unsafe fn plan_store(slot: *mut SourceSlot, offset: usize, value: u64) {
    let cell = edit(|s| {
        (0..2)
            .find(|i| {
                s.rows
                    .get(&("slot", bytes(&SlotMap::key(*i))))
                    .is_some_and(|r| r.ptr::<SourceSlot>() == slot)
            })
            .expect("plan belongs to a separate typed slot allocation")
    });
    notice(format!("plan before cell={cell} offset={offset}"));
    unsafe { actual_plan_store(slot, offset, value) };
    script(|s| s.plans.push((cell, offset, value)));
    notice(format!(
        "plan after cell={cell} offset={offset} value={value}"
    ));
}
fn cleanup_pending_x(target: &Target, frame: *mut BindPendingValue) {
    script(|s| s.cleanup_targets.push(coords(target)));
    observed("cleanup_pending_x", || {
        actual_cleanup_pending_x(target, frame)
    });
}
fn dispatch_producer_outcome(
    control: *mut ProducerControl,
    target: &Target,
    frame: *mut BindPendingValue,
    owner: u64,
    outcome: u64,
) {
    script(|s| s.dispatch_targets.push(coords(target)));
    observed("dispatch_producer_outcome", || {
        actual_dispatch_producer_outcome(control, target, frame, owner, outcome)
    });
}
static TYPED_ADMISSION: Map<TypedSiteKey, TypedAdmission> = Map::new("admission");
static THREAD_IDENTITY: Map<ThreadIdentityKey, ThreadIdentityValue> = Map::new("thread");
mod writer_gate {
    pub fn admitted() -> bool {
        super::notice("ADMIT lookup".into());
        super::script(|s| !s.closed)
    }
}
fn user_read<T: Copy>(pointer: *const T) -> Result<T, i64> {
    let width = core::mem::size_of::<T>();
    assert!(matches!(width, 4 | 8));
    let address = pointer as u64;
    notice(format!("user read={address} width={width}"));
    let value = script(|s| s.words.get(&(address, width)).copied()).ok_or(-1)?;
    let mut result = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            value.to_ne_bytes().as_ptr(),
            result.as_mut_ptr().cast::<u8>(),
            width,
        );
        Ok(result.assume_init())
    }
}
mod source_vma {
    #[derive(Default)]
    pub struct SourceLocation {
        pub inode: u64,
        pub file_offset: u64,
    }
}
fn code_vma_join(address: u64, out: &mut source_vma::SourceLocation) -> bool {
    notice(format!("query source join={address}"));
    assert_eq!(address, 0x30000);
    out.inode = 71;
    out.file_offset = 72;
    true
}
fn publish_code_role(
    _control: *mut ProducerControl,
    target: &Target,
    location: &source_vma::SourceLocation,
    opfun: u64,
    occurrence: u64,
) -> bool {
    assert_eq!(coords(target), [11, 12, 13, 14, 15]);
    notice(format!(
        "query publish opfun={opfun} occurrence={occurrence}"
    ));
    script(|s| {
        s.query
            .push((location.inode, location.file_offset, opfun, occurrence))
    });
    true
}
fn site_key(cookie: u64) -> TypedSiteKey {
    TypedSiteKey {
        cookie,
        process_incarnation: 11,
        image_epoch: 12,
    }
}
fn admit(role: u32) {
    let (api, operation, function) = TypedAdmission::admission_parts(role).unwrap();
    TYPED_ADMISSION.set(
        site_key(0x8000_0001),
        TypedAdmission {
            role_id: role,
            public_api_id: api,
            operation,
            function,
            abi_epoch: 1,
            source_epoch: 31,
        },
    );
    THREAD_IDENTITY.set(
        ThreadIdentityKey {
            process_incarnation: 11,
            tid: 78,
            reserved: 0,
        },
        ThreadIdentityValue {
            thread_incarnation: 21,
            image_epoch: 12,
        },
    );
}
fn root_frame(role: u32, occurrence: u64, depth: u32) -> Transaction {
    let key = BindPendingKey {
        process_incarnation: 11,
        image_epoch: 12,
        thread_incarnation: 21,
        depth,
        reserved: 0,
    };
    let mut frame: BindPendingValue = unsafe { core::mem::zeroed() };
    frame.occurrence_id = occurrence;
    frame.api_cookie = 0x8000_0001;
    frame.api_role = role;
    frame.relation_epoch = 13;
    frame.loss_epoch = 14;
    assert!(source_state::claim_pending());
    assert!(BIND_PENDING.insert(key, frame, 1).is_ok());
    Transaction {
        key,
        frame: BIND_PENDING.get_ptr_mut(key).unwrap(),
        owner: 0x2000,
        context: 0x2200,
        occurrence,
    }
}
fn run_root(tx: &Transaction, role: u32) {
    admit(role);
    phase("root-input");
    assert_eq!(
        typed_return(&RetProbeContext(tx.owner), 0x8000_0001, 77, 78, 900),
        0
    );
}
fn count_event(needle: &str) -> usize {
    edit(|s| s.events.iter().filter(|e| e.operation == needle).count())
}
fn assert_released(tx: &Transaction) {
    assert!(
        BIND_PENDING.peek(tx.key).is_none(),
        "original K must be removed"
    );
    assert_eq!(
        count_event("observe enter release_frame"),
        1,
        "one original frame release"
    );
    assert_eq!(
        ATTR_STATE.peek(0).unwrap().pending_claims,
        2,
        "pending claim refunded exactly once"
    );
}
fn assert_no_tail() {
    assert_eq!(
        ITER_SLOT.peek(1).unwrap().staging,
        [0xa5a5_a5a5_a5a5_a5a5; 32],
        "cell1 sentinel before tail authorization"
    );
    assert!(
        script(|s| s.plans.iter().all(|(cell, _, _)| *cell == 0)),
        "no earlier cell1 stores"
    );
}
fn assert_original_resolutions(count: usize) {
    let values = script(|s| s.resolutions.clone());
    assert_eq!(values.len(), count, "original resolution count");
    assert!(
        values.iter().all(|(e, _, _)| *e == 15),
        "all resolutions use original E: {values:?}"
    );
}
mod return_controls {
    use super::*;
    #[test]
    fn root_constructor_uses_all_four_original_resolutions() {
        for family in [3, 4] {
            reset(family);
            let tx = prepare(family, 21, 0x2000, 0x2200, 91, false);
            run_root(&tx, if family == 3 { 147 } else { 148 });
            assert_released(&tx);
            assert_original_resolutions(5);
            assert_owner(&tx, family, 1001, 16, 1006, 1007);
            assert_eq!(
                script(|s| s.plans.iter().filter(|(c, _, _)| *c == 1).count()),
                21
            );
            trace();
        }
    }
    #[test]
    fn root_fetch_publishes_complete_method_and_request() {
        for (family, role, name) in [(3, 130, b"HMAC"), (4, 131, b"HKDF")] {
            reset(family);
            let tx = root_frame(role, 91, 0);
            unsafe {
                (*tx.frame).entry_handle = 0x7000;
                (*tx.frame).name_state = NAME_COMPLETE;
                (*tx.frame).name_length = 4;
                (&mut (*tx.frame).name)[..4].copy_from_slice(name);
            }
            run_root(&tx, role);
            assert_released(&tx);
            let method = REL
                .peek(rel_key(13, tx.owner, 0, REL_METHOD, family))
                .unwrap();
            let mut expected = blank_rel();
            expected.witness_id = 1002;
            expected.parent_id = 1001;
            expected.evidence_epoch = 13;
            expected.born_ns = 900;
            expected.state = REL_WITNESS;
            expected.data[0] = 0x7000;
            expected.data[1] = 13;
            assert_eq!(bytes(&method), bytes(&expected), "complete METHOD row");
            let request = REL
                .peek(global_key(1001, REL_REQUEST_NAME, family))
                .unwrap();
            let mut expected = blank_rel();
            expected.witness_id = 1001;
            expected.born_ns = 900;
            expected.state = REL_WITNESS;
            expected.data[0] = u64::from(family);
            expected.data[1] = 4;
            expected.tail[..4].copy_from_slice(name);
            assert_eq!(
                bytes(&request),
                bytes(&expected),
                "complete REQUEST_NAME row"
            );
            assert_no_tail();
            assert_original_resolutions(2);
            trace();
        }
    }
    #[test]
    fn root_query_preserves_original_target_and_consumes_frame() {
        reset(3);
        let mut tx = root_frame(161, 91, 0);
        tx.owner = 0x10000;
        unsafe {
            (*tx.frame).entry_handle = 3;
            (*tx.frame).provider_witness = 0x9000;
        }
        script(|s| {
            s.words.extend([
                ((0x9000, 4), 0),
                ((0x10000, 8), 0x40000),
                ((0x10010, 8), 0x20000),
                ((0x10020, 8), 0),
                ((0x20000, 4), 1),
                ((0x20008, 8), 0x30000),
                ((0x20010, 4), 0),
            ]);
        });
        run_root(&tx, 161);
        assert_released(&tx);
        assert_original_resolutions(2);
        assert_eq!(
            script(|s| s.query.clone()),
            vec![(71, 72, (1u64 << 32) | 3, 91)]
        );
        assert_no_tail();
        trace();
    }
    #[test]
    fn root_gates_leave_unselected_frames_and_operands_alone() {
        for case in 0..9 {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            admit(147);
            match case {
                0 => script(|s| s.closed = true),
                1 => {
                    TYPED_ADMISSION.remove(site_key(0x8000_0001)).unwrap();
                }
                2 => {
                    let p = TYPED_ADMISSION.get_ptr_mut(site_key(0x8000_0001)).unwrap();
                    unsafe {
                        (*p).operation = 0x10003;
                    }
                }
                3 => admit(5),
                4 => {
                    SITE_BIND.remove(site_key(0x8000_0001)).unwrap();
                }
                5 => {
                    let p = SOURCE_GUARD.get_ptr_mut(71).unwrap();
                    unsafe {
                        (*p).state = GUARD_RETIRED;
                    }
                }
                6 => {
                    let p = THREAD_IDENTITY
                        .get_ptr_mut(ThreadIdentityKey {
                            process_incarnation: 11,
                            tid: 78,
                            reserved: 0,
                        })
                        .unwrap();
                    unsafe {
                        (*p).image_epoch = 99;
                    }
                }
                7 => unsafe {
                    (*tx.frame).api_cookie = 0x8000_0099;
                },
                8 => unsafe {
                    (*tx.frame).occurrence_id = 0;
                },
                _ => unreachable!(),
            }
            let before = bytes(&BIND_PENDING.peek(tx.key).unwrap());
            typed_return(&RetProbeContext(tx.owner), 0x8000_0001, 77, 78, 900);
            assert_eq!(
                bytes(&BIND_PENDING.peek(tx.key).unwrap()),
                before,
                "gate case {case} preserves frame"
            );
            assert_eq!(count_event("observe enter release_frame"), 0);
            assert_eq!(
                count_event("observe return operand=8192"),
                0,
                "no premature operand case {case}"
            );
            assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 3);
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn root_malformed_popped_fields_consume_only_original_key() {
        // Reserved/mapping/high-bit fields are deliberate malformed-frame
        // probes; stale epochs also occur after legitimate domain retirement.
        for case in 0..7 {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            unsafe {
                match case {
                    0 => (*tx.frame).api_role = 148,
                    1 => (*tx.frame).relation_epoch = 12,
                    2 => (*tx.frame).loss_epoch = 13,
                    3 => (*tx.frame).mapping_epoch = 1,
                    4 => (*tx.frame).reserved = 1,
                    5 => (*tx.frame).transaction_flags = TXN_AMBIGUITY,
                    6 => (*tx.frame).api_role = 0x10093,
                    _ => unreachable!(),
                }
            }
            run_root(&tx, 147);
            assert_released(&tx);
            assert_eq!(count_event("observe return operand=8192"), 0);
            assert_eq!(count_event("observe enter bind_prepare"), 0);
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn root_selects_deepest_matching_cookie_and_keeps_other_claims() {
        reset(3);
        let low = root_frame(142, 90, 0);
        let selected = root_frame(142, 91, 3);
        let high = root_frame(142, 92, 7);
        unsafe {
            (*high.frame).api_cookie = 0x8000_0002;
        }
        admit(142);
        typed_return(&RetProbeContext(0), 0x8000_0001, 77, 78, 900);
        assert!(BIND_PENDING.peek(selected.key).is_none());
        assert_eq!(BIND_PENDING.peek(low.key).unwrap().occurrence_id, 90);
        assert_eq!(BIND_PENDING.peek(high.key).unwrap().occurrence_id, 92);
        assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 4);
        assert_eq!(count_event("observe enter release_frame"), 1);
        assert_original_resolutions(2);
        assert_no_tail();
        trace();
    }
    #[test]
    fn every_nonquery_return_revalidates_before_null_operand() {
        for role in [130, 131, 142, 143, 146, 258, 259, 290, 291, 151, 152] {
            reset(if [131, 143, 259, 291, 152].contains(&role) {
                4
            } else {
                3
            });
            let mut tx = root_frame(role, 91, 0);
            tx.owner = 0;
            run_root(&tx, role);
            assert_released(&tx);
            assert_original_resolutions(2);
            assert_eq!(count_event("observe return operand=0"), 1);
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn getter_returns_intersect_parent_and_reject_duplicates() {
        for family in [3, 4] {
            for (kind, case) in [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)] {
                reset(family);
                let parent = root_frame(if family == 3 { 147 } else { 148 }, 90, 0);
                let role = if kind == 0 {
                    if family == 3 {
                        142
                    } else {
                        143
                    }
                } else {
                    146
                };
                let mut child = root_frame(role, 91, 1);
                unsafe {
                    (*parent.frame).entry_handle = 0x4000;
                    (*parent.frame).current_p = if case == 0 { 0 } else { 0x5000 };
                    (*parent.frame).getter_count = if kind == 1 && case == 2 { 1 } else { 0 };
                    (*child.frame).parent_occurrence_id = 90;
                    (*child.frame).entry_handle = if kind == 0 {
                        0x4000
                    } else {
                        if case == 1 {
                            0x5001
                        } else {
                            0x5000
                        }
                    };
                }
                child.owner = if kind == 0 {
                    if case == 1 {
                        0x5001
                    } else {
                        0x5000
                    }
                } else {
                    0x6000
                };
                run_root(&child, role);
                assert!(BIND_PENDING.peek(child.key).is_none());
                assert!(BIND_PENDING.peek(parent.key).is_some());
                assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 3);
                let row = unsafe { *parent.frame };
                assert_eq!(row.current_p, 0x5000);
                let ambiguous = case == 1 || (kind == 1 && case == 2);
                assert_eq!(
                    row.transaction_flags,
                    if ambiguous { TXN_AMBIGUITY } else { 0 }
                );
                assert_eq!(
                    row.current_c,
                    if kind == 1 && !ambiguous { 0x6000 } else { 0 }
                );
                assert_eq!(
                    row.getter_count,
                    if kind == 1 && (case == 0 || case == 2) {
                        1
                    } else {
                        0
                    }
                );
                assert_no_tail();
                trace();
            }
        }
    }
    #[test]
    fn seven_id_attempts_remain_unconditional_at_each_exhaustion() {
        for family in [3, 4] {
            for first in 1..=7u64 {
                reset(family);
                let tx = prepare(family, 21, 0x2000, 0x2200, 91, false);
                let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
                unsafe {
                    (*control).next_producer_id = u64::MAX - (first - 1);
                }
                run_root(&tx, if family == 3 { 147 } else { 148 });
                assert_released(&tx);
                assert_no_tail();
                assert_eq!(
                    count_event("observe enter alloc_id"),
                    7,
                    "all seven ID attempts even after failure {first}"
                );
                assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, u64::MAX);
                assert_eq!(
                    ATTRIB_CONTROL.peek(0).unwrap().producer_mode,
                    PRODUCER_POISONED
                );
                assert_eq!(
                    REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                        .unwrap()
                        .data[5],
                    3
                );
                assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
                trace();
            }
        }
    }
    #[test]
    fn allocator_contention_is_real_cas_interference_and_keeps_later_attempts() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
        for value in 1001..1009 {
            hook(format!("cas:id:{value}:{}", value + 1), 1, move || {
                observed("competitor", || unsafe {
                    assert!(compare(
                        addr_of_mut!((*control).next_producer_id),
                        value,
                        value + 1
                    ));
                })
            });
        }
        run_root(&tx, 147);
        assert_released(&tx);
        assert_no_tail();
        assert_eq!(count_event("observe enter alloc_id"), 7);
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1015);
        assert_eq!(
            ATTRIB_CONTROL.peek(0).unwrap().producer_mode,
            PRODUCER_ADMITTED
        );
        assert!(script(|s| s.hooks.is_empty()));
        trace();
    }
    #[test]
    fn legal_poison_before_bind_or_commit_cleans_original_domain() {
        for at in ["enter bind_prepare", "enter commit_publish"] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            hook(at, 1, poison_domain);
            run_root(&tx, 147);
            assert_released(&tx);
            assert_no_tail();
            let control = ATTRIB_CONTROL.peek(0).unwrap();
            assert_eq!(
                (
                    control.producer_mode,
                    control.relation_epoch,
                    control.loss_epoch
                ),
                (1, 14, 15)
            );
            assert_eq!(
                REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                    .unwrap()
                    .data[5],
                3,
                "D0 pending X retired after epoch advance"
            );
            assert!(REL
                .peek(rel_key(14, tx.context, 0, REL_X_INDEX, 0))
                .is_none());
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            assert_original_resolutions(if at == "enter bind_prepare" { 2 } else { 3 });
            trace();
        }
    }
    #[test]
    fn busy_lock_attempts_and_unlock_have_exact_transaction_scope() {
        for release_before in 1..=9 {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            let state = ATTR_STATE.get_ptr_mut(0).unwrap();
            observed("competitor", || unsafe {
                assert!(compare(addr_of_mut!((*state).publication_busy), 0, 1));
            });
            if release_before <= 8 {
                hook("cas:busy:0:1", release_before, move || {
                    observed("competitor", || unsafe {
                        assert!(compare(addr_of_mut!((*state).publication_busy), 1, 0));
                    })
                });
            }
            run_root(&tx, 147);
            assert_released(&tx);
            let (attempts, unlocks) = edit(|s| {
                let events: Vec<_> = s
                    .events
                    .iter()
                    .filter(|e| {
                        e.scopes.last() == Some(&"commit_publish")
                            && e.operation.starts_with("cas state ")
                            && e.operation.contains("field=busy")
                    })
                    .collect();
                (
                    events
                        .iter()
                        .filter(|e| e.operation.contains("expected=0 new=1"))
                        .count(),
                    events
                        .iter()
                        .filter(|e| e.operation.contains("expected=1 new=0"))
                        .count(),
                )
            });
            assert_eq!(attempts, release_before.min(8));
            assert_eq!(unlocks, usize::from(release_before <= 8));
            if release_before <= 8 {
                assert_owner(&tx, 3, 1001, 16, 1006, 1007);
            } else {
                assert_no_tail();
                assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
                assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 1);
            }
            trace();
        }
    }
    #[test]
    fn legal_post_bound_poison_preserves_partial_bound_rows_and_cell1() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        hook("exit publish_bound_selector", 1, poison_domain);
        run_root(&tx, 147);
        assert_released(&tx);
        assert_no_tail();
        assert_original_resolutions(5);
        assert_eq!(
            ATTRIB_CONTROL.peek(0).unwrap().producer_mode,
            PRODUCER_POISONED
        );
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
        assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 0);
        assert!(REL.peek(global_key(1005, REL_OBJECT_SELECTOR, 3)).is_some());
        assert!(SELECTOR_DICT
            .peek(SelectorDictionaryKey {
                session_id: 1,
                selector_id: 1006
            })
            .is_some());
        assert!(REL.peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0)).is_none());
        assert_eq!(
            REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                .unwrap()
                .data[5],
            3
        );
        trace();
    }
    #[test]
    fn late_terminal_poison_keeps_successful_sequence_and_revokes_both_handles() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        hook("cas-done:sequence:15:16", 1, poison_domain);
        run_root(&tx, 147);
        assert_released(&tx);
        assert_original_resolutions(5);
        assert_eq!(
            ATTR_STATE.peek(0).unwrap().published_sequence,
            16,
            "late refusal cannot reverse published sequence"
        );
        assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 0);
        assert_eq!(
            ATTRIB_CONTROL.peek(0).unwrap().producer_mode,
            PRODUCER_POISONED
        );
        assert_owner(&tx, 3, 1001, 16, 1006, 1007);
        assert!(quarantined(&target(), tx.context, QUARANTINE_CONTEXT_X));
        assert!(quarantined(&target(), tx.owner, QUARANTINE_OWNER_U));
        let order = edit(|s| {
            s.events
                .iter()
                .filter_map(|e| {
                    if e.scopes.last() == Some(&"commit_publish")
                        && e.operation.starts_with("cas state ")
                        && e.operation.contains("field=busy expected=1 new=0")
                    {
                        Some("unlock")
                    } else if e.operation == "observe enter dispatch_producer_outcome" {
                        Some("dispatch")
                    } else if e.operation == "observe enter cleanup_pending_x" {
                        Some("cleanup")
                    } else if e.operation == "observe enter release_frame" {
                        Some("release")
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(order, vec!["unlock", "dispatch", "cleanup", "release"]);
        trace();
    }
    #[test]
    fn constructor_and_provider_dup_stage_only_the_linked_parent() {
        for family in [3, 4] {
            for duplicate in [false, true] {
                reset(family);
                let parent_role = match (family, duplicate) {
                    (3, false) => 147,
                    (4, false) => 148,
                    (3, true) => 151,
                    _ => 152,
                };
                let child_role = match (family, duplicate) {
                    (3, false) => 258,
                    (4, false) => 259,
                    (3, true) => 290,
                    _ => 291,
                };
                let parent = root_frame(parent_role, 90, 0);
                let mut child = root_frame(child_role, 91, 1);
                child.owner = 0x2200;
                unsafe {
                    (*parent.frame).entry_handle = 0x2000;
                    (*parent.frame).current_c = 0x6000;
                    (*child.frame).entry_handle = if duplicate { 0x1100 } else { 0x6000 };
                    (*child.frame).parent_occurrence_id = 90;
                    (*child.frame).constructor_cookie = 0x8000_0002;
                }
                run_root(&child, child_role);
                assert!(BIND_PENDING.peek(child.key).is_none());
                assert!(BIND_PENDING.peek(parent.key).is_some());
                let row = unsafe { *parent.frame };
                assert_eq!(row.staged_x, 0x2200);
                assert_eq!(row.transaction_flags, 0);
                assert_eq!(row.constructor_count, if duplicate { 0 } else { 1 });
                if !duplicate {
                    assert_eq!(
                        (
                            row.constructor_cookie,
                            row.source_object_id,
                            row.source_epoch
                        ),
                        (0x8000_0002, 0x8000_0002, 31)
                    );
                }
                let x = REL.peek(rel_key(13, 0x2200, 0, REL_X_INDEX, 0)).unwrap();
                let mut expected = blank_rel();
                expected.witness_id = 90;
                expected.parent_id = 90;
                expected.evidence_epoch = 13;
                expected.born_ns = 900;
                expected.state = REL_WITNESS;
                expected.data[..7].copy_from_slice(&[0, 90, 21, 1, 0, 1, u64::from(family)]);
                assert_eq!(
                    bytes(&x),
                    bytes(&expected),
                    "complete parent-owned pending X"
                );
                assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 3);
                assert_no_tail();
                trace();
            }
        }
    }
    #[test]
    fn constructor_refusals_preserve_parent_staging_and_mark_conflicts() {
        for case in 0..6 {
            reset(3);
            let parent = root_frame(147, 90, 0);
            let mut child = root_frame(258, 91, 1);
            child.owner = 0x2200;
            unsafe {
                (*parent.frame).current_c = 0x6000;
                (*child.frame).entry_handle = 0x6000;
                (*child.frame).parent_occurrence_id = 90;
                (*child.frame).constructor_cookie = 0x8000_0002;
            }
            match case {
                0 => unsafe {
                    (*child.frame).parent_occurrence_id = 0;
                },
                1 => unsafe {
                    (*parent.frame).api_role = 151;
                },
                2 => unsafe {
                    (*parent.frame).current_c = 0;
                },
                3 => unsafe {
                    (*child.frame).entry_handle = 0x6001;
                },
                4 => unsafe {
                    (*parent.frame).constructor_count = 1;
                },
                5 => {
                    SITE_BIND.remove(site_key(0x8000_0002)).unwrap();
                }
                _ => unreachable!(),
            }
            run_root(&child, 258);
            assert!(BIND_PENDING.peek(child.key).is_none());
            let row = unsafe { *parent.frame };
            assert_eq!(row.staged_x, 0);
            assert_eq!(row.constructor_count, if case == 4 { 1 } else { 0 });
            assert_eq!(
                row.transaction_flags,
                match case {
                    2..=4 => TXN_AMBIGUITY,
                    5 => TXN_GUARD_CHANGED,
                    _ => 0,
                }
            );
            assert!(REL
                .peek(rel_key(13, child.owner, 0, REL_X_INDEX, 0))
                .is_none());
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn public_dup_retires_pending_context_even_for_null_destination() {
        for family in [3, 4] {
            for destination in [0, 0x2000, 0x3000] {
                reset(family);
                let mut tx = prepare(family, 21, destination, 0x2200, 91, false);
                let role = if family == 3 { 151 } else { 152 };
                unsafe {
                    (*tx.frame).api_role = role;
                    (*tx.frame).entry_handle = 0x2000;
                }
                tx.owner = destination;
                run_root(&tx, role);
                assert_released(&tx);
                let x = REL
                    .peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                    .unwrap();
                assert_eq!((x.data[0], x.data[1], x.data[5]), (0, 91, 3));
                assert!(REL
                    .peek(rel_key(13, destination, 0, REL_U_INDEX, 0))
                    .is_none());
                assert_eq!(
                    quarantined(&target(), 0x2000, QUARANTINE_OWNER_U),
                    destination == 0x2000
                );
                assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
                assert_no_tail();
                trace();
            }
        }
    }
    #[test]
    fn original_sequence_survives_publication_counter_advance_probe() {
        // Only a counter transition is modeled here, not a full peer
        // publication. This sensitivity probe cannot establish a legal
        // cross-CPU publisher schedule or stand in for such a trace.
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let state = ATTR_STATE.get_ptr_mut(0).unwrap();
        hook("enter bind_prepare", 1, move || {
            observed("counter-advance-probe", || unsafe {
                assert!(compare(addr_of_mut!((*state).published_sequence), 15, 16));
            })
        });
        run_root(&tx, 147);
        assert_released(&tx);
        assert_original_resolutions(5);
        assert_owner(&tx, 3, 1001, 17, 1006, 1007);
        trace();
    }
    #[test]
    fn post_bound_relation_comparisons_are_independent_fault_probes() {
        for change_control in [false, true] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            let frame = tx.frame;
            let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
            // Deliberate under-lock corruption. First case changes only the
            // frame; second makes post Target agree with changed frame while
            // disagreeing with the worker's original relation snapshot.
            hook("exit publish_bound_selector", 1, move || unsafe {
                (*frame).relation_epoch = 14;
                if change_control {
                    (*control).relation_epoch = 14;
                }
            });
            run_root(&tx, 147);
            assert_released(&tx);
            assert_original_resolutions(5);
            assert_no_tail();
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            assert_eq!(
                REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                    .unwrap()
                    .data[5],
                3,
                "cleanup uses saved D0, never the changed frame/control"
            );
            assert!(REL
                .peek(rel_key(14, tx.context, 0, REL_X_INDEX, 0))
                .is_none());
            trace();
        }
    }
    #[test]
    fn all_tail_words_precede_clobber_and_survive_each_tail_helper() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let expected = [
            11, 12, 13, 0x2000, 1001, 0x2200, 91, 16, 3, 900, 82, 31, 0x4000, 81, 0x5000, 1002,
            1004, 1003, 61, 1006, 1007,
        ];
        for at in [
            "enter flip_x_tail",
            "exit flip_x_tail",
            "exit insert_u_tail",
            "exit insert_owner_selector_tail",
            "exit insert_owner_tail",
        ] {
            hook(at, 1, move || {
                let slot = ITER_SLOT.peek(1).unwrap();
                assert_eq!(slot.staging[..21], expected, "all original tail survivors");
                assert_eq!(
                    slot.staging[21..],
                    [0xa5a5_a5a5_a5a5_a5a5; 11],
                    "tail padding unchanged"
                );
            });
        }
        run_root(&tx, 147);
        assert_released(&tx);
        assert_owner(&tx, 3, 1001, 16, 1006, 1007);
        let plans = script(|s| {
            s.plans
                .iter()
                .filter(|(c, _, _)| *c == 1)
                .copied()
                .collect::<Vec<_>>()
        });
        assert_eq!(
            plans,
            (0..21).map(|i| (1, i * 8, expected[i])).collect::<Vec<_>>(),
            "21 ordered cell1 writes only at original phase"
        );
        assert!(script(|s| s.hooks.is_empty()));
        trace();
    }
    #[test]
    fn bound_insert_failures_keep_exact_successful_prefix() {
        for family in [3, 4] {
            for failed in 0..4 {
                reset(family);
                let tx = prepare(family, 21, 0x2000, 0x2200, 91, false);
                let mut exact = ExactNameKey {
                    object_domain: 61,
                    operation: family,
                    name_length: 4,
                    name: [0; 128],
                };
                exact.name[..4].copy_from_slice(if family == 3 { b"HMAC" } else { b"HKDF" });
                let object = global_key(1005, REL_OBJECT_SELECTOR, family);
                let dictionary = SelectorDictionaryKey {
                    session_id: 1,
                    selector_id: 1006,
                };
                match failed {
                    0 => deny("exact", exact),
                    1 => deny("rel", object),
                    2 => deny("dictionary", dictionary),
                    3 => hook("enter publish_bound_selector", 1, move || {
                        let slot = ITER_SLOT.peek(0).unwrap();
                        let data = bytes(&slot.staging);
                        let mut digest = DigestKey {
                            code_object_id: 61,
                            operation: family,
                            reserved: 0,
                            digest: [0; 32],
                        };
                        digest.digest.copy_from_slice(&data[144..176]);
                        deny("digest", digest);
                    }),
                    _ => unreachable!(),
                }
                run_root(&tx, if family == 3 { 147 } else { 148 });
                assert_released(&tx);
                assert_no_tail();
                assert_eq!(EXACT_NAME.peek(exact).is_some(), failed >= 1);
                assert_eq!(REL.peek(object).is_some(), failed >= 2);
                assert_eq!(SELECTOR_DICT.peek(dictionary).is_some(), failed >= 3);
                assert_eq!(
                    edit(|s| s.rows.keys().filter(|(m, _)| *m == "digest").count()),
                    0
                );
                assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
                assert_eq!(
                    REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                        .unwrap()
                        .data[5],
                    3
                );
                assert!(REL.peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0)).is_none());
                assert_eq!(
                    ATTRIB_CONTROL.peek(0).unwrap().relation_epoch,
                    14,
                    "deferred poison after partial refusal"
                );
                trace();
            }
        }
    }
    #[test]
    fn owner_insert_failures_keep_flipped_x_and_complete_u_without_sequence() {
        for failed in [REL_OWNER_SELECTOR, REL_OWNER] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            let selected = rel_key(1001, 1004, 61, REL_OWNER_SELECTOR, 3);
            let owner = rel_key(1001, tx.owner, tx.context, REL_OWNER, 3);
            deny(
                "rel",
                if failed == REL_OWNER_SELECTOR {
                    selected
                } else {
                    owner
                },
            );
            run_root(&tx, 147);
            assert_released(&tx);
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            assert_eq!(REL.peek(selected).is_some(), failed == REL_OWNER);
            assert!(REL.peek(owner).is_none());
            let mut expected = blank_rel();
            expected.witness_id = 1001;
            expected.parent_id = 91;
            expected.evidence_epoch = 13;
            expected.born_ns = 900;
            expected.state = REL_WITNESS;
            expected.data[..8].copy_from_slice(&[1001, 91, 0, 0, 0x2200, 2, 3, 16]);
            assert_eq!(
                bytes(&REL.peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0)).unwrap()),
                bytes(&expected),
                "partial publication retains full U row"
            );
            let x = REL
                .peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                .unwrap();
            assert_eq!(
                (
                    x.witness_id,
                    x.data[0],
                    x.data[1],
                    x.data[4],
                    x.data[5],
                    x.data[7]
                ),
                (1001, 1001, 91, tx.owner, 2, 16),
                "cleanup cannot retire a flipped X"
            );
            assert!(quarantined(&target(), tx.context, QUARANTINE_CONTEXT_X));
            assert!(quarantined(&target(), tx.owner, QUARANTINE_OWNER_U));
            trace();
        }
    }
    #[test]
    fn failed_x_cas_retains_preceding_stores_and_never_inserts_u() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let x = REL
            .get_ptr_mut(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
            .unwrap();
        // Exact real competing retirement transition. This focuses the tail
        // primitive; reachability of an invalidator at this point is separate.
        hook("cas:index_state:1:2", 1, move || {
            observed("retirement-probe", || unsafe {
                assert!(compare(addr_of_mut!((*x).data[5]), 1, 3));
            })
        });
        run_root(&tx, 147);
        assert_released(&tx);
        let row = unsafe { *x };
        assert_eq!(
            (
                row.witness_id,
                row.data[0],
                row.data[4],
                row.data[5],
                row.data[7]
            ),
            (1001, 1001, tx.owner, 3, 16)
        );
        assert!(REL.peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0)).is_none());
        assert_eq!(count_event("observe enter insert_u_tail"), 0);
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
        trace();
    }
    #[test]
    fn per_cpu_staging_allocations_keep_all_retained_handles_independent() {
        reset(3);
        assert_eq!(core::mem::size_of::<SlotKey>(), 8);
        let a = ITER_SLOT.get_ptr_mut(0).unwrap();
        let b = ITER_SLOT.get_ptr_mut(1).unwrap();
        let (c, d) = on_cpu(1, || {
            initialize_cpu_slots();
            (
                ITER_SLOT.get_ptr_mut(0).unwrap(),
                ITER_SLOT.get_ptr_mut(1).unwrap(),
            )
        });
        let all = [a, b, c, d];
        for i in 0..4 {
            for j in 0..i {
                assert_ne!(all[i], all[j], "four separate typed SourceSlot allocations");
            }
        }
        unsafe {
            plan_store(a, 240, 111);
            plan_store(b, 240, 222);
        }
        on_cpu(1, || unsafe {
            plan_store(c, 240, 333);
            plan_store(d, 240, 444);
        });
        assert_eq!(ITER_SLOT.peek(0).unwrap().staging[30], 111);
        assert_eq!(ITER_SLOT.peek(1).unwrap().staging[30], 222);
        on_cpu(1, || {
            assert_eq!(ITER_SLOT.peek(0).unwrap().staging[30], 333);
            assert_eq!(ITER_SLOT.peek(1).unwrap().staging[30], 444);
        });
        assert_eq!(unsafe { plan_load(a, 240) }, 111);
        assert_eq!(unsafe { plan_load(c, 240) }, 333);
        trace();
    }
    #[test]
    fn legal_two_prepared_publishers_preserve_equal_digest_fail_closed_policy() {
        reset(3);
        let current = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let peer = on_cpu(1, || {
            initialize_cpu_slots();
            prepare(3, 22, 0x1000, 0x1100, 90, false)
        });
        let peer_key = peer.key;
        THREAD_IDENTITY.set(
            ThreadIdentityKey {
                process_incarnation: 11,
                tid: 79,
                reserved: 0,
            },
            ThreadIdentityValue {
                thread_incarnation: 22,
                image_epoch: 12,
            },
        );
        hook("exit bind_prepare", 1, move || {
            on_cpu(1, || {
                // The current publisher has its own complete create plan on CPU0.
                // CPU1 executes its full real root on its independent slots.
                assert_eq!(
                    typed_return(&RetProbeContext(0x1000), 0x8000_0001, 77, 79, 900),
                    0
                );
                assert!(BIND_PENDING.peek(peer_key).is_none());
                assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 16);
            })
        });
        run_root(&current, 147);
        assert!(BIND_PENDING.peek(current.key).is_none());
        assert!(BIND_PENDING.peek(peer.key).is_none());
        assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
        assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 0);
        assert_eq!(
            ATTR_STATE.peek(0).unwrap().published_sequence,
            16,
            "loser must not advance sequence"
        );
        assert_eq!(
            ATTRIB_CONTROL.peek(0).unwrap().next_producer_id,
            1015,
            "both sets of seven ordered IDs stay spent"
        );
        assert_eq!(
            (
                ATTRIB_CONTROL.peek(0).unwrap().relation_epoch,
                ATTRIB_CONTROL.peek(0).unwrap().loss_epoch
            ),
            (14, 15),
            "equal-digest race remains deferred poison"
        );
        assert_eq!(
            REL.peek(rel_key(13, current.context, 0, REL_X_INDEX, 0))
                .unwrap()
                .data[5],
            3
        );
        assert!(REL
            .peek(rel_key(13, current.owner, 0, REL_U_INDEX, 0))
            .is_none());
        assert_owner(&peer, 3, 1008, 16, 1013, 1014);
        assert_eq!(
            ITER_SLOT.peek(1).unwrap().staging,
            [0xa5a5_a5a5_a5a5_a5a5; 32],
            "losing CPU never stages tail"
        );
        assert_eq!(count_event("observe enter conflict_digest"), 1);
        for key in [current.key, peer.key] {
            let expected = format!("remove map=pending key={:?} result=Ok(())", bytes(&key));
            assert_eq!(count_event(&expected), 1, "each original K removed once");
        }
        assert!(script(|s| s.hooks.is_empty()));
        trace();
    }
    #[test]
    fn seeded_digest_collision_compares_all_bytes_lengths_and_both_requests() {
        // Abstract digest-identity collision inputs, not a real SHA collision.
        // Tail127 and deleted immutable request are explicitly stronger data
        // probes; the function must still preserve its full defensive reads.
        for case in 0..6 {
            reset(3);
            let mut ours = blank_rel();
            ours.witness_id = 82;
            ours.state = REL_WITNESS;
            ours.data[0] = 3;
            ours.data[1] = 64;
            ours.tail[..64].fill(b'A');
            let mut theirs = ours;
            theirs.witness_id = 83;
            match case {
                0 => {}
                1 => theirs.tail[0] = b'B',
                2 => theirs.tail[63] = b'B',
                3 => theirs.tail[127] = b'B',
                4 => {
                    theirs.data[1] = 65;
                    theirs.tail[64] = b'B';
                }
                5 => {}
                _ => unreachable!(),
            }
            REL.set(global_key(82, REL_REQUEST_NAME, 3), ours);
            REL.set(global_key(83, REL_REQUEST_NAME, 3), theirs);
            let mut bound = blank_rel();
            bound.witness_id = 50;
            bound.state = REL_WITNESS;
            bound.data[..5].copy_from_slice(&[61, 3, 83, 56, 57]);
            bound.tail[..32].fill(0x11);
            REL.set(global_key(50, REL_OBJECT_SELECTOR, 3), bound);
            let digest = DigestKey {
                code_object_id: 61,
                operation: 3,
                reserved: 0,
                digest: [0x11; 32],
            };
            DIGEST_INDEX.set(digest, 50);
            if case == 5 {
                REL.remove(global_key(82, REL_REQUEST_NAME, 3)).unwrap();
            }
            let result = conflict_digest(50, 82, 3, 61);
            let unequal = matches!(case, 1..=4);
            assert_eq!(
                result, unequal,
                "full byte/length collision decision case{case}"
            );
            let after = REL.peek(global_key(50, REL_OBJECT_SELECTOR, 3)).unwrap();
            let mut expected = bound;
            if unequal {
                expected.state = REL_CONFLICT;
            }
            assert_eq!(bytes(&after), bytes(&expected));
            assert_eq!(
                DIGEST_INDEX.peek(digest),
                Some(if unequal { 0 } else { 50 })
            );
            for request in [82, 83] {
                assert_eq!(
                    count_event(&format!(
                        "observe {}",
                        point("lookup", "rel", &global_key(request, REL_REQUEST_NAME, 3))
                    )),
                    1,
                    "both request lookups before combined miss"
                );
            }
            assert_eq!(
                PRODUCER_LOSS.peek(LOSS_CONFLICT).unwrap(),
                u64::from(unequal)
            );
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn bound_collision_path_zeros_digest_index_before_loss_without_new_owner() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        hook("enter publish_bound_selector", 1, || {
            let data = bytes(&ITER_SLOT.peek(0).unwrap().staging);
            let mut digest = DigestKey {
                code_object_id: 61,
                operation: 3,
                reserved: 0,
                digest: [0; 32],
            };
            digest.digest.copy_from_slice(&data[144..176]);
            // Existing immutable facts share the candidate's seeded digest
            // identity but name the already distinct request83. This is an
            // abstract collision fixture; no hash algorithm is substituted.
            let mut bound = blank_rel();
            bound.witness_id = 50;
            bound.state = REL_WITNESS;
            bound.data[..5].copy_from_slice(&[61, 3, 83, 56, 57]);
            bound.tail[..32].copy_from_slice(&digest.digest);
            REL.set(global_key(50, REL_OBJECT_SELECTOR, 3), bound);
            DIGEST_INDEX.set(digest, 50);
        });
        run_root(&tx, 147);
        assert_released(&tx);
        assert_no_tail();
        assert_eq!(
            REL.peek(global_key(50, REL_OBJECT_SELECTOR, 3))
                .unwrap()
                .state,
            REL_CONFLICT
        );
        assert!(REL.peek(global_key(1005, REL_OBJECT_SELECTOR, 3)).is_none());
        assert!(REL.peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0)).is_none());
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().relation_epoch, 13);
        let (conflict, zero, loss) = edit(|s| {
            let conflict = s
                .events
                .iter()
                .position(|e| {
                    e.operation.starts_with("cas rel ")
                        && e.operation.contains("field=state expected=1 new=4")
                })
                .unwrap();
            let zero = s
                .events
                .iter()
                .position(|e| e.operation.starts_with("insert map=digest "))
                .unwrap();
            assert!(s.events[zero].operation.contains("flags=0"));
            let loss = s
                .events
                .iter()
                .position(|e| {
                    e.operation
                        == format!(
                            "lookup map=loss key={:?} present=true",
                            bytes(&LOSS_CONFLICT)
                        )
                })
                .unwrap();
            (conflict, zero, loss)
        });
        assert!(
            conflict < zero && zero < loss,
            "conflict then BPF_ANY zero then loss"
        );
        assert_eq!(PRODUCER_LOSS.peek(LOSS_CONFLICT).unwrap(), 1);
        trace();
    }
    #[test]
    fn bind_scalar_guard_faults_stop_before_allocation_or_staging() {
        // Direct primitive probes isolate each predicate, including malformed
        // fields that the actual root rejects even earlier.
        for case in 0..20 {
            reset(3);
            let mut tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            unsafe {
                match case {
                    0 => tx.owner = 0,
                    1 => (*tx.frame).entry_handle = 0,
                    2 => (*tx.frame).method_observation_id = 0,
                    3 => (*tx.frame).selector_or_set_id = 0,
                    4 => (*tx.frame).current_p = 0,
                    5 => (*tx.frame).current_c = 0,
                    6 => (*tx.frame).staged_x = 0,
                    7 => (*tx.frame).getter_count = 0,
                    8 => (*tx.frame).getter_count = 2,
                    9 => (*tx.frame).constructor_count = 0,
                    10 => (*tx.frame).constructor_count = 2,
                    11 => (*tx.frame).constructor_cookie = 0,
                    12 => (*tx.frame).source_epoch = 0,
                    13 => (*tx.frame).source_object_id = 0,
                    14 => (*tx.frame).relation_epoch = 12,
                    15 => (*tx.frame).loss_epoch = 13,
                    16 => (*tx.frame).mapping_epoch = 1,
                    17 => (*tx.frame).reserved = 1,
                    18 => (*tx.frame).transaction_flags = 1,
                    19 => (*tx.frame).api_role = 130,
                    _ => unreachable!(),
                }
            }
            let before = ITER_SLOT.peek(0).unwrap();
            let begin = edit(|s| s.events.len());
            assert!(!bind_prepare(
                ATTRIB_CONTROL.get_ptr_mut(0).unwrap(),
                tx.frame,
                (77u64 << 32) | 78,
                &mut target(),
                tx.owner
            ));
            assert_eq!(
                bytes(&ITER_SLOT.peek(0).unwrap()),
                bytes(&before),
                "no scratch write at scalar guard {case}"
            );
            assert_eq!(
                edit(|s| s.events[begin..]
                    .iter()
                    .filter(|e| e.operation == "observe enter alloc_id")
                    .count()),
                0
            );
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn bind_dependency_faults_preserve_first_failed_lookup_order() {
        for case in 0..12 {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            let method = rel_key(13, 0x4000, 0, REL_METHOD, 3);
            let ambiguity = rel_key(0, 0x4000, 0, REL_METHOD_AMBIGUITY, 3);
            let quarantine = rel_key(0, 0x2200, QUARANTINE_CONTEXT_X, REL_CONTEXT_QUARANTINE, 0);
            let x = rel_key(13, 0x2200, 0, REL_X_INDEX, 0);
            let request = global_key(82, REL_REQUEST_NAME, 3);
            match case {
                0 => {
                    REL.remove(method).unwrap();
                }
                1 => {
                    let p = REL.get_ptr_mut(method).unwrap();
                    unsafe {
                        (*p).witness_id = 99;
                    }
                }
                2 => {
                    let p = REL.get_ptr_mut(method).unwrap();
                    unsafe {
                        (*p).parent_id = 99;
                    }
                }
                3 => retire_row(REL.get_ptr_mut(method).unwrap()),
                4 => REL.set(ambiguity, blank_rel()),
                5 => REL.set(quarantine, blank_rel()),
                6 => {
                    let p = REL.get_ptr_mut(x).unwrap();
                    unsafe {
                        (*p).data[1] = 99;
                    }
                }
                7 => {
                    SITE_BIND.remove(site_key(0x8000_0002)).unwrap();
                }
                8 => {
                    let p = SITE_BIND.get_ptr_mut(site_key(0x8000_0002)).unwrap();
                    unsafe {
                        (*p).code_object_id = 0;
                    }
                }
                9 => {
                    REL.remove(request).unwrap();
                }
                10 => {
                    let p = REL.get_ptr_mut(request).unwrap();
                    unsafe {
                        (*p).data[0] = 4;
                    }
                }
                11 => {
                    let p = REL.get_ptr_mut(request).unwrap();
                    unsafe {
                        (*p).data[1] = 127;
                    }
                }
                _ => unreachable!(),
            }
            let begin = edit(|s| s.events.len());
            let before = ITER_SLOT.peek(0).unwrap();
            assert!(!bind_prepare(
                ATTRIB_CONTROL.get_ptr_mut(0).unwrap(),
                tx.frame,
                (77u64 << 32) | 78,
                &mut target(),
                tx.owner
            ));
            let actual = edit(|s| {
                s.events[begin..]
                    .iter()
                    .filter(|e| {
                        e.operation.starts_with("lookup map=rel ")
                            || e.operation.starts_with("lookup map=bind ")
                    })
                    .map(|e| e.operation.split(" present=").next().unwrap().to_owned())
                    .collect::<Vec<_>>()
            });
            let keys = [
                format!("lookup map=rel key={:?}", bytes(&method)),
                format!("lookup map=rel key={:?}", bytes(&ambiguity)),
                format!("lookup map=rel key={:?}", bytes(&quarantine)),
                format!("lookup map=rel key={:?}", bytes(&x)),
                format!("lookup map=bind key={:?}", bytes(&site_key(0x8000_0002))),
                format!("lookup map=rel key={:?}", bytes(&request)),
            ];
            let length = match case {
                0..=3 => 1,
                4 => 2,
                5 => 3,
                6 => 4,
                7..=8 => 5,
                _ => 6,
            };
            assert_eq!(actual, keys[..length], "first-failed dependency case{case}");
            assert_eq!(bytes(&ITER_SLOT.peek(0).unwrap()), bytes(&before));
            assert_eq!(
                edit(|s| s.events[begin..]
                    .iter()
                    .filter(|e| e.operation == "observe enter alloc_id")
                    .count()),
                0
            );
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn source_retirement_after_bind_prevents_lock_and_keeps_original_cleanup() {
        for method in [false, true] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            hook("exit bind_prepare", 1, move || {
                if method {
                    retire_row(
                        REL.get_ptr_mut(rel_key(13, 0x4000, 0, REL_METHOD, 3))
                            .unwrap(),
                    );
                } else {
                    let guard = SOURCE_GUARD.get_ptr_mut(71).unwrap();
                    unsafe {
                        assert!(compare(
                            addr_of_mut!((*guard).state),
                            GUARD_LIVE,
                            GUARD_RETIRED
                        ));
                    }
                }
            });
            run_root(&tx, 147);
            assert_released(&tx);
            assert_no_tail();
            assert_eq!(count_event("observe enter commit_publish_locked"), 0);
            assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 0);
            assert_eq!(
                REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                    .unwrap()
                    .data[5],
                3
            );
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            trace();
        }
    }
    #[test]
    fn under_lock_quota_and_real_charge_contention_do_not_refund_or_stage_tail() {
        for contended in [false, true] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            let state = ATTR_STATE.get_ptr_mut(0).unwrap();
            if !contended {
                unsafe {
                    (*state).relationship_claims = 8192;
                }
            } else {
                for current in 2..10 {
                    hook(
                        format!("cas:relationships:{current}:{}", current + 7),
                        1,
                        move || {
                            observed("competitor-charge", || unsafe {
                                assert!(compare(
                                    addr_of_mut!((*state).relationship_claims),
                                    current,
                                    current + 1
                                ));
                            })
                        },
                    );
                }
            }
            run_root(&tx, 147);
            assert_released(&tx);
            assert_no_tail();
            assert_eq!(
                ATTR_STATE.peek(0).unwrap().relationship_claims,
                if contended { 10 } else { 8192 }
            );
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            assert_eq!(ATTR_STATE.peek(0).unwrap().publication_busy, 0);
            assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1008);
            assert_eq!(count_event("observe enter publish_bound_selector"), 0);
            assert_eq!(PRODUCER_LOSS.peek(LOSS_CHARGE).unwrap(), 1);
            trace();
        }
    }
    #[test]
    fn maximum_sequence_refuses_before_charge_and_preserves_value() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let state = ATTR_STATE.get_ptr_mut(0).unwrap();
        unsafe {
            (*state).published_sequence = u64::MAX;
        }
        run_root(&tx, 147);
        assert_released(&tx);
        assert_no_tail();
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, u64::MAX);
        assert_eq!(ATTR_STATE.peek(0).unwrap().relationship_claims, 2);
        assert_eq!(count_event("observe enter publish_bound_selector"), 0);
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().relation_epoch, 14);
        trace();
    }
    #[test]
    fn root_scalar_snapshots_survive_immutable_configuration_fault_probes() {
        for role_probe in [false, true] {
            reset(3);
            let tx = if role_probe {
                prepare(3, 21, 0x2000, 0x2200, 91, false)
            } else {
                let mut tx = root_frame(142, 91, 0);
                tx.owner = 0;
                tx
            };
            admit(if role_probe { 147 } else { 142 });
            if role_probe {
                hook(point("lookup", "bind", &site_key(0x8000_0001)), 1, || {
                    let row = TYPED_ADMISSION.get_ptr_mut(site_key(0x8000_0001)).unwrap();
                    unsafe {
                        (*row).role_id = 148;
                        (*row).operation = 4;
                    }
                });
            } else {
                hook(
                    point(
                        "lookup",
                        "rel",
                        &rel_key(0, 0x8000_0001, 31, SOURCE_READY, 0),
                    ),
                    1,
                    || {
                        let row = SITE_BIND.get_ptr_mut(site_key(0x8000_0001)).unwrap();
                        unsafe {
                            (*row).source_epoch = 32;
                        }
                    },
                );
            }
            typed_return(&RetProbeContext(tx.owner), 0x8000_0001, 77, 78, 900);
            assert_released(&tx);
            if role_probe {
                assert_owner(&tx, 3, 1001, 16, 1006, 1007);
            } else {
                assert_no_tail();
            }
            trace();
        }
    }
    #[test]
    fn cleanup_restores_original_full_target_after_domain_and_frame_faults() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let frame = tx.frame;
        hook("exit publish_bound_selector", 1, move || {
            // Live-image replacement is an explicit impossible-state probe.
            // Preserve relation so the existing two relation checks pass;
            // flip-X then misses the foreign domain and must abort.
            let domain = SOURCE_DOMAIN.get_ptr_mut(77).unwrap();
            let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
            unsafe {
                (*domain).process_incarnation = 88;
                (*domain).current_image = 99;
                (*control).loss_epoch = 15;
                (*frame).loss_epoch = 77;
            }
        });
        run_root(&tx, 147);
        assert_released(&tx);
        assert_eq!(
            script(|s| s.cleanup_targets.clone()),
            vec![[11, 12, 13, 14, 15]],
            "saved original D0 and E, never changed frame/control/Target"
        );
        assert_eq!(
            REL.peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
                .unwrap()
                .data[5],
            3
        );
        assert_eq!(ITER_SLOT.peek(1).unwrap().staging[..3], [88, 99, 13]);
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
        trace();
    }
    #[test]
    fn release_contention_retains_our_reservation_after_original_key_removal() {
        reset(3);
        let mut tx = root_frame(142, 91, 0);
        tx.owner = 0;
        for current in 3..11 {
            hook(format!("cas:pending:{current}:{}", current - 1), 1, || {
                observed("competing-pending-claim", || {
                    assert!(source_state::claim_pending());
                })
            });
        }
        run_root(&tx, 142);
        assert!(BIND_PENDING.peek(tx.key).is_none());
        assert_eq!(count_event("observe enter release_frame"), 1);
        assert_eq!(
            ATTR_STATE.peek(0).unwrap().pending_claims,
            11,
            "eight other claims plus the unrefunded original reservation and fixed pair"
        );
        assert_eq!(PRODUCER_LOSS.peek(LOSS_PAIR).unwrap(), 1);
        assert!(script(|s| s.hooks.is_empty()));
        assert_no_tail();
        trace();
    }
    #[test]
    fn deferred_marker_failures_and_order_preserve_original_domain() {
        for failed in [0, 1, 2] {
            reset(3);
            let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
            deny("rel", rel_key(1001, tx.owner, tx.context, REL_OWNER, 3));
            let qx = rel_key(
                0,
                tx.context,
                QUARANTINE_CONTEXT_X,
                REL_CONTEXT_QUARANTINE,
                0,
            );
            let qu = rel_key(0, tx.owner, QUARANTINE_OWNER_U, REL_CONTEXT_QUARANTINE, 0);
            if failed == 1 {
                deny("rel", qx);
            } else if failed == 2 {
                deny("rel", qu);
            }
            run_root(&tx, 147);
            assert_released(&tx);
            assert_eq!(REL.peek(qx).is_some(), failed != 1);
            assert_eq!(REL.peek(qu).is_some(), failed != 2);
            assert_eq!(
                script(|s| s.dispatch_targets.clone()),
                vec![[11, 12, 13, 14, 15]]
            );
            assert_eq!(
                script(|s| s.cleanup_targets.clone()),
                vec![[11, 12, 13, 14, 15]]
            );
            assert_eq!(
                ATTRIB_CONTROL.peek(0).unwrap().relation_epoch,
                if failed == 0 { 14 } else { 15 }
            );
            assert_eq!(
                ATTRIB_CONTROL.peek(0).unwrap().loss_epoch,
                if failed == 0 { 15 } else { 16 }
            );
            let (qx_at, qu_at) = edit(|s| {
                let x = s
                    .events
                    .iter()
                    .position(|e| {
                        e.operation
                            .starts_with(&format!("insert map=rel key={:?} ", bytes(&qx)))
                    })
                    .unwrap();
                let u = s
                    .events
                    .iter()
                    .position(|e| {
                        e.operation
                            .starts_with(&format!("insert map=rel key={:?} ", bytes(&qu)))
                    })
                    .unwrap();
                (x, u)
            });
            assert!(
                qx_at < qu_at,
                "required QX precedes QU even when its insert fails"
            );
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 15);
            trace();
        }
    }
    #[test]
    fn quarantine_duplicate_insert_race_is_durable_and_does_not_poison() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        on_cpu(1, initialize_cpu_slots);
        let key = rel_key(
            0,
            tx.context,
            QUARANTINE_CONTEXT_X,
            REL_CONTEXT_QUARANTINE,
            0,
        );
        hook(point("insert", "rel", &key), 1, || {
            on_cpu(1, || {
                let target = resolve_target(77).unwrap();
                let tomb = Tombstone {
                    control: ATTRIB_CONTROL.get_ptr_mut(0).unwrap(),
                    target: &target,
                    handle: 0x2200,
                    domain: QUARANTINE_CONTEXT_X,
                    reason: CONFLICT_SHARED_X,
                    occurrence: 92,
                    now_ns: 900,
                };
                assert!(quarantine(&tomb));
            })
        });
        let target = target();
        let tomb = Tombstone {
            control: ATTRIB_CONTROL.get_ptr_mut(0).unwrap(),
            target: &target,
            handle: 0x2200,
            domain: QUARANTINE_CONTEXT_X,
            reason: CONFLICT_SHARED_X,
            occurrence: 91,
            now_ns: 900,
        };
        assert!(quarantine(&tomb));
        let row = REL.peek(key).unwrap();
        assert_eq!(
            (row.witness_id, row.data[0], row.data[1]),
            (1002, CONFLICT_SHARED_X, 92)
        );
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1003);
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().relation_epoch, 13);
        assert_eq!(ATTR_STATE.peek(0).unwrap().relationship_claims, 4);
        let before = bytes(&row);
        assert!(quarantine(&tomb));
        assert_eq!(bytes(&REL.peek(key).unwrap()), before);
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, 1003);
        assert_no_tail();
        trace();
    }
    #[test]
    fn sequence_lock_breach_refuses_without_rolling_back_external_value() {
        reset(3);
        let tx = prepare(3, 21, 0x2000, 0x2200, 91, false);
        let state = ATTR_STATE.get_ptr_mut(0).unwrap();
        hook("cas:sequence:15:16", 1, move || {
            observed("sequence-lock-breach", || unsafe {
                assert!(compare(addr_of_mut!((*state).published_sequence), 15, 20));
            })
        });
        run_root(&tx, 147);
        assert_released(&tx);
        assert_eq!(
            ATTR_STATE.peek(0).unwrap().published_sequence,
            20,
            "strong-CAS refusal does not roll back another value"
        );
        assert_owner(&tx, 3, 1001, 16, 1006, 1007);
        assert!(quarantined(&target(), tx.context, QUARANTINE_CONTEXT_X));
        assert!(quarantined(&target(), tx.owner, QUARANTINE_OWNER_U));
        assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().relation_epoch, 14);
        trace();
    }
    #[test]
    fn retired_u_is_reclaimed_without_rewriting_prior_owner_or_context() {
        for family in [3, 4] {
            reset(family);
            let prior = prepare(family, 22, 0x2000, 0x1100, 90, false);
            assert_eq!(publish(&prior), OUT_OK);
            retire_owner_reachable(&target(), REL_U_INDEX, prior.owner);
            let old_owner = REL
                .peek(rel_key(1001, prior.owner, prior.context, REL_OWNER, family))
                .unwrap();
            let old_x = REL
                .peek(rel_key(13, prior.context, 0, REL_X_INDEX, 0))
                .unwrap();
            assert_eq!(old_owner.state, REL_RETIRED);
            assert_eq!(old_x.data[5], 3);
            let current = prepare(family, 21, 0x2000, 0x2200, 91, false);
            run_root(&current, if family == 3 { 147 } else { 148 });
            assert!(BIND_PENDING.peek(current.key).is_none());
            assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
            assert_owner(&current, family, 1008, 17, 1006, 1007);
            assert_eq!(
                bytes(
                    &REL.peek(rel_key(1001, prior.owner, prior.context, REL_OWNER, family))
                        .unwrap()
                ),
                bytes(&old_owner)
            );
            assert_eq!(
                bytes(
                    &REL.peek(rel_key(13, prior.context, 0, REL_X_INDEX, 0))
                        .unwrap()
                ),
                bytes(&old_x)
            );
            trace();
        }
    }
    #[test]
    fn live_u_collision_and_fault_variants_preserve_partial_effects() {
        // Case0 is a real repeated live owner handle; the other cases are
        // explicit missing/foreign/malformed immutable-index probes.
        for case in 0..6 {
            reset(3);
            let prior = prepare(3, 22, 0x2000, 0x1100, 90, false);
            assert_eq!(publish(&prior), OUT_OK);
            let old_u_key = rel_key(13, prior.owner, 0, REL_U_INDEX, 0);
            let old_x_key = rel_key(13, prior.context, 0, REL_X_INDEX, 0);
            let old_owner_key = rel_key(1001, prior.owner, prior.context, REL_OWNER, 3);
            match case {
                1 => {
                    REL.remove(old_x_key).unwrap();
                }
                2 => {
                    let p = REL.get_ptr_mut(old_x_key).unwrap();
                    unsafe {
                        (*p).data[0] = 999;
                    }
                }
                3 => {
                    let p = REL.get_ptr_mut(old_owner_key).unwrap();
                    unsafe {
                        (*p).witness_id = 999;
                    }
                }
                4 => {
                    let p = REL.get_ptr_mut(old_u_key).unwrap();
                    unsafe {
                        (*p).data[5] = 1;
                    }
                }
                5 => {
                    let p = REL.get_ptr_mut(old_u_key).unwrap();
                    unsafe {
                        (*p).data[5] = 0;
                    }
                }
                _ => {}
            }
            let mut expected_u = REL.peek(old_u_key).unwrap();
            let mut expected_owner = REL.peek(old_owner_key).unwrap();
            let expected_x = REL.peek(old_x_key);
            let current = prepare(3, 21, 0x2000, 0x2200, 91, false);
            run_root(&current, 147);
            assert!(BIND_PENDING.peek(current.key).is_none());
            assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
            if case != 5 {
                expected_u.data[5] = 3;
                if case != 3 {
                    expected_owner.state = REL_CONFLICT;
                }
            }
            assert_eq!(bytes(&REL.peek(old_u_key).unwrap()), bytes(&expected_u));
            assert_eq!(
                bytes(&REL.peek(old_owner_key).unwrap()),
                bytes(&expected_owner)
            );
            match expected_x {
                None => assert!(REL.peek(old_x_key).is_none()),
                Some(mut row) => {
                    if !matches!(case, 2 | 5) {
                        row.data[5] = 3;
                    }
                    assert_eq!(
                        bytes(&REL.peek(old_x_key).unwrap()),
                        bytes(&row),
                        "matching sibling only"
                    );
                }
            }
            let x = REL
                .peek(rel_key(13, current.context, 0, REL_X_INDEX, 0))
                .unwrap();
            assert_eq!(
                (x.witness_id, x.data[0], x.data[4], x.data[5], x.data[7]),
                (1008, 1008, current.owner, 2, 17)
            );
            assert!(REL
                .peek(rel_key(1008, current.owner, current.context, REL_OWNER, 3))
                .is_none());
            assert!(REL
                .peek(rel_key(1008, 1011, 61, REL_OWNER_SELECTOR, 3))
                .is_none());
            assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 16);
            assert_eq!(
                ATTRIB_CONTROL.peek(0).unwrap().relation_epoch,
                if case == 5 { 14 } else { 13 }
            );
            assert!(quarantined(
                &target(),
                current.context,
                QUARANTINE_CONTEXT_X
            ));
            assert!(quarantined(&target(), current.owner, QUARANTINE_OWNER_U));
            trace();
        }
    }
    #[test]
    fn constructor_live_x_collision_conflicts_matching_owner_and_u() {
        reset(3);
        let prior = prepare(3, 22, 0x1000, 0x1100, 89, false);
        assert_eq!(publish(&prior), OUT_OK);
        let parent = root_frame(147, 90, 0);
        let mut child = root_frame(258, 91, 1);
        child.owner = prior.context;
        unsafe {
            (*parent.frame).current_c = 0x6000;
            (*child.frame).entry_handle = 0x6000;
            (*child.frame).parent_occurrence_id = 90;
            (*child.frame).constructor_cookie = 0x8000_0002;
        }
        run_root(&child, 258);
        assert!(BIND_PENDING.peek(child.key).is_none());
        assert_eq!(unsafe { (*parent.frame).staged_x }, 0);
        assert_eq!(unsafe { (*parent.frame).constructor_count }, 0);
        assert_eq!(unsafe { (*parent.frame).transaction_flags }, TXN_COLLISION);
        assert_eq!(
            REL.peek(rel_key(13, prior.context, 0, REL_X_INDEX, 0))
                .unwrap()
                .data[5],
            3
        );
        assert_eq!(
            REL.peek(rel_key(13, prior.owner, 0, REL_U_INDEX, 0))
                .unwrap()
                .data[5],
            3
        );
        assert_eq!(
            REL.peek(rel_key(1001, prior.owner, prior.context, REL_OWNER, 3))
                .unwrap()
                .state,
            REL_CONFLICT
        );
        assert!(quarantined(&target(), prior.context, QUARANTINE_CONTEXT_X));
        assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 16);
        assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 3);
        trace();
    }
    #[test]
    fn incompatible_fetch_spelling_persists_ambiguity_and_retires_only_method() {
        for family in [3, 4] {
            request_rebuild(family);
            let role = if family == 3 { 130 } else { 131 };
            let tx = root_frame(role, 91, 0);
            unsafe {
                (*tx.frame).entry_handle = 0x7000;
                (*tx.frame).name_state = NAME_COMPLETE;
                (*tx.frame).name_length = 5;
                (&mut (*tx.frame).name)[..5].copy_from_slice(b"OTHER");
            }
            run_root(&tx, role);
            assert_released(&tx);
            let method = REL
                .peek(rel_key(13, tx.owner, 0, REL_METHOD, family))
                .unwrap();
            assert_eq!(
                (method.witness_id, method.parent_id, method.state),
                (1002, 1001, REL_RETIRED)
            );
            let ambiguity = REL
                .peek(rel_key(0, tx.owner, 0, REL_METHOD_AMBIGUITY, family))
                .unwrap();
            let mut expected = blank_rel();
            expected.witness_id = 1004;
            expected.evidence_epoch = 13;
            expected.born_ns = 900;
            expected.state = REL_WITNESS;
            expected.data[..2].copy_from_slice(&[CONFLICT_METHOD_NAME, 91]);
            assert_eq!(bytes(&ambiguity), bytes(&expected));
            assert_eq!(
                REL.peek(global_key(1001, REL_REQUEST_NAME, family))
                    .unwrap()
                    .state,
                REL_WITNESS
            );
            let before = ATTRIB_CONTROL.peek(0).unwrap().next_producer_id;
            let claims = ATTR_STATE.peek(0).unwrap().relationship_claims;
            let again = root_frame(role, 92, 0);
            unsafe {
                (*again.frame).name_state = NAME_COMPLETE;
                (*again.frame).name_length = 1;
                (*again.frame).name[0] = b'X';
            }
            run_root(&again, role);
            assert!(BIND_PENDING.peek(again.key).is_none());
            assert_eq!(ATTRIB_CONTROL.peek(0).unwrap().next_producer_id, before);
            assert_eq!(ATTR_STATE.peek(0).unwrap().relationship_claims, claims);
            assert_no_tail();
            trace();
        }
    }
    #[test]
    fn provider_dup_equality_quarantines_even_without_public_parent() {
        for family in [3, 4] {
            reset(family);
            let role = if family == 3 { 290 } else { 291 };
            let mut tx = root_frame(role, 91, 0);
            tx.owner = 0x1100;
            unsafe {
                (*tx.frame).entry_handle = tx.owner;
            }
            run_root(&tx, role);
            assert_released(&tx);
            let row = REL
                .peek(rel_key(
                    0,
                    tx.owner,
                    QUARANTINE_CONTEXT_X,
                    REL_CONTEXT_QUARANTINE,
                    0,
                ))
                .unwrap();
            assert_eq!((row.data[0], row.data[1]), (CONFLICT_DUP_EQUALITY, 91));
            assert!(REL.peek(rel_key(13, tx.owner, 0, REL_X_INDEX, 0)).is_none());
            assert_no_tail();
            trace();
        }
    }
}
