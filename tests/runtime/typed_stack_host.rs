// SPDX-License-Identifier: GPL-3.0-or-later
// Appended to extracted production entry/pending/authority bodies. Only maps,
// atomics, operands, clock and the out-of-scope invalidator effects are doubled.
use std::{
    any::Any,
    borrow::Borrow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};
const BPF_NOEXIST: u64 = 1;
const LOSS_CHARGE: u32 = 0;
const LOSS_MAP: u32 = 1;
const LOSS_PAIR: u32 = 2;
const LOSS_POISON: u32 = 3;
const CODE_SHAPE_NEWCTX: u64 = 1;
const CODE_SHAPE_DUPCTX: u64 = 2;
const CODE_SHAPE_FREECTX: u64 = 3;
const CODE_SHAPE_MAC_INIT: u64 = 4;
const CODE_SHAPE_UPDATE: u64 = 5;
const CODE_SHAPE_MAC_FINAL: u64 = 6;
const CODE_SHAPE_KDF_RESET: u64 = 7;
const COOKIE: u64 = 0x8000_0001;
type CellKey = (&'static str, Vec<u8>);
#[derive(Default)]
struct State {
    rows: BTreeMap<CellKey, Box<dyn Any>>,
    events: Vec<String>,
    gets: BTreeMap<&'static str, usize>,
    gate: bool,
    fail_insert: BTreeSet<u32>,
    miss: Option<(&'static str, usize)>,
    deny_refund: bool,
    deny_alloc: bool,
    deny_claim: bool,
    join_fail: bool,
    retire_on_second_resolution: bool,
    mode_on_second_resolution: Option<u64>,
    advance_code_on_second_resolution: bool,
    mutate_admission_on_thread: bool,
    mutate_method_on_thread: bool,
    mutate_admission_on_bind: bool,
    string_error: bool,
}
thread_local! { static HOST: RefCell<State> = RefCell::new(State::default()); }
fn edit<R>(f: impl FnOnce(&mut State) -> R) -> R {
    HOST.with(|s| f(&mut s.borrow_mut()))
}
fn bytes<T>(value: &T) -> Vec<u8> {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast(), std::mem::size_of::<T>()).to_vec()
    }
}
struct Map<K, V> {
    name: &'static str,
    marker: PhantomData<fn(K) -> V>,
}
impl<K: Copy, V: Copy + 'static> Map<K, V> {
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            marker: PhantomData,
        }
    }
    fn set(&self, key: K, value: V) {
        edit(|s| {
            s.rows.insert((self.name, bytes(&key)), Box::new(value));
        });
    }
    fn peek(&self, key: K) -> Option<V> {
        edit(|s| {
            s.rows
                .get(&(self.name, bytes(&key)))
                .map(|v| *v.downcast_ref::<V>().unwrap())
        })
    }
    fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        let key = key.borrow();
        edit(|s| {
            let count = s.gets.entry(self.name).or_default();
            *count += 1;
            let count = *count;
            let mut event = format!("get:{}", self.name);
            if self.name == "pending" {
                let k = unsafe { &*(key as *const K).cast::<BindPendingKey>() };
                event = format!("lookup:{}", k.depth);
            }
            s.events.push(event);
            if self.name == "domain" && count == 2 {
                if s.retire_on_second_resolution {
                    row_mut::<SourceDomain>(s, "domain", bytes(&77u32)).state = DOMAIN_RETIRED;
                }
                if let Some(mode) = s.mode_on_second_resolution {
                    row_mut::<ProducerControl>(s, "control", bytes(&0u32)).producer_mode = mode;
                }
            }
            if self.name == "control" && count == 2 && s.advance_code_on_second_resolution {
                // Publication happens after root READY, before the handler
                // can accidentally take a fresh sequence for re-resolution.
                row_mut::<SourceControl>(s, "state", bytes(&0u32)).published_sequence = 20;
                let mut code = blank_rel();
                code.state = REL_CERTIFIED;
                code.witness_id = 53;
                code.evidence_epoch = 31;
                code.data[0] = 3;
                code.data[1] = 1;
                code.data[3] = 72;
                code.data[6] = 20;
                assert!(s
                    .rows
                    .insert(("rel", bytes(&late_code_key())), Box::new(code))
                    .is_none());
            }
            if self.name == "thread" && s.mutate_admission_on_thread {
                // Deliberately stronger than immutable configuration: a
                // differential probe for accidental post-helper rereads.
                row_mut::<TypedAdmission>(s, "admission", bytes(&site_key())).role_id = 308;
            }
            if self.name == "bind" && s.mutate_admission_on_bind {
                // A stronger immutable-row mutation probe: root must retain
                // the role/operation/function snapshot taken before this call.
                let row = row_mut::<TypedAdmission>(s, "admission", bytes(&site_key()));
                row.role_id = 308;
                row.operation = 99;
                row.function = 99;
            }
            if self.name == "thread" && s.mutate_method_on_thread {
                // Stronger than immutable witness fields; tests that callers
                // use validated scalar snapshots rather than deferred rereads.
                let row = row_mut::<RelValue>(s, "rel", bytes(&literal_method_key()));
                row.witness_id = 91;
                row.parent_id = 92;
            }
            if s.miss == Some((self.name, count)) {
                return None;
            }
            s.rows
                .get_mut(&(self.name, bytes(key)))
                .map(|v| v.downcast_mut::<V>().unwrap() as *mut V)
        })
    }
    unsafe fn get(&self, key: impl Borrow<K>) -> Option<&'static V> {
        self.get_ptr_mut(key).map(|p| unsafe { &*p })
    }
    fn insert(&self, key: impl Borrow<K>, value: impl Borrow<V>, flags: u64) -> Result<(), i64> {
        let key = key.borrow();
        let value = value.borrow();
        edit(|s| {
            assert_eq!(flags, 1, "insertion must exclude an existing row");
            if self.name == "pending" {
                let k = unsafe { &*(key as *const K).cast::<BindPendingKey>() };
                assert_eq!(
                    (
                        k.process_incarnation,
                        k.image_epoch,
                        k.thread_incarnation,
                        k.reserved
                    ),
                    (11, 12, 21, 0)
                );
                let input = bytes(value);
                assert_eq!(input.len(), 304);
                assert!(
                    input.iter().all(|b| *b == 0),
                    "actual insertion input must have all 304 bytes zero"
                );
                s.events.push(format!("insert:{}", k.depth));
                if s.fail_insert.contains(&k.depth) {
                    return Err(-1);
                }
            }
            let key = (self.name, bytes(key));
            if s.rows.contains_key(&key) {
                return Err(-17);
            }
            s.rows.insert(key, Box::new(*value));
            Ok(())
        })
    }
    fn remove(&self, key: impl Borrow<K>) -> Result<(), i64> {
        edit(|s| {
            s.events.push(format!("remove:{}", self.name));
            s.rows
                .remove(&(self.name, bytes(key.borrow())))
                .ok_or(-1)
                .map(|_| ())
        })
    }
}
fn row_mut<'a, V: 'static>(s: &'a mut State, name: &'static str, key: Vec<u8>) -> &'a mut V {
    s.rows
        .get_mut(&(name, key))
        .unwrap()
        .downcast_mut()
        .unwrap()
}
static ATTRIB_CONTROL: Map<u32, ProducerControl> = Map::new("control");
static ATTR_STATE: Map<u32, SourceControl> = Map::new("state");
struct ConfigMap(Map<u32, SourceConfig>);
impl ConfigMap {
    fn get(&self, key: u32) -> Option<&'static SourceConfig> {
        unsafe { self.0.get(key) }
    }
    fn set(&self, key: u32, value: SourceConfig) {
        self.0.set(key, value);
    }
}
static SOURCE_CONFIG: ConfigMap = ConfigMap(Map::new("config"));
static SOURCE_DOMAIN: Map<u32, SourceDomain> = Map::new("domain");
static SOURCE_GUARD: Map<u64, SourceGuard> = Map::new("guard");
static TYPED_ADMISSION: Map<TypedSiteKey, TypedAdmission> = Map::new("admission");
static SITE_BIND: Map<TypedSiteKey, SiteBindValue> = Map::new("bind");
static REL: Map<RelKey, RelValue> = Map::new("rel");
static THREAD_IDENTITY: Map<ThreadIdentityKey, ThreadIdentityValue> = Map::new("thread");
static BIND_PENDING: Map<BindPendingKey, BindPendingValue> = Map::new("pending");
mod shared_maps {
    pub(super) use super::ATTR_STATE;
}
mod writer_gate {
    pub fn admitted() -> bool {
        super::edit(|s| {
            s.events.push("admit".into());
            s.gate
        })
    }
}
unsafe fn ordered_read(p: *mut u64) -> u64 {
    unsafe { *p }
}
unsafe fn exchange(p: *mut u64, v: u64) {
    unsafe {
        *p = v;
    }
}
unsafe fn host_cxchg(p: *mut u64, old: u64, new: u64) -> (u64, bool) {
    let failed = edit(|s| {
        let state = row_mut::<SourceControl>(s, "state", bytes(&0u32)) as *mut SourceControl;
        let control =
            row_mut::<ProducerControl>(s, "control", bytes(&0u32)) as *mut ProducerControl;
        if p == unsafe { addr_of_mut!((*state).pending_claims) } {
            let claim = new > old;
            s.events.push(if claim { "claim" } else { "refund" }.into());
            if claim {
                s.deny_claim
            } else {
                s.deny_refund
            }
        } else if p == unsafe { addr_of_mut!((*control).next_producer_id) } {
            s.events.push("id".into());
            s.deny_alloc
        } else {
            s.events.push("relationship-charge".into());
            false
        }
    });
    let seen = unsafe { *p };
    let ok = seen == old && !failed;
    if ok {
        unsafe {
            *p = new;
        }
    }
    (seen, ok)
}
fn loss(cell: u32) {
    edit(|s| s.events.push(format!("loss:{cell}")));
}
struct ProbeContext {
    args: [u64; 3],
}
impl ProbeContext {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        (self as *const Self).cast_mut().cast()
    }
    fn arg(&self, index: usize) -> Option<u64> {
        edit(|s| s.events.push(format!("arg:{index}")));
        self.args.get(index).copied()
    }
}
mod helpers {
    pub unsafe fn bpf_get_attach_cookie(_: *mut core::ffi::c_void) -> u64 {
        super::edit(|s| s.events.push("cookie".into()));
        super::COOKIE
    }
    pub unsafe fn bpf_ktime_get_ns() -> u64 {
        super::edit(|s| s.events.push("clock".into()));
        900
    }
    pub unsafe fn bpf_probe_read_user_str_bytes<'a>(
        p: *const u8,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], i64> {
        assert_eq!(p as u64, 0x2000);
        super::edit(|s| s.events.push("name-read".into()));
        if super::edit(|s| s.string_error) {
            return Err(-1);
        }
        out[..5].copy_from_slice(b"HMAC\0");
        Ok(&out[..4])
    }
}
fn join_firing_identity(_: &ProbeContext) -> Option<(u64, u64)> {
    edit(|s| {
        s.events.push("join".into());
        (!s.join_fail).then_some((71, 72))
    })
}
fn retire_method(t: &Target, handle: u64, operation: u32) {
    assert_eq!((t.process, t.image, handle), (11, 12, 0x1000));
    edit(|s| s.events.push(format!("retire-method:{operation}")));
}
fn retire_owner_reachable(t: &Target, kind: u32, handle: u64) {
    assert_eq!((t.process, t.image, handle), (11, 12, 0x1000));
    edit(|s| s.events.push(format!("retire-owner:{kind}")));
}
fn poison_domain() {
    edit(|s| s.events.push("poison".into()));
}
fn target() -> Target {
    Target {
        process: 11,
        image: 12,
        relation: 13,
        loss_epoch: 14,
        entry_seq: 15,
    }
}
fn site_key() -> TypedSiteKey {
    TypedSiteKey {
        cookie: COOKIE,
        process_incarnation: 11,
        image_epoch: 12,
    }
}
fn ready_key() -> RelKey {
    RelKey {
        process_incarnation: 11,
        image_epoch: 12,
        relation_epoch: 0,
        primary_handle: COOKIE,
        secondary_handle: 31,
        kind: SOURCE_READY,
        operation: 0,
    }
}
fn pending_key(depth: u32) -> BindPendingKey {
    BindPendingKey {
        process_incarnation: 11,
        image_epoch: 12,
        thread_incarnation: 21,
        depth,
        reserved: 0,
    }
}
fn blank_frame() -> BindPendingValue {
    unsafe { core::mem::zeroed() }
}
fn blank_rel() -> RelValue {
    unsafe { core::mem::zeroed() }
}
fn reset(role: u32, operation: u32, function: u32, api: u32) {
    edit(|s| {
        *s = State {
            gate: true,
            ..State::default()
        }
    });
    ATTRIB_CONTROL.set(
        0,
        ProducerControl {
            producer_mode: 1,
            session_id: 1,
            admission_epoch: 2,
            cut_id: 3,
            next_producer_id: 41,
            relation_epoch: 13,
            loss_epoch: 14,
            reserved: 0,
        },
    );
    ATTR_STATE.set(
        0,
        SourceControl {
            published_sequence: 15,
            source_mode: 1,
            pending_claims: 2,
            ..SourceControl::PREPARED
        },
    );
    SOURCE_CONFIG.set(
        0,
        SourceConfig {
            page_shift: 12,
            pending_limit: 4096,
        },
    );
    SOURCE_DOMAIN.set(
        77,
        SourceDomain {
            process_incarnation: 11,
            current_image: 12,
            state: DOMAIN_ACTIVE,
            ..SourceDomain::default()
        },
    );
    TYPED_ADMISSION.set(
        site_key(),
        TypedAdmission {
            role_id: role,
            public_api_id: api,
            operation,
            function,
            abi_epoch: 1,
            source_epoch: 31,
        },
    );
    SITE_BIND.set(
        site_key(),
        SiteBindValue {
            site_id: 1,
            source_epoch: 31,
            code_object_id: 61,
            object_sha256: [0; 32],
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
    SOURCE_GUARD.set(
        51,
        SourceGuard {
            source_epoch: 31,
            state: GUARD_LIVE,
        },
    );
    SOURCE_GUARD.set(
        52,
        SourceGuard {
            source_epoch: 31,
            state: GUARD_LIVE,
        },
    );
    let mut ready = blank_rel();
    ready.state = REL_WITNESS;
    ready.evidence_epoch = 31;
    ready.data[..3].copy_from_slice(&[51, 52, 15]);
    REL.set(ready_key(), ready);
    let mut reg = blank_rel();
    reg.state = REL_WITNESS;
    reg.witness_id = 52;
    reg.parent_id = 51;
    reg.evidence_epoch = 31;
    reg.data[..6].copy_from_slice(&[61, 72, COOKIE, 3, 3, 15]);
    REL.set(
        RelKey {
            kind: SOURCE_REG,
            ..ready_key()
        },
        reg,
    );
    let mut anchor = blank_rel();
    anchor.state = REL_WITNESS;
    anchor.witness_id = 51;
    anchor.evidence_epoch = 31;
    anchor.data[..3].copy_from_slice(&[61, 31, 15]);
    REL.set(
        RelKey {
            kind: SOURCE_ANCHOR,
            primary_handle: 71,
            secondary_handle: 51,
            ..ready_key()
        },
        anchor,
    );
    let mut code = blank_rel();
    code.state = REL_CERTIFIED;
    code.witness_id = 53;
    code.evidence_epoch = 31;
    code.data[0] = operation as u64;
    code.data[1] = function as u64;
    code.data[3] = 72;
    code.data[6] = 15;
    REL.set(
        RelKey {
            process_incarnation: 11,
            image_epoch: 12,
            relation_epoch: 0,
            primary_handle: 71,
            secondary_handle: 72,
            kind: REL_CODE_ROLE,
            operation: (function << 16) | operation,
        },
        code,
    );
    // The independent ABI key encoding is checked below against actual access.
    let mut method = blank_rel();
    method.state = REL_WITNESS;
    method.witness_id = 81;
    method.parent_id = 82;
    REL.set(
        RelKey {
            process_incarnation: 11,
            image_epoch: 12,
            relation_epoch: 13,
            primary_handle: 0x1000,
            secondary_handle: 0,
            kind: REL_METHOD,
            operation,
        },
        method,
    );
}
fn clear_events() {
    edit(|s| {
        s.events.clear();
        s.gets.clear();
    });
}
fn events() -> Vec<String> {
    edit(|s| s.events.clone())
}
fn pending_events() -> Vec<String> {
    events()
        .into_iter()
        .filter(|e| {
            e.starts_with("lookup:")
                || e.starts_with("insert:")
                || e == "claim"
                || e == "refund"
                || e.starts_with("loss:")
                || e.starts_with("remove:")
        })
        .collect()
}
fn claims() -> u64 {
    ATTR_STATE.peek(0).unwrap().pending_claims
}
fn count_frames() -> usize {
    edit(|s| s.rows.keys().filter(|(n, _)| *n == "pending").count())
}
fn trace(want: &[&str]) {
    assert_eq!(pending_events(), want);
}
fn occupied(depth: u32, role: u32, occurrence: u64, method: u64) {
    let mut f = blank_frame();
    f.api_role = role;
    f.occurrence_id = occurrence;
    f.entry_handle = method;
    f.api_cookie = COOKIE;
    BIND_PENDING.set(pending_key(depth), f);
    let mut state = ATTR_STATE.peek(0).unwrap();
    state.pending_claims += 1;
    ATTR_STATE.set(0, state);
}
fn stage(thread: u64, cookie: u64, occurrence: u64) -> Option<(u32, *mut BindPendingValue)> {
    let t = target();
    let params = StageParams {
        target: &t,
        thread,
        cookie,
        role: 130,
        occurrence,
        now_ns: 900,
    };
    let mut out = StagedFrame {
        frame: std::ptr::null_mut(),
        depth: 0,
    };
    stage_frame(&params, &mut out).then_some((out.depth, out.frame))
}
fn enter(args: [u64; 3]) {
    typed_entry(&ProbeContext { args }, COOKIE, 77, 78, 999);
}
fn before(a: &str, b: &str) {
    let e = events();
    assert!(
        e.iter().position(|x| x == a).unwrap() < e.iter().position(|x| x == b).unwrap(),
        "{a} must precede {b}: {e:?}"
    );
}
fn no_operands() {
    assert!(!events().iter().any(|e| e.starts_with("arg:")));
    assert_eq!(count_frames(), 0);
}
fn case(name: &str) {
    println!("PASS {name}");
}
fn staging_controls() {
    for (thread, cookie, occurrence) in [(0, COOKIE, 41), (21, 0, 41), (21, COOKIE, 0)] {
        reset(130, 3, 0, 12);
        assert!(stage(thread, cookie, occurrence).is_none());
        trace(&[]);
        assert_eq!(claims(), 2);
    }
    case("zero staging operands");
    reset(130, 3, 0, 12);
    let (depth, p) = stage(21, COOKIE, 41).unwrap();
    assert_eq!(depth, 0);
    trace(&["lookup:0", "claim", "insert:0", "lookup:0"]);
    let f = unsafe { *p };
    assert_eq!(
        (
            f.occurrence_id,
            f.api_cookie,
            f.relation_epoch,
            f.loss_epoch,
            f.entry_ns,
            f.api_role
        ),
        (41, COOKIE, 13, 14, 900, 130)
    );
    assert_eq!((claims(), count_frames()), (3, 1));
    let popped = pop_frame(&target(), 21, COOKIE).unwrap();
    assert_eq!(
        (
            popped.0.process_incarnation,
            popped.0.image_epoch,
            popped.0.thread_incarnation,
            popped.0.depth
        ),
        (11, 12, 21, 0)
    );
    clear_events();
    release_frame(&popped.0);
    trace(&["remove:pending", "refund"]);
    assert_eq!((claims(), count_frames()), (2, 0));
    case("metadata, pop identity, exactly one cleanup");
    for depth in 0..8 {
        reset(130, 3, 0, 12);
        for d in 0..depth {
            occupied(d, 147, 50 + d as u64, 0x1000);
        }
        if depth < 7 {
            occupied(depth + 1, 148, 70, 0x1000);
        }
        let before = BIND_PENDING.peek(pending_key(depth + 1));
        let (found, _) = stage(21, COOKIE, 41).unwrap();
        assert_eq!(found, depth);
        if let Some(before) = before {
            assert_eq!(
                bytes(&BIND_PENDING.peek(pending_key(depth + 1)).unwrap()),
                bytes(&before)
            );
        }
        assert_eq!(claims(), depth as u64 + 3 + u64::from(depth < 7));
    }
    case("every successful depth 0 through 7, occupied above gap preserved");
    reset(130, 3, 0, 12);
    for d in 0..8 {
        occupied(d, 147, 50 + d as u64, 0x1000);
    }
    assert!(stage(21, COOKIE, 41).is_none());
    trace(&[
        "lookup:0", "lookup:1", "lookup:2", "lookup:3", "lookup:4", "lookup:5", "lookup:6",
        "lookup:7", "loss:1",
    ]);
    assert_eq!(claims(), 10);
    case("depth exhaustion without overwrite or claim");
    reset(130, 3, 0, 12);
    SOURCE_CONFIG.set(
        0,
        SourceConfig {
            page_shift: 12,
            pending_limit: 0,
        },
    );
    assert!(stage(21, COOKIE, 41).is_none());
    trace(&["lookup:0", "loss:1"]);
    assert_eq!(claims(), 2);
    case("quota refused before insert");
    reset(130, 3, 0, 12);
    edit(|s| s.fail_insert = [0, 1].into_iter().collect());
    let (d, _) = stage(21, COOKIE, 41).unwrap();
    assert_eq!(d, 2);
    trace(&[
        "lookup:0", "claim", "insert:0", "refund", "lookup:1", "claim", "insert:1", "refund",
        "lookup:2", "claim", "insert:2", "lookup:2",
    ]);
    assert_eq!((claims(), count_frames()), (3, 1));
    case("failed insert refunds and continues");
    reset(130, 3, 0, 12);
    edit(|s| s.fail_insert = (0..8).collect());
    assert!(stage(21, COOKIE, 41).is_none());
    assert_eq!(events().iter().filter(|e| *e == "refund").count(), 8);
    assert_eq!((claims(), count_frames()), (2, 0));
    assert_eq!(events().last().unwrap(), "loss:1");
    case("all eight insertion failures");
    reset(130, 3, 0, 12);
    edit(|s| {
        s.fail_insert.insert(0);
        s.deny_refund = true;
    });
    assert_eq!(stage(21, COOKIE, 41).unwrap().0, 1);
    assert_eq!(events().iter().filter(|e| *e == "refund").count(), 8);
    assert_eq!((claims(), count_frames()), (4, 1));
    case("missed compensation retains charge and continues");
    reset(130, 3, 0, 12);
    edit(|s| s.miss = Some(("pending", 2)));
    assert!(stage(21, COOKIE, 41).is_none());
    trace(&[
        "lookup:0", "claim", "insert:0", "lookup:0", "refund", "loss:1",
    ]);
    assert_eq!((claims(), count_frames()), (2, 1));
    assert!(bytes(&BIND_PENDING.peek(pending_key(0)).unwrap())
        .iter()
        .all(|b| *b == 0));
    case("stronger retained-row NULL lookup injection: trace preserved, accounting NOT certified");
    reset(130, 3, 0, 12);
    let mut state = ATTR_STATE.peek(0).unwrap();
    state.source_mode = 0;
    state.pending_claims = 99;
    ATTR_STATE.set(0, state);
    assert!(stage(21, COOKIE, 41).is_some());
    trace(&["lookup:0", "insert:0", "lookup:0"]);
    release_frame(&pending_key(0));
    assert_eq!(claims(), 99);
    case("mode zero bypass does not charge or refund");
    reset(130, 3, 0, 12);
    let mut state = ATTR_STATE.peek(0).unwrap();
    state.source_mode = 2;
    ATTR_STATE.set(0, state);
    assert!(stage(21, COOKIE, 41).is_none());
    assert_eq!(count_frames(), 0);
    case("invalid source mode refuses");
    reset(130, 3, 0, 12);
    edit(|s| s.deny_claim = true);
    assert!(stage(21, COOKIE, 41).is_none());
    assert_eq!(events().iter().filter(|e| *e == "claim").count(), 8);
    assert_eq!(claims(), 2);
    case("bounded claim contention");
    reset(130, 3, 0, 12);
    occupied(0, 130, 41, 0);
    edit(|s| s.deny_refund = true);
    release_frame(&pending_key(0));
    assert_eq!((claims(), count_frames()), (3, 0));
    assert_eq!(events().last().unwrap(), "loss:2");
    case("failed release loss and conservative reservation");
}
fn entry_controls() {
    // Independent complete role/triple table, not admission_parts as oracle.
    let roles = [
        (130, 3, 0, 12),
        (131, 4, 0, 13),
        (147, 3, 0, 0),
        (148, 4, 0, 0),
        (151, 3, 0, 0),
        (152, 4, 0, 0),
        (142, 3, 0, 0),
        (143, 4, 0, 0),
        (146, 0, 0, 0),
        (258, 3, 1, 0),
        (259, 4, 1, 0),
        (290, 3, 2, 0),
        (291, 4, 2, 0),
        (161, 0, 0, 8),
    ];
    for (role, op, fun, api) in roles {
        reset(role, op, fun, api);
        enter(if role == 161 {
            [0x1000, 3, 0x2000]
        } else {
            [0x1000, 0x2000, 0]
        });
        let f = BIND_PENDING
            .peek(pending_key(0))
            .unwrap_or_else(|| panic!("role {role} failed: {:?}", events()));
        assert_eq!((f.api_role, f.occurrence_id, f.entry_ns), (role, 41, 900));
        assert_eq!(f.entry_handle, if role == 161 { 3 } else { 0x1000 });
        assert_eq!(
            edit(|s| s.gets["domain"]),
            2,
            "each handler must re-resolve"
        );
        before("admit", if role == 161 { "arg:1" } else { "arg:0" });
        if matches!(role, 130 | 131) {
            before("insert:0", "arg:0");
            before("insert:0", "name-read");
            assert_eq!((f.name_state, f.name_length), (NAME_COMPLETE, 4));
            assert_eq!(&f.name[..5], b"HMAC\0");
        } else {
            before(if role == 161 { "arg:1" } else { "arg:0" }, "insert:0");
        }
        if matches!(role, 258 | 259 | 290 | 291) {
            before("join", "arg:0");
            assert_eq!(f.constructor_cookie, COOKIE);
        }
        if role == 161 {
            assert_eq!(f.provider_witness, 0x2000);
            assert!(!events().iter().any(|e| e == "name-read"));
        }
    }
    case("all fourteen paired roles and operand ordering");
    for bad in 0..7 {
        reset(130, 3, 0, 12);
        match bad {
            0 => edit(|s| s.gate = false),
            1 => {
                TYPED_ADMISSION.remove(site_key()).unwrap();
            }
            2 => {
                let mut a = TYPED_ADMISSION.peek(site_key()).unwrap();
                a.abi_epoch = 0;
                TYPED_ADMISSION.set(site_key(), a);
            }
            3 => {
                let mut a = TYPED_ADMISSION.peek(site_key()).unwrap();
                a.operation = 4;
                TYPED_ADMISSION.set(site_key(), a);
            }
            4 => {
                REL.remove(ready_key()).unwrap();
            }
            5 => {
                let mut r = REL.peek(ready_key()).unwrap();
                r.data[2] = 16;
                REL.set(ready_key(), r);
            }
            6 => SOURCE_GUARD.set(
                51,
                SourceGuard {
                    source_epoch: 31,
                    state: GUARD_RETIRED,
                },
            ),
            _ => unreachable!(),
        };
        clear_events();
        enter([0x1000, 0x2000, 0]);
        no_operands();
    }
    case("ADMIT, admission, missing/late READY and retired guard refusal before operands");
    for (role, op, fun, api) in roles {
        reset(role, op, fun, api);
        edit(|s| s.retire_on_second_resolution = true);
        enter([0x1000, 3, 0x2000]);
        no_operands();
    }
    case("every paired handler retains re-resolution on domain retirement");
    reset(258, 3, 1, 0);
    REL.remove(late_code_key()).unwrap();
    edit(|s| s.advance_code_on_second_resolution = true);
    enter([0x1000, 0, 0]);
    no_operands();
    assert_eq!(ATTR_STATE.peek(0).unwrap().published_sequence, 20);
    case("captured entry sequence rejects newly published CODE_ROLE");
    for (role, op, fun) in [
        (258, 3, 1),
        (259, 4, 1),
        (290, 3, 2),
        (291, 4, 2),
        (274, 3, 3),
        (275, 4, 3),
    ] {
        reset(role, op, fun, 0);
        edit(|s| s.join_fail = true);
        enter([0x1000, 0, 0]);
        no_operands();
    }
    case("copied-role join precedes operands including invalidators");
    for (role, op, fun, api) in roles {
        reset(role, op, fun, api);
        edit(|s| s.mutate_admission_on_thread = true);
        enter(if role == 161 {
            [0, 3, 0x2000]
        } else {
            [0x1000, 0x2000, 0]
        });
        assert_eq!(BIND_PENDING.peek(pending_key(0)).unwrap().api_role, role);
    }
    case("stronger immutable-admission mutation probe retains pre-helper role snapshot");
    reset(130, 3, 0, 12);
    edit(|s| s.deny_alloc = true);
    enter([0x1000, 0x2000, 0]);
    no_operands();
    assert_eq!(events().iter().filter(|e| *e == "id").count(), 8);
    case("failed occurrence allocation precedes fetch operands");
    reset(130, 3, 0, 12);
    edit(|s| s.string_error = true);
    enter([0, 0x2000, 0]);
    let f = BIND_PENDING.peek(pending_key(0)).unwrap();
    assert_eq!(
        (f.entry_handle, f.name_state, f.name_length),
        (0, NAME_UNREADABLE, 0)
    );
    case("null libctx and unreadable name remain staged");
    for (role, op, fun, api) in roles {
        if matches!(role, 130 | 131) {
            continue;
        }
        reset(role, op, fun, api);
        enter([0, 0, 0]);
        assert_eq!(count_frames(), 0);
    }
    case("null operands and out-of-slice query refuse");
    for op in [3, 4] {
        reset(161, 0, 0, 8);
        enter([0, op, 0x2000]);
        assert_eq!(BIND_PENDING.peek(pending_key(0)).unwrap().entry_handle, op);
    }
    case("MAC and KDF query entry");
    reset(147, 3, 0, 0);
    REL.set(
        RelKey {
            process_incarnation: 11,
            image_epoch: 12,
            relation_epoch: 0,
            primary_handle: 0x1000,
            secondary_handle: 0,
            kind: REL_METHOD_AMBIGUITY,
            operation: 3,
        },
        blank_rel(),
    );
    enter([0x1000, 0, 0]);
    assert_eq!(count_frames(), 0);
    case("constructor ambiguity refuses");
}
fn parent_controls() {
    // (child, family, function, lower role, lower occurrence, lower method,
    // nearest role, nearest occurrence, nearest method, expected parent).
    for (child, op, fun, low, lo, method, near, no, nmethod, want) in [
        (142, 3, 0, 147, 50, 0x1000, 148, 60, 0x1000, 60),
        (143, 4, 0, 148, 50, 0x1000, 147, 60, 0x2000, 50),
        (146, 0, 0, 147, 50, 0x1000, 148, 0, 0x1000, 50),
        (258, 3, 1, 147, 50, 0x1000, 151, 60, 0x1000, 50),
        (259, 4, 1, 148, 50, 0x1000, 151, 60, 0x1000, 50),
        (290, 3, 2, 151, 50, 0x1000, 147, 60, 0x1000, 50),
        (291, 4, 2, 152, 50, 0x1000, 151, 60, 0x1000, 60),
        (142, 3, 0, 151, 50, 0x1000, 148, 60, 0x2000, 0),
    ] {
        reset(child, op, fun, 0);
        occupied(0, low, lo, method);
        occupied(1, near, no, nmethod);
        enter([0x1000, 0, 0]);
        assert_eq!(
            BIND_PENDING
                .peek(pending_key(2))
                .unwrap()
                .parent_occurrence_id,
            want,
            "child {child}"
        );
    }
    case("nearest parent, zero occurrence, wrong roles, getter mismatch and dup parent");
    reset(142, 3, 0, 0);
    occupied(0, 147, 50, 0x1000);
    occupied(2, 148, 60, 0x1000);
    enter([0x1000, 0, 0]);
    assert_eq!(
        BIND_PENDING
            .peek(pending_key(1))
            .unwrap()
            .parent_occurrence_id,
        50
    );
    case("parent scan excludes occupied rows above insertion gap");
    reset(142, 3, 0, 0);
    occupied(0, 147, 50, 0x1000);
    edit(|s| s.fail_insert.insert(1));
    enter([0x1000, 0, 0]);
    assert_eq!(
        BIND_PENDING
            .peek(pending_key(2))
            .unwrap()
            .parent_occurrence_id,
        50
    );
    case("parent lookup spans genuine lower-depth gap after failed insertion");
}
fn initialization_controls() {
    // Every byte is poisoned before executing the exact production initializer.
    for poison in [0x55, 0xaa, 0xff] {
        let mut value = core::mem::MaybeUninit::<BindPendingValue>::uninit();
        unsafe {
            std::ptr::write_bytes(value.as_mut_ptr().cast::<u8>(), poison, 304);
        }
        initialize_pending_zero(&mut value);
        let actual = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), 304) };
        for (index, byte) in actual.iter().enumerate() {
            assert_eq!(*byte, 0, "pending byte {index}");
        }
    }
    for poison in [0x55, 0xaa, 0xff] {
        let mut value = core::mem::MaybeUninit::<Target>::uninit();
        unsafe {
            std::ptr::write_bytes(value.as_mut_ptr().cast::<u8>(), poison, 40);
        }
        initialize_entry_target(&mut value);
        for (index, byte) in unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), 40) }
            .iter()
            .enumerate()
        {
            assert_eq!(*byte, 0, "target byte {index}");
        }
    }
    reset(130, 3, 0, 12);
    assert!(insert_empty_frame(&pending_key(0)));
    assert!(!insert_empty_frame(&pending_key(0)));
    assert_eq!(count_frames(), 1);
    assert_eq!(claims(), 2);
    case("poisoned 304 bytes and actual key-only NOEXIST leaf");
}
fn main() {
    initialization_controls();
    packed_role_controls();
    staging_controls();
    entry_controls();
    parent_controls();
    method_and_failure_controls();
    println!("ALL PRODUCTION ENTRY CONTROLS PASSED");
}

fn late_code_key() -> RelKey {
    RelKey {
        process_incarnation: 11,
        image_epoch: 12,
        relation_epoch: 0,
        primary_handle: 71,
        secondary_handle: 72,
        kind: REL_CODE_ROLE,
        operation: 0x0001_0003,
    }
}
fn packed_role_controls() {
    // Literal entire admission table, independent of admission_parts/packer.
    for (role, op, fun, api) in [
        (5, 0, 0, 5),
        (18, 0, 0, 0),
        (130, 3, 0, 12),
        (131, 4, 0, 13),
        (136, 3, 0, 0),
        (137, 4, 0, 0),
        (142, 3, 0, 0),
        (143, 4, 0, 0),
        (146, 0, 0, 0),
        (147, 3, 0, 0),
        (148, 4, 0, 0),
        (149, 3, 0, 0),
        (150, 4, 0, 0),
        (151, 3, 0, 0),
        (152, 4, 0, 0),
        (153, 4, 0, 0),
        (154, 0, 0, 0),
        (155, 0, 0, 0),
        (161, 0, 0, 8),
        (258, 3, 1, 0),
        (259, 4, 1, 0),
        (274, 3, 3, 0),
        (275, 4, 3, 0),
        (290, 3, 2, 0),
        (291, 4, 2, 0),
        (304, 3, 4, 0),
        (305, 3, 5, 0),
        (306, 3, 6, 0),
        (307, 4, 5, 0),
        (308, 4, 4, 0),
    ] {
        let packed = pack_entry_role(role, op, fun);
        assert_ne!(packed, 0);
        assert_eq!(
            (
                packed as u32,
                ((packed >> 32) & 0xffff) as u32,
                (packed >> 48) as u32
            ),
            (role, op, fun)
        );
        reset(role, op, fun, api);
        let accepted = entry_authorized(COOKIE, &target());
        if role >= 304 {
            assert_eq!(accepted, 0);
        } else {
            assert_eq!(accepted, packed);
        }
        for bad in 0..2 {
            let mut admission = TYPED_ADMISSION.peek(site_key()).unwrap();
            if bad == 0 {
                admission.operation = op | 0x10000;
            } else {
                admission.function = fun | 0x10000;
            }
            TYPED_ADMISSION.set(site_key(), admission);
            clear_events();
            assert_eq!(entry_authorized(COOKIE, &target()), 0);
            assert!(!events().iter().any(|e| e == "get:bind"));
            reset(role, op, fun, api);
        }
    }
    assert_eq!(pack_entry_role(0, 3, 1), 0);
    assert_eq!(pack_entry_role(0xffff_ffff, 0xffff, 0xffff), u64::MAX);
    assert_eq!(pack_entry_role(258, 0x10003, 1), 0);
    assert_eq!(pack_entry_role(258, 3, 0x10001), 0);
    case("all 30 role triples, refusal sentinel, every role bit, high-bit validation and width guard");
    for (role, op, fun, want) in [
        (136, 3, 0, "retire-method:3"),
        (137, 4, 0, "retire-method:4"),
        (149, 3, 0, "retire-owner:14"),
        (150, 4, 0, "retire-owner:14"),
        (153, 4, 0, "retire-owner:14"),
        (274, 3, 3, "retire-owner:13"),
        (275, 4, 3, "retire-owner:13"),
    ] {
        reset(role, op, fun, 0);
        enter([0x1000, 0, 0]);
        assert_eq!(events().last().unwrap(), want);
        assert_eq!(count_frames(), 0);
        if role >= 274 {
            before("join", "arg:0");
        }
    }
    for (role, api) in [(5, 5), (18, 0), (154, 0), (155, 0)] {
        reset(role, 0, 0, api);
        enter([0x1000, 0, 0]);
        no_operands();
        assert_eq!(events().last().unwrap(), "poison");
    }
    case("all invalidator dispatch outcomes and copied checks");
}

fn literal_method_key() -> RelKey {
    RelKey {
        process_incarnation: 11,
        image_epoch: 12,
        relation_epoch: 13,
        primary_handle: 0x1000,
        secondary_handle: 0,
        kind: REL_METHOD,
        operation: 3,
    }
}
fn method_and_failure_controls() {
    for boundary in [("state", 1), ("config", 1)] {
        reset(130, 3, 0, 12);
        edit(|s| s.miss = Some(boundary));
        assert!(stage(21, COOKIE, 41).is_none());
        trace(&["lookup:0", "loss:1"]);
        assert_eq!((claims(), count_frames()), (2, 0));
    }
    reset(130, 3, 0, 12);
    edit(|s| s.fail_insert = [0, 1].into_iter().collect());
    enter([0x1000, 0x2000, 0]);
    assert_eq!(events().iter().filter(|e| *e == "id").count(), 1);
    assert_eq!(events().iter().filter(|e| *e == "clock").count(), 1);
    before("id", "clock");
    before("clock", "lookup:0");
    let frame = BIND_PENDING.peek(pending_key(2)).unwrap();
    assert_eq!((frame.occurrence_id, frame.entry_ns), (41, 900));
    case("missing quota maps and original ID/clock acquisition across insertion retries");
    for bad in 0..6 {
        reset(130, 3, 0, 12);
        let mut a = TYPED_ADMISSION.peek(site_key()).unwrap();
        match bad {
            0 => a.role_id = 0,
            1 => a.role_id = 999,
            2 => a.public_api_id = 13,
            3 => a.abi_epoch = 0,
            4 => a.source_epoch = 0,
            5 => a.function = 1,
            _ => unreachable!(),
        };
        TYPED_ADMISSION.set(site_key(), a);
        clear_events();
        enter([0x1000, 0x2000, 0]);
        no_operands();
        assert!(!events().iter().any(|e| e == "get:bind"));
    }
    for bad in 0..3 {
        reset(130, 3, 0, 12);
        let mut b = SITE_BIND.peek(site_key()).unwrap();
        match bad {
            0 => b.site_id = 0,
            1 => b.source_epoch = 0,
            2 => b.code_object_id = 0,
            _ => unreachable!(),
        };
        SITE_BIND.set(site_key(), b);
        clear_events();
        enter([0x1000, 0x2000, 0]);
        no_operands();
        assert!(!events().iter().any(|e| e == "get:rel"));
    }
    reset(130, 3, 0, 12);
    SOURCE_GUARD.set(
        52,
        SourceGuard {
            source_epoch: 31,
            state: GUARD_RETIRED,
        },
    );
    enter([0x1000, 0x2000, 0]);
    no_operands();
    case("complete admission/bind validation and second guard refusal before operands");

    for bad in 0..5 {
        reset(147, 3, 0, 0);
        let key = literal_method_key();
        let mut row = REL.peek(key).unwrap();
        match bad {
            0 => {
                REL.remove(key).unwrap();
            }
            1 => {
                row.witness_id = 0;
                REL.set(key, row);
            }
            2 => {
                row.parent_id = 0;
                REL.set(key, row);
            }
            3 => {
                row.state = REL_RETIRED;
                REL.set(key, row);
            }
            4 => {
                row.cardinality = 1;
                REL.set(key, row);
            }
            _ => unreachable!(),
        }
        clear_events();
        let mut out = MethodEntry {
            witness: 0,
            request: 0,
        };
        assert!(!method_entry(&target(), 0x1000, 3, &mut out));
        assert_eq!(events(), ["get:rel"]);
    }
    reset(147, 3, 0, 0);
    clear_events();
    let mut out = MethodEntry {
        witness: 0,
        request: 0,
    };
    assert!(method_entry(&target(), 0x1000, 3, &mut out));
    assert_eq!((out.witness, out.request), (81, 82));
    assert_eq!(events(), ["get:rel", "get:rel"]);
    reset(147, 3, 0, 0);
    edit(|s| s.mutate_method_on_thread = true);
    enter([0x1000, 0, 0]);
    let f = BIND_PENDING.peek(pending_key(0)).unwrap();
    assert_eq!((f.method_observation_id, f.selector_or_set_id), (81, 82));
    case("method failures short-circuit ambiguity; stronger witness mutation preserves validated scalars");
    for (role, op, fun) in [(136, 3, 0), (137, 4, 0), (274, 3, 3), (275, 4, 3)] {
        reset(role, op, fun, 0);
        edit(|s| s.mutate_admission_on_bind = true);
        enter([0x1000, 0, 0]);
        assert_eq!(
            events().last().unwrap(),
            if role == 136 {
                "retire-method:3"
            } else if role == 137 {
                "retire-method:4"
            } else {
                "retire-owner:13"
            }
        );
    }
    case("stronger immutable-row mutation preserves root role, operation and function snapshots");
    for boundary in [
        ("state", 1),
        ("control", 1),
        ("control", 2),
        ("control", 3),
        ("domain", 1),
        ("domain", 2),
        ("admission", 2),
        ("bind", 1),
    ] {
        reset(130, 3, 0, 12);
        edit(|s| s.miss = Some(boundary));
        enter([0x1000, 0x2000, 0]);
        no_operands();
    }
    reset(130, 3, 0, 12);
    THREAD_IDENTITY
        .remove(ThreadIdentityKey {
            process_incarnation: 11,
            tid: 78,
            reserved: 0,
        })
        .unwrap();
    let mut state = ATTR_STATE.peek(0).unwrap();
    state.relationship_claims = 8192;
    ATTR_STATE.set(0, state);
    enter([0x1000, 0x2000, 0]);
    no_operands();
    assert_eq!(events().last().unwrap(), "loss:0");
    for mode in [0, 2, 3] {
        reset(130, 3, 0, 12);
        let mut c = ATTRIB_CONTROL.peek(0).unwrap();
        c.producer_mode = mode;
        ATTRIB_CONTROL.set(0, c);
        enter([0x1000, 0x2000, 0]);
        no_operands();
    }
    case("failed map/helper boundaries, thread capacity and producer-mode refusal");
}
