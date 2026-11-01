// SPDX-License-Identifier: GPL-3.0-or-later
// Appended to complete production bind/publication definitions. Entry/getter/
// constructor observations are valid prepared inputs; reserve, bind, commit,
// tail, deferred cleanup and frame release execute their actual bodies.
use std::{
    any::Any,
    borrow::Borrow,
    cell::{RefCell, UnsafeCell},
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
};

type CellKey = (&'static str, Vec<u8>);
type Snapshot = BTreeMap<CellKey, Vec<u8>>;
struct Row {
    value: Rc<dyn Any>,
    snapshot: fn(&dyn Any) -> Vec<u8>,
}
impl Row {
    fn new<V: Copy + 'static>(value: V) -> Self {
        Self {
            value: Rc::new(UnsafeCell::new(value)),
            snapshot: |cell| {
                // Copy through UnsafeCell's shared raw pointer. No exclusive
                // value borrow may invalidate an earlier production handle.
                let value = unsafe { *cell.downcast_ref::<UnsafeCell<V>>().unwrap().get() };
                bytes(&value)
            },
        }
    }
    fn ptr<V: 'static>(&self) -> *mut V {
        self.value.downcast_ref::<UnsafeCell<V>>().unwrap().get()
    }
}
#[derive(Debug)]
struct Event {
    phase: &'static str,
    operation: String,
    changes: Vec<(CellKey, Option<Vec<u8>>, Option<Vec<u8>>)>,
}
#[derive(Default)]
struct State {
    rows: BTreeMap<CellKey, Row>,
    // Removed/replaced allocations remain alive until the case finishes;
    // callers must never use a handle across reset.
    retired: Vec<Row>,
    previous: Snapshot,
    events: Vec<Event>,
    phase: &'static str,
}
thread_local! { static HOST: RefCell<State> = RefCell::new(State::default()); }
fn edit<R>(f: impl FnOnce(&mut State) -> R) -> R {
    HOST.with(|s| f(&mut s.borrow_mut()))
}
fn bytes<T>(value: &T) -> Vec<u8> {
    // All fixture map keys/values are the fully initialized, padding-free
    // contract layouts (or u32/u64). No arbitrary Rust struct is serialized.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast(), std::mem::size_of::<T>()).to_vec()
    }
}
fn snapshot(s: &State) -> Snapshot {
    s.rows
        .iter()
        .map(|(key, row)| (key.clone(), (row.snapshot)(row.value.as_ref())))
        .collect()
}
fn record(s: &mut State, operation: String) {
    let current = snapshot(s);
    let mut keys: Vec<_> = s.previous.keys().chain(current.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    let changes = keys
        .into_iter()
        .filter_map(|key| {
            let before = s.previous.get(&key).cloned();
            let after = current.get(&key).cloned();
            (before != after).then_some((key, before, after))
        })
        .collect();
    s.events.push(Event {
        phase: s.phase,
        operation,
        changes,
    });
    s.previous = current;
}
fn phase(name: &'static str) {
    edit(|s| {
        s.phase = name;
        record(s, "boundary".into());
    });
}
fn trace() {
    edit(|s| {
        record(s, "final".into());
        // Record every complete snapshot under Miri too. Rendering tens of
        // thousands of byte values adds interpreter cost without exercising
        // another production access; ordinary runs print the full trace.
        if cfg!(miri) {
            println!("TRACE recorded {} complete boundary events", s.events.len());
            return;
        }
        for event in &s.events {
            println!("TRACE {event:?}");
        }
    });
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
            if let Some(old) = s.rows.insert((self.name, bytes(&key)), Row::new(value)) {
                s.retired.push(old);
            }
        });
    }
    fn peek(&self, key: K) -> Option<V> {
        edit(|s| {
            s.rows
                .get(&(self.name, bytes(&key)))
                .map(|row| unsafe { *row.ptr::<V>() })
        })
    }
    fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        let key = bytes(key.borrow());
        edit(|s| {
            let result = s.rows.get(&(self.name, key.clone())).map(Row::ptr::<V>);
            record(
                s,
                format!(
                    "lookup map={} key={key:?} present={}",
                    self.name,
                    result.is_some()
                ),
            );
            result
        })
    }
    unsafe fn get(&self, key: impl Borrow<K>) -> Option<&'static V> {
        // Match the unsafe map API. Extracted callers copy immediately and
        // never retain a value reference across mutation or case reset.
        self.get_ptr_mut(key).map(|p| unsafe { &*p })
    }
    fn insert(&self, key: impl Borrow<K>, value: impl Borrow<V>, flags: u64) -> Result<(), i64> {
        let key = bytes(key.borrow());
        let value = *value.borrow();
        edit(|s| {
            assert!(matches!(flags, 0 | 1), "only BPF_ANY/NOEXIST supported");
            let map_key = (self.name, key.clone());
            let result = if flags == 1 && s.rows.contains_key(&map_key) {
                Err(-17)
            } else {
                if let Some(old) = s.rows.insert(map_key, Row::new(value)) {
                    s.retired.push(old);
                }
                Ok(())
            };
            record(
                s,
                format!(
                    "insert map={} key={key:?} flags={flags} value={:?} result={result:?}",
                    self.name,
                    bytes(&value)
                ),
            );
            result
        })
    }
    fn remove(&self, key: impl Borrow<K>) -> Result<(), i64> {
        let key = bytes(key.borrow());
        edit(|s| {
            let result = if let Some(old) = s.rows.remove(&(self.name, key.clone())) {
                s.retired.push(old);
                Ok(())
            } else {
                Err(-2)
            };
            record(
                s,
                format!("remove map={} key={key:?} result={result:?}", self.name),
            );
            result
        })
    }
}
static ATTRIB_CONTROL: Map<u32, ProducerControl> = Map::new("control");
static ATTR_STATE: Map<u32, SourceControl> = Map::new("state");
static SOURCE_DOMAIN: Map<u32, SourceDomain> = Map::new("domain");
static SOURCE_GUARD: Map<u64, SourceGuard> = Map::new("guard");
static SITE_BIND: Map<TypedSiteKey, SiteBindValue> = Map::new("bind");
static REL: Map<RelKey, RelValue> = Map::new("rel");
static BIND_PENDING: Map<BindPendingKey, BindPendingValue> = Map::new("pending");
static EXACT_NAME: Map<ExactNameKey, u64> = Map::new("exact");
static DIGEST_INDEX: Map<DigestKey, u64> = Map::new("digest");
static SELECTOR_DICT: Map<SelectorDictionaryKey, SelectorDictionaryValue> = Map::new("dictionary");
static ITER_SLOT: Map<u32, SourceSlot> = Map::new("slot");
static PRODUCER_LOSS: Map<u32, u64> = Map::new("loss");
struct ConfigMap(Map<u32, SourceConfig>);
impl ConfigMap {
    fn get(&self, key: u32) -> Option<&'static SourceConfig> {
        unsafe { self.0.get(key) }
    }
}
static SOURCE_CONFIG: ConfigMap = ConfigMap(Map::new("config"));
mod shared_maps {
    pub(super) use super::{ATTR_STATE, ITER_SLOT};
}
fn atomic_identity(s: &State, p: *mut u64) -> String {
    for ((map, key), row) in &s.rows {
        let fields: Vec<(&str, *mut u64)> = unsafe {
            match *map {
                "control" => {
                    let r = row.ptr::<ProducerControl>();
                    vec![
                        ("id", addr_of_mut!((*r).next_producer_id)),
                        ("mode", addr_of_mut!((*r).producer_mode)),
                        ("relation", addr_of_mut!((*r).relation_epoch)),
                        ("loss", addr_of_mut!((*r).loss_epoch)),
                    ]
                }
                "state" => {
                    let r = row.ptr::<SourceControl>();
                    vec![
                        ("busy", addr_of_mut!((*r).publication_busy)),
                        ("sequence", addr_of_mut!((*r).published_sequence)),
                        ("relationships", addr_of_mut!((*r).relationship_claims)),
                        ("pending", addr_of_mut!((*r).pending_claims)),
                    ]
                }
                "domain" => {
                    let r = row.ptr::<SourceDomain>();
                    vec![
                        ("state", addr_of_mut!((*r).state)),
                        ("image", addr_of_mut!((*r).current_image)),
                    ]
                }
                "rel" => {
                    let r = row.ptr::<RelValue>();
                    vec![
                        ("state", addr_of_mut!((*r).state).cast::<u64>()),
                        ("index_state", addr_of_mut!((*r).data[5])),
                    ]
                }
                _ => vec![],
            }
        };
        for (field, address) in fields {
            if p == address {
                return format!("{map} key={key:?} field={field}");
            }
        }
    }
    panic!("unclassified atomic address");
}
unsafe fn host_cxchg(p: *mut u64, expected: u64, new: u64) -> (u64, bool) {
    edit(|s| {
        let identity = atomic_identity(s, p);
        let observed = unsafe { *p };
        let success = observed == expected;
        if success {
            unsafe { *p = new };
        }
        record(s, format!("cas {identity} expected={expected} new={new} observed={observed} success={success}"));
        (observed, success)
    })
}
unsafe fn host_xchg(p: *mut u64, new: u64) -> u64 {
    edit(|s| {
        let identity = atomic_identity(s, p);
        let observed = unsafe { *p };
        unsafe { *p = new };
        record(
            s,
            format!("exchange {identity} new={new} observed={observed}"),
        );
        observed
    })
}
mod helpers {
    pub unsafe fn bpf_ktime_get_ns() -> u64 {
        super::edit(|s| super::record(s, "clock value=900".into()));
        900
    }
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
fn blank_rel() -> RelValue {
    unsafe { core::mem::zeroed() }
}
fn rel_key(epoch: u64, primary: u64, secondary: u64, kind: u32, operation: u32) -> RelKey {
    // Independent fixture coordinates, never the production key builders.
    RelKey {
        process_incarnation: 11,
        image_epoch: 12,
        relation_epoch: epoch,
        primary_handle: primary,
        secondary_handle: secondary,
        kind,
        operation,
    }
}
fn global_key(primary: u64, kind: u32, operation: u32) -> RelKey {
    RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: primary,
        secondary_handle: 0,
        kind,
        operation,
    }
}
fn reset(family: u32) {
    edit(|s| *s = State::default());
    ATTRIB_CONTROL.set(
        0,
        ProducerControl {
            producer_mode: 1,
            session_id: 1,
            admission_epoch: 2,
            cut_id: 3,
            next_producer_id: 1001,
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
            ..SourceControl::PREPARED
        },
    );
    SOURCE_CONFIG.0.set(
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
    for cell in 0..2 {
        ITER_SLOT.set(
            cell,
            SourceSlot {
                slot: 0,
                staging: [0xa5a5_a5a5_a5a5_a5a5; 32],
            },
        );
    }
    for cell in 0..5 {
        PRODUCER_LOSS.set(cell, 0);
    }
    for cookie in [0x8000_0001, 0x8000_0002] {
        SITE_BIND.set(
            TypedSiteKey {
                cookie,
                process_incarnation: 11,
                image_epoch: 12,
            },
            SiteBindValue {
                site_id: 51,
                source_epoch: 31,
                code_object_id: 61,
                object_sha256: [0x11; 32],
            },
        );
        let mut ready = blank_rel();
        ready.evidence_epoch = 31;
        ready.state = REL_WITNESS;
        ready.data[..3].copy_from_slice(&[71, 72, 15]);
        REL.set(rel_key(0, cookie, 31, SOURCE_READY, 0), ready);
    }
    for id in [71, 72] {
        SOURCE_GUARD.set(
            id,
            SourceGuard {
                source_epoch: 31,
                state: GUARD_LIVE,
            },
        );
    }
    for (method, witness, request, name) in [
        (0x4000, 81, 82, if family == 3 { b"HMAC" } else { b"HKDF" }),
        (0x4100, 84, 83, b"ALT!"),
    ] {
        let mut row = blank_rel();
        row.witness_id = witness;
        row.parent_id = request;
        row.state = REL_WITNESS;
        REL.set(rel_key(13, method, 0, REL_METHOD, family), row);
        let mut row = blank_rel();
        row.witness_id = request;
        row.state = REL_WITNESS;
        row.data[..2].copy_from_slice(&[u64::from(family), 4]);
        row.tail[..4].copy_from_slice(name);
        REL.set(global_key(request, REL_REQUEST_NAME, family), row);
    }
    phase("setup");
}
struct Transaction {
    key: BindPendingKey,
    frame: *mut BindPendingValue,
    owner: u64,
    context: u64,
    occurrence: u64,
}
fn prepare(
    family: u32,
    thread: u64,
    owner: u64,
    context: u64,
    occurrence: u64,
    alternate: bool,
) -> Transaction {
    phase("prepare-input");
    let key = BindPendingKey {
        process_incarnation: 11,
        image_epoch: 12,
        thread_incarnation: thread,
        depth: 0,
        reserved: 0,
    };
    let mut frame: BindPendingValue = unsafe { core::mem::zeroed() };
    frame.occurrence_id = occurrence;
    frame.api_cookie = 0x8000_0001;
    frame.api_role = if family == 3 { 147 } else { 148 };
    frame.entry_handle = if alternate { 0x4100 } else { 0x4000 };
    frame.method_observation_id = if alternate { 84 } else { 81 };
    frame.selector_or_set_id = if alternate { 83 } else { 82 };
    frame.relation_epoch = 13;
    frame.loss_epoch = 14;
    frame.current_p = 0x5000;
    frame.current_c = 0x6000;
    frame.staged_x = context;
    frame.source_object_id = 61;
    frame.source_epoch = 31;
    frame.constructor_cookie = 0x8000_0002;
    frame.getter_count = 1;
    frame.constructor_count = 1;
    assert!(source_state::claim_pending());
    assert!(BIND_PENDING.insert(key, frame, 1).is_ok());
    let frame = BIND_PENDING.get_ptr_mut(key).unwrap();
    assert!(reserve_pending_x(
        ATTRIB_CONTROL.get_ptr_mut(0).unwrap(),
        &target(),
        frame,
        family,
        context,
        thread,
        0,
        900
    ));
    Transaction {
        key,
        frame,
        owner,
        context,
        occurrence,
    }
}
fn publish(tx: &Transaction) -> u64 {
    let control = ATTRIB_CONTROL.get_ptr_mut(0).unwrap();
    let root = resolve_target(77).unwrap();
    let entry_seq = root.entry_seq;
    phase("bind");
    assert!(
        bind_prepare(control, tx.frame, (77u64 << 32) | 78, entry_seq, tx.owner),
        "valid bind input refused"
    );
    phase("commit");
    let outcome = commit_publish(control, tx.frame, (77u64 << 32) | 78, entry_seq, tx.owner);
    phase("commit-returned");
    println!("OUTCOME current_owner={} outcome={outcome}", tx.owner);
    // This is the unchanged constructor caller's cleanup protocol. Root
    // admission/pop dispatch is separately covered by its owning fixture.
    if outcome != OUT_OK {
        phase("dispatch");
        dispatch_producer_outcome(control, &root, tx.frame, tx.owner, outcome);
        phase("cleanup");
        cleanup_pending_x(&root, tx.frame);
    }
    phase("release");
    release_frame(&tx.key);
    phase("released");
    assert!(BIND_PENDING.peek(tx.key).is_none());
    outcome
}
fn owner_namespace(handle: u64) -> Snapshot {
    edit(|s| {
        s.rows
            .iter()
            .filter_map(|(key, row)| {
                if key.0 != "rel" {
                    return None;
                }
                let k = unsafe { core::ptr::read_unaligned(key.1.as_ptr().cast::<RelKey>()) };
                let value = unsafe { *row.ptr::<RelValue>() };
                let belongs = (k.kind == REL_U_INDEX && k.primary_handle == handle)
                    || (k.kind == REL_OWNER && k.primary_handle == handle)
                    || (k.kind == REL_X_INDEX && value.data[4] == handle);
                belongs.then(|| (key.clone(), bytes(&value)))
            })
            .collect()
    })
}
fn assert_owner(
    tx: &Transaction,
    family: u32,
    owner_id: u64,
    sequence: u64,
    selector: u64,
    epoch: u64,
) {
    // The independently authored owner handle is never read from the plan,
    // tail, X peer or another published row to construct an expected key.
    let x = REL
        .peek(rel_key(13, tx.context, 0, REL_X_INDEX, 0))
        .unwrap();
    assert_eq!(x.data[4], tx.owner, "current-owner X peer");
    assert_eq!(x.data[0], owner_id, "fresh owner identity in X");
    assert_eq!(
        (x.data[1], x.data[5], x.data[6], x.data[7]),
        (tx.occurrence, 2, u64::from(family), sequence),
        "complete X identity"
    );
    let u = REL
        .peek(rel_key(13, tx.owner, 0, REL_U_INDEX, 0))
        .expect("current-owner U key");
    let mut expected_u = blank_rel();
    expected_u.witness_id = owner_id;
    expected_u.parent_id = tx.occurrence;
    expected_u.evidence_epoch = 13;
    expected_u.born_ns = 900;
    expected_u.state = REL_WITNESS;
    expected_u.data[..8].copy_from_slice(&[
        owner_id,
        tx.occurrence,
        0,
        0,
        tx.context,
        2,
        u64::from(family),
        sequence,
    ]);
    assert_eq!(
        bytes(&u),
        bytes(&expected_u),
        "complete current-owner U row"
    );
    let owner = REL
        .peek(rel_key(owner_id, tx.owner, tx.context, REL_OWNER, family))
        .expect("current-owner OWNER primary handle");
    let mut expected_owner = blank_rel();
    expected_owner.witness_id = owner_id;
    expected_owner.parent_id = 81;
    expected_owner.evidence_epoch = 13;
    expected_owner.born_ns = 900;
    expected_owner.state = REL_WITNESS;
    expected_owner.data[..9].copy_from_slice(&[
        owner_id + 1,
        82,
        owner_id + 3,
        owner_id + 2,
        0x5000,
        13,
        0,
        0x4000,
        sequence,
    ]);
    assert_eq!(
        bytes(&owner),
        bytes(&expected_owner),
        "complete current-owner OWNER row"
    );
    let selected = REL
        .peek(rel_key(
            owner_id,
            owner_id + 3,
            61,
            REL_OWNER_SELECTOR,
            family,
        ))
        .unwrap();
    assert_eq!(
        selected.data[..4],
        [selector, epoch, 82, 31],
        "reused selector coordinates"
    );
    // No extra U or OWNER key may silently point the new identity elsewhere.
    edit(|s| {
        let owners: Vec<_> = s
            .rows
            .iter()
            .filter_map(|((map, key), row)| {
                if *map != "rel" {
                    return None;
                }
                let k = unsafe { core::ptr::read_unaligned(key.as_ptr().cast::<RelKey>()) };
                let value = unsafe { *row.ptr::<RelValue>() };
                (matches!(k.kind, REL_U_INDEX | REL_OWNER) && value.witness_id == owner_id)
                    .then_some((k.kind, k.primary_handle, k.secondary_handle))
            })
            .collect();
        assert_eq!(owners.len(), 2, "exact current-owner U/OWNER namespace");
        assert!(owners.contains(&(REL_U_INDEX, tx.owner, 0)));
        assert!(owners.contains(&(REL_OWNER, tx.owner, tx.context)));
    });
}
fn completed_create(family: u32) {
    reset(family);
    let first = prepare(family, 21, 0x1000, 0x1100, 101, false);
    assert_eq!(publish(&first), OUT_OK);
    trace();
    assert_owner(&first, family, 1001, 16, 1006, 1007);
    assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
}
fn zero_carryover(family: u32) {
    reset(family);
    // Both constructors have already staged their X on distinct threads.
    // Their public returns then run sequentially on this modeled CPU.
    let first = prepare(family, 21, 0x1000, 0x1100, 101, false);
    let current = prepare(family, 22, 0x2000, 0x2200, 202, false);
    assert_eq!(publish(&first), OUT_OK);
    assert_owner(&first, family, 1001, 16, 1006, 1007);
    let previous = owner_namespace(first.owner);
    assert_eq!(
        ITER_SLOT.peek(0).unwrap().staging[30],
        0,
        "successful OWNER build really clears previous plan owner"
    );
    let outcome = publish(&current);
    trace();
    assert_eq!(
        outcome, OUT_OK,
        "current-owner reuse after successful create must publish"
    );
    assert_owner(&current, family, 1008, 17, 1006, 1007);
    assert_eq!(
        owner_namespace(first.owner),
        previous,
        "prior owner namespace unchanged"
    );
    assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
}
fn stale_carryover(family: u32) {
    reset(family);
    let first = prepare(family, 21, 0x1000, 0x1100, 101, false);
    assert_eq!(publish(&first), OUT_OK);
    assert_owner(&first, family, 1001, 16, 1006, 1007);
    let first_namespace = owner_namespace(first.owner);
    // B is prepared before A's public return. It may have been scheduled
    // away after its provider constructor; no BPF callback is preempted.
    let current = prepare(family, 22, 0x2000, 0x2200, 202, false);
    let aborted = prepare(family, 23, 0x3000, 0x3300, 303, true);
    let state = ATTR_STATE.get_ptr_mut(0).unwrap();
    phase("competitor-acquire");
    assert!(unsafe { compare(addr_of_mut!((*state).publication_busy), 0, 1) });
    assert_eq!(publish(&aborted), OUT_ABORT);
    let attempts = edit(|s| {
        s.events
            .iter()
            .filter(|e| {
                e.phase == "commit"
                    && e.operation
                        .contains("field=busy expected=0 new=1 observed=1 success=false")
            })
            .count()
    });
    assert_eq!(attempts, 8, "eight genuine failed lock attempts");
    assert_eq!(
        ATTR_STATE.peek(0).unwrap().publication_busy,
        1,
        "abort did not unlock competitor"
    );
    assert_eq!(
        ATTR_STATE.peek(0).unwrap().published_sequence,
        16,
        "abort preserves publication sequence"
    );
    let control = ATTRIB_CONTROL.peek(0).unwrap();
    assert_eq!(
        (
            control.producer_mode,
            control.relation_epoch,
            control.loss_epoch
        ),
        (1, 13, 14),
        "abort preserves mode and epochs"
    );
    assert_eq!(
        ITER_SLOT.peek(0).unwrap().staging[30],
        0x3000,
        "aborted create retains its own return handle through real cleanup"
    );
    assert_eq!(
        REL.peek(rel_key(13, aborted.context, 0, REL_X_INDEX, 0))
            .unwrap()
            .data[5],
        3
    );
    let aborted_namespace = owner_namespace(aborted.owner);
    assert!(
        aborted_namespace.is_empty(),
        "aborted A has no committed owner namespace"
    );
    let residue = bytes(&ITER_SLOT.peek(0).unwrap());
    phase("competitor-release");
    assert!(unsafe { compare(addr_of_mut!((*state).publication_busy), 1, 0) });
    assert_eq!(
        bytes(&ITER_SLOT.peek(0).unwrap()),
        residue,
        "no later B entry staging between A residue and B bind"
    );
    let outcome = publish(&current);
    trace();
    assert_eq!(
        outcome, OUT_OK,
        "current-owner reuse after lock abort must publish"
    );
    assert_owner(&current, family, 1015, 17, 1006, 1007);
    assert_eq!(
        owner_namespace(aborted.owner),
        aborted_namespace,
        "aborted prior owner namespace unchanged"
    );
    assert_eq!(
        owner_namespace(first.owner),
        first_namespace,
        "existing selector owner namespace unchanged"
    );
    assert_eq!(ATTR_STATE.peek(0).unwrap().pending_claims, 2);
}
mod bind_controls {
    use super::*;
    #[test]
    fn zero_owner_mac() {
        zero_carryover(3);
    }
    #[test]
    fn zero_owner_kdf() {
        zero_carryover(4);
    }
    #[test]
    fn stale_owner_mac() {
        stale_carryover(3);
    }
    #[test]
    fn stale_owner_kdf() {
        stale_carryover(4);
    }
    #[test]
    fn completed_create_mac() {
        completed_create(3);
    }
    #[test]
    fn completed_create_kdf() {
        completed_create(4);
    }
    #[test]
    fn retained_lookup_handles() {
        reset(3);
        let p = ATTR_STATE.get_ptr_mut(0).unwrap();
        let q = ATTR_STATE.get_ptr_mut(0).unwrap();
        unsafe {
            (*p).relationship_claims = 8;
            (*q).pending_claims = 5;
        }
        assert_eq!(unsafe { (*p).pending_claims }, 5);
        assert_eq!(unsafe { (*q).relationship_claims }, 8);
    }
    #[test]
    fn retained_helper_handles() {
        reset(3);
        let p = ATTR_STATE.get_ptr_mut(0).unwrap();
        assert!(spend(7));
        unsafe {
            (*p).pending_claims = 4;
        }
        assert!(source_state::release_pending());
        assert_eq!(unsafe { (*p).relationship_claims }, 8);
        assert_eq!(unsafe { (*p).pending_claims }, 3);
        let a = ITER_SLOT.get_ptr_mut(0).unwrap();
        let b = ITER_SLOT.get_ptr_mut(1).unwrap();
        assert_ne!(a, b, "separate typed SourceSlot allocations");
        unsafe {
            plan_store(a, 240, 123);
            plan_store(b, 240, 456);
        }
        assert_eq!(unsafe { plan_load(a, 240) }, 123);
        assert_eq!(unsafe { plan_load(b, 240) }, 456);
    }
    #[test]
    fn retired_row_handles() {
        reset(3);
        let key = global_key(500, REL_OBJECT_SELECTOR, 3);
        let mut value = blank_rel();
        value.witness_id = 501;
        assert!(REL.insert(key, value, 1).is_ok());
        let p = REL.get_ptr_mut(key).unwrap();
        value.witness_id = 502;
        assert_eq!(REL.insert(key, value, 1), Err(-17));
        assert_eq!(REL.peek(key).unwrap().witness_id, 501);
        assert!(REL.insert(key, value, 0).is_ok());
        let q = REL.get_ptr_mut(key).unwrap();
        assert!(REL.remove(key).is_ok());
        assert!(REL.peek(key).is_none());
        unsafe {
            (*p).witness_id = 503;
            (*q).witness_id = 504;
        }
        assert_eq!(unsafe { (*p).witness_id }, 503);
        assert_eq!(unsafe { (*q).witness_id }, 504);
    }
}
