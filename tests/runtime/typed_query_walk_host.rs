// SPDX-License-Identifier: GPL-3.0-or-later
// Appended to the exact production query-return/walker bodies by the owning
// session test. These doubles replace external boundaries, never traversal.
use std::{cell::RefCell, collections::BTreeMap};

const TABLE: u64 = 0x1000;
const NOCACHE: u64 = 0x2000;
const DISPATCH: u64 = 0x4000;
const FUN: u64 = 0x9000;
const LOSS_MAP: u32 = 1;

#[derive(Debug, PartialEq)]
enum Event {
    Read(u64, usize),
    Join(u64),
    Publish(u64, u64, u64, u64),
    Loss,
}
#[derive(Default)]
struct State {
    words: BTreeMap<(u64, usize), u64>,
    events: Vec<Event>,
    published: usize,
    deny_after: Option<usize>,
    failed_join: bool,
    zero_inode: bool,
    unresolved: bool,
}
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}
fn edit(f: impl FnOnce(&mut State)) {
    STATE.with(|state| f(&mut state.borrow_mut()));
}
fn word(address: u64, width: usize, value: u64) {
    edit(|state| {
        assert!(state.words.insert((address, width), value).is_none());
    });
}
fn reset() {
    edit(|state| *state = State::default());
}
fn algorithms(rows: &[(u64, u64)]) {
    for (index, &(names, implementation)) in rows.iter().enumerate() {
        word(TABLE + index as u64 * 32, 8, names);
        word(TABLE + index as u64 * 32 + 16, 8, implementation);
    }
}
fn dispatch(rows: &[(u32, u64)]) {
    for (index, &(id, function)) in rows.iter().enumerate() {
        word(DISPATCH + index as u64 * 16, 4, u64::from(id));
        word(DISPATCH + index as u64 * 16 + 8, 8, function);
    }
}
fn one_algorithm() {
    // Names/property/description contents are intentionally absent. They must
    // never be read: only the names pointer is a termination discriminator.
    algorithms(&[(0xdead_beef, DISPATCH), (0, 0)]);
}
mod helpers {
    pub unsafe fn bpf_probe_read_user<T: Copy>(pointer: *const T) -> Result<T, i64> {
        let width = core::mem::size_of::<T>();
        assert!(matches!(width, 4 | 8));
        let address = pointer as u64;
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            // A regression cannot hang the host controls or read an unbounded
            // population. This exceeds the independent 4224-read maximum.
            assert!(state.events.len() < 10_000, "finite traversal exceeded");
            state.events.push(super::Event::Read(address, width));
            let value = *state.words.get(&(address, width)).ok_or(-1)?;
            let mut result = core::mem::MaybeUninit::<T>::uninit();
            core::ptr::copy_nonoverlapping(
                value.to_ne_bytes().as_ptr(),
                result.as_mut_ptr().cast::<u8>(),
                width,
            );
            Ok(result.assume_init())
        })
    }
    pub unsafe fn bpf_loop(
        _count: u32,
        _callback: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
        _flags: u64,
    ) -> i64 {
        panic!("typed source traversal must not require helper callbacks/program BTF")
    }
}
struct RetProbeContext(u64);
impl RetProbeContext {
    fn ret(&self) -> u64 {
        self.0
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
fn resolve_inner(tgid: u32, entry_seq: u64, out: &mut Target) -> bool {
    assert_eq!((tgid, entry_seq), (77, 15));
    if STATE.with(|state| state.borrow().unresolved) {
        return false;
    }
    *out = target();
    true
}
fn loss(cell: u32) {
    assert_eq!(cell, LOSS_MAP);
    edit(|state| state.events.push(Event::Loss));
}
fn code_vma_join(address: u64, out: &mut source_vma::SourceLocation) -> bool {
    assert_eq!(address, FUN);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.events.push(Event::Join(address));
        out.inode = if state.zero_inode { 0 } else { 71 };
        out.file_offset = 72;
        !state.failed_join
    })
}
fn publish_code_role(
    control: *mut ProducerControl,
    target: &Target,
    location: &source_vma::SourceLocation,
    opfun: u64,
    occurrence: u64,
) -> bool {
    assert!(!control.is_null());
    assert_eq!(
        (
            target.process,
            target.image,
            target.relation,
            target.loss_epoch,
            target.entry_seq
        ),
        (11, 12, 13, 14, 15)
    );
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.events.push(Event::Publish(
            location.inode,
            location.file_offset,
            opfun,
            occurrence,
        ));
        if state
            .deny_after
            .is_some_and(|limit| state.published >= limit)
        {
            return false;
        }
        state.published += 1;
        true
    })
}
fn walk(table: u64) {
    query_walk_table(&mut ProducerControl::default(), &target(), table, 3, 99);
}
fn query(table: u64, operation: u64, nocache: u64, occurrence: u64) {
    let mut frame: BindPendingValue = unsafe { core::mem::zeroed() };
    frame.entry_handle = operation;
    frame.provider_witness = nocache;
    frame.occurrence_id = occurrence;
    // The return handler must repeat source resolution using the captured
    // entry sequence, then publish with the refreshed coordinates. Reusing
    // caller storage must not turn it into authority for stale coordinates.
    let mut caller_target = Target {
        process: 101,
        image: 102,
        relation: 103,
        loss_epoch: 104,
        entry_seq: 15,
    };
    typed_query_return(
        &RetProbeContext(table),
        &mut ProducerControl::default(),
        &mut frame,
        77,
        &mut caller_target,
    );
}
fn check(name: &str, reads: usize, losses: usize, attempts: usize, published: usize) {
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state
                .events
                .iter()
                .filter(|e| matches!(e, Event::Read(..)))
                .count(),
            reads,
            "{name}: reads"
        );
        assert_eq!(
            state
                .events
                .iter()
                .filter(|e| matches!(e, Event::Loss))
                .count(),
            losses,
            "{name}: loss"
        );
        assert_eq!(
            state
                .events
                .iter()
                .filter(|e| matches!(e, Event::Publish(..)))
                .count(),
            attempts,
            "{name}: publication attempts"
        );
        assert_eq!(state.published, published, "{name}: published");
    });
    println!("PASS {name}: reads={reads} loss={losses} attempts={attempts} published={published}");
}
fn main() {
    reset();
    algorithms(&[(0, 0)]);
    walk(TABLE);
    check("first algorithm terminator", 1, 0, 0, 0);

    reset();
    one_algorithm();
    dispatch(&[(0, 0)]);
    walk(TABLE);
    check("first dispatch terminator", 4, 0, 0, 0);

    reset();
    let mut rows = vec![(1, DISPATCH); 63];
    rows.push((0, 0));
    algorithms(&rows);
    dispatch(&[(0, 0)]);
    walk(TABLE);
    check("algorithm terminator at slot 63", 190, 0, 0, 0);

    reset();
    one_algorithm();
    let mut rows = vec![(1, FUN); 31];
    rows.push((0, 0));
    dispatch(&rows);
    walk(TABLE);
    check("dispatch terminator at slot 31", 66, 0, 31, 31);

    reset();
    algorithms(&[(1, DISPATCH); 64]);
    dispatch(&[(0, 0)]);
    walk(TABLE);
    check("unterminated 64 algorithms", 192, 1, 0, 0);

    reset();
    one_algorithm();
    dispatch(&[(1, FUN); 32]);
    walk(TABLE);
    check("unterminated 32 dispatch entries", 67, 1, 32, 32);

    reset();
    algorithms(&[(1, DISPATCH); 64]);
    dispatch(&[(1, FUN); 32]);
    walk(TABLE);
    check("maximum 64 by 32 traversal", 4224, 65, 2048, 2048);

    reset();
    walk(TABLE);
    check("unreadable names pointer", 1, 1, 0, 0);

    reset();
    word(TABLE, 8, 1);
    walk(TABLE);
    check("unreadable implementation", 2, 1, 0, 0);

    reset();
    one_algorithm();
    walk(TABLE);
    check("unreadable dispatch id", 4, 1, 0, 0);

    reset();
    one_algorithm();
    word(DISPATCH, 4, 1);
    walk(TABLE);
    check("unreadable function", 5, 1, 0, 0);

    reset();
    word(u64::MAX - 31, 8, 1);
    word(u64::MAX - 15, 8, DISPATCH);
    dispatch(&[(0, 0)]);
    walk(u64::MAX - 31);
    check("algorithm slot address overflow", 3, 1, 0, 0);

    reset();
    algorithms(&[(1, u64::MAX - 15), (0, 0)]);
    word(u64::MAX - 15, 4, 1);
    word(u64::MAX - 7, 8, FUN);
    walk(TABLE);
    check("dispatch slot address overflow", 5, 1, 1, 1);

    reset();
    word(u64::MAX - 7, 8, 1);
    walk(u64::MAX - 7);
    check("implementation field address overflow", 1, 1, 0, 0);

    reset();
    algorithms(&[(1, u64::MAX - 3), (0, 0)]);
    word(u64::MAX - 3, 4, 1);
    walk(TABLE);
    check("function field address overflow", 4, 1, 0, 0);

    reset();
    algorithms(&[(1, 0), (0, 0)]);
    walk(TABLE);
    check("null implementation", 3, 1, 0, 0);

    reset();
    one_algorithm();
    dispatch(&[(1, 0), (0, 0)]);
    walk(TABLE);
    check("null function", 6, 1, 0, 0);

    reset();
    one_algorithm();
    dispatch(&[(7, FUN), (0, 0)]);
    walk(TABLE);
    check("unrecognized positive function id", 6, 0, 0, 0);

    reset();
    one_algorithm();
    dispatch(&[(0x8000_0000, FUN), (1, FUN)]);
    walk(TABLE);
    check("invalid signed function id", 4, 1, 0, 0);

    for (name, failed_join, zero_inode) in [
        ("failed source join", true, false),
        ("zero inode join", false, true),
    ] {
        reset();
        one_algorithm();
        dispatch(&[(1, FUN), (0, 0)]);
        edit(|state| {
            state.failed_join = failed_join;
            state.zero_inode = zero_inode;
        });
        walk(TABLE);
        check(name, 6, 1, 0, 0);
    }

    reset();
    one_algorithm();
    dispatch(&[(1, FUN), (2, FUN), (3, FUN), (0, 0)]);
    edit(|state| state.deny_after = Some(1));
    walk(TABLE);
    check("publication denial after prior valid slot", 10, 2, 3, 1);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().events,
            [
                Event::Read(0x1000, 8),
                Event::Read(0x1010, 8),
                Event::Read(0x4000, 4),
                Event::Read(0x4008, 8),
                Event::Join(0x9000),
                Event::Publish(71, 72, 0x1_0000_0003, 99),
                Event::Read(0x4010, 4),
                Event::Read(0x4018, 8),
                Event::Join(0x9000),
                Event::Publish(71, 72, 0x2_0000_0003, 99),
                Event::Loss,
                Event::Read(0x4020, 4),
                Event::Read(0x4028, 8),
                Event::Join(0x9000),
                Event::Publish(71, 72, 0x3_0000_0003, 99),
                Event::Loss,
                Event::Read(0x4030, 4),
                Event::Read(0x1020, 8),
            ]
        );
    });

    reset();
    word(NOCACHE, 4, 1);
    query(TABLE, 3, NOCACHE, 99);
    check("no-cache return", 1, 0, 0, 0);

    reset();
    query(TABLE, 3, NOCACHE, 99);
    check("unreadable no-cache result", 1, 1, 0, 0);

    for operation in [3, 4] {
        reset();
        one_algorithm();
        dispatch(&[(1, FUN), (0, 0)]);
        word(NOCACHE, 4, 0);
        query(TABLE, operation, NOCACHE, 99);
        check("cacheable MAC/KDF return", 7, 0, 1, 1);
        STATE.with(|state| {
            assert!(state.borrow().events.contains(&Event::Publish(
                71,
                72,
                (1 << 32) | operation,
                99
            )))
        });
    }

    for (name, table, operation, nocache, occurrence) in [
        ("null returned table", 0, 3, NOCACHE, 99),
        ("out-of-slice operation", TABLE, 5, NOCACHE, 99),
        ("null no-cache pointer", TABLE, 3, 0, 99),
        ("missing query occurrence", TABLE, 3, NOCACHE, 0),
    ] {
        reset();
        query(table, operation, nocache, occurrence);
        check(name, 0, 0, 0, 0);
    }
    reset();
    edit(|state| state.unresolved = true);
    query(TABLE, 3, NOCACHE, 99);
    check("unresolved target", 0, 0, 0, 0);
}
