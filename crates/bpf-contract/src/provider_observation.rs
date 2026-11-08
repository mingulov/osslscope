// SPDX-License-Identifier: GPL-2.0-or-later
//! Finite observation ABI. No opaque target handle is a transport field.
pub const VERSION: u32 = 5;
pub const EVENT_SIZE: usize = 112;
pub const MAX_DEPTH: u32 = 8;
pub const MAX_PENDING: u32 = 4096;
pub const MAX_RANGES: u32 = 128;
pub const OTHER: u32 = 65535;
pub const ATTEMPT: u32 = 1;
pub const RESULT: u32 = 2;
pub const INIT: u32 = 3;
pub const QUERY: u32 = 4;
pub const ALGORITHM: u32 = 5;
pub const IMPLEMENTATION: u32 = 6;
pub const INVALIDATION: u32 = 7;
pub const GAP: u32 = 8;
/// Internal finite alias: algorithm=class, function=canon, outcome=weak, status=index.
pub const ALIAS: u32 = 9;
/// Internal terminator: function=segment count, status=0/2/3/4, algorithm=OTHER.
pub const ALIAS_END: u32 = 10;
/// Explicit per-algorithm boundary within one synchronous returned table.
pub const ALGORITHM_BEGIN: u32 = 11;
pub const MAX_ALGORITHMS: u32 = 512;
pub const LOAD: u32 = 1;
pub const TRY_LOAD: u32 = 2;
pub const LOAD_EX: u32 = 3;
pub const TRY_LOAD_EX: u32 = 4;
pub const UNLOAD: u32 = 5;
pub const ADD_BUILTIN: u32 = 6;
pub const PROVIDER_INIT: u32 = 7;
pub const PUBLIC_QUERY: u32 = 8;
pub const PUBLIC_UNQUERY: u32 = 9;
pub const GET_DISPATCH: u32 = 16;
pub const QUERY_CALLBACK: u32 = 17;
pub const TEARDOWN: u32 = 18;
pub const UNQUERY_CALLBACK: u32 = 19;
pub const LOSS_RING: u32 = 0;
pub const LOSS_MAP: u32 = 1;
pub const LOSS_DEPTH: u32 = 2;
pub const LOSS_PAIR: u32 = 3;
pub const LOSS_READ: u32 = 4;
pub const LOSS_RANGE: u32 = 5;
pub const LOSS_TRUNC: u32 = 6;
pub const LOSS_NAMESPACE: u32 = 7;
pub const LOSS_MAX: u32 = 8;
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Record {
    pub version: u32,
    pub kind: u32,
    pub size: u32,
    pub api: u32,
    pub pid: u32,
    pub tid: u32,
    pub cookie: u64,
    pub generation: u64,
    pub monotonic_ns: u64,
    pub invocation: u64,
    pub outcome: u32,
    pub operation: u32,
    pub algorithm: u32,
    pub function: u32,
    pub cacheability: u32,
    pub status: u32,
    /// Only INIT and cacheable IMPLEMENTATION may contain a verified-range code operand.
    pub code: u64,
    pub algorithm_index: u32,
    pub reserved: u32,
    /// BPF-stamped task incarnation (fix4): the emitting thread's
    /// `task_struct.start_time` (CLOCK_MONOTONIC ns, kernel-assigned,
    /// immutable per task). Host pairing namespaces on this, so
    /// recycled-tid edges never pair across incarnations in EITHER
    /// recycle order. Always nonzero on the wire (the decoder
    /// rejects 0 — a zero stamp means the BPF offset read failed).
    pub start_time_ns: u64,
    /// BPF-stamped creation seed (fix6): the emitting THREADS row's
    /// `Thread.seed` (bytes 104..112). Host pairing namespaces on
    /// this, so invocations — which restart at 1 per row BY DESIGN
    /// — never pair across row creations. Seed 0 is the legitimate
    /// first creation: the decoder applies NO nonzero gate.
    pub seed: u64,
}
/// BPF-side sanity ceiling for `Config.task_off`: the verifier
/// needs a bounded scalar for the task-pointer arithmetic, and
/// any offset at/above this is not a `start_time` field (the
/// loader refuses it before any program runs; BPF stamps 0).
pub const TASK_OFF_MAX: u64 = 65536;
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Config {
    pub generation: u64,
    pub object: u64,
    pub pid: u32,
    pub api: u32,
    /// Load-time-resolved `task_struct.start_time` byte offset
    /// (fix4): userspace parses it from kernel BTF once and
    /// programs it into every row; BPF stamps
    /// `probe_read(task + task_off)` into `Record.start_time_ns`.
    /// 0 = unprogrammed (BPF stamps 0 → host rejects; the loader
    /// refuses to run any program with an unprogrammed offset).
    pub task_off: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Member {
    pub generation: u64,
    pub epoch: u64,
    pub range_count: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Namespace {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct RangeKey {
    pub pid: u32,
    pub index: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ThreadKey {
    pub pid: u32,
    pub tid: u32,
    pub generation: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Thread {
    pub next: u64,
    pub depth: u32,
    pub overflow: u32,
    /// Creation seed (fix6): the `seed_next()` value this row was
    /// born with (24 B value). The row's pairing namespace:
    /// invocations restart at 1 per row BY DESIGN, scoped by this
    /// seed (the fix5 "never restarts" claim INVERTS — R6-1 proved
    /// unique seeds with overlapping ranges still mispair, so the
    /// seed joins the pairing key as identity, not arithmetic).
    /// Immutable after creation (`enter`/`skip_return`/
    /// `failed_entry` never touch it). `API_THREADS` rows carry a
    /// vestigial 0 (their `next` is write-only — never emitted).
    pub seed: u64,
    /// Window-blind entries outstanding (fix7, R7-3): calls whose
    /// ENTRY was rejected by the operational window (resolved
    /// identity, closed window — the call executes unobserved)
    /// and whose returns will execute-but-reject. Each such entry
    /// arms exactly one tombstone (`blind_entry`); window-rejected
    /// returns consume T-first (`blind_return`). ACCEPTED returns
    /// never touch this counter (their skip reads `overflow`
    /// only), so blind tombstones can never hijack a framed
    /// return the way a bare overflow unit does.
    ///
    /// WHY a separate counter rather than the naive "rejected
    /// returns consume overflow": a window-rejected return either
    /// OWNS an overflow marker (its entry was accepted, then
    /// overflowed — the R7-3 shape — and must consume) or OWNS
    /// NOTHING (its entry was window-rejected — and must not
    /// consume, else it steals a same-cookie overflow owner's
    /// marker and shifts the cascade the other way). Entry-time
    /// window state is lost by return time, so the entry records
    /// it here. SOUND under the never-reopen window (programmed
    /// once per capture): tombstone-first attribution is then
    /// EXACT — at a marker-owner's rejected return T==0 always
    /// (T>0 would need a closed-entry before its open-entry ⟹
    /// reopen), so it consumes its own overflow unit; at a
    /// nothing-owner's rejected return T>=1 (its own), so outer
    /// markers survive. Past the precondition (mixed T+O) counts
    /// still balance fungibly (pinned below).
    /// `API_THREADS` rows carry a vestigial 0 (blind is armed
    /// only on the shared trace machine's closed-window entries).
    pub blind: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingKey {
    pub thread: ThreadKey,
    pub depth: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Pending {
    pub cookie: u64,
    pub invocation: u64,
    pub object: u64,
    pub arg0: u64,
    pub arg2: u64,
    pub operation: u32,
    pub api: u32,
    pub name: u32,
    pub suppressed: u32,
}
/// Positive future public operation IDs are preserved, independently of registry.
pub const fn known_operation(op: u32) -> u32 {
    match op {
        0..=0x7fff_ffff => op,
        _ => 0,
    }
}
pub const fn load_api(api: u32) -> bool {
    api >= LOAD && api <= TRY_LOAD_EX
}
pub const fn query_api(api: u32) -> bool {
    api == PUBLIC_QUERY || api == QUERY_CALLBACK
}

/// Wrapper variants collapse only within one object/library-context stack;
/// a same-API recursive call is always a distinct invocation.
pub fn suppress_wrapper(parent: &Pending, child: &Pending) -> bool {
    load_api(parent.api)
        && load_api(child.api)
        && parent.api != child.api
        && parent.object == child.object
        && parent.arg0 == child.arg0
}
impl Thread {
    pub fn enter(&mut self) -> Option<u64> {
        if self.depth >= MAX_DEPTH || self.overflow != 0 {
            self.overflow = self.overflow.saturating_add(1);
            return None;
        }
        if self.next == u64::MAX {
            self.overflow = self.overflow.saturating_add(1);
            return None;
        }
        self.next += 1;
        self.depth += 1;
        Some(self.next)
    }
    pub fn failed_entry(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        self.overflow = self.overflow.saturating_add(1);
    }
    /// Cross-edge skip, ACCEPTED returns only: consume one
    /// overflow marker armed by an earlier overflowed (or
    /// entry-failed) call on this thread. Counter-only, no depth
    /// change, no frame pop — the matching entry pushed no frame,
    /// so the return emits nothing. Never touches `blind` (blind
    /// tombstones belong to window-rejected calls and are consumed
    /// only by window-rejected returns — accepted returns must not
    /// hijack them, and tombstones must not hijack framed
    /// returns).
    ///
    /// fix7 (R7-3) follow-on to the documented cross-edge skip: a
    /// return REJECTED by the operational window used to consume
    /// nothing, orphaning its overflow marker for the next
    /// accepted return — which consumed it WITHOUT popping its
    /// own frame, so the FOLLOWING same-cookie return popped the
    /// wrong frame (frame-shift + cascade, up to 7 mislabeled
    /// RESULTs). Rejected returns now consume T-first-then-O via
    /// `blind_return` (marker only, never a pop); accepted
    /// behavior here is unchanged.
    pub fn skip_return(&mut self) -> bool {
        if self.overflow != 0 {
            self.overflow -= 1;
            true
        } else {
            false
        }
    }
    /// Arm one window-blind tombstone: the ENTRY was rejected by
    /// the operational window (resolved identity, closed window),
    /// so the executing call owns no frame and no overflow marker
    /// — but its return WILL execute (and reject), and must then
    /// consume exactly this tombstone rather than stealing an
    /// outer overflow marker. Saturating (2^32 nested blind calls
    /// is unreachable — bounded by thread stack depth).
    pub fn blind_entry(&mut self) {
        self.blind = self.blind.saturating_add(1);
    }
    /// Consume one unit for a WINDOW-REJECTED return (resolved
    /// identity, closed window): its own blind tombstone first,
    /// else one overflow marker (under the never-reopen window,
    /// T==0 at a rejected return proves marker ownership — see
    /// `blind`). Marker only — NEVER a pop (a rejected return has
    /// no addressable frame; popping would steal same-cookie
    /// frames). Returns whether a unit was consumed. Rejections
    /// that cannot attribute (tgid/generation/CONFIG mismatch —
    /// a different row) must NOT call this.
    pub fn blind_return(&mut self) -> bool {
        if self.blind != 0 {
            self.blind -= 1;
            true
        } else if self.overflow != 0 {
            self.overflow -= 1;
            true
        } else {
            false
        }
    }
}

/// `enter()`-None arm disposition (fix6, R6-4 backstop): what the
/// BPF entry path does with the row when `enter()` refuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnterNoneDisposition {
    /// Delete the row (a `next == MAX` row would wedge every
    /// later entry — returns clear only `overflow`).
    Delete,
    /// (Re)insert the row (depth-overflow Nones need their
    /// overflow to arm `skip_return` pairing).
    Insert,
}

/// Pure disposition for the `enter()`-None arm: delete iff
/// `next == MAX`. Distinguished by the counter value, NOT by
/// row freshness (a fresh MAX row and a pre-existing MAX row
/// both delete; depth-overflow and normal rows both insert).
/// BPF-safe (`const`, no allocation) and host-unit-tested.
pub const fn enter_none_disposition(next: u64) -> EnterNoneDisposition {
    if next == u64::MAX {
        EnterNoneDisposition::Delete
    } else {
        EnterNoneDisposition::Insert
    }
}

/// Exact finite load taxonomy, unrolled to avoid a compiler-local memcmp
/// subprogram that the strict reachable-subset loader cannot relocate.
#[inline(always)]
pub fn provider_name_class(b: &[u8; 32], len: usize) -> u32 {
    if len == 31 {
        return 5;
    }
    if len == 7
        && b[7] == 0
        && b[0] == b'd'
        && b[1] == b'e'
        && b[2] == b'f'
        && b[3] == b'a'
        && b[4] == b'u'
        && b[5] == b'l'
        && b[6] == b't'
    {
        2
    } else if len == 6
        && b[6] == 0
        && b[0] == b'l'
        && b[1] == b'e'
        && b[2] == b'g'
        && b[3] == b'a'
        && b[4] == b'c'
        && b[5] == b'y'
    {
        1
    } else if len == 4 && b[4] == 0 && b[0] == b'f' && b[1] == b'i' && b[2] == b'p' && b[3] == b's'
    {
        3
    } else {
        0
    }
}

/// Documented int APIs return exactly one for success, zero for failure.
/// Other int values remain unknown and never authorize an output-table walk.
pub const fn int_outcome(rv: u64) -> u32 {
    match rv as u32 {
        1 => 1,
        0 => 2,
        _ => 0,
    }
}

/// Executable-range membership, with no target-memory reads.
#[inline(always)]
pub fn code_in_ranges(
    address: u64,
    count: u32,
    mut lookup: impl FnMut(u32) -> Option<Range>,
) -> bool {
    if !(4096..=0x0000_ffff_ffff_ffff).contains(&address) || count == 0 || count > MAX_RANGES {
        return false;
    }
    // Upper-bound search for the last start <= address. Host admission proves
    // sorted, nonempty, disjoint intervals. Eight steps cover all 128 slots.
    let mut low = 0u32;
    let mut high = count;
    let mut end = 0u64;
    for _ in 0..8 {
        if low >= high {
            break;
        }
        let mid = (low + high) / 2;
        let Some(range) = lookup(mid) else {
            return false;
        };
        if address < range.start {
            high = mid
        } else {
            low = mid + 1;
            end = range.end
        }
    }
    address < end
}

/// Aggregate already classified finite alias identities; never raw target bytes.
#[derive(Clone, Copy)]
pub struct FiniteEvidence {
    minimum: u16,
    weak: bool,
    canon: Option<u16>,
    mixed: bool,
}
impl Default for FiniteEvidence {
    fn default() -> Self {
        Self::new()
    }
}
impl FiniteEvidence {
    pub const fn new() -> Self {
        Self {
            minimum: u16::MAX,
            weak: false,
            canon: None,
            mixed: false,
        }
    }
    pub fn include(&mut self, class: u16, weak: u8, canon: u16) {
        if weak > 1 {
            return;
        }
        if class == u16::MAX {
            if canon == u16::MAX && weak == 1 {
                self.weak = true;
            }
            return;
        }
        if canon == u16::MAX {
            return;
        }
        self.minimum = self.minimum.min(class);
        self.weak |= weak == 1;
        if let Some(previous) = self.canon {
            self.mixed |= previous != canon;
        } else {
            self.canon = Some(canon);
        }
    }
    pub fn finish(self, truncated: bool) -> (u16, bool, u8) {
        (
            self.minimum,
            self.weak || truncated,
            if truncated {
                3
            } else if self.canon.is_none() {
                1
            } else if self.mixed {
                5
            } else {
                0
            },
        )
    }
}

/// Public operational return class; no target arguments participate.
/// IDs 49-72 are the Task 7 (5G) additive range (D1-D4 in task-7-report
/// §7); 20-48 behavior is bit-identical to before.
pub const fn operational_outcome(api: u32, rv: u64) -> u32 {
    if !operational_api(api) {
        return 0;
    }
    // D1: void-return exports have no scalar. A paired return proves the
    // teardown call completed; rv is caller garbage and is ignored.
    if matches!(api, 68 | 70 | 72) {
        return 1;
    }
    // D2: pointer-return exports compare the FULL 64-bit scalar: NULL is
    // failure, any nonzero pointer is success. This precedes the int
    // truncation below, which would misread a nonzero pointer with zero
    // low 32 bits as NULL.
    if matches!(api, 65 | 67 | 69 | 71) {
        return if rv == 0 { 2 } else { 1 };
    }
    let rv = rv as u32 as i32;
    if rv == 1 {
        return 1;
    }
    if rv == 0 {
        return if matches!(api, 40 | 45 | 47) { 3 } else { 2 };
    }
    if matches!(api, 39..=43 | 49..=58) && rv == -2 {
        return 4;
    }
    // D3 CHECK arm: doc-literal "1 success, others failure".
    if matches!(api, 56..=58) {
        return 2;
    }
    if matches!(api, 39..=43 | 48 | 49..=55) && rv < 0 || matches!(api, 45 | 47) {
        return 2;
    }
    0
}
pub const fn operational_api(api: u32) -> bool {
    api >= 20 && api <= 72
}
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_OFF: u32 = 0;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_METADATA: u32 = 1;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_LATENCY: u32 = 2;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_STATUS: u32 = 3;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_ALL: u32 = 4;
/// Edge-bearing predicate (§6D-0 D0-1): only 2/3/4 emit operational edges.
pub const fn trace_edge_bearing(mode: u32) -> bool {
    matches!(mode, 2..=4)
}
/// Cookie-bound scalars; no target handles or arguments. Counters are per CPU.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ApiAggregate {
    pub entries: u64,
    pub success: u64,
    pub failure: u64,
    pub mismatch: u64,
    pub unsupported: u64,
    pub unsupported_return: u64,
    pub map: u64,
    pub depth: u64,
    pub unpaired: u64,
}
/// Pair independently by export cookie; nested wrappers remain separate rows.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ApiThreadKey {
    pub thread: ThreadKey,
    pub cookie: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_mode_words_match_frozen_order() {
        assert_eq!(
            (
                TRACE_MODE_OFF,
                TRACE_MODE_METADATA,
                TRACE_MODE_LATENCY,
                TRACE_MODE_STATUS,
                TRACE_MODE_ALL
            ),
            (0, 1, 2, 3, 4)
        );
        for mode in [0, 1, 5, 6, 100, u32::MAX] {
            assert!(!trace_edge_bearing(mode), "mode {mode}");
        }
        for mode in [2, 3, 4] {
            assert!(trace_edge_bearing(mode), "mode {mode}");
        }
    }

    #[test]
    fn record_wire_layout_is_112_with_seed_at_104() {
        // fix6 (R6-1): exact wire bytes for the A2 rev4 delta —
        // 112 B total, VERSION 5, seed APPENDED at bytes 104..112
        // (every earlier offset unchanged, so the bump is clean
        // under the exact-size + version envelope checks).
        assert_eq!(VERSION, 5);
        assert_eq!(EVENT_SIZE, 112);
        assert_eq!(core::mem::size_of::<Record>(), 112);
        assert_eq!(core::mem::offset_of!(Record, version), 0);
        assert_eq!(core::mem::offset_of!(Record, invocation), 48);
        assert_eq!(core::mem::offset_of!(Record, start_time_ns), 96);
        assert_eq!(core::mem::offset_of!(Record, seed), 104);
    }

    #[test]
    fn enter_none_disposition_pins_max_delete_overflow_insert() {
        // fix6 (R6-4 backstop): the `enter()`-None arm disposition —
        // distinguished by `next == MAX`, NOT by freshness. A MAX
        // row must be DELETED (persisting it wedges every later
        // entry — returns clear only `overflow`); depth-overflow
        // Nones still INSERT (their overflow arms `skip_return`
        // pairing).
        // MAX + fresh → delete (unreachable post-refusal, still deletes).
        let fresh_max = Thread {
            seed: 7,
            next: u64::MAX,
            depth: 0,
            overflow: 0,
            blind: 0,
        };
        assert_eq!(
            enter_none_disposition(fresh_max.next),
            EnterNoneDisposition::Delete
        );
        // MAX + pre-existing → delete (the backstop: a saturated row).
        let old_max = Thread {
            seed: 3,
            next: u64::MAX,
            depth: 2,
            overflow: 0,
            blind: 0,
        };
        assert_eq!(
            enter_none_disposition(old_max.next),
            EnterNoneDisposition::Delete
        );
        // Depth-overflow (MAX_DEPTH breached, overflow armed) → insert.
        let overflow = Thread {
            seed: 3,
            next: 41,
            depth: MAX_DEPTH,
            overflow: 1,
            blind: 0,
        };
        assert_eq!(
            enter_none_disposition(overflow.next),
            EnterNoneDisposition::Insert
        );
        // Normal next (only reachable via depth/overflow) → insert.
        let normal = Thread {
            seed: 3,
            next: 41,
            depth: 1,
            overflow: 0,
            blind: 0,
        };
        assert_eq!(
            enter_none_disposition(normal.next),
            EnterNoneDisposition::Insert
        );
        // Boundary: only EXACT max deletes.
        assert_eq!(
            enter_none_disposition(u64::MAX - 1),
            EnterNoneDisposition::Insert
        );
    }

    /// fix7 F3: host model of the BPF return-path bookkeeping —
    /// a fixed frame stack (the depth-indexed PENDING analog)
    /// driven ONLY through production `Thread` methods, so the
    /// regression pins below go RED if the production rule is
    /// neutered. Single-cookie (the shift needs same-cookie
    /// frames); blind/tombstone calls never pop, so their cookie
    /// is irrelevant to the model.
    struct Fix7Model {
        thread: Thread,
        frames: [u64; MAX_DEPTH as usize],
        emitted: [(u64, u64); MAX_DEPTH as usize],
        emitted_len: usize,
    }
    impl Fix7Model {
        fn new() -> Self {
            Self {
                thread: Thread::default(),
                frames: [0; MAX_DEPTH as usize],
                emitted: [(0, 0); MAX_DEPTH as usize],
                emitted_len: 0,
            }
        }
        /// Frame an entry (production `enter` + PENDING push at
        /// the pre-increment depth).
        fn frame(&mut self) -> u64 {
            let slot = self.thread.depth as usize;
            let inv = self.thread.enter().expect("framed entry");
            self.frames[slot] = inv;
            inv
        }
        /// Overflow an entry (production `enter` → None: no frame).
        fn overflow(&mut self) {
            assert_eq!(self.thread.enter(), None);
        }
        /// Window-rejected entry (production `blind_entry`).
        fn blind_enter(&mut self) {
            self.thread.blind_entry();
        }
        /// Window-rejected return (production `blind_return` —
        /// marker only, never a pop, never an emission).
        /// Returns whether a unit was consumed.
        fn reject(&mut self) -> bool {
            self.thread.blind_return()
        }
        /// Accepted return that MUST skip (overflow owner): pins
        /// skip-true + depth unchanged + no emission.
        fn accept_skip(&mut self) {
            let depth = self.thread.depth;
            assert!(self.thread.skip_return(), "overflow owner must skip");
            assert_eq!(self.thread.depth, depth);
        }
        /// Accepted return of invocation `rv` that MUST pop its
        /// frame; records the (frame, rv) emission.
        fn accept_pop(&mut self, rv: u64) {
            assert!(
                !self.thread.skip_return(),
                "framed return of {rv} must not skip"
            );
            assert!(self.thread.depth > 0);
            self.thread.depth -= 1;
            let frame = self.frames[self.thread.depth as usize];
            self.emitted[self.emitted_len] = (frame, rv);
            self.emitted_len += 1;
        }
        /// Every emission paired its own frame with its own rv.
        fn assert_aligned(&self) {
            for (i, &(frame, rv)) in self.emitted[..self.emitted_len].iter().enumerate() {
                assert_eq!(frame, rv, "emission {i} mislabeled");
            }
        }
    }
    #[test]
    fn fix7_blind_return_resyncs_r73_cascade() {
        // fix7 F3 regression (R7-3): the R7-3 schedule — 8
        // same-cookie framed calls, a nested overflow, the
        // overflow owner's return window-rejected — resyncs ALL 7
        // cascade levels (not 1): the rejected return consumes its
        // own marker, then every framed return pops its own frame
        // with its own rv. (RED pre-fix: 7 mislabels under the
        // consume-nothing rule — quoted in the fix7 report.)
        let mut m = Fix7Model::new();
        let mut invs = [0u64; 8];
        for slot in invs.iter_mut() {
            *slot = m.frame();
        }
        assert_eq!(invs, [1, 2, 3, 4, 5, 6, 7, 8]);
        m.overflow();
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (8, 1, 0)
        );
        assert!(m.reject(), "marker-owner's rejected return consumes");
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        for rv in invs.iter().rev() {
            m.accept_pop(*rv);
        }
        assert_eq!(m.emitted_len, 8);
        m.assert_aligned();
        assert_eq!(
            m.emitted,
            [
                (8, 8),
                (7, 7),
                (6, 6),
                (5, 5),
                (4, 4),
                (3, 3),
                (2, 2),
                (1, 1)
            ]
        );
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
    }
    #[test]
    fn fix7_blind_entry_keeps_entry_rejected_returns_from_stealing() {
        // fix7 F3 regression (R7-3 soundness): the mirror shape an
        // unconditional consume-on-reject would BREAK — a
        // same-cookie overflow owner X with a window-rejected
        // operational call E nested inside it. E's return consumes
        // its OWN tombstone (outer marker survives); X's accepted
        // return then skips its own marker; frames pop own. Every
        // return consumes exactly its owned unit.
        let mut m = Fix7Model::new();
        for _ in 0..8 {
            m.frame();
        }
        m.overflow();
        m.blind_enter();
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 1));
        assert!(m.reject(), "nothing-owner consumes its tombstone");
        assert_eq!(
            (m.thread.overflow, m.thread.blind),
            (1, 0),
            "the outer marker must survive E's return"
        );
        m.accept_skip();
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        for rv in (1..=8u64).rev() {
            m.accept_pop(rv);
        }
        m.assert_aligned();
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
    }
    #[test]
    fn fix7_normal_overflow_skip_unchanged() {
        // fix7 F3 no-change pin (R7-3): plain overflow with NO
        // rejection behaves exactly as before — the overflow
        // owner's accepted return skips, framed returns pop own,
        // `blind` stays 0 throughout (never armed, never read).
        let mut m = Fix7Model::new();
        for _ in 0..8 {
            m.frame();
        }
        m.overflow();
        assert_eq!(m.thread.blind, 0);
        m.accept_skip();
        assert_eq!(m.thread.blind, 0);
        for rv in (1..=8u64).rev() {
            m.accept_pop(rv);
        }
        m.assert_aligned();
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
    }
    #[test]
    fn fix7_same_cookie_nesting_unchanged() {
        // fix7 F3 no-change pin (R7-3): 8-deep same-cookie nesting
        // with no overflow and no rejection — strict LIFO pops,
        // `blind` never armed.
        let mut m = Fix7Model::new();
        for _ in 0..8 {
            m.frame();
        }
        assert_eq!(m.thread.blind, 0);
        for rv in (1..=8u64).rev() {
            m.accept_pop(rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
    }
    #[test]
    fn fix7_mixed_tombstone_and_marker_balances_fungibly() {
        // fix7 F3 defense-in-depth (R7-3): T-outer/O-inner is
        // UNREACHABLE under the never-reopen window (it would need
        // a closed-entry before an open-entry), but even there
        // counts balance: the inner marker-owner's rejected return
        // takes the tombstone, the outer nothing-owner's takes the
        // marker — two rejected returns, two units, frames pop own.
        let mut m = Fix7Model::new();
        for _ in 0..8 {
            m.frame();
        }
        m.blind_enter();
        m.overflow();
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 1));
        assert!(m.reject());
        assert!(m.reject());
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        for rv in (1..=8u64).rev() {
            m.accept_pop(rv);
        }
        m.assert_aligned();
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
    }
    #[test]
    fn fix7_blind_counter_units() {
        // fix7 F3 unit pins (R7-3): empty reject consumes nothing;
        // skip ignores blind; tombstones nest; saturation holds.
        let mut t = Thread::default();
        assert!(!t.blind_return());
        assert_eq!((t.overflow, t.blind), (0, 0));
        t.blind_entry();
        t.blind_entry();
        for _ in 0..8 {
            assert!(t.enter().is_some());
        }
        assert_eq!(t.enter(), None);
        assert_eq!((t.overflow, t.blind), (1, 2));
        assert!(t.skip_return(), "accepted skip reads overflow only");
        assert_eq!((t.overflow, t.blind), (0, 2));
        assert!(t.blind_return());
        assert_eq!((t.overflow, t.blind), (0, 1));
        assert!(t.blind_return());
        assert_eq!((t.overflow, t.blind), (0, 0));
        assert!(!t.blind_return());
        t.blind = u32::MAX;
        t.blind_entry();
        assert_eq!(t.blind, u32::MAX, "tombstones saturate, never wrap");
    }
    #[test]
    fn thread_value_is_32_with_blind_at_24() {
        // fix6 (R6-1): THREADS/API_THREADS value 16→24 B, seed
        // APPENDED (existing field offsets unchanged). fix7 (R7-3):
        // 24→32 B, blind APPENDED after seed (all existing offsets
        // unchanged). The loader `specs()` mirrors these sizes
        // exactly.
        assert_eq!(core::mem::size_of::<Thread>(), 32);
        assert_eq!(core::mem::offset_of!(Thread, next), 0);
        assert_eq!(core::mem::offset_of!(Thread, depth), 8);
        assert_eq!(core::mem::offset_of!(Thread, overflow), 12);
        assert_eq!(core::mem::offset_of!(Thread, seed), 16);
        assert_eq!(core::mem::offset_of!(Thread, blind), 24);
    }
}
