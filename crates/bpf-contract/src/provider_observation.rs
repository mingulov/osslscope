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
    /// identity, closed window — the call executes unobserved).
    /// fix8 (R8-2): this counter is now the FALLBACK — blind
    /// entries slot a positional T-marker first and arm a
    /// tombstone (`blind_entry`) only on marker refusal
    /// (collision, quota, map). fix7's "returns will
    /// execute-but-reject" does NOT hold under longjmp (the kernel
    /// discards the skipped uretprobe instance — the return never
    /// runs — orphaning a fungible tombstone for the next rejected
    /// return to eat, which recurs the cascade); slotted markers
    /// are discarded instead (never shifting frames). Slotted
    /// returns pop their own slot and never touch this counter;
    /// counter-owned rejected returns consume T-first
    /// (`blind_return`); ACCEPTED returns never touch it (an
    /// accepted return provably owns no blind unit — its entry
    /// was accepted and the window never reopens).
    ///
    /// WHY a separate counter rather than the naive "rejected
    /// returns consume overflow": a window-rejected return either
    /// OWNS an overflow unit (its entry was accepted, then
    /// overflowed — the R7-3 shape — and must consume) or OWNS a
    /// blind unit (its entry was window-rejected — and must not
    /// consume the overflow unit, else it steals a same-cookie
    /// overflow owner's unit and shifts the cascade the other
    /// way). Entry-time window state is lost by return time, so
    /// the entry records its kind here. `API_THREADS` rows carry
    /// a vestigial 0 (blind is armed only on the shared trace
    /// machine's closed-window entries).
    pub blind: u32,
}
/// fix8 (R8-2): `PendingKey.reserved` slot kind. Frames keep 0
/// (every pre-fix key); overflow/blind markers take 1/2. Lateral
/// same-level O+T markers never collide (kind-selected pops); a
/// second same-kind marker at one level falls back to the fungible
/// counter (NOEXIST refusal — the old behavior, still correct for
/// counter-owned returns). Key layout UNCHANGED (24 B).
pub const PENDING_FRAME: u32 = 0;
pub const PENDING_OVERFLOW_MARKER: u32 = 1;
pub const PENDING_BLIND_MARKER: u32 = 2;
/// fix8 (R8-2): `Pending.suppressed` marker value. Frames use
/// 0/1 (emit/suppress); markers always suppress AND are keyed by
/// kind, so the pop path branches on the key, never this value.
/// Value layout UNCHANGED (56 B).
pub const MARKER_SUPPRESSED: u32 = 2;
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
impl Pending {
    /// fix8 (R8-2): a positional suppress-marker for an entry that
    /// owns no frame (overflow) or no observation (closed window).
    /// Carries the OWNER cookie (the pop path matches returns to
    /// their own slot by it) and consumes no invocation. Popping a
    /// marker suppresses exactly one return and realigns the stack —
    /// a longjmp'd marker is discarded by the next outer return
    /// (availability), never shifting frames (no cascade).
    pub fn marker(cookie: u64) -> Self {
        Self {
            cookie,
            suppressed: MARKER_SUPPRESSED,
            ..Self::default()
        }
    }
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
    /// fix8 (R8-2): pure frame attempt for the trace machine —
    /// wounds depth and mints an invocation, or refuses WITHOUT
    /// arming any counter (the caller slots an overflow marker or
    /// falls back to the fungible counter). Refusal conditions are
    /// exactly `enter`'s (depth cap, sticky overflow, exhausted
    /// invocations); only the counter side effect moves to the
    /// caller. BPF-safe (no allocation).
    pub fn enter_frame(&mut self) -> Option<u64> {
        if self.depth >= MAX_DEPTH || self.overflow != 0 {
            return None;
        }
        if self.next == u64::MAX {
            return None;
        }
        self.next += 1;
        self.depth += 1;
        Some(self.next)
    }
    pub fn enter(&mut self) -> Option<u64> {
        match self.enter_frame() {
            Some(invocation) => Some(invocation),
            None => {
                self.overflow = self.overflow.saturating_add(1);
                None
            }
        }
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
    /// RESULTs). fix8 (R8-2): slotted returns pop their own slot
    /// (positional, skip-safe) and reach here only when they own
    /// no slot (marker refusal fell back to the fungible
    /// counter); the aggregate machine still pairs purely through
    /// here. Accepted behavior is unchanged.
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
    /// so the executing call owns no frame and no overflow unit —
    /// and its return (if it executes — longjmp can skip it, R8-2)
    /// must then consume exactly this tombstone rather than
    /// stealing an outer overflow unit. fix8: called only on
    /// T-marker refusal (the slotted marker is the primary arm).
    /// Saturating (2^32 nested blind calls is unreachable —
    /// bounded by thread stack depth).
    pub fn blind_entry(&mut self) {
        self.blind = self.blind.saturating_add(1);
    }
    /// Consume one unit for a WINDOW-REJECTED return (resolved
    /// identity, closed window): its own blind tombstone first,
    /// else one overflow marker. fix8 (R8-2): slotted returns pop
    /// their own slot instead and reach here only when they own
    /// no slot (marker refusal fell back to the fungible
    /// counter). Returns whether a unit was consumed. Rejections
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
/// fix8 (R8-2): non-MAX Nones slot a positional overflow marker
/// first and (re)insert the row only on marker refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnterNoneDisposition {
    /// Delete the row (a `next == MAX` row would wedge every
    /// later entry — returns clear only `overflow`).
    Delete,
    /// Slot an overflow marker, else (re)insert the row
    /// (marker-refused Nones need their overflow to arm
    /// `skip_return` pairing).
    Insert,
}

/// Pure disposition for the `enter()`-None arm: delete iff
/// `next == MAX`. Distinguished by the counter value, NOT by
/// row freshness (a fresh MAX row and a pre-existing MAX row
/// both delete; depth-overflow and normal rows both take the
/// marker-first arm, inserting only on marker refusal).
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
    /// is irrelevant to the model. fix8: this pins the COUNTER
    /// semantics (aggregate machine + counter-fallback arms —
    /// unchanged); the trace machine's positional pop path is
    /// pinned by `Fix8Model` below.
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
    /// fix8 F2: host model of the BPF return-path bookkeeping WITH
    /// skipped returns (the fix7 model's gap — "all returns execute"
    /// is exactly what longjmp violates) and positional marker
    /// slots (`find_mine` + `discard_deeper` + pop, mirrored block
    /// for block — see the BPF≡model correspondence in the fix8
    /// report). Every entry arms exactly one unit (frame slot,
    /// marker slot, or fungible counter); every executed return
    /// pops its own slot (fast path: own frame; slow path: deepest
    /// mine after discarding deeper stale slots) or consumes its
    /// counter unit. `skip()` documents a longjmp'd return (kernel
    /// discards the uretprobe instance — the return NEVER runs,
    /// consuming nothing).
    struct Fix8Model {
        thread: Thread,
        frames: [Option<(u64, u64)>; 9],
        omarks: [Option<u64>; 9],
        tmarks: [Option<u64>; 9],
        emitted: [(u64, u64); MAX_DEPTH as usize],
        emitted_len: usize,
        suppressed: u32,
        discarded: u32,
        quota_fail: bool,
        force_counter: bool,
    }
    impl Fix8Model {
        fn new() -> Self {
            Self {
                thread: Thread::default(),
                frames: [None; 9],
                omarks: [None; 9],
                tmarks: [None; 9],
                emitted: [(0, 0); MAX_DEPTH as usize],
                emitted_len: 0,
                suppressed: 0,
                discarded: 0,
                quota_fail: false,
                force_counter: false,
            }
        }
        /// Framed entry: production `enter_frame` + frame slot.
        fn frame(&mut self, cookie: u64) -> u64 {
            let slot = self.thread.depth as usize;
            let inv = self.thread.enter_frame().expect("framed entry");
            assert!(self.frames[slot].is_none(), "frame slot collision");
            self.frames[slot] = Some((cookie, inv));
            inv
        }
        /// Overflow entry: refused frame, then an O-marker slot at
        /// the current depth — or the fungible counter on marker
        /// refusal (collision/quota/neuter), mirroring the BPF
        /// None arm exactly.
        fn overflow(&mut self, cookie: u64) {
            assert_eq!(self.thread.enter_frame(), None, "must refuse a frame");
            let slot = self.thread.depth as usize;
            if !self.force_counter && !self.quota_fail && self.omarks[slot].is_none() {
                self.omarks[slot] = Some(cookie);
            } else {
                self.thread.overflow = self.thread.overflow.saturating_add(1);
            }
        }
        /// Closed-window entry: a T-marker slot at the current
        /// depth — or the fungible tombstone on marker refusal,
        /// mirroring `blind_arm_entry` exactly.
        fn blind_enter(&mut self, cookie: u64) {
            let slot = self.thread.depth as usize;
            if !self.force_counter && !self.quota_fail && self.tmarks[slot].is_none() {
                self.tmarks[slot] = Some(cookie);
            } else {
                self.thread.blind_entry();
            }
        }
        /// A longjmp'd return: never executes, consumes nothing.
        fn skip(&mut self) {}
        /// Deepest slot owned by `cookie` (level, kind 0/1/2):
        /// levels deep→shallow; within a level frame, then T
        /// (rejected only), then O — mirroring `find_mine`.
        fn find_mine(&self, cookie: u64, include_t: bool) -> Option<(usize, u32)> {
            let top = (self.thread.depth as usize).min(MAX_DEPTH as usize);
            for level in (0..=top).rev() {
                if let Some((owner, _)) = self.frames[level] {
                    if owner == cookie {
                        return Some((level, PENDING_FRAME));
                    }
                }
                if include_t && self.tmarks[level] == Some(cookie) {
                    return Some((level, PENDING_BLIND_MARKER));
                }
                if self.omarks[level] == Some(cookie) {
                    return Some((level, PENDING_OVERFLOW_MARKER));
                }
            }
            None
        }
        /// Discard slots strictly deeper than `mine` (all kinds —
        /// mirroring `discard_deeper` with include_t=1).
        fn discard_deeper(&mut self, mine: usize) {
            let top = (self.thread.depth as usize).min(MAX_DEPTH as usize);
            for level in (mine + 1..=top).rev() {
                if self.frames[level].take().is_some() {
                    self.thread.depth = self.thread.depth.saturating_sub(1);
                    self.discarded += 1;
                }
                if self.tmarks[level].take().is_some() {
                    self.discarded += 1;
                }
                if self.omarks[level].take().is_some() {
                    self.discarded += 1;
                }
            }
        }
        /// Accepted return of `cookie` (rv observed on emit):
        /// fast-path own frame, else slow search (T excluded),
        /// else the overflow counter — mirroring `pop_return`'s
        /// accepted arm exactly.
        fn marker_at(&self, level: usize) -> bool {
            self.omarks[level].is_some() || self.tmarks[level].is_some()
        }
        fn return_accept(&mut self, cookie: u64, rv: u64) {
            if self.thread.depth > 0 {
                let slot = self.thread.depth as usize - 1;
                if let Some((owner, inv)) = self.frames[slot] {
                    if owner == cookie && !self.marker_at(self.thread.depth as usize) {
                        self.frames[slot] = None;
                        self.thread.depth -= 1;
                        self.emitted[self.emitted_len] = (inv, rv);
                        self.emitted_len += 1;
                        return;
                    }
                }
            }
            if let Some((mine, kind)) = self.find_mine(cookie, false) {
                self.discard_deeper(mine);
                if kind == PENDING_FRAME {
                    let (_, inv) = self.frames[mine].take().unwrap();
                    self.thread.depth = self.thread.depth.saturating_sub(1);
                    self.emitted[self.emitted_len] = (inv, rv);
                    self.emitted_len += 1;
                } else {
                    assert_eq!(kind, PENDING_OVERFLOW_MARKER);
                    self.omarks[mine] = None;
                    self.suppressed += 1;
                }
                return;
            }
            assert!(self.thread.skip_return(), "counter-owned accepted return");
        }
        /// Window-rejected return of `cookie`: fast-path own frame
        /// (popped, suppressed), else slow search (all kinds),
        /// else the T-first counter — mirroring `pop_return`'s
        /// rejected arm exactly. Never emits.
        fn return_reject(&mut self, cookie: u64) -> bool {
            if self.thread.depth > 0 {
                let slot = self.thread.depth as usize - 1;
                if let Some((owner, _)) = self.frames[slot] {
                    if owner == cookie && !self.marker_at(self.thread.depth as usize) {
                        self.frames[slot] = None;
                        self.thread.depth -= 1;
                        return true;
                    }
                }
            }
            if let Some((mine, kind)) = self.find_mine(cookie, true) {
                self.discard_deeper(mine);
                if kind == PENDING_FRAME {
                    self.frames[mine] = None;
                    self.thread.depth = self.thread.depth.saturating_sub(1);
                } else if kind == PENDING_BLIND_MARKER {
                    self.tmarks[mine] = None;
                    self.suppressed += 1;
                } else {
                    self.omarks[mine] = None;
                    self.suppressed += 1;
                }
                return true;
            }
            // No slot of mine: the T-first counter (fix7 residual);
            // a unit-less return consumes nothing (BPF: silent).
            self.thread.blind_return()
        }
        /// Every emission paired its own frame with its own rv.
        fn assert_aligned(&self) {
            for (i, &(frame, rv)) in self.emitted[..self.emitted_len].iter().enumerate() {
                assert_eq!(frame, rv, "emission {i} mislabeled");
            }
        }
        fn assert_quiescent(&self) {
            assert_eq!(
                (self.thread.depth, self.thread.overflow, self.thread.blind),
                (0, 0, 0)
            );
            assert!(self.frames.iter().all(|slot| slot.is_none()));
            assert!(self.omarks.iter().all(|slot| slot.is_none()));
            assert!(self.tmarks.iter().all(|slot| slot.is_none()));
        }
    }
    #[test]
    fn fix8_longjmp_skip_stays_aligned() {
        // fix8 F2 GREEN (R8-2 — the realizable mixed-cookie shape:
        // non-operational A-frames, operational overflow B +
        // blind C): C longjmps; B's rejected return discards C's
        // stale T-marker and pops its own O-marker; every A pops
        // its own frame. (RED pre-fix: this schedule asserted the
        // exact [(8,7)..(2,1)] cascade — quoted in the fix8 report.)
        const A: u64 = 0xA11CE;
        const B: u64 = 0xB00B;
        const C: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        let mut invs = [0u64; 8];
        for slot in invs.iter_mut() {
            *slot = m.frame(A);
        }
        assert_eq!(invs, [1, 2, 3, 4, 5, 6, 7, 8]);
        m.overflow(B);
        m.blind_enter(C);
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (8, 0, 0),
            "both markers slotted, counters untouched"
        );
        m.skip();
        m.return_reject(B);
        // B pops its own lateral O; C's stale lateral T waits (a
        // lateral slot is never discarded — it may be outer-live).
        assert_eq!((m.suppressed, m.discarded), (1, 0));
        m.return_accept(A, 8);
        // A8's return reaps the now-deeper stale T, then pops own.
        assert_eq!((m.suppressed, m.discarded), (1, 1));
        for rv in invs[..7].iter().rev() {
            m.return_accept(A, *rv);
        }
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
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_r73_marker_owner_reject_resyncs() {
        // fix8 F2 (R7-3 via markers): the overflow owner's rejected
        // return pops its own O-marker; frames pop own. No skip,
        // no tombstone, full-cascade resync preserved.
        const A: u64 = 0xA11CE;
        const B: u64 = 0xB00B;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.overflow(B);
        m.return_reject(B);
        assert_eq!((m.suppressed, m.discarded), (1, 0));
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        m.assert_quiescent();
    }
    #[test]
    fn fix8_mirror_blind_nested_in_overflow() {
        // fix8 F2 (mirror via lateral markers): X's O-marker and
        // E's T-marker share level 8; E's rejected return pops its
        // own T (the lateral O survives); X's accepted return pops
        // its own O; frames pop own.
        const A: u64 = 0xA11CE;
        const X: u64 = 0xB00B;
        const E: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.overflow(X);
        m.blind_enter(E);
        m.return_reject(E);
        assert_eq!((m.suppressed, m.discarded), (1, 0));
        m.return_accept(X, 0);
        assert_eq!((m.suppressed, m.discarded), (2, 0));
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_mirror_flip_overflow_nested_in_blind() {
        // fix8 F2 (lateral tie, both orders): E's T-marker outer,
        // X's O-marker inner at one level. X returns first (LIFO
        // execution) — accepted AND rejected variants — and must
        // pop its own O without touching E's lateral T; E then pops
        // its own T. (E-then-X placement is reverse-temporal under
        // the global never-reopening window — E-blind means post-end,
        // X-open means inside, so X's entry came first — pinned here
        // as lateral-isolation characterization, not a realizable
        // schedule.)
        const A: u64 = 0xA11CE;
        const X: u64 = 0xB00B;
        const E: u64 = 0xC10C;
        for rejected in [false, true] {
            let mut m = Fix8Model::new();
            for _ in 0..8 {
                m.frame(A);
            }
            m.blind_enter(E);
            m.overflow(X);
            if rejected {
                m.return_reject(X);
            } else {
                m.return_accept(X, 0);
            }
            assert!(m.tmarks[8].is_some(), "rejected={rejected}: E's T survives");
            m.return_reject(E);
            for rv in (1..=8u64).rev() {
                m.return_accept(A, rv);
            }
            m.assert_aligned();
            m.assert_quiescent();
        }
    }
    #[test]
    fn fix8_same_cookie_skip_still_cascades_impossibility() {
        // fix8 F2 impossibility pin (R8-2): the SAME schedule with
        // ONE cookie still cascades [(8,7)..(2,1)] — PROVABLY
        // unfixable (same-cookie return events are ambiguous: B's
        // return and C's return are the identical observation, so
        // no deterministic rule pops correctly in both the skip and
        // no-skip worlds). Unrealizable for the R8-2 mixed
        // reject/accept shape (never-reopen forbids it); pinned so
        // the boundary stays documented, not so it stays broken by
        // accident. The mechanism degrades exactly to the old
        // cascade here — no worse.
        const S: u64 = 0x5A4E;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S);
        m.blind_enter(S);
        m.skip();
        m.return_reject(S);
        // Eight returns: the first pops B's orphaned O (suppressing
        // A8's RESULT), then every pop shifts by one.
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [(8, 7), (7, 6), (6, 5), (5, 4), (4, 3), (3, 2), (2, 1)]
        );
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (1, 0, 0)
        );
    }
    #[test]
    fn fix8_same_cookie_r73_and_mirror_unchanged() {
        // fix8 F2 no-skip pins (TRULY single-cookie R7-3 + mirror,
        // the fix7 model shapes ported to markers): both align —
        // LIFO order carries them (the marker owner returns first
        // and the fast path stands down while markers sit deep).
        const S: u64 = 0x5A4E;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S);
        m.return_reject(S);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S);
        m.blind_enter(S);
        m.return_reject(S);
        m.return_accept(S, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_normal_overflow_and_nesting_unchanged() {
        // fix8 F2 no-change pins (R7-3): plain overflow with NO
        // rejection pops its O-marker (replacing the accepted
        // skip — same observable); 8-deep nesting pops LIFO;
        // `blind` never armed in either.
        const A: u64 = 0xA11CE;
        const X: u64 = 0xB00B;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.overflow(X);
        assert_eq!(m.thread.blind, 0);
        m.return_accept(X, 0);
        assert_eq!((m.suppressed, m.discarded), (1, 0));
        assert_eq!(m.thread.blind, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        assert_eq!(m.thread.blind, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        m.assert_quiescent();
    }
    #[test]
    fn fix8_counter_fallback_collision_stays_aligned() {
        // fix8 F2 (same-kind same-level collision → fungible
        // counter): Y's O collides with X's slotted O (Y owns a
        // counter unit); Y's accepted return consumes it; X pops
        // its slot; frames pop own. T-collision mirrors it.
        const A: u64 = 0xA11CE;
        const X: u64 = 0xB00B;
        const Y: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.overflow(X);
        m.overflow(Y);
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 0));
        m.return_accept(Y, 0);
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        m.return_accept(X, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        const E: u64 = 0xE11E;
        const F: u64 = 0xF11F;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.blind_enter(E);
        m.blind_enter(F);
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 1));
        assert!(m.return_reject(F));
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        assert!(m.return_reject(E));
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_counter_skip_heals_without_cascade() {
        // fix8 F2 (S2 shape): R1 owns a refused counter unit with
        // a slotted blind C nested inside; C skips; R1's rejected
        // return consumes its unit (C's stale slot waits); the next
        // outer return discards C and pops own. Counter-skips heal
        // (slotted pops bypass counters entirely) — strictly better
        // than the old fungible eating, which cascaded here.
        const A: u64 = 0xA11CE;
        const R1: u64 = 0xB00B;
        const C: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.quota_fail = true;
        m.overflow(R1);
        m.quota_fail = false;
        assert_eq!(m.thread.overflow, 1);
        m.blind_enter(C);
        m.skip();
        assert!(m.return_reject(R1));
        assert_eq!(m.thread.overflow, 0);
        assert!(m.tmarks[8].is_some(), "C's stale slot waits");
        m.return_accept(A, 8);
        assert_eq!(m.discarded, 1);
        for rv in (1..=7u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_quota_refusal_falls_back_to_counters() {
        // fix8 F2 (quota exhaustion → fungible counters): refused
        // markers arm exactly the old units; owned returns consume
        // them; frames pop own. Graceful degradation, still
        // aligned.
        const A: u64 = 0xA11CE;
        const B: u64 = 0xB00B;
        const C: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.quota_fail = true;
        m.overflow(B);
        m.blind_enter(C);
        m.quota_fail = false;
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 1));
        assert!(m.return_reject(C));
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 0));
        assert!(m.return_reject(B));
        assert_eq!((m.thread.overflow, m.thread.blind), (0, 0));
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_rejected_frame_pops_suppressed() {
        // fix8 F2 (straddling close): a framed call whose return is
        // window-rejected pops its frame WITHOUT emitting (slot
        // hygiene — pre-fix the frame leaked). A foreign-cookie
        // reject consumes nothing and disturbs nothing. The outer
        // frames pop own.
        const A: u64 = 0xA11CE;
        const B: u64 = 0xB00B;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        assert!(m.return_reject(A));
        assert_eq!(m.emitted_len, 0, "rejected pops never emit");
        assert_eq!(m.thread.depth, 7);
        assert!(!m.return_reject(B), "foreign reject consumes nothing");
        assert_eq!(m.thread.depth, 7);
        for rv in (1..=7u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn fix8_neuter_counter_only_cascades_same_cookie() {
        // fix8 F2 neuter (N2-analog): with markers disabled, the
        // SAME-cookie overflow shape cascades — the fast path pops
        // the outer frame for the marker-owner's return and every
        // later pop shifts. The positional mechanism (not the
        // tests) carries the fix.
        const S: u64 = 0x5A4E;
        let mut m = Fix8Model::new();
        m.force_counter = true;
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S);
        assert_eq!((m.thread.overflow, m.thread.blind), (1, 0));
        m.return_accept(S, 100);
        for rv in (3..=8u64).rev() {
            m.return_accept(S, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [(8, 100), (7, 8), (6, 7), (5, 6), (4, 5), (3, 4), (2, 3)]
        );
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (1, 1, 0),
            "A1's frame leaks and X's unit orphans"
        );
    }
    #[test]
    fn fix8_neuter_skip_first_order_misattributes_mixed_slots() {
        // fix8 F2 design neuter (order): the OLD skip-first
        // accepted order eats a counter unit even when the
        // returning call owns a slot — here F2's return consumes
        // R1's unit and orphans its own O-slot. The positional
        // bypass (slots before counters) exists for exactly this
        // mix; with it, both consume own (pinned above).
        const A: u64 = 0xA11CE;
        const R1: u64 = 0xB00B;
        const F2: u64 = 0xF222;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.quota_fail = true;
        m.overflow(R1);
        m.quota_fail = false;
        m.overflow(F2);
        assert_eq!(m.thread.overflow, 1);
        assert!(m.thread.skip_return(), "skip-first eats R1's unit");
        assert!(m.omarks[8].is_some(), "F2's own slot orphans");
        assert_eq!(m.thread.overflow, 0);
    }
    #[test]
    fn fix8_enter_frame_refuses_cleanly_and_enter_matches() {
        // fix8 F2 units (R8-2): `enter_frame` wounds+mints on
        // success and touches NOTHING on refusal (depth cap,
        // sticky overflow, exhausted invocations); `enter` is
        // exactly `enter_frame` + bump-on-None (aggregate-machine
        // behavior unchanged — differential over a state grid).
        let mut t = Thread::default();
        assert_eq!(t.enter_frame(), Some(1));
        assert_eq!((t.next, t.depth, t.overflow), (1, 1, 0));
        for grid in 0..9u32 {
            for overflow in [0u32, 1, u32::MAX] {
                for next in [0u64, 41, u64::MAX - 1, u64::MAX] {
                    let mut a = Thread {
                        next,
                        depth: grid,
                        overflow,
                        seed: 3,
                        blind: 0,
                    };
                    let mut b = a;
                    let frame = a.enter_frame();
                    let classic = b.enter();
                    assert_eq!(frame, classic, "grid={grid} o={overflow} next={next}");
                    assert_eq!((a.next, a.depth), (b.next, b.depth));
                    match frame {
                        Some(_) => {
                            assert_eq!(a.overflow, overflow, "success bumps nothing");
                            assert_eq!(b.overflow, overflow);
                        }
                        None => {
                            assert_eq!(a.overflow, overflow, "refusal arms nothing");
                            assert_eq!(b.overflow, overflow.saturating_add(1));
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn fix8_marker_slots_reuse_layouts() {
        // fix8 F2 units (R8-2): marker kinds reuse the frozen
        // layouts — frames keep key 0, markers take 1/2; marker
        // values suppress and carry the owner cookie with no
        // invocation. NO map-layout change (specs untouched).
        assert_eq!(
            (PENDING_FRAME, PENDING_OVERFLOW_MARKER, PENDING_BLIND_MARKER),
            (0, 1, 2)
        );
        assert_eq!(MARKER_SUPPRESSED, 2);
        let marker = Pending::marker(0xC00E);
        assert_eq!(marker.cookie, 0xC00E);
        assert_eq!(marker.suppressed, MARKER_SUPPRESSED);
        assert_eq!(marker.invocation, 0);
        assert_eq!(core::mem::size_of::<Pending>(), 56);
        assert_eq!(core::mem::size_of::<PendingKey>(), 24);
        assert_eq!(core::mem::offset_of!(PendingKey, reserved), 20);
        assert_eq!(core::mem::size_of::<Thread>(), 32);
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
