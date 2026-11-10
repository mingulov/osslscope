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
    /// Bounded owner stack for the fungible `overflow` counter
    /// (round-6 1a, REPLACING the R10 1b single-owner record —
    /// R11-P2-1 proved a mixed-cookie arm must not clear
    /// ownership: after one unit settles, the remainder's owner
    /// is still known from arm ORDER, and slot-first on unknown
    /// reopens the balanced hijack with no skip). The stack keeps
    /// the FIRST (bottom: `counter_owner`/`counter_related`) and
    /// LATEST (top: `counter_owner2`/`counter_related2`) arming
    /// owners; `counter_len` is 0/1/2 (no sentinel cookie: the
    /// length — never an owner value — gates every read, so
    /// `Default`/`API_THREADS` rows are unknown, never
    /// owned-by-0). Only the TOP owner's return may consume
    /// before popping (`counter_owned_by`); every other return
    /// pops its own slot first (`d7c431a` order) — in balanced
    /// LIFO the top entry is exactly the innermost outstanding
    /// unit owner's, so top-match is exact there.
    ///
    /// Recording (entry fallback arms, AFTER the `overflow`
    /// bump): len 0→1 pushes the bottom; len 1→2 pushes the top
    /// (same-cookie duplicates kept — order, not identity, is
    /// the disambiguator); a len-2 arm REPLACES the top, keeps
    /// the bottom, and bumps `counter_evicted` (middle eviction:
    /// the saturating arm's owner is the most likely next
    /// settler under LIFO; the bottom is the most likely
    /// survivor after settles). A drain to 0 clears all six
    /// words (clear-at-zero — a later arm re-records). An
    /// O-marker removal (pop or discard, either return arm)
    /// drops RELATED entries only, compacting survivors (the
    /// round-3 lifetime lesson scoped per entry: a related
    /// entry's evidence died with its marker; round-5 N2: an
    /// unrelated entry references no marker and survives).
    /// T-marker and frame removals never retire. `API_THREADS`
    /// rows carry vestigial 0s (classic `enter` never records;
    /// the aggregate path consumes through `skip_return`
    /// without consulting the record).
    ///
    /// Saturation (documented residual — a NAMED PINNED
    /// limitation, an explicit coverage trade, NOT a proven
    /// necessity or minimality result): an evicted middle owner
    /// falls back to slot-first and may hijack on a same-cookie
    /// slot collision (K+1 arms with a same-cookie top collision
    /// reach identical Thread+PENDING bytes with conflicting
    /// consume/pop mandates — the generalized round-3 identity
    /// construction — so exact reconstruction is unachievable
    /// there; it does NOT prove strict fail-closed saturation
    /// impossible for finite depth — see the Amendment 6D-A2
    /// saturation residual). Every distinct-cookie world is
    /// served exactly; every residual hole needs same-cookie
    /// ambiguity (the R11-accepted b3/b4 class). Eviction is
    /// detectable (`counter_evicted`, cleared only at drain).
    pub counter_len: u32,
    /// Bottom (first-arm) owner cookie (meaningful only when
    /// `counter_len` ≥ 1; always cleared together with it — no
    /// stale owner is ever observable).
    pub counter_owner: u64,
    /// Marker-relatedness for the bottom entry (round-5 N2,
    /// per entry): 1 iff that arm observed a live O-marker at
    /// the arm level. Only a related entry retires on O-marker
    /// removal. There is no WHICH-marker ambiguity: all live
    /// related entries share one reference marker (two would
    /// need depth at two levels at once — round-5 (iii)), so
    /// any O-removal is the reference itself or follows its
    /// discard in the same op, and retiring is exact.
    pub counter_related: u32,
    /// Top (latest-arm) owner cookie (meaningful only when
    /// `counter_len` is 2; a saturating arm replaces it and
    /// bumps `counter_evicted` below).
    pub counter_owner2: u64,
    /// Marker-relatedness for the top entry (same rule as the
    /// bottom entry above, probed at the top entry's own arm).
    pub counter_related2: u32,
    /// Middle-eviction count: arm-time replacements of the top
    /// entry while `counter_len` was 2 (saturating arms). The
    /// forgotten middles stay outstanding-but-unknown. Cleared
    /// only by clear-at-zero (never by retire/settle — it is
    /// history, and retire/settle drops are visible in the
    /// length transitions). Observability only: no rule reads
    /// it.
    pub counter_evicted: u32,
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
    /// Record one overflow fallback arm by `cookie` (round-6
    /// 1a): call AFTER the `overflow` bump, at every site that
    /// arms the fungible counter (entry None arm, both
    /// `failed_entry` arms). Len 0→1 pushes the bottom entry;
    /// len 1→2 pushes the top entry (same-cookie duplicates are
    /// kept — ORDER, not identity, disambiguates); a len-2 arm
    /// REPLACES the top, keeps the bottom, and bumps
    /// `counter_evicted` (middle eviction — the saturating
    /// armer settles next under LIFO; the bottom survives
    /// settles). Relatedness comes from `marker_live` (round-5
    /// N2: whether a live O-marker occupies the arm level —
    /// probed by the caller), per entry. BPF-safe (no
    /// allocation).
    pub fn record_counter_owner(&mut self, cookie: u64, marker_live: bool) {
        if self.counter_len == 0 {
            self.counter_owner = cookie;
            self.counter_related = u32::from(marker_live);
            self.counter_len = 1;
        } else if self.counter_len == 1 {
            self.counter_owner2 = cookie;
            self.counter_related2 = u32::from(marker_live);
            self.counter_len = 2;
        } else {
            // Saturating arm: the middle is forgotten (its owner
            // falls back to slot-first — documented residual),
            // the latest armer takes the top.
            self.counter_owner2 = cookie;
            self.counter_related2 = u32::from(marker_live);
            self.counter_evicted = self.counter_evicted.saturating_add(1);
        }
    }
    /// Retire counter-owner entries (R10 1b, scoped per entry by
    /// round-5 N2, extended to the stack by round-6 1a): call
    /// when an O-marker is REMOVED (pop or discard, either
    /// return arm). A marker-RELATED entry's reference marker
    /// is gone — applying it to a later marker is the finding-1
    /// staleness — so drop every related entry, compacting
    /// survivors (no stale owner stays observable). A
    /// marker-UNRELATED entry (quota/map arm with the level
    /// free) references no marker and survives. BPF-safe.
    pub fn retire_counter_owner(&mut self) {
        if self.counter_len == 2 {
            let top_related = self.counter_related2 != 0;
            let bottom_related = self.counter_related != 0;
            if top_related && bottom_related {
                self.counter_owner = 0;
                self.counter_related = 0;
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_len = 0;
            } else if top_related {
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_len = 1;
            } else if bottom_related {
                self.counter_owner = self.counter_owner2;
                self.counter_related = self.counter_related2;
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_len = 1;
            }
        } else if self.counter_len == 1 && self.counter_related != 0 {
            self.counter_owner = 0;
            self.counter_related = 0;
            self.counter_len = 0;
        }
    }
    /// Whether `cookie`'s accepted return may consume a counter
    /// unit before popping its matched slot (round-6 1a): only
    /// the TOP (latest-arm) owner's return, only while a unit
    /// is outstanding. Kind-independent (O-slot and frame
    /// matches alike — same-cookie units are fungible
    /// suppressions). BPF-safe.
    pub fn counter_owned_by(&self, cookie: u64) -> bool {
        if self.overflow == 0 || self.counter_len == 0 {
            return false;
        }
        let top = if self.counter_len == 2 {
            self.counter_owner2
        } else {
            self.counter_owner
        };
        top == cookie
    }
    /// Settle one consumed unit for `cookie`'s return
    /// (round-6 1a; round-7 R12-P2-1: the rejected arm settles
    /// too): call after a successful counter consume on EITHER
    /// arm — accepted (owner consume + no-match consume, after
    /// `skip_return`) or rejected (overflow consume, inside
    /// `blind_return` — the blind-tombstone arm consumes no
    /// counter unit and never settles). A count-only rejected
    /// consume leaves a stale top owner standing for the next
    /// accepted return to trust (the R12 trigger — B pops Y8's
    /// frame on C's stale top). Removes `cookie`'s topmost
    /// entry (top-first — the returner is innermost under LIFO,
    /// so its unit is the latest matching one); a returner
    /// with no entry (evicted middle, retired record, foreign
    /// settler) removes nothing and only trims a stale bottom
    /// while the length exceeds the count (skew self-heal —
    /// the top, the newest knowledge, is kept).
    /// BPF-safe.
    pub fn settle_counter_owner(&mut self, cookie: u64) {
        if self.counter_len == 2 && self.counter_owner2 == cookie {
            self.counter_owner2 = 0;
            self.counter_related2 = 0;
            self.counter_len = 1;
        } else if self.counter_len == 2 && self.counter_owner == cookie {
            self.counter_owner = self.counter_owner2;
            self.counter_related = self.counter_related2;
            self.counter_owner2 = 0;
            self.counter_related2 = 0;
            self.counter_len = 1;
        } else if self.counter_len == 1 && self.counter_owner == cookie {
            self.counter_owner = 0;
            self.counter_related = 0;
            self.counter_len = 0;
        } else if self.counter_len > self.overflow {
            // No entry of mine: the consumed unit is unknown
            // (evicted/retired/foreign) — forget the stalest
            // (bottom) so the length never exceeds the count.
            if self.counter_len == 2 {
                self.counter_owner = self.counter_owner2;
                self.counter_related = self.counter_related2;
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_len = 1;
            } else if self.counter_len == 1 {
                self.counter_owner = 0;
                self.counter_related = 0;
                self.counter_len = 0;
            }
        }
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
            // R10 1b clear-at-zero (round-6 1a: all six stack
            // words): the last unit carried the record's whole
            // meaning — a drained counter owns nothing (a later
            // arm re-records). Rows that never record
            // (`API_THREADS`) hold 0 and behave exactly as
            // before.
            if self.overflow == 0 {
                self.counter_owner = 0;
                self.counter_len = 0;
                self.counter_related = 0;
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_evicted = 0;
            }
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
    /// Consume one unit for a WINDOW-REJECTED return of
    /// `cookie` (resolved identity, closed window): its own
    /// blind tombstone first, else one overflow marker. fix8
    /// (R8-2): slotted returns pop their own slot instead and
    /// reach here only when they own no slot (marker refusal
    /// fell back to the fungible counter). Returns whether a
    /// unit was consumed. Rejections that cannot attribute
    /// (tgid/generation/CONFIG mismatch — a different row) must
    /// NOT call this. Round-7 R12-P2-1: the overflow arm settles
    /// the returner's stack entry (a partial drain must not
    /// leave a stale top for the next accepted return); the
    /// blind-tombstone arm consumes no counter unit, so it
    /// never settles (the stack describes overflow units only).
    pub fn blind_return(&mut self, cookie: u64) -> bool {
        if self.blind != 0 {
            self.blind -= 1;
            true
        } else if self.overflow != 0 {
            self.overflow -= 1;
            // R10 1b: the same clear-at-zero as `skip_return`
            // (round-6 1a: all six stack words; the rejected
            // arm itself is unchanged — slot-first, T-first —
            // this only drops the record when the drain takes
            // the last unit).
            if self.overflow == 0 {
                self.counter_owner = 0;
                self.counter_len = 0;
                self.counter_related = 0;
                self.counter_owner2 = 0;
                self.counter_related2 = 0;
                self.counter_evicted = 0;
            }
            self.settle_counter_owner(cookie);
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
            counter_len: 0,
            counter_owner: 0,
            counter_related: 0,
            counter_owner2: 0,
            counter_related2: 0,
            counter_evicted: 0,
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
            counter_len: 0,
            counter_owner: 0,
            counter_related: 0,
            counter_owner2: 0,
            counter_related2: 0,
            counter_evicted: 0,
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
            counter_len: 0,
            counter_owner: 0,
            counter_related: 0,
            counter_owner2: 0,
            counter_related2: 0,
            counter_evicted: 0,
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
            counter_len: 0,
            counter_owner: 0,
            counter_related: 0,
            counter_owner2: 0,
            counter_related2: 0,
            counter_evicted: 0,
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
        /// Returns whether a unit was consumed. This model arms
        /// only through `enter`/`blind_entry` (never recording),
        /// so the stack is always empty and the round-7 settle
        /// inside `blind_return` is a no-op — the cookie value
        /// is irrelevant here.
        fn reject(&mut self) -> bool {
            self.thread.blind_return(0)
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
        assert!(!t.blind_return(0));
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
        assert!(t.blind_return(0));
        assert_eq!((t.overflow, t.blind), (0, 1));
        assert!(t.blind_return(0));
        assert_eq!((t.overflow, t.blind), (0, 0));
        assert!(!t.blind_return(0));
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
        /// Pre-fix-mechanism bare units (R9-P2-1, model-only):
        /// `force_counter` neuters the fixed BPF entry (no marker
        /// AND no owner recording — the old bare count), so those
        /// units are unknown and never trigger the
        /// consume-before-pop rule. Real BPF always records
        /// (`bare` is 0 there and `owned()` is `overflow`).
        /// Every schedule sets `force_counter` once or never —
        /// bare/owned mixing is unsupported.
        bare: u32,
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
                bare: 0,
            }
        }
        /// Overflow units with a recorded owner (round-6 1a):
        /// the BPF `thread.overflow` (real BPF records every
        /// fallback, so all its units are owned — `bare` is
        /// model-only).
        fn owned(&self) -> u32 {
            self.thread.overflow.saturating_sub(self.bare)
        }
        /// Consume one overflow unit for `cookie`'s accepted
        /// return through production `skip_return` (which clears
        /// the record at zero) + `settle_counter_owner` (which
        /// removes the settler's topmost entry), retiring a bare
        /// unit first when the schedule neuters the mechanism
        /// (bare rows hold len 0, so the settle is a no-op
        /// there). Mirrors the BPF consume (whose rows hold no
        /// bare units).
        fn consume_counter(&mut self, cookie: u64) -> bool {
            if self.thread.overflow == 0 {
                return false;
            }
            assert!(self.thread.skip_return());
            self.thread.settle_counter_owner(cookie);
            if self.bare > 0 {
                self.bare -= 1;
            }
            true
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
        /// None arm exactly. Round-6 1a: a recorded fallback
        /// pushes its owner (`record_counter_owner` — len 0→1
        /// bottom, len 1→2 top, len-2 arms replace the top and
        /// evict the middle); round-5 N2: each arm also records
        /// marker-relatedness (live O at the arm level — the BPF
        /// `o_marker_at` probe); the `force_counter` neuter
        /// records nothing (bare old-BPF count → unknown).
        fn overflow(&mut self, cookie: u64) {
            assert_eq!(self.thread.enter_frame(), None, "must refuse a frame");
            let slot = self.thread.depth as usize;
            if !self.force_counter && !self.quota_fail && self.omarks[slot].is_none() {
                self.omarks[slot] = Some(cookie);
            } else {
                self.thread.overflow = self.thread.overflow.saturating_add(1);
                if self.force_counter {
                    self.bare = self.bare.saturating_add(1);
                } else {
                    let marker_live = self.omarks[slot].is_some();
                    self.thread.record_counter_owner(cookie, marker_live);
                }
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
        /// Failed frame insert (quota/map) by `cookie`:
        /// production `enter_frame` wounds depth and mints, then
        /// production `failed_entry` unwinds depth and arms the
        /// fungible counter — mirroring the BPF frame-insert
        /// failure arms exactly (R10 1b: including the owner
        /// recording; round-5 N2: relatedness probed at the
        /// unwound level). No slot is placed.
        fn failed_frame(&mut self, cookie: u64) {
            self.thread
                .enter_frame()
                .expect("failed entry wounds first");
            self.thread.failed_entry();
            let slot = self.thread.depth as usize;
            let marker_live = self.omarks[slot].is_some();
            self.thread.record_counter_owner(cookie, marker_live);
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
        /// mirroring `discard_deeper` with include_t=1: single pass,
        /// levels top→0, counting discards; the BPF drives the pass
        /// via `bpf_loop` and hoists the depth unwinding after (ONE
        /// saturating subtract — net-identical to per-delete
        /// decrements). Round-6 1a: a discarded O-marker drops
        /// RELATED stack entries (round-5 N2: unrelated entries
        /// survive); T/frame discards never retire.
        fn discard_deeper(&mut self, mine: usize) {
            let top = (self.thread.depth as usize).min(MAX_DEPTH as usize);
            let mut unwound: u32 = 0;
            for level in (mine + 1..=top).rev() {
                if self.frames[level].take().is_some() {
                    unwound += 1;
                    self.discarded += 1;
                }
                if self.tmarks[level].take().is_some() {
                    self.discarded += 1;
                }
                if self.omarks[level].take().is_some() {
                    self.discarded += 1;
                    self.thread.retire_counter_owner();
                }
            }
            self.thread.depth = self.thread.depth.saturating_sub(unwound);
        }
        /// Accepted return of `cookie` (rv observed on emit):
        /// fast-path own frame, else slow search (T excluded),
        /// else the overflow counter — mirroring `pop_return`'s
        /// accepted arm exactly. Round-6 1a: a cookie match is
        /// not ownership, so an ambiguous match consumes instead
        /// of popping ONLY when the returner is the TOP (latest
        /// arm) counter owner (`counter_owned_by`,
        /// kind-independent — O-slot and frame matches alike);
        /// every other match pops its own slot first (`d7c431a`
        /// order) — and a consume pops and discards nothing. A
        /// popped O-marker drops RELATED stack entries (round-5
        /// N2: unrelated entries survive).
        fn marker_at(&self, level: usize) -> bool {
            self.omarks[level].is_some() || self.tmarks[level].is_some()
        }
        fn owner_consumes(&self, cookie: u64) -> bool {
            self.owned() > 0 && self.thread.counter_owned_by(cookie)
        }
        fn return_accept(&mut self, cookie: u64, rv: u64) {
            if self.thread.depth > 0 {
                let slot = self.thread.depth as usize - 1;
                if let Some((owner, inv)) = self.frames[slot] {
                    if owner == cookie
                        && !self.marker_at(self.thread.depth as usize)
                        && !self.owner_consumes(cookie)
                    {
                        self.frames[slot] = None;
                        self.thread.depth -= 1;
                        self.emitted[self.emitted_len] = (inv, rv);
                        self.emitted_len += 1;
                        return;
                    }
                }
            }
            if let Some((mine, kind)) = self.find_mine(cookie, false) {
                if self.owner_consumes(cookie) {
                    assert!(
                        self.consume_counter(cookie),
                        "owned counter unit must exist"
                    );
                    return;
                }
                self.discard_deeper(mine);
                if kind == PENDING_FRAME {
                    let (_, inv) = self.frames[mine].take().unwrap();
                    self.thread.depth = self.thread.depth.saturating_sub(1);
                    self.emitted[self.emitted_len] = (inv, rv);
                    self.emitted_len += 1;
                } else {
                    assert_eq!(kind, PENDING_OVERFLOW_MARKER);
                    self.omarks[mine] = None;
                    self.thread.retire_counter_owner();
                    self.suppressed += 1;
                }
                return;
            }
            assert!(
                self.consume_counter(cookie),
                "counter-owned accepted return"
            );
        }
        /// Window-rejected return of `cookie`: fast-path own frame
        /// (popped, suppressed), else slow search (all kinds),
        /// else the T-first counter — mirroring `pop_return`'s
        /// rejected arm exactly. Never emits. Round-6 1a: a
        /// popped O-marker drops RELATED stack entries (round-5
        /// N2 scoping; slot-first + T-first preserved).
        /// Round-7 R12-P2-1: a rejected overflow consume settles
        /// the returner's stack entry (inside `blind_return` —
        /// a partial drain must not leave a stale top); slot
        /// pops consume no counter unit (frame/T pops settle
        /// nothing) and blind-tombstone consumes never settle.
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
                    self.thread.retire_counter_owner();
                    self.suppressed += 1;
                }
                return true;
            }
            // No slot of mine: the T-first counter (fix7 residual;
            // round-7: the overflow arm settles the returner's
            // entry inside `blind_return`); a unit-less return
            // consumes nothing (BPF: silent).
            self.thread.blind_return(cookie)
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
        // its own frame. (RED pre-fix: this schedule cascaded the
        // exact [(8,7)..(2,1)] through the old cookie-blind counter
        // rule; the cascade shape stays pinned post-fix by
        // `fix8_same_cookie_skip_still_cascades_documented_limitation`.)
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
    fn fix8_same_cookie_skip_still_cascades_documented_limitation() {
        // fix8 F2 documented limitation (R8-2 — an explicit
        // coverage trade, NOT a proven necessity result): the SAME
        // schedule with ONE cookie still cascades [(8,7)..(2,1)] —
        // exact reconstruction is unachievable there (same-cookie
        // return events are ambiguous: B's return and C's return
        // are the identical observation, so no deterministic rule
        // pops correctly in both the skip and no-skip worlds).
        // Unrealizable for the R8-2 mixed
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
                        counter_len: 0,
                        counter_owner: 0,
                        counter_related: 0,
                        counter_owner2: 0,
                        counter_related2: 0,
                        counter_evicted: 0,
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
        // invocation. `Pending`/`PendingKey` shapes frozen
        // (56/24 B); `Thread` is 64 B per the round-6 1a layout
        // pin below (specs mirror it).
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
        assert_eq!(core::mem::size_of::<Thread>(), 64);
    }
    #[test]
    fn r9_same_cookie_complete_chain_must_keep_all_pairs_aligned() {
        // R9-P2-1 (collision): ten nested same-cookie calls, all
        // accepted. A1..A8 frame; B slots the O-marker; C collides
        // onto the fungible counter. C's and B's returns must
        // suppress via their own units; every frame pops own.
        // (RED pre-fix: C takes B's marker, B takes A8's frame —
        // [(8,9),(7,8)..(1,2)], then A1 suppressed.)
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S); // B: slotted O at depth 8
        m.overflow(S); // C: same-kind collision → counter
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (8, 1, 0)
        );
        m.return_accept(S, 10); // C: must consume its counter unit
        assert_eq!(
            (m.suppressed, m.emitted_len),
            (0, 0),
            "C owns no slot and must pop nothing"
        );
        m.return_accept(S, 9); // B: must pop its own O-marker
        assert_eq!((m.suppressed, m.emitted_len), (1, 0));
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn r9_same_cookie_quota_fallback_must_not_emit_outer_frame() {
        // R9-P2-1 (quota/map refusal): the overflow entry places
        // no marker (quota refused) and owns a fungible counter
        // unit; its accepted return must suppress, not emit A8's
        // frame. (RED pre-fix: the fast path pops A8's frame →
        // [(8,900)].)
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(S);
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        m.return_accept(S, 900);
        assert_eq!(
            m.emitted_len, 0,
            "unframed overflow return must suppress, not emit A8"
        );
        assert_eq!(m.thread.depth, 8);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn r9_mixed_cookie_counter_return_must_not_discard_live_outer_marker() {
        // R9-P2-1 (mixed cookies): B's O-marker is outer-live when
        // the inner same-level A overflows onto the counter
        // (same-kind collision). A's accepted return must consume
        // its own counter unit — popping nothing, discarding
        // nothing. (RED pre-fix: A pops A8's frame and discards
        // B's live marker as supposedly skipped garbage.)
        const A: u64 = 1;
        const B: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.overflow(B); // live outer B's O-marker
        m.overflow(A); // inner A collides onto the counter
        m.return_accept(A, 900);
        assert_eq!(
            m.emitted_len, 0,
            "counter-owned A must not hijack an older A frame"
        );
        assert_eq!(m.omarks[8], Some(B), "B is still executing, not skipped");
        assert_eq!(m.discarded, 0);
        m.return_accept(B, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn r9_failed_frame_entry_must_suppress_its_accepted_return() {
        // R9-P2-1 (failed-frame entry): the entry wounds depth and
        // mints an invocation but the frame insert fails
        // (quota/map) — `failed_entry` unwinds depth and arms the
        // fungible counter. Its accepted return must suppress, not
        // pop an outer frame. (RED pre-fix: the fast path pops
        // A7's frame.)
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..7 {
            m.frame(S);
        }
        m.failed_frame(S); // A8's frame insert refused
        assert_eq!((m.thread.depth, m.thread.overflow), (7, 1));
        m.return_accept(S, 800);
        assert_eq!(
            m.emitted_len, 0,
            "failed-frame return owns a counter unit, not A7's frame"
        );
        for rv in (1..=7u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn r9_all_accepted_o_skip_cascade_is_documented_limitation() {
        // R9-P2-2 limitation pin (A2 rev7): eight framed
        // non-operational S calls; a ninth S call slots an
        // O-marker and is skipped by longjmp; all surviving
        // returns accepted. A8's return pops the orphaned
        // O-marker (same-cookie slot matches are ambiguous — the
        // skip is unobservable online), then every pop shifts by
        // one: [(8,7)..(2,1)], ending (1,0,0). Pre-existing
        // (predates fix8); rev7 qualifies the "never shifts"
        // assurance to exclude this all-accepted O-skip shape —
        // it sits outside the never-reopen proof, which covers
        // only the T/O rejected→accepted pin. (RED in
        // assert-aligned form pre- and post-P2-1-fix — the P2-1
        // fix provably does not alter this counter-free path.)
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S);
        m.skip();
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
    fn n1_quota_skip_cascade_is_documented_limitation() {
        // Re-review N1 limitation pin (A2 rev8): eight framed S
        // calls; a ninth S call quota-refused onto the fungible
        // counter (NO marker) is skipped by longjmp; all
        // surviving returns accepted. The first surviving
        // return consumes the orphaned counter unit (R9-mandated
        // consume-before-pop: the skip is unobservable online —
        // identical cookie/overflow/owner/frame-match
        // observations in both worlds), then every pop shifts by
        // one: [(8,7)..(2,1)], ending (1,0,0) with suppr 0 — the
        // same cascade as the pinned O-skip limitation (one
        // RESULT lost, one frame orphaned; survivors SHIFT, not
        // aligned).
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(S);
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        m.skip();
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
        assert_eq!((m.suppressed, m.discarded), (0, 0));
    }
    #[test]
    fn n1_collision_skip_cascade_is_documented_limitation() {
        // Re-review N1 limitation pin (A2 rev8): eight framed S
        // calls; B slots the O-marker; C collides onto the
        // fungible counter (owner-recorded) and is skipped by
        // longjmp;
        // all nine survivors accepted. The first surviving
        // return consumes C's orphaned counter unit, the next
        // pops B's orphaned O-marker (suppr 1), then every pop
        // shifts by one: [(8,7)..(2,1)], ending (1,0,0) — the
        // identical cascade to quota-skip plus one suppression.
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S); // B: slotted O at depth 8
        m.overflow(S); // C: same-kind collision → counter (owned by S)
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, S),
            "C's unit records its owner"
        );
        m.skip(); // C's return longjmp'd
        for rv in (1..=9u64).rev() {
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
        assert_eq!((m.suppressed, m.discarded), (1, 0));
    }
    #[test]
    fn r10_trigger1_rejected_slot_then_new_o_preserves_accepted_pairs() {
        // R10-P2 finding 1 (doubles as the b1 guard): eight framed
        // S calls; operational B(X) slots an O-marker; nested C(X)
        // collides onto the counter; the window closes; C's rejected
        // return pops B's O-marker; B calls D(S), which slots a
        // fresh O-marker; D returns accepted; B returns rejected;
        // the S ancestors return accepted. Under 1b (R10 fix):
        // C's pop retires the counter-owner record (the innerness
        // evidence died with its marker), so D pops its OWN
        // marker, B's rejected return settles the counter unit,
        // and all eight S pairs stay aligned and quiescent.
        // (RED pre-fix: D consumes the stale inner unit —
        // `suppressed` 0, not 1 — and the survivors cascade
        // [(8,7)..(2,1)] to (1,0,0). NOT R10's verbatim
        // intermediate assert: finding-1's (overflow,inner)
        // (1,1) becomes (overflow,known) (1,0) under any sound
        // fix — the (1,1) pins the OLD stale state.)
        const S: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(X); // B: slotted O at depth 8
        m.overflow(X); // C: same-kind collision → counter
        assert!(m.return_reject(X)); // C returns after close; B still executing
        assert_eq!(m.thread.overflow, 1);
        assert!(m.omarks[8].is_none());
        assert_eq!(m.suppressed, 1, "C's rejected return pops B's O-marker");
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (0, 0, 0),
            "C's pop retires the owner record with its marker"
        );
        m.overflow(S); // B calls D: fresh O-marker
        m.return_accept(S, 900); // D returns: must pop its own marker
        assert_eq!(m.suppressed, 2, "D pops its own marker");
        assert_eq!(m.thread.overflow, 1, "stale unit must not be consumed by D");
        assert!(m.return_reject(X)); // B returns: settles the counter
        assert_eq!(m.thread.overflow, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2,
                m.thread.counter_evicted
            ),
            (0, 0, 0, 0),
            "clear-at-zero leaves no stale record"
        );
    }
    #[test]
    fn r10_trigger1_same_cookie_new_o_pops_after_retirement() {
        // R10-P2 finding-1 lifetime variant (retirement's
        // behavioral pin — NOT R10-verbatim): trigger 1's
        // schedule with D sharing X's cookie. C's rejected
        // return pops B's O-marker and retires the record; D(X)
        // slots a fresh O-marker; D's accepted return must pop
        // its OWN marker (empty stack → slot-first) even though
        // the orphaned unit's armer was also X — the record died
        // with B's marker. B's rejected return settles the
        // counter; all eight S pairs stay aligned and quiescent
        // with nothing discarded. (Without retirement D consumes
        // the orphan — `suppressed` 1, not 2 — and D's marker is
        // discarded by a later S return.)
        const S: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(X); // B: slotted O at depth 8
        m.overflow(X); // C: same-kind collision → counter
        assert_eq!((m.thread.counter_len, m.thread.counter_owner), (1, X));
        assert!(m.return_reject(X)); // C returns after close; B still executing
        assert_eq!(m.thread.overflow, 1);
        assert!(m.omarks[8].is_none());
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (0, 0, 0),
            "C's pop retires the owner record with its marker"
        );
        m.overflow(X); // B calls D(X): fresh O-marker, same cookie
        m.return_accept(X, 900); // D returns: must pop its own marker
        assert_eq!(m.suppressed, 2, "D pops its own marker");
        assert_eq!(
            m.thread.overflow, 1,
            "retired record must not be consumed by D"
        );
        assert!(m.return_reject(X)); // B returns: settles the counter
        assert_eq!(m.thread.overflow, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        assert_eq!(m.discarded, 0);
    }
    #[test]
    fn r10_trigger2_foreign_counter_skip_keeps_frames_aligned() {
        // R10-P2 counterexample 2 (doubles as the b2 guard):
        // eight framed S calls; operational B(X) quota-refused
        // onto the counter (NO marker) and skipped by longjmp;
        // all survivors accepted. Under 1b: the orphaned unit's
        // recorded owner (X) is foreign to every S return, so
        // each S return pops its OWN frame (slot-first,
        // `d7c431a` behavior) — eight aligned pairs with the
        // orphaned counter retained (0,1,0), never a
        // manufactured pairing. (RED pre-fix: the first S
        // return consumes the orphan and the survivors cascade
        // [(8,7)..(2,1)] to (1,0,0).)
        const S: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(X); // foreign cookie, accepted entry, no marker
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "the 0→1 arm records len+bottom"
        );
        m.skip();
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 1, 0)
        );
        assert_eq!((m.suppressed, m.discarded), (0, 0));
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "foreign frame pops never retire the record"
        );
    }
    #[test]
    fn r10_trigger3_skipped_blind_same_cookie_keeps_frames_aligned() {
        // R10-P2 finding 2 (doubles as the b5 guard): eight framed
        // S calls; operational B(X) quota-refused onto the counter;
        // the window closes; C(X) slots a T-marker and longjmps
        // back to B; B's rejected return pops C's T-marker,
        // leaving the overflow debt; all S survivors accepted.
        // Under 1b: the debt's recorded owner (X) is foreign to
        // every S return, so each S return pops its OWN frame
        // (slot-first, `d7c431a` behavior) — eight aligned pairs
        // with the debt retained (0,1,0). (RED pre-fix: S8
        // consumes the debt and S7 emits against S8's frame —
        // [(8,7)..(2,1)] to (1,0,0).)
        const S: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(X); // B, operational/open
        m.quota_fail = false;
        m.blind_enter(X); // C, same operational cookie as B
        m.skip(); // C longjmps back to B
        assert!(m.return_reject(X)); // B takes C's T, leaving overflow=1
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(m.suppressed, 1, "B's rejected return pops C's T-marker");
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "T-marker removal never retires the record"
        );
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 1, 0)
        );
        assert_eq!(m.discarded, 0);
    }
    #[test]
    fn r10_outer_counter_then_later_o_pops_slot_first() {
        // R10 legitimate control (mixed-slot order guard — GREEN
        // pre-fix and post-fix): eight framed S calls; B
        // quota-refused onto the counter (OUTER unit, owner B);
        // D slots a LATER O-marker; D's accepted return must pop
        // its own marker BEFORE the outer counter settles (B is
        // foreign to D — slot-first); B's accepted return then
        // consumes its own unit; every frame pops own. Owned
        // returns consume, foreign slots pop: the R9 mandate and
        // the `d7c431a` mixed-slot order coincide here.
        const S: u64 = 1;
        const B: u64 = 2;
        const D: u64 = 3;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(B);
        m.quota_fail = false;
        m.overflow(D);
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        assert_eq!((m.thread.counter_len, m.thread.counter_owner), (1, B));
        m.return_accept(D, 900);
        assert_eq!(m.thread.overflow, 1, "later slot pops before outer counter");
        assert!(m.omarks[8].is_none());
        assert_eq!(m.suppressed, 1);
        m.return_accept(B, 800);
        assert_eq!(m.thread.overflow, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        assert_eq!(core::mem::size_of::<Thread>(), 64);
        assert_eq!(core::mem::offset_of!(Thread, counter_len), 28);
        assert_eq!(core::mem::offset_of!(Thread, counter_owner), 32);
        assert_eq!(core::mem::offset_of!(Thread, counter_related), 40);
        assert_eq!(core::mem::offset_of!(Thread, counter_owner2), 48);
        assert_eq!(core::mem::offset_of!(Thread, counter_related2), 56);
        assert_eq!(core::mem::offset_of!(Thread, counter_evicted), 60);
    }
    #[test]
    fn r10_mixed_cookie_second_arm_falls_back_to_slot_first() {
        // R10 1b residual pin, round-6 1a: >1 outstanding
        // mixed-cookie units KEEP both owners in arm order (the
        // 1b clearing is GONE — R11-P2-1 proved clearing reopens
        // the balanced hijack). Eight framed A calls; B arms a
        // quota unit (bottom B); C arms a second quota unit
        // (top C — no clearing); F2 slots a later O-marker.
        // F2's accepted return pops its OWN marker (top C is
        // foreign to F2 → slot-first, never a guess); C's and
        // B's slotless returns settle their units top-first
        // (no-match settles unconditionally — there is no slot
        // to pop); every frame pops own. Aligned + quiescent
        // throughout the residual.
        const A: u64 = 0xA11CE;
        const B: u64 = 0xB00B;
        const C: u64 = 0xC10C;
        const F2: u64 = 0xF222;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.quota_fail = true;
        m.overflow(B);
        m.overflow(C);
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 2));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, B, C),
            "mixed-cookie arm preserves both owners in order"
        );
        m.overflow(F2); // later O-marker slots (no arm, no record change)
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, B, C)
        );
        m.return_accept(F2, 0);
        assert_eq!(m.thread.overflow, 2, "foreign top → slot-first");
        assert!(m.omarks[8].is_none());
        m.return_accept(C, 0);
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, B),
            "C settles the top, B stays bottom"
        );
        m.return_accept(B, 0);
        assert_eq!(m.thread.overflow, 0);
        assert_eq!(m.thread.counter_len, 0);
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
    }
    #[test]
    fn r10_same_cookie_rejected_steal_cascade_is_documented_limitation() {
        // R10 1b same-cookie limitation pin (A2 rev9): eight
        // framed S calls; B(S) quota-refused onto the counter;
        // B's REJECTED return pops A8's frame (slot-first
        // rejected arm, unchanged — orphaning B's own unit, and
        // a frame pop is not an O-marker removal so the record
        // stands); A7's accepted return consumes the orphan
        // (same-cookie owner match), then every pop shifts by
        // one: [(7,6)..(2,1)], ending (1,0,0) with suppr 0 —
        // the N1-family cascade at depth 7 (one RESULT lost, one
        // frame orphaned; `d7c431a` aligns seven pairs here and
        // ends (0,1,0) — verified on the base model).
        // Same-cookie counter-orphan, same unobservability class
        // as the N1 pins (at A7's return the BPF state is
        // field-identical to the R9-pinned live-owner shape —
        // only the R9-mandated consume fits both). Restoring
        // `d7c431a` here needs rejected-path owner-CONSUME
        // (settle) — out of the 1b spec, named as the
        // follow-up, not smuggled in. Bare retirement is
        // hazardous: S1's steal-return would destroy the valid
        // record of an S2-live same-cookie unit.
        const S: u64 = 42;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.quota_fail = true;
        m.overflow(S); // B: counter unit, owner S
        m.quota_fail = false;
        assert!(m.return_reject(S)); // B pops A8's frame, orphans its unit
        assert_eq!((m.thread.depth, m.thread.overflow), (7, 1));
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, S),
            "frame pops never retire the record"
        );
        m.return_accept(S, 7); // A7 consumes B's orphaned unit
        assert_eq!(m.thread.overflow, 0);
        assert_eq!(m.emitted_len, 0);
        for rv in (1..=6u64).rev() {
            m.return_accept(S, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [(7, 6), (6, 5), (5, 4), (4, 3), (3, 2), (2, 1)]
        );
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (1, 0, 0)
        );
        assert_eq!((m.suppressed, m.discarded), (0, 0));
    }
    #[test]
    fn n2_unrelated_quota_arm_survives_foreign_o_pop() {
        // Round-5 N2 regression (1b blanket retirement): X1 framed
        // @0 (cookie X) + 7 S frames (depth 8 = MAX) + X2(X)
        // quota-refused onto the counter (NO marker live at arm —
        // the arm is marker-UNRELATED) + F slots and pops its own
        // O @8, all accepted, strict LIFO, no skips. F's foreign
        // O-pop must NOT retire X2's live owner record: X2
        // consumes its own unit; X1's frame + 7 S frames stay
        // intact; all eight pairs align and the machine ends
        // quiescent (the `f341f8d` end-state — R9's occupancy
        // rule kept this green; 1b's blanket retirement broke
        // it). (RED pre-fix: X2 pops X1's frame and discards the
        // 7 S frames — the R9-P2-1-class hijack in plain LIFO.)
        const S: u64 = 1;
        const X: u64 = 2;
        const F: u64 = 3;
        let mut m = Fix8Model::new();
        assert_eq!(m.frame(X), 1, "X1 framed @0");
        for _ in 0..7 {
            m.frame(S);
        }
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (8, 0, 0)
        );
        m.quota_fail = true;
        m.overflow(X); // X2: counter unit, no marker live at arm
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 1));
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "the 0→1 arm records len+bottom"
        );
        assert_eq!(
            m.thread.counter_related, 0,
            "quota arm with the level free records unrelated"
        );
        m.overflow(F); // F slots its own O @8 (level free)
        m.return_accept(F, 0); // F pops its own O
        assert_eq!(m.suppressed, 1, "F pops its own marker");
        assert!(m.omarks[8].is_none());
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "foreign O-pop must not retire a marker-unrelated record"
        );
        assert_eq!(
            m.thread.counter_related, 0,
            "the unrelated record stands through the foreign O-pop"
        );
        m.return_accept(X, 900); // X2: must consume its own unit
        assert_eq!(m.emitted_len, 0, "X2 owns a counter unit, not X1's frame");
        assert_eq!(m.thread.depth, 8);
        assert_eq!(m.discarded, 0);
        for rv in (2..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.return_accept(X, 1); // X1 pops its own frame, last
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        m.assert_quiescent();
    }
    #[test]
    fn thread_value_is_64_with_stack_at_28() {
        // fix6 (R6-1): THREADS/API_THREADS value 16→24 B, seed
        // APPENDED (existing field offsets unchanged). fix7 (R7-3):
        // 24→32 B, blind APPENDED after seed (all existing offsets
        // unchanged). R10 1b: 32→40 B — the R9 `overflow_inner`
        // padding word becomes `counter_known` (offset 28,
        // unchanged value), and `counter_owner: u64` is APPENDED
        // at 32 (all existing offsets unchanged). Round-5 N2:
        // 40→48 B — `counter_related: u32` APPENDED at 40 (all
        // existing offsets unchanged). Round-6 1a: 48→64 B — the
        // `counter_known` word becomes `counter_len` (offset 28,
        // values 0/1/2), and `counter_owner2: u64`,
        // `counter_related2: u32`, `counter_evicted: u32` are
        // APPENDED at 48/56/60 (all existing offsets unchanged).
        // The loader `specs()` mirrors these sizes exactly.
        assert_eq!(core::mem::size_of::<Thread>(), 64);
        assert_eq!(core::mem::offset_of!(Thread, next), 0);
        assert_eq!(core::mem::offset_of!(Thread, depth), 8);
        assert_eq!(core::mem::offset_of!(Thread, overflow), 12);
        assert_eq!(core::mem::offset_of!(Thread, seed), 16);
        assert_eq!(core::mem::offset_of!(Thread, blind), 24);
        assert_eq!(core::mem::offset_of!(Thread, counter_len), 28);
        assert_eq!(core::mem::offset_of!(Thread, counter_owner), 32);
        assert_eq!(core::mem::offset_of!(Thread, counter_related), 40);
        assert_eq!(core::mem::offset_of!(Thread, counter_owner2), 48);
        assert_eq!(core::mem::offset_of!(Thread, counter_related2), 56);
        assert_eq!(core::mem::offset_of!(Thread, counter_evicted), 60);
    }
    #[test]
    fn r11_mixed_counter_batch_must_not_reopen_balanced_hijack() {
        // R11-P2-1 (mixed-owner fallback): eight framed S calls; B(S)
        // slots the O-marker; C(S) collides onto the counter; D(Y)
        // collides onto the counter (mixed batch). All accepted,
        // strict LIFO, no skips. D settles slotless; C must consume
        // the remaining unit (it is C's — order preserved), NOT take
        // B's O-marker; B pops its own marker; every frame pops own:
        // D, C, B suppressed, [(8,8)..(1,1)], quiescent — R11's
        // Expected exactly. (RED pre-fix: C takes B's marker, B
        // takes S8's frame — [(8,9)..(1,2)].)
        const S: u64 = 1;
        const Y: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S); // B: O-marker, logical call 9
        m.overflow(S); // C: counter unit, call 10
        m.overflow(Y); // D: counter unit, call 11
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 2));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2,
                m.thread.counter_evicted
            ),
            (2, S, Y, 0),
            "mixed batch keeps both owners in arm order"
        );
        assert_eq!(
            (m.thread.counter_related, m.thread.counter_related2),
            (1, 1),
            "both arms saw B's live O-marker"
        );
        m.return_accept(Y, 11); // D settles slotless
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, S),
            "D settles the top; the remainder is C's"
        );
        assert_eq!(m.emitted_len, 0);
        m.return_accept(S, 10); // C: must consume, not take B's O
        assert_eq!(m.emitted_len, 0, "C owns a counter unit, not B's marker");
        assert_eq!(m.thread.counter_len, 0);
        assert!(m.omarks[8].is_some(), "B's marker survives C's return");
        m.return_accept(S, 9); // B: pops its own O-marker
        assert_eq!((m.suppressed, m.emitted_len), (1, 0));
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        m.assert_quiescent();
        assert_eq!((m.suppressed, m.discarded), (1, 0));
    }
    #[test]
    fn r11_saturated_batch_preserves_oldest_and_latest_owners() {
        // Round-6 1a saturation pin: three quota units (X, Y, Z)
        // over eight framed A calls. The third arm evicts the
        // MIDDLE (sticky bottom X + latest top Z, `evicted` 1);
        // all three settlers are slotless, so each settles its
        // unit exactly (Z pops the top, Y's settle finds no
        // entry and trims nothing, X pops the bottom); every
        // frame pops own. Aligned + quiescent, eviction
        // detectable mid-schedule and cleared at drain.
        const A: u64 = 0xA11CE;
        const X: u64 = 1;
        const Y: u64 = 2;
        const Z: u64 = 3;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(A);
        }
        m.quota_fail = true;
        m.overflow(X);
        m.overflow(Y);
        m.overflow(Z);
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 3));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2,
                m.thread.counter_evicted
            ),
            (2, X, Z, 1),
            "saturating arm keeps bottom+latest, evicts the middle"
        );
        m.return_accept(Z, 0);
        assert_eq!(m.thread.overflow, 2);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "Z settles the top"
        );
        m.return_accept(Y, 0);
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, X),
            "evicted Y settles slotless; X untouched, no trim needed"
        );
        m.return_accept(X, 0);
        assert_eq!(m.thread.overflow, 0);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_evicted),
            (0, 0),
            "clear-at-zero clears the stack and the eviction count"
        );
        for rv in (1..=8u64).rev() {
            m.return_accept(A, rv);
        }
        m.assert_aligned();
        m.assert_quiescent();
        assert_eq!((m.suppressed, m.discarded), (0, 0));
    }
    #[test]
    fn r11_evicted_middle_owner_falls_back_to_slot_first() {
        // Round-6 1a saturation residual (a NAMED PINNED
        // limitation — an explicit coverage trade, NOT a proven
        // necessity result: the generalized round-3 identity
        // construction — K+1 arms with a same-cookie top
        // collision reach identical state with conflicting
        // mandates — shows exact reconstruction unachievable
        // there): B(S) slots the O-marker;
        // C(X), D(S), E(Y) collide onto the counter (D evicted);
        // E settles; D — the forgotten middle — matches B's
        // marker and falls back to slot-first, popping it; C
        // settles; B pops S8's frame and the survivors shift
        // [(8,9)..(1,2)] with S1 settling D's orphan. Every
        // residual hole needs this same-cookie ambiguity (the
        // R11-accepted b3/b4 class); distinct-cookie batches
        // settle exactly (pinned above).
        const S: u64 = 1;
        const X: u64 = 2;
        const Y: u64 = 3;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(S); // B: O-marker
        m.overflow(X); // C: bottom unit
        m.overflow(S); // D: middle unit (evicted next)
        m.overflow(Y); // E: top unit, evicts D
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 3));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2,
                m.thread.counter_evicted
            ),
            (2, X, Y, 1),
            "D(S) is the forgotten middle"
        );
        m.return_accept(Y, 12); // E settles the top
        assert_eq!(m.thread.overflow, 2);
        assert_eq!((m.thread.counter_len, m.thread.counter_owner), (1, X));
        m.return_accept(S, 11); // D: evicted → slot-first, pops B's O
        assert_eq!(m.suppressed, 1, "D takes B's marker (fallback)");
        assert_eq!(
            m.thread.counter_len, 0,
            "the pop retires X's related entry with the marker"
        );
        m.return_accept(X, 10); // C settles slotless, record empty
        assert_eq!(m.thread.overflow, 1);
        m.return_accept(S, 9); // B: marker gone → pops S8's frame
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [
                (8, 9),
                (7, 8),
                (6, 7),
                (5, 6),
                (4, 5),
                (3, 4),
                (2, 3),
                (1, 2)
            ]
        );
        m.assert_quiescent();
        assert_eq!((m.suppressed, m.discarded), (1, 0));
    }
    #[test]
    fn r11_cross_cookie_retirement_is_needed_after_skipped_counter() {
        // R11's valid cross-cookie control (replaces the report's
        // incorrect G(X) argument): eight framed (non-operational)
        // S calls; operational B(X) slots an O-marker; an S call
        // collides onto the counter (marker-related) and is
        // skipped; B's rejected return pops its own O-marker and
        // MUST retire S's record despite the cookie mismatch —
        // else the S survivors orphan-consume and cascade. Eight
        // aligned pairs with the debt retained (0,1,0).
        const S: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(S);
        }
        m.overflow(X); // B: O-marker, operational
        m.overflow(S); // S descendant: counter unit, related
        assert_eq!((m.thread.counter_len, m.thread.counter_owner), (1, S));
        m.skip(); // S descendant longjmps
        assert!(m.return_reject(X)); // B pops its own O
        assert_eq!(
            m.thread.counter_len, 0,
            "retire despite the cookie mismatch"
        );
        for rv in (1..=8u64).rev() {
            m.return_accept(S, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 1, 0)
        );
    }
    #[test]
    fn r11_stack_settle_trims_stale_bottom_on_skew() {
        // Round-6 1a method unit: an accepted no-match settle by
        // a cookie with no entry removes nothing and trims the
        // stalest (bottom) entry while the length exceeds the
        // count (rejected-skew self-heal — the top, the newest
        // knowledge, is kept). A trim is not an eviction.
        const X: u64 = 1;
        const Y: u64 = 2;
        const Z: u64 = 3;
        let mut t = Thread {
            depth: MAX_DEPTH,
            ..Default::default()
        };
        assert_eq!(t.enter(), None);
        t.record_counter_owner(X, false);
        assert_eq!(t.enter(), None);
        t.record_counter_owner(Y, false);
        assert_eq!((t.overflow, t.counter_len), (2, 2));
        assert!(t.skip_return());
        t.settle_counter_owner(Z);
        assert_eq!(
            (t.counter_len, t.counter_owner),
            (1, Y),
            "trim keeps the newest"
        );
        assert_eq!(t.counter_evicted, 0);
    }
    #[test]
    fn r11_stack_retire_drops_only_related_entries() {
        // Round-6 1a method unit: O-marker removal drops RELATED
        // stack entries only, compacting survivors in order.
        const X: u64 = 1;
        const Y: u64 = 2;
        let mut both = Thread::default();
        both.counter_len = 2;
        both.counter_owner = X;
        both.counter_related = 1;
        both.counter_owner2 = Y;
        both.counter_related2 = 1;
        both.retire_counter_owner();
        assert_eq!(both.counter_len, 0);
        let mut top_only = Thread::default();
        top_only.counter_len = 2;
        top_only.counter_owner = X;
        top_only.counter_related = 0;
        top_only.counter_owner2 = Y;
        top_only.counter_related2 = 1;
        top_only.retire_counter_owner();
        assert_eq!(
            (top_only.counter_len, top_only.counter_owner),
            (1, X),
            "unrelated bottom survives"
        );
        let mut bottom_only = Thread::default();
        bottom_only.counter_len = 2;
        bottom_only.counter_owner = X;
        bottom_only.counter_related = 1;
        bottom_only.counter_owner2 = Y;
        bottom_only.counter_related2 = 0;
        bottom_only.retire_counter_owner();
        assert_eq!(
            (
                bottom_only.counter_len,
                bottom_only.counter_owner,
                bottom_only.counter_related
            ),
            (1, Y, 0),
            "surviving top shifts to bottom"
        );
        let mut neither = Thread::default();
        neither.counter_len = 2;
        neither.counter_owner = X;
        neither.counter_related = 0;
        neither.counter_owner2 = Y;
        neither.counter_related2 = 0;
        neither.retire_counter_owner();
        assert_eq!(
            (neither.counter_len, neither.counter_owner),
            (2, X),
            "unrelated stack stands"
        );
    }
    #[test]
    fn r12_rejected_counter_consume_settles_owner_record() {
        // R12-P2-1: eight framed non-operational Y calls; B(Y)
        // and nested operational C(X) enter while open, both
        // marker insertions quota-refused onto the counter
        // ([Y,X], overflow 2, strict LIFO, no skips, no
        // eviction). The window closes; C's rejected return
        // consumes its unit AND settles its top entry (len 2 →
        // 1 [Y], overflow 1); B's accepted return then consumes
        // its own unit (top-Y match) instead of popping Y8's
        // frame; all eight Y pairs align and the machine ends
        // quiescent with nothing evicted. (RED pre-fix: the
        // consume is count-only — the stale top X stands, so B
        // pops Y8's frame → [(8,900),(7,8)..(1,2)].)
        const Y: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..8 {
            m.frame(Y);
        }
        m.quota_fail = true;
        m.overflow(Y); // B: accepted non-operational counter unit
        m.overflow(X); // C: operational counter unit, accepted entry
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 2));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, Y, X)
        );
        assert!(m.return_reject(X)); // C returns after close
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, Y),
            "C's rejected consume settles C's top entry"
        );
        m.return_accept(Y, 900); // B returns; must consume, not emit A8
        assert_eq!(
            m.emitted_len, 0,
            "live B owns a counter unit; C's stale top is not evidence B owns A8"
        );
        assert_eq!(m.thread.depth, 8);
        for rv in (1..=8u64).rev() {
            m.return_accept(Y, rv);
        }
        m.assert_aligned();
        assert_eq!(m.emitted_len, 8);
        m.assert_quiescent();
        assert_eq!(m.thread.counter_evicted, 0);
        assert_eq!((m.suppressed, m.discarded), (0, 0));
    }
    #[test]
    fn r12_mixed_skip_analog_mislabels_once_then_discards() {
        // R12 world-(b) behavioral pin (re-scope ACCEPTED —
        // CURRENT behavior pinned, not fixed): 6 A frames +
        // Y3@6 + Y2@7 (inv 7, 8); X + Y quota counter units;
        // the innermost unit owner Y is skipped by longjmp.
        // X settles slotless; Y2's return consumes the
        // skip-orphaned Y unit (forced: the twin — a slotless
        // unit-owner Y return — reaches byte-identical decision
        // state and mandates consume per R9, so no deterministic
        // rule pops correctly in both worlds); Y3's return then
        // pops Y2's frame → the single false pair (8,7); the A
        // returns align; Y3's frame is discarded. Final
        // [(8,7),(6,6)..(1,1)] to (0,0,0) with suppr 0, disc 1
        // (partial radius — one mislabel, not the b3 full
        // cascade; the no-skip class is pure improvement).
        const A: u64 = 0xA11CE;
        const X: u64 = 0xB00B;
        const Y: u64 = 0xC10C;
        let mut m = Fix8Model::new();
        for _ in 0..6 {
            m.frame(A);
        }
        m.frame(Y); // Y3 @6, inv 7
        m.frame(Y); // Y2 @7, inv 8
        m.quota_fail = true;
        m.overflow(X);
        m.overflow(Y);
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 2));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, X, Y)
        );
        m.skip(); // Y (innermost unit owner) never returns
        m.return_accept(X, 100); // X settles slotless
        assert_eq!(m.thread.overflow, 1);
        assert_eq!((m.thread.counter_len, m.thread.counter_owner), (1, Y));
        m.return_accept(Y, 200); // Y2's return consumes the orphan
        assert_eq!(m.emitted_len, 0);
        assert_eq!(m.thread.overflow, 0);
        assert_eq!(m.thread.counter_len, 0);
        m.return_accept(Y, 7); // Y3's return pops Y2's frame
        assert_eq!(m.emitted[..m.emitted_len], [(8, 7)]);
        for rv in (1..=6u64).rev() {
            m.return_accept(A, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [(8, 7), (6, 6), (5, 5), (4, 4), (3, 3), (2, 2), (1, 1)]
        );
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (0, 0, 0)
        );
        assert_eq!((m.suppressed, m.discarded), (0, 1));
    }
    #[test]
    fn r13_mixed_rejected_steal_is_documented_limitation() {
        // R13 mixed rejected-steal behavioral pin (re-scope
        // ACCEPTED — CURRENT behavior pinned, not fixed): seven
        // framed non-operational Y calls + operational X1's frame
        // (inv 8, depth 8); A(Y) + B(X) quota counter units
        // ([Y,X], strict LIFO, no skips, no eviction). The window
        // closes; B's rejected return pops X1's frame (slot-first
        // rejected arm — its own counter unit survives); the stale
        // X top then permits A's accepted return to emit (7,900)
        // against Y7's frame; X1's genuine rejected return
        // consumes B's orphaned unit ([Y,X]→[Y]); Y's next return
        // consumes A's unit slotless; the six outer Y returns pop
        // own frames. Final [(7,900),(6,6)..(1,1)] to (0,0,0)
        // with suppr 0, disc 0, evicted 0 (one mislabel — the
        // all-live mixed analog of the R10 same-cookie
        // rejected-steal; every call returns normally in LIFO
        // order, no skip or reopening). (RED pre-pin: the rev12
        // :2897 assurance expected [(7,7)..(1,1)] — the failure's
        // `left` quoted [(7,900)..(1,1)], refuting it.)
        const Y: u64 = 1;
        const X: u64 = 2;
        let mut m = Fix8Model::new();
        for _ in 0..7 {
            m.frame(Y);
        }
        m.frame(X); // X1, invocation 8
        m.quota_fail = true;
        m.overflow(Y); // A(Y), outer counter unit
        m.overflow(X); // B(X), inner counter unit, both enter while open
        m.quota_fail = false;
        assert_eq!((m.thread.depth, m.thread.overflow), (8, 2));
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, Y, X)
        );
        assert!(m.return_reject(X)); // B steals X1's frame, keeps its unit
        assert_eq!(
            (m.thread.depth, m.thread.overflow, m.thread.blind),
            (7, 2, 0)
        );
        assert_eq!(
            (
                m.thread.counter_len,
                m.thread.counter_owner,
                m.thread.counter_owner2
            ),
            (2, Y, X),
            "a frame pop settles nothing"
        );
        m.return_accept(Y, 900); // A emits against Y7's frame
        assert_eq!(m.emitted[..m.emitted_len], [(7, 900)]);
        assert!(m.return_reject(X)); // X1's genuine return eats B's orphan
        assert_eq!(m.thread.overflow, 1);
        assert_eq!(
            (m.thread.counter_len, m.thread.counter_owner),
            (1, Y),
            "X1's rejected consume settles X's top entry"
        );
        m.return_accept(Y, 7); // Y consumes A's unit slotless
        assert_eq!(m.emitted_len, 1);
        assert_eq!(m.thread.overflow, 0);
        assert_eq!(m.thread.counter_len, 0);
        for rv in (1..=6u64).rev() {
            m.return_accept(Y, rv);
        }
        assert_eq!(
            m.emitted[..m.emitted_len],
            [(7, 900), (6, 6), (5, 5), (4, 4), (3, 3), (2, 2), (1, 1)]
        );
        m.assert_quiescent();
        assert_eq!(m.thread.counter_evicted, 0);
        assert_eq!((m.suppressed, m.discarded), (0, 0));
    }
}
