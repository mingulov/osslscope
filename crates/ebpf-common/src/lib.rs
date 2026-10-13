//! SPDX-License-Identifier: GPL-3.0-or-later
//! Key/value structs shared between `crates/ebpf` and userspace.
//! Single source of truth for the P2 capture-map wire format; both
//! sides `include` this crate, so drift is a compile error, not a
//! golden mismatch. `no_std`-compatible; the `user` feature gates
//! userspace-only impls (drain-side aggregation helpers).
#![no_std]

/// COUNTS key: plan cookie (u32) in the high half, generation epoch
/// (u32) in the low half. Cookies are attach-time plan indices (<
/// 2^32 by construction); the generation fences re-plans (§5).
pub const fn make_key(cookie: u32, generation: u32) -> u64 {
    ((cookie as u64) << 32) | (generation as u64)
}

/// Split a COUNTS key back into (cookie, generation).
pub const fn split_key(key: u64) -> (u32, u32) {
    ((key >> 32) as u32, key as u32)
}

/// Invocation sequence fold (P7 item 3, §5.1): birth:16 | ctr:48.
/// Never reused across eviction or tid-reuse (SEQ map is
/// supersede-only); the counter saturates (never wraps — a wrap
/// would silently reuse an id).
pub const SEQ_CTR_MASK: u64 = (1 << 48) - 1;
pub const SEQ_CTR_MAX: u64 = (1 << 48) - 1;
/// Birth value that freezes a tid (64k incarnations exhausted —
/// fail-closed SKIP, §5.1).
pub const BIRTH_FROZEN: u16 = u16::MAX;

pub const fn make_seq(birth: u16, ctr: u64) -> u64 {
    ((birth as u64) << 48) | (ctr & SEQ_CTR_MASK)
}

pub const fn split_seq(seq: u64) -> (u16, u64) {
    ((seq >> 48) as u16, seq & SEQ_CTR_MASK)
}

/// Next counter value: saturates at 48 bits (the saturated regime
/// yields duplicate seqs, which §5.2 rule 2 taints as
/// NESTED-PARTIAL — honest degradation in an unreachable regime).
pub const fn seq_ctr_next(ctr: u64) -> u64 {
    if ctr >= SEQ_CTR_MAX {
        SEQ_CTR_MAX
    } else {
        ctr + 1
    }
}

pub const fn birth_frozen(birth: u16) -> bool {
    birth == BIRTH_FROZEN
}

/// Per-key aggregate. `count` saturates (never wraps);
/// `first_ns`/`last_ns` are `bpf_ktime_get_ns` window bounds, NOT
/// latency (latency is v2+). 24 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountValue {
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

const _: () = assert!(size_of::<CountValue>() == 24);
const _: () = assert!(align_of::<CountValue>() == 8);

/// Typed map reads over the drain path. Sound: `repr(C)`, all-`u64`,
/// zero padding (size 24 = 3×8, asserted above), `Copy`.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CountValue {}

/// Userspace drain-side fold: saturating sum + min/max bounds.
#[cfg(feature = "user")]
impl CountValue {
    pub fn fold(&mut self, other: &CountValue) {
        if other.count == 0 {
            return;
        }
        let was_empty = self.count == 0;
        self.count = self.count.saturating_add(other.count);
        if was_empty || other.first_ns < self.first_ns {
            self.first_ns = other.first_ns;
        }
        if was_empty || other.last_ns > self.last_ns {
            self.last_ns = other.last_ns;
        }
    }
}

// Count wire ABI v2 (T07 kernel admission window): `WINDOW` is a
// 2-cell `Array<u64>` holding the monotonic admission interval
// `[start_ns, deadline_ns)` in `bpf_ktime_get_ns` time. A hit counts
// iff `start <= now < deadline`. The zeroed map admits nothing
// until userspace programs it at window open (fail-closed), and
// `TARGET=0` still closes the window unconditionally. The v1
// key/value shapes (`make_key`/`CountValue`) are unchanged, and
// `COUNTS` stays a bounded non-LRU hash: inserts past capacity fail
// into `DROPFAIL` (loud loss), entries are never evicted, and the
// count path performs no target-memory reads (entry-only).

/// Count wire-shape version. Bump with loader enforcement on any
/// incompatible count-map change.
pub const COUNT_ABI_VERSION: u32 = 2;

/// `WINDOW` cells. Userspace programs both at window open; BPF only
/// reads them.
pub const WINDOW_CELLS: u32 = 2;
pub const WINDOW_START: u32 = 0;
pub const WINDOW_DEADLINE: u32 = 1;

/// Open-ended deadline: admit everything at/after start.
pub const WINDOW_NO_DEADLINE: u64 = u64::MAX;

// Discovery wire ABI v2 (T02 classify-before-emission): the ring
// carries finite numeric class IDs plus internal structural join
// addresses only. Raw target name/argument bytes never cross; the
// kernel classifies bounded strings against observer-populated
// tables (`ALG_CLASS`/`TRIP_CLASS` maps) and emits
// `(class, status)` numerics. Both sides share these definitions,
// so wire drift is a compile error. The classifier logic below is
// generic over the table backend: BPF passes map lookups, host
// tests pass `HashMap` lookups over identically built tables.
//
// Endianness: same-host little-endian, embodied by the target pair
// (`bpfel-unknown-none` + x86-64). Map values serialize explicitly
// little-endian; no `transmute` crosses this boundary.

/// Discovery wire-shape version. Bump with loader enforcement on any
/// incompatible event change.
pub const DISCOVERY_ABI_VERSION: u32 = 2;

/// Ring event kinds (frozen). Kind 6 (`KIND_WALKDBG`) was retired in
/// ABI v2: walk-abort forensics left the ring (TRUNC bits keep the
/// abort signal), so decoders must reject kind 6.
pub const KIND_INIT_RET: u32 = 1;
pub const KIND_QUERY_RET: u32 = 2;
pub const KIND_ROW: u32 = 3;
pub const KIND_ALG: u32 = 4;
pub const KIND_TRIP: u32 = 5;
/// Scan-plane kinds (P7 item 3, members ring only): the §5.1
/// QUERY_CALL take record, the §5.3 QUERY_RET member-0 return
/// marker, and the §5.3 guard verdict. Fresh numbers — `KIND_QUERY_RET
/// = 2` is the sampler's row-shaped cursor marker on a different
/// ring, and aliasing it would corrupt any future shared decode.
/// v2 reshapes all events (item 7); the numbers stay.
pub const KIND_SCAN_CALL: u32 = 7;
pub const KIND_SCAN_RET: u32 = 8;
pub const KIND_GUARD: u32 = 9;

/// Kernel string-read windows (bytes, NUL-inclusive).
pub const ALG_WINDOW: usize = 128;
pub const TRIP_WINDOW: usize = 32;

/// Max `:`-separated alias segments classified per algorithm name.
/// Real provider alias lists hold a handful of segments (81-char
/// census max); longer lists emit `ALG_TRUNCATED` with weak failed
/// closed rather than silently dropping tail evidence.
pub const MAX_ALG_SEGMENTS: usize = 8;

/// Map-value name capacities (bytes). Population fails closed if the
/// registry outgrows them.
pub const MAX_ALG_NAME: usize = 36;
pub const MAX_TRIP_NAME: usize = 16;

/// Algorithm class for unregistered/overlong/unreadable primaries.
/// Never a valid registry index (asserted by protocol tests).
pub const OTHER_CLASS: u16 = u16::MAX;

/// Algorithm verdict statuses (u8 wire; strict vocabulary).
/// `ALG_UNREADABLE` is emitted by BPF when the string helper fails
/// (the pure [`classify_alg_with`] never returns it: its input is
/// already-read bytes, and saturation maps to `ALG_OVERLONG`).
pub const ALG_OK: u8 = 0;
pub const ALG_UNKNOWN: u8 = 1;
pub const ALG_OVERLONG: u8 = 2;
pub const ALG_TRUNCATED: u8 = 3;
pub const ALG_UNREADABLE: u8 = 4;
pub const ALG_MIXED: u8 = 5;

/// Trip verdict statuses (u8 wire; strict vocabulary).
pub const TRIP_OK: u8 = 0;
pub const TRIP_UNREADABLE: u8 = 1;
pub const TRIP_OVERLONG: u8 = 2;

/// `TRUNC[op]` walk-shape bits (T03: frozen here so BPF and
/// userspace share one vocabulary; the doc carries raw bits for
/// stability, `coverage::primary_reason` ranks them). Bits 1..32
/// are the historical walker signals; `TRUNC_NO_STORE` is new.
pub const TRUNC_ALGS: u64 = 1;
pub const TRUNC_DISPATCH: u64 = 2;
pub const TRUNC_WALK_READ: u64 = 4;
pub const TRUNC_WALK_EMPTY: u64 = 8;
pub const TRUNC_WALK_NOIMP: u64 = 16;
pub const TRUNC_WALK_NAME: u64 = 32;
/// `no_store` table: the provider forbids caching the array, so the
/// walker samples slot 0 only and never advances a persistent
/// counter across queries (T03 honesty: never COMPLETE).
pub const TRUNC_NO_STORE: u64 = 64;

/// `LOSS[src]` failure counters (T03: every ring-reserve and
/// map-update failure has a source-tagged counter; userspace forces
/// PARTIAL on any nonzero entry). Keys are these `u32` ids.
pub const LOSS_RING_ALG: u32 = 1;
pub const LOSS_RING_ROW: u32 = 2;
pub const LOSS_RING_TRIP: u32 = 3;
pub const LOSS_RING_INIT: u32 = 4;
pub const LOSS_MAP_QUERY_NEXT: u32 = 5;
pub const LOSS_MAP_TRUNC: u32 = 6;
pub const LOSS_MAP_CALLS: u32 = 7;
pub const LOSS_MAP_TRIP: u32 = 8;
pub const LOSS_MAP_LGCALLS: u32 = 9;
pub const LOSS_MAP_TERMD: u32 = 10;
pub const LOSS_PENDING_INIT_FULL: u32 = 11;
pub const LOSS_PENDING_QUERY_FULL: u32 = 12;
pub const LOSS_PENDING_INIT_MISS: u32 = 13;
pub const LOSS_PENDING_QUERY_MISS: u32 = 14;
pub const LOSS_INIT_SCAN: u32 = 15;
/// Member attach-cookie mismatch (P7 item 2): a member's baked slot
/// disagrees with its link cookie — a loader slot-permutation bug,
/// never a kernel event. Fail-closed: skip the slot, count it.
pub const LOSS_MEMBER_COOKIE: u32 = 16;
/// Scan-plane loss vocabulary (P7 item 3, §5.1/§5.3/§5.4): every
/// skip cause and every scan-plane failure has a source-tagged
/// counter (userspace forces PARTIAL on any nonzero entry).
/// 17–26 predate the ring trio; all fit the 32-cell LOSS map.
pub const LOSS_BIRTH_PENDING: u32 = 17;
pub const LOSS_SEQ_FULL: u32 = 18;
pub const LOSS_BIRTH_WRAP: u32 = 19;
pub const LOSS_SCAN_EVICTED: u32 = 20;
pub const LOSS_RETIRE_FAIL: u32 = 21;
pub const LOSS_GUARD_READ_ABORT: u32 = 22;
pub const LOSS_RING_PRESSURE: u32 = 23;
pub const LOSS_ENTRY_COOKIE: u32 = 24;
pub const LOSS_SCAN_CHURNED: u32 = 25;
pub const LOSS_SKIP_ALL: u32 = 26;
pub const LOSS_RING_CALL: u32 = 27;
pub const LOSS_RING_RET: u32 = 28;
pub const LOSS_RING_GUARD: u32 = 29;

/// Entry skip causes (P7 item 3): the `ScanCallEvent.flags` cause
/// field. 0 = admitted (no counter); each nonzero cause maps to
/// its loss-proof counter via [`loss_for_skip_cause`].
pub const SKIP_ADMITTED: u8 = 0;
pub const SKIP_BIRTH_PENDING: u8 = 1;
pub const SKIP_SEQ_FULL: u8 = 2;
pub const SKIP_BIRTH_WRAP: u8 = 3;
pub const SKIP_RING_PRESSURE: u8 = 4;
pub const SKIP_ALL: u8 = 5;
pub const SKIP_ENTRY_COOKIE: u8 = 6;

/// `ScanCallEvent.flags` layout: bit 0 = NESTED_HINT (advisory —
/// §5.2 rules corroborate); cause in bits 8..16; all other bits
/// reserved zero (parsers reject nonzero reserved bits).
pub const CALL_FLAG_NESTED_HINT: u32 = 1 << 0;
pub const CALL_CAUSE_SHIFT: u32 = 8;

pub const fn make_call_flags(hint: bool, cause: u8) -> u32 {
    ((hint as u32) & 1) | ((cause as u32) << CALL_CAUSE_SHIFT)
}

pub const fn split_call_flags(flags: u32) -> (bool, u8) {
    (flags & 1 != 0, ((flags >> CALL_CAUSE_SHIFT) & 0xFF) as u8)
}

/// Loss-proof counter for a skip cause (0 = none — admitted
/// queries are counted in CALLS, not LOSS). Callers only pass
/// parse-gated causes 0..=6.
pub const fn loss_for_skip_cause(cause: u8) -> u32 {
    match cause {
        SKIP_BIRTH_PENDING => LOSS_BIRTH_PENDING,
        SKIP_SEQ_FULL => LOSS_SEQ_FULL,
        SKIP_BIRTH_WRAP => LOSS_BIRTH_WRAP,
        SKIP_RING_PRESSURE => LOSS_RING_PRESSURE,
        SKIP_ALL => LOSS_SKIP_ALL,
        SKIP_ENTRY_COOKIE => LOSS_ENTRY_COOKIE,
        _ => 0,
    }
}

/// Member-entry attach cookie (P7 item 2, single source for BPF +
/// host): the loader attaches `member_entry` with this cookie and
/// `member_J` with cookie J; members peek the entry's PENDING record
/// under `pend_key` of this cookie. First non-member index.
pub const MEMBER_ENTRY_COOKIE: u64 = 512;

/// `TERMD[arr]` termination proof (T03): keyed by query-returned
/// array base, value packs the op (low 32) and the proven live-slot
/// count (high 32). Recorded exactly when the walker reads the
/// terminator (`names == 0`) — directly, or at slot 512 via the
/// overrun guard. `no_store` arrays are never recorded (uncacheable).
/// A table without proof is a prefix, never COMPLETE.
pub const fn make_termd(op: u32, len: u32) -> u64 {
    ((len as u64) << 32) | (op as u64)
}

/// Split a TERMD value back into (op, len).
pub const fn split_termd(v: u64) -> (u32, u32) {
    ((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32)
}

/// `PENDING_QUERY` entry→return pair (BPF-internal shape,
/// loader-pinned): the op plus the caller's `no_store` out-pointer,
/// dereferenced once at return. 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendQuery {
    pub op: u64,
    pub ns_ptr: u64,
}

const _: () = assert!(size_of::<PendQuery>() == 16);

/// `SCAN[tid]` record (P7 item 3, §5.1): one in-flight scan per
/// thread. The ENTRY prog is the sole writer (taker semantics);
/// members are peek-only readers. No T/proof fields (entry fires
/// before the array address exists — T lives in `T_CACHE`, proofs
/// in WALK-DONE/GUARD). 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRec {
    pub op: u64,
    pub ns_ptr: u64,
    pub seq: u64,
    pub expected: u32,
    pub _pad: u32,
    pub epoch: u64,
}

const _: () = assert!(size_of::<ScanRec>() == 40);
const _: () = assert!(align_of::<ScanRec>() == 8);

/// `T_CACHE[array]` entry (P7 item 3, §5.3): terminator index +
/// generation, single-userspace-writer. Members peek + validate
/// GEN (already in the walk path) and skip-silent past T.
/// 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCacheValue {
    pub t: u64,
    pub generation: u64,
}

const _: () = assert!(size_of::<TCacheValue>() == 16);

/// `CTRL[0]` session control (P7 item 3, §5.1/§5.4/§5.5):
/// userspace-owned EXPECTED / membership-epoch / SKIP-ALL /
/// governor threshold (bytes of ring headroom required to
/// admit). Programmed by the loader at attach. 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtrlValue {
    pub expected: u32,
    pub skip_all: u8,
    pub _pad: [u8; 3],
    pub epoch: u64,
    pub governor: u64,
}

const _: () = assert!(size_of::<CtrlValue>() == 24);
const _: () = assert!(align_of::<CtrlValue>() == 8);

/// Trip classes (u16 wire). Engine and load taxonomies share the
/// numeric space; the probe program (cookie context) selects the
/// decoder, so the values never mix.
pub const TRIP_OTHER: u16 = 0;
pub const ENGINE_DYNAMIC: u16 = 1;
pub const ENGINE_BUILTIN: u16 = 2;
pub const LOAD_LEGACY: u16 = 1;
pub const LOAD_DEFAULT: u16 = 2;
pub const LOAD_FIPS: u16 = 3;

/// Classified algorithm record: 40 bytes. `arr`/`idx` are the
/// internal structural join keys (array base + alg index) consumed
/// at relocation/attribution and never serialized. `gen` is the
/// producer-side incarnation cookie (F-H/H1): the value of
/// `GEN[arr]` when BPF emitted the record (0 when the map has no
/// entry yet — the array's first observation). The host drops any
/// record whose `gen` disagrees with the array's current
/// generation instead of attributing it against newer mappings.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgEvent {
    pub kind: u32,
    pub op: u32,
    pub class: u16,
    pub status: u8,
    pub weak: u8,
    pub _pad: u32,
    pub arr: u64,
    pub idx: u64,
    pub generation: u64,
}

const _: () = assert!(size_of::<AlgEvent>() == 40);
const _: () = assert!(align_of::<AlgEvent>() == 8);

/// Classified tripwire hit: 16 bytes. `cookie` selects the probe
/// (hence the taxonomy); `class`/`status` are the kernel verdict.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TripEvent {
    pub kind: u32,
    pub cookie: u32,
    pub class: u16,
    pub status: u8,
    pub _pad: u8,
    pub _pad2: u32,
}

const _: () = assert!(size_of::<TripEvent>() == 16);
const _: () = assert!(align_of::<TripEvent>() == 4);

/// Dispatch row: 48 bytes (no strings by construction). Shared
/// here so BPF cannot drift the layout. `gen` is the
/// producer-side incarnation cookie (F-H/H1): the value of
/// `GEN[arr]` when BPF emitted the row (0 when the map has no
/// entry yet — the array's first observation). The host drops any
/// row whose `gen` disagrees with the array's current generation
/// instead of attributing it against newer mappings.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowEvent {
    pub kind: u32,
    pub op: u32,
    pub funcid: u32,
    pub _pad: u32,
    pub addr: u64,
    pub aux: u64,
    pub idx: u64,
    pub generation: u64,
}

const _: () = assert!(size_of::<RowEvent>() == 48);
const _: () = assert!(align_of::<RowEvent>() == 8);

/// Init-return anchor report: 32 bytes (`addr` = query-fn address
/// for stage-2 attach, `aux` = attach cookie). Shrunk from the
/// 160-byte v1 generic event; the name payload is gone.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitRetEvent {
    pub kind: u32,
    pub op: u32,
    pub funcid: u32,
    pub _pad: u32,
    pub addr: u64,
    pub aux: u64,
}

const _: () = assert!(size_of::<InitRetEvent>() == 32);
const _: () = assert!(align_of::<InitRetEvent>() == 8);

/// Entry take record (P7 item 3, §5.1 QUERY_CALL): one per entry
/// hit, admitted or skipped-with-cause, so userspace sees every
/// attempt (skips are evidence, never silence). `seq` is the
/// birth:16|ctr:48 fold, minted only on the admit path (every
/// skip gate precedes the SEQ step, so all skips carry seq 0).
/// 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanCallEvent {
    pub kind: u32,
    pub op: u32,
    pub tid: u32,
    pub flags: u32,
    pub seq: u64,
}

const _: () = assert!(size_of::<ScanCallEvent>() == 24);
const _: () = assert!(align_of::<ScanCallEvent>() == 8);

/// Member-0 return marker (P7 item 3, §5.3 QUERY_RET): one per
/// admitted invocation, emitted early (a slot-0 read abort must
/// still present RET, else HOLE-0 is indistinguishable from
/// abort). rv == 0 sets EMPTY (COMPLETE-EMPTY, members 1..511
/// silent). 32 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRetEvent {
    pub kind: u32,
    pub op: u32,
    pub flags: u32,
    pub _pad: u32,
    pub arr: u64,
    pub generation: u64,
}

const _: () = assert!(size_of::<ScanRetEvent>() == 32);
const _: () = assert!(align_of::<ScanRetEvent>() == 8);

/// `ScanRetEvent.flags`: rv == 0 (COMPLETE-EMPTY).
pub const RET_FLAG_EMPTY: u32 = 1 << 0;

/// 511-guard verdict (P7 item 3, §5.3 T = 512 exception): member
/// 511 also reads slot 512 on warm-T==512 scans. EMPTY = clean-full
/// proof; VALID = contract violation (TRUNC_ALGS too); ERROR =
/// read-abort/UNKNOWN-TERMINATOR (LOSS_GUARD_READ_ABORT too,
/// re-covers on retry). 32 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardEvent {
    pub kind: u32,
    pub op: u32,
    pub verdict: u32,
    pub _pad: u32,
    pub arr: u64,
    pub generation: u64,
}

const _: () = assert!(size_of::<GuardEvent>() == 32);
const _: () = assert!(align_of::<GuardEvent>() == 8);

pub const GUARD_EMPTY: u32 = 0;
pub const GUARD_VALID: u32 = 1;
pub const GUARD_ERROR: u32 = 2;
pub const GUARD_VERDICT_MAX: u32 = GUARD_ERROR;

/// `ALG_CLASS` map value, keyed by FNV-1a-64 of the exact registry
/// spelling: 42 bytes. Membership is hash+exact-length (`len` is
/// checked; `name` is populated but unread — reserved; a byte
/// confirm does not fit the 6.12 verifier budget, see
/// `classify_alg_with`). `weak` is 0/1. `canon` is the
/// BPF-internal group id (H3: alias spellings share their
/// group's id, so multi-spelling lists stay OK while
/// cross-group lists mix — first-appearance order at table
/// build; only the mixed flag leaves the kernel).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgClassValue {
    pub class: u16,
    pub weak: u8,
    pub len: u8,
    pub canon: u16,
    pub name: [u8; MAX_ALG_NAME],
}

const _: () = assert!(size_of::<AlgClassValue>() == 42);
const _: () = assert!(align_of::<AlgClassValue>() == 2);

/// `TRIP_CLASS` map value, keyed by FNV-1a-64 of the exact pattern:
/// 22 bytes. Both taxonomy classes ride one entry (today's patterns
/// belong to exactly one taxonomy each, but the shape tolerates a
/// future shared spelling).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TripClassValue {
    pub engine: u16,
    pub load: u16,
    pub len: u16,
    pub name: [u8; MAX_TRIP_NAME],
}

const _: () = assert!(size_of::<TripClassValue>() == 22);
const _: () = assert!(align_of::<TripClassValue>() == 2);

/// Explicit little-endian map-value encodings for population (no
/// `transmute`: the byte layout is pinned here, once).
pub fn alg_value_bytes(v: &AlgClassValue) -> [u8; 42] {
    let mut b = [0u8; 42];
    b[0..2].copy_from_slice(&v.class.to_le_bytes());
    b[2] = v.weak;
    b[3] = v.len;
    b[4..6].copy_from_slice(&v.canon.to_le_bytes());
    b[6..6 + MAX_ALG_NAME].copy_from_slice(&v.name);
    b
}

pub fn trip_value_bytes(v: &TripClassValue) -> [u8; 22] {
    let mut b = [0u8; 22];
    b[0..2].copy_from_slice(&v.engine.to_le_bytes());
    b[2..4].copy_from_slice(&v.load.to_le_bytes());
    b[4..6].copy_from_slice(&v.len.to_le_bytes());
    b[6..6 + MAX_TRIP_NAME].copy_from_slice(&v.name);
    b
}

/// FNV-1a-64 (IETF draft-eastlake-fnv, non-cryptographic).
/// Algorithm membership is hash+exact-length (a 2^-64 accidental
/// collision misclassifies; adversarial preimages are infeasible
/// and moot — a hostile provider claims any name directly).
/// Within-table collisions stay impossible (population fails
/// closed). Trip membership keeps an exact byte confirm.
pub const FNV1A64_BASIS: u64 = 14695981039346656037;
const FNV1A64_PRIME: u64 = 1099511628211;

#[inline(always)]
pub const fn fnv1a64_step(h: u64, b: u8) -> u64 {
    (h ^ b as u64).wrapping_mul(FNV1A64_PRIME)
}

pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV1A64_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        h = fnv1a64_step(h, bytes[i]);
        i += 1;
    }
    h
}

// Verifier-shape contract for the classifiers below: the alg
// scan is ONE fixed 128-iteration pass, branchless except the
// unavoidable map-miss check per byte (masked arithmetic selects,
// never data branches — any per-byte branch multiplies states
// past the 1M-insn ceiling). The trip classifier below is a
// smaller two-loop shape (32 scan + 16 confirm, single segment)
// that fits the budget with plain branches. Matching is
// hash+length for alg (no byte confirm — see `classify_alg_with`),
// hash+exact-confirm for trip. Any check failure fails closed to
// "unknown segment", never to a partial decode.

/// Kernel algorithm verdict over one alias-list window.
pub struct AlgVerdict {
    pub class: u16,
    pub weak: bool,
    pub status: u8,
}

/// Classify one `:`-separated alias window (the string-helper slice:
/// no NUL inside, at most `ALG_WINDOW - 1` bytes). `saturated` is
/// true when the window filled completely, in which case the input
/// is `OVERLONG` without parsing (an exact-fit window and a
/// truncated read are indistinguishable — the helper forces NUL —
/// so saturation fails closed with no retained prefix).
///
/// `buf` is the full 128-byte window (BPF: the zero-initialized
/// stack array; host tests: zero-padded the same way) and `len` is
/// the live length within it (`len < ALG_WINDOW`; overlong inputs
/// return before the scan). `lookup` resolves a segment hash to
/// its populated table entry; BPF passes map lookups, host tests
/// pass `HashMap` lookups.
///
/// The label is the canonical minimum: the smallest class id
/// over ALL recognized segments (F-A/A5), never the primary
/// alone — alias order cannot change the verdict. Unrecognized
/// segments contribute nothing (weak still folds across every
/// matched segment, including weak-only table extras, which carry
/// `OTHER_CLASS` and can never win the minimum). `ALG_OK` iff at
/// least one segment is recognized and all recognized segments
/// share one group (H3); a list no segment of which the registry
/// knows is `ALG_UNKNOWN`, never a silent pick. A mixed-group
/// list keeps the min label but reports `ALG_MIXED` — the
/// ambiguity is explicit instead of collapsing silently.
/// (Hostile providers are out of model since they can claim any
/// name directly, exactly like hash preimages.) Groups are the
/// registry `group` strings (alias spellings share one group);
/// same-group multi-spelling lists stay OK.
///
/// Matching is hash+length: an FNV-1a-64 prefilter plus an exact
/// length check against the table entry. There is deliberately NO
/// byte-compare confirm: a variable stack index escaping the frame
/// is rejected outright (`query_return` insn 1208 on 6.12), and the
/// 128-way length partitioning times any inner byte loop exceeds
/// the 1M-insn verifier ceiling (F-BPF-1). Accepted residual: a
/// 2^-64 accidental hash collision misclassifies (within-table
/// collisions stay impossible — population fails closed, pinned by
/// test); adversarial preimages are infeasible (2^64) and moot (a
/// hostile provider claims any name directly). The trip classifier
/// below keeps its exact confirm (its 32x16 single-segment shape
/// fits the budget).
///
/// Verifier shape: ONE fixed 128-iteration scan, branchless except
/// the unavoidable map-miss check per byte. Every accumulator
/// updates arithmetically (masked selects — BPF has no `cmov`, so
/// the masks are explicit bit tricks, never `?:` and never data
/// branches): per-byte states stay ~4-8 (weak bit × mixed bit ×
/// hit/miss; first-seen stays a range) and merge across
/// iterations (counters stay ranges, hashes stay symbolic), so
/// the whole scan costs ~30k insns and exits with a handful of
/// states. Any data branch in the scan body (early exit, bounds
/// split, per-byte confirm) multiplies states past the ceiling —
/// keep the body straight-line; the trailing resolve and verdict
/// below may branch (shallow, outside the scan).
pub fn classify_alg_with<F>(
    buf: &[u8; ALG_WINDOW],
    len: usize,
    saturated: bool,
    lookup: F,
) -> AlgVerdict
where
    F: Fn(u64) -> Option<AlgClassValue>,
{
    if saturated || len >= ALG_WINDOW {
        return AlgVerdict {
            class: OTHER_CLASS,
            weak: false,
            status: ALG_OVERLONG,
        };
    }
    // Branchless single pass: hash each `:`-separated segment (FNV
    // streams byte by byte), resolve every segment end against the
    // table, fold class/weak/count arithmetically. The window reads
    // are infallible raw loads: `i` is a pure loop counter (fixed
    // offset per unrolled iteration, the phase-1-proven pattern),
    // always `< 128` = the array length (loop bound), and bytes at
    // or past `len` are zero (zero-init) and masked out of every
    // update below — never decoded.
    let mut h = FNV1A64_BASIS;
    let mut seg_len: u64 = 0;
    let mut seg_idx: u64 = 0;
    let mut class_min: u64 = OTHER_CLASS as u64;
    let mut weak_acc: u64 = 0;
    // Mixed detection (H3): first-seen group id + flag. The
    // `OTHER_CLASS` sentinel doubles as the unlatched marker —
    // recognized records never carry it (build-guarded), so no
    // separate seen bit (verifier states stay ~4-8, not ~8-16).
    let mut first_canon: u64 = OTHER_CLASS as u64;
    let mut mixed_acc: u64 = 0;
    let mut i: usize = 0;
    while i < ALG_WINDOW {
        // SAFETY: `i < ALG_WINDOW` (loop bound) indexes the array.
        let b = unsafe { *buf.as_ptr().add(i) };
        // ALU-only conditions (BPF has no `setcc`: even
        // `u64::from(x < y)` lowers to a branch, which would
        // partition ranges on every byte — these identities are
        // straight-line by construction; see the helpers).
        let active = alu_lt(i as u64, len as u64);
        let is_colon = alu_eq(b as u64, 0x3A) & active;
        // Resolve-attempt for the segment ending here (masked: only
        // a segment end in the first 8 with a length-ok hit
        // applies). The lookup runs unconditionally (map ops don't
        // branch); only the miss check branches (1/byte).
        let apply0 = is_colon & alu_lt(seg_idx, MAX_ALG_SEGMENTS as u64);
        if let Some(v) = lookup(h) {
            let len_ok = alu_eq(v.len as u64, seg_len) & alu_lt(seg_len, MAX_ALG_NAME as u64 + 1);
            let m = apply0 & len_ok;
            // Canonical minimum (F-A/A5): straight-line fold, no
            // per-segment branch — the scan stays in budget.
            let take = m & alu_lt(v.class as u64, class_min);
            class_min = select_u64(mask(take), v.class as u64, class_min);
            weak_acc |= (v.weak as u64) & m;
            // Mixed detection (H3): also straight-line. Only
            // RECOGNIZED records participate (`rec` excludes
            // OTHER-class weak-only extras); the first one latches
            // `first_canon`, later ones set the flag on group
            // difference. Single-group lists (incl. multi-spelling
            // alias lists) never set it.
            let rec = m & (1 - alu_eq(v.class as u64, OTHER_CLASS as u64));
            let latched = 1 - alu_eq(first_canon, OTHER_CLASS as u64);
            mixed_acc |= rec & latched & (1 - alu_eq(v.canon as u64, first_canon));
            let take_first = rec & (1 - latched);
            first_canon = select_u64(mask(take_first), v.canon as u64, first_canon);
        }
        // Fold this byte into the running segment (masked: past-`len`
        // bytes change nothing; a colon resets for the next one).
        let h_step = fnv1a64_step(h, b);
        h = select_u64(
            mask(is_colon),
            FNV1A64_BASIS,
            select_u64(mask(active), h_step, h),
        );
        seg_len = select_u64(mask(is_colon), 0, seg_len + active);
        seg_idx += is_colon;
        i += 1;
    }
    // Trailing segment (also the sole empty segment of empty input,
    // matching `str::split(':')` semantics incl. edge splits):
    // resolve + verdict with plain branches (shallow, outside the
    // scan — a handful of states).
    if seg_idx < MAX_ALG_SEGMENTS as u64 {
        if let Some(v) = lookup(h) {
            if v.len as u64 == seg_len && seg_len <= MAX_ALG_NAME as u64 {
                if (v.class as u64) < class_min {
                    class_min = v.class as u64;
                }
                weak_acc |= v.weak as u64;
                // H3: the trailing segment can only DIFFER from the
                // latched group — latching here would be a dead
                // store (no segments follow; the verdict reads
                // only mixed_acc). An unlatched scan means the
                // trailing segment is the sole group: not mixed.
                if v.class != OTHER_CLASS
                    && first_canon != OTHER_CLASS as u64
                    && v.canon as u64 != first_canon
                {
                    mixed_acc = 1;
                }
            }
        }
    }
    let total = seg_idx + 1;
    if total > MAX_ALG_SEGMENTS as u64 {
        // Pathological alias list: the canonical minimum over the
        // observed segments is kept, but weak fails closed —
        // unseen tail segments may be weak — and the status stays
        // explicit. TRUNCATED wins over MIXED (H3): the unseen
        // tail may hold anything, so mixed-ness over the observed
        // prefix is not the verdict.
        return AlgVerdict {
            class: class_min as u16,
            weak: true,
            status: ALG_TRUNCATED,
        };
    }
    let class = class_min as u16;
    AlgVerdict {
        class,
        weak: weak_acc != 0,
        status: if class == OTHER_CLASS {
            ALG_UNKNOWN
        } else if mixed_acc != 0 {
            ALG_MIXED
        } else {
            ALG_OK
        },
    }
}

/// All-ones mask for a 0/1 condition (explicit bit trick — BPF has
/// no `cmov`, so `?:`/`if` on data would branch; this is ALU-only).
/// The fence hides the range from the optimizer (which would use
/// it to form a `select`, and BPF lowers `select` to branches).
#[inline(always)]
fn mask(cond: u64) -> u64 {
    debug_assert!(cond <= 1);
    core::hint::black_box(cond).wrapping_neg()
}

/// Arithmetic select: `a` when `m` is all-ones, `b` when zero.
/// Written add/sub/and (NOT the `(a & m) | (b & !m)` idiom, which
/// the optimizer recognizes and lowers to a branch on BPF); every
/// intermediate is fenced so no comparison/select pattern forms.
/// Emits straight-line ALU; pinned by `alu_conditions_are_exact`.
#[inline(always)]
fn select_u64(m: u64, a: u64, b: u64) -> u64 {
    use core::hint::black_box;
    let m = black_box(m);
    let d = black_box(a).wrapping_sub(black_box(b));
    black_box(b).wrapping_add(black_box(d) & m)
}

/// `1` iff `x == 0`, else `0` — ALU-only (BPF has no `setcc`, so
/// even `u64::from(x == 0)` lowers to a branch). Identity: for
/// nonzero `x`, `x | -x` always has the top bit set; for zero it
/// is zero. Every intermediate is fenced (the optimizer folds the
/// naked idiom back to a comparison+branch); fences emit no code.
/// Pinned by `alu_conditions_are_exact` below; the classifier scan
/// depends on these compiling branchless (verify with
/// `llvm-objdump` after touching them).
#[inline(always)]
fn alu_is_zero(x: u64) -> u64 {
    use core::hint::black_box;
    let neg = black_box(black_box(x).wrapping_neg());
    let o = black_box(black_box(x) | neg);
    black_box(o >> 63) ^ 1
}

/// `1` iff `a == b`, else `0` — ALU-only (see [`alu_is_zero`]).
#[inline(always)]
fn alu_eq(a: u64, b: u64) -> u64 {
    alu_is_zero(core::hint::black_box(a) ^ core::hint::black_box(b))
}

/// `1` iff `a < b` (unsigned), else `0` — ALU-only (see
/// [`alu_is_zero`]). Identity: `a - b` borrows (top bit set) iff
/// `a < b`, provided `b - a <= u64::MAX / 2` (all classifier
/// operands are byte-scale — asserted).
#[inline(always)]
fn alu_lt(a: u64, b: u64) -> u64 {
    use core::hint::black_box;
    debug_assert!(a < (1 << 32) && b < (1 << 32));
    black_box(black_box(a).wrapping_sub(black_box(b))) >> 63
}

/// Trip taxonomy selected by the probe program (`trip_str0` watches
/// `ENGINE_by_id`, `trip_str1` watches provider loads).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TripTaxonomy {
    Engine,
    Load,
}

/// Kernel trip verdict over one argument window.
pub struct TripVerdict {
    pub class: u16,
    pub status: u8,
}

/// Classify one trip argument window (same window/saturation
/// contract as [`classify_alg_with`], single segment, no alias
/// splitting). Readable-but-unregistered input is `TRIP_OK` with
/// class `TRIP_OTHER` (matching the historical `other` counts);
/// only saturated windows are `TRIP_OVERLONG`. NULL/unreadable
/// arguments never reach this function: the probe emits
/// `TRIP_UNREADABLE` for them directly.
pub fn classify_trip_with<F>(
    arg: &[u8],
    saturated: bool,
    taxonomy: TripTaxonomy,
    lookup: F,
) -> TripVerdict
where
    F: Fn(u64) -> Option<TripClassValue>,
{
    if saturated || arg.len() >= TRIP_WINDOW {
        return TripVerdict {
            class: TRIP_OTHER,
            status: TRIP_OVERLONG,
        };
    }
    let mut h = FNV1A64_BASIS;
    let mut i: usize = 0;
    while i < TRIP_WINDOW {
        let b = match arg.get(i) {
            Some(b) => *b,
            None => break,
        };
        h = fnv1a64_step(h, b);
        i += 1;
    }
    if let Some(v) = lookup(h) {
        if v.len as usize == arg.len() && arg.len() <= MAX_TRIP_NAME {
            let mut i = 0usize;
            let mut same = true;
            while i < MAX_TRIP_NAME {
                if i >= arg.len() {
                    break;
                }
                if arg.get(i) != v.name.get(i) {
                    same = false;
                    break;
                }
                i += 1;
            }
            if same {
                let class = match taxonomy {
                    TripTaxonomy::Engine => v.engine,
                    TripTaxonomy::Load => v.load,
                };
                return TripVerdict {
                    class,
                    status: TRIP_OK,
                };
            }
        }
    }
    TripVerdict {
        class: TRIP_OTHER,
        status: TRIP_OK,
    }
}

/// Taxonomy decoders: known ids become their labels, anything else
/// is `None` (fail closed to a dropped hit, never to a wrong
/// specific class). Callers validate with cookie context right
/// after [`parse_trip_event`], since the class range is
/// taxonomy-relative.
pub fn engine_class_name(id: u16) -> Option<&'static str> {
    match id {
        ENGINE_DYNAMIC => Some("dynamic"),
        ENGINE_BUILTIN => Some("builtin"),
        TRIP_OTHER => Some("other"),
        _ => None,
    }
}

pub fn load_class_name(id: u16) -> Option<&'static str> {
    match id {
        LOAD_LEGACY => Some("legacy"),
        LOAD_DEFAULT => Some("default"),
        LOAD_FIPS => Some("fips"),
        TRIP_OTHER => Some("other"),
        _ => None,
    }
}

/// Strict wire-decode failures. Every rejection drops the event (and
/// logs); nothing rejected ever becomes a label or a count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireErr {
    Length,
    Kind,
    ClassRange,
    StatusRange,
    WeakRange,
    Contradiction,
}

fn read_event<T: Copy>(b: &[u8]) -> Option<T> {
    // Exact size: ring items are fixed-size reservations, so a short
    // OR oversized payload is corruption, never a longer variant.
    if b.len() != size_of::<T>() {
        return None;
    }
    // Sound: `T` is `repr(C)` all-integer (every bit pattern valid),
    // the length is exact, `read_unaligned` tolerates ring
    // alignment. Padding bytes are real (BPF zeroes `_pad`s).
    Some(unsafe { b.as_ptr().cast::<T>().read_unaligned() })
}

/// Kernel algorithm-status labels for row emission. Total over the
/// strict vocabulary; decode-time validation guarantees membership.
pub fn alg_status_name(s: u8) -> Option<&'static str> {
    match s {
        ALG_OK => Some("ok"),
        ALG_UNKNOWN => Some("unknown"),
        ALG_OVERLONG => Some("overlong"),
        ALG_TRUNCATED => Some("truncated"),
        ALG_UNREADABLE => Some("unreadable"),
        ALG_MIXED => Some("mixed"),
        _ => None,
    }
}

/// Decode one `AlgEvent`: exact length, kind, class range (`OTHER` or
/// a live registry index — `class_count` comes from the single
/// registry at runtime, never from the wire), strict status/weak
/// vocabularies, and combination validity (each status admits only
/// the classes/weak values the kernel actually emits with it).
pub fn parse_alg_event(b: &[u8], class_count: u16) -> Result<AlgEvent, WireErr> {
    let e: AlgEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_ALG {
        return Err(WireErr::Kind);
    }
    if e.class != OTHER_CLASS && e.class >= class_count {
        return Err(WireErr::ClassRange);
    }
    match e.status {
        ALG_OK | ALG_UNKNOWN | ALG_OVERLONG | ALG_TRUNCATED | ALG_UNREADABLE | ALG_MIXED => {}
        _ => return Err(WireErr::StatusRange),
    }
    if e.weak > 1 {
        return Err(WireErr::WeakRange);
    }
    let combo_ok = match e.status {
        ALG_OK | ALG_MIXED => e.class != OTHER_CLASS,
        ALG_UNKNOWN => e.class == OTHER_CLASS,
        ALG_OVERLONG | ALG_UNREADABLE => e.class == OTHER_CLASS && e.weak == 0,
        ALG_TRUNCATED => e.weak == 1,
        _ => false,
    };
    if !combo_ok {
        return Err(WireErr::Contradiction);
    }
    Ok(e)
}

/// Decode one `TripEvent`: exact length, kind, strict status, and
/// combination validity (non-OK statuses always pair with `OTHER`).
/// The class range itself is taxonomy-relative, so the caller
/// validates it via [`engine_class_name`]/[`load_class_name`] with
/// cookie context.
pub fn parse_trip_event(b: &[u8]) -> Result<TripEvent, WireErr> {
    let e: TripEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_TRIP {
        return Err(WireErr::Kind);
    }
    match e.status {
        TRIP_OK => {}
        TRIP_UNREADABLE | TRIP_OVERLONG => {
            if e.class != TRIP_OTHER {
                return Err(WireErr::Contradiction);
            }
        }
        _ => return Err(WireErr::StatusRange),
    }
    Ok(e)
}

/// Decode one `RowEvent` (`KIND_ROW`) or first-hit liveness record
/// (`KIND_QUERY_RET`, same shape). All remaining fields are opaque
/// internal join/relocation numerics.
pub fn parse_row_event(b: &[u8]) -> Result<RowEvent, WireErr> {
    let e: RowEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_ROW && e.kind != KIND_QUERY_RET {
        return Err(WireErr::Kind);
    }
    Ok(e)
}

/// Decode one `InitRetEvent` (stage-1 anchor report).
pub fn parse_init_ret_event(b: &[u8]) -> Result<InitRetEvent, WireErr> {
    let e: InitRetEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_INIT_RET {
        return Err(WireErr::Kind);
    }
    Ok(e)
}

/// Decode one `ScanCallEvent`: exact size + kind + cause range +
/// zero reserved flag bits (bit 0 hint, cause bits 8..16).
pub fn parse_scan_call_event(b: &[u8]) -> Result<ScanCallEvent, WireErr> {
    let e: ScanCallEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_SCAN_CALL {
        return Err(WireErr::Kind);
    }
    let (hint, cause) = split_call_flags(e.flags);
    if cause > SKIP_ENTRY_COOKIE {
        return Err(WireErr::StatusRange);
    }
    if e.flags != make_call_flags(hint, cause) {
        return Err(WireErr::StatusRange);
    }
    Ok(e)
}

/// Decode one `ScanRetEvent`: exact size + kind + EMPTY-only flags.
pub fn parse_scan_ret_event(b: &[u8]) -> Result<ScanRetEvent, WireErr> {
    let e: ScanRetEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_SCAN_RET {
        return Err(WireErr::Kind);
    }
    if e.flags & !RET_FLAG_EMPTY != 0 {
        return Err(WireErr::StatusRange);
    }
    Ok(e)
}

/// Decode one `GuardEvent`: exact size + kind + verdict range.
pub fn parse_guard_event(b: &[u8]) -> Result<GuardEvent, WireErr> {
    let e: GuardEvent = read_event(b).ok_or(WireErr::Length)?;
    if e.kind != KIND_GUARD {
        return Err(WireErr::Kind);
    }
    if e.verdict > GUARD_VERDICT_MAX {
        return Err(WireErr::StatusRange);
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let (c, g) = (0xDEAD_BEEF, 0x1234_5678);
        assert_eq!(split_key(make_key(c, g)), (c, g));
        assert_eq!(make_key(1, 0), 1 << 32);
    }

    #[test]
    fn alu_conditions_are_exact() {
        for x in [0, 1, 2, 57, 58, 59, 127, 128, 255, u64::MAX / 2, u64::MAX] {
            assert_eq!(alu_is_zero(x), u64::from(x == 0), "is_zero({x})");
        }
        for (a, b) in [
            (0, 0),
            (0, 1),
            (1, 0),
            (57, 58),
            (58, 58),
            (127, 128),
            (128, 128),
            (u64::MAX, u64::MAX),
            (u64::MAX - 1, u64::MAX),
        ] {
            assert_eq!(alu_eq(a, b), u64::from(a == b), "eq({a},{b})");
        }
        for (a, b) in [
            (0, 0),
            (0, 1),
            (1, 0),
            (0, 128),
            (127, 128),
            (128, 128),
            (128, 127),
            (36, 37),
            (37, 37),
            (8, 9),
            (255, 256),
            ((1 << 32) - 2, (1 << 32) - 1),
        ] {
            assert_eq!(alu_lt(a, b), u64::from(a < b), "lt({a},{b})");
        }
        assert_eq!(mask(0), 0);
        assert_eq!(mask(1), u64::MAX);
        assert_eq!(select_u64(u64::MAX, 11, 22), 11);
        assert_eq!(select_u64(0, 11, 22), 22);
    }

    #[test]
    fn hash_len_match_needs_no_confirm_bytes() {
        // The match inputs are (hash, len) only: a registered
        // (hash, len) matches without any byte compare (documented
        // 2^-64 residual — within-table collisions stay impossible,
        // pinned by the registry test).
        let mut name = [0u8; MAX_ALG_NAME];
        name[..3].copy_from_slice(b"MD5");
        let entry = AlgClassValue {
            class: 7,
            weak: 0,
            len: 3,
            canon: 9,
            name,
        };
        let md5 = fnv1a64(b"MD5");
        let lookup = |h: u64| if h == md5 { Some(entry) } else { None };
        let mut buf = [0u8; ALG_WINDOW];
        buf[..3].copy_from_slice(b"MD5");
        let v = classify_alg_with(&buf, 3, false, lookup);
        assert_eq!((v.class, v.status), (7, ALG_OK));
        // Unregistered names miss the hash and stay unknown.
        buf[..4].copy_from_slice(b"MD5X");
        let v = classify_alg_with(&buf, 4, false, lookup);
        assert_eq!(v.status, ALG_UNKNOWN);
    }

    #[cfg(feature = "user")]
    #[test]
    fn fold_bounds() {
        let mut a = CountValue {
            count: 2,
            first_ns: 10,
            last_ns: 20,
        };
        a.fold(&CountValue {
            count: 3,
            first_ns: 5,
            last_ns: 15,
        });
        assert_eq!(
            a,
            CountValue {
                count: 5,
                first_ns: 5,
                last_ns: 20
            }
        );
        a.fold(&CountValue {
            count: u64::MAX,
            first_ns: 0,
            last_ns: 99,
        });
        assert_eq!(a.count, u64::MAX);
        assert_eq!((a.first_ns, a.last_ns), (0, 99));
    }

    #[test]
    fn scan_wire_shapes() {
        // Map-value + event layouts (P7 item 3 §2): exact wire.
        assert_eq!(size_of::<ScanRec>(), 40);
        assert_eq!(align_of::<ScanRec>(), 8);
        assert_eq!(size_of::<TCacheValue>(), 16);
        assert_eq!(size_of::<CtrlValue>(), 24);
        assert_eq!(align_of::<CtrlValue>(), 8);
        assert_eq!(size_of::<ScanCallEvent>(), 24);
        assert_eq!(size_of::<ScanRetEvent>(), 32);
        assert_eq!(size_of::<GuardEvent>(), 32);
        assert_eq!(
            (KIND_SCAN_CALL, KIND_SCAN_RET, KIND_GUARD),
            (7, 8, 9),
            "fresh kinds, no sampler aliasing"
        );
        // Tuples cap at 12 for PartialEq — two asserts.
        assert_eq!(
            (
                LOSS_BIRTH_PENDING,
                LOSS_SEQ_FULL,
                LOSS_BIRTH_WRAP,
                LOSS_SCAN_EVICTED,
                LOSS_RETIRE_FAIL,
                LOSS_GUARD_READ_ABORT,
                LOSS_RING_PRESSURE,
            ),
            (17, 18, 19, 20, 21, 22, 23)
        );
        assert_eq!(
            (
                LOSS_ENTRY_COOKIE,
                LOSS_SCAN_CHURNED,
                LOSS_SKIP_ALL,
                LOSS_RING_CALL,
                LOSS_RING_RET,
                LOSS_RING_GUARD
            ),
            (24, 25, 26, 27, 28, 29)
        );
    }

    #[test]
    fn seq_fold_unfold_saturates() {
        assert_eq!(split_seq(make_seq(1, 0)), (1, 0));
        assert_eq!(
            split_seq(make_seq(0xABCD, (1 << 48) - 1)),
            (0xABCD, (1 << 48) - 1)
        );
        // ctr wider than 48 bits truncates into the fold (callers
        // saturate before folding — never wrap-and-reuse).
        assert_eq!(split_seq(make_seq(2, 1 << 48)), (2, 0));
        assert_eq!(seq_ctr_next((1 << 48) - 1), (1 << 48) - 1, "saturates");
        assert_eq!(seq_ctr_next(41), 42);
        assert!(!birth_frozen(0));
        assert!(!birth_frozen(u16::MAX - 1));
        assert!(birth_frozen(u16::MAX), "MAX birth freezes the tid");
    }

    #[test]
    fn skip_cause_vocabulary() {
        // Every skip cause maps to its loss-proof counter.
        assert_eq!(
            (
                SKIP_ADMITTED,
                SKIP_BIRTH_PENDING,
                SKIP_SEQ_FULL,
                SKIP_BIRTH_WRAP,
                SKIP_RING_PRESSURE,
                SKIP_ALL,
                SKIP_ENTRY_COOKIE
            ),
            (0, 1, 2, 3, 4, 5, 6)
        );
        assert_eq!(loss_for_skip_cause(SKIP_BIRTH_PENDING), LOSS_BIRTH_PENDING);
        assert_eq!(loss_for_skip_cause(SKIP_SEQ_FULL), LOSS_SEQ_FULL);
        assert_eq!(loss_for_skip_cause(SKIP_BIRTH_WRAP), LOSS_BIRTH_WRAP);
        assert_eq!(loss_for_skip_cause(SKIP_RING_PRESSURE), LOSS_RING_PRESSURE);
        assert_eq!(loss_for_skip_cause(SKIP_ALL), LOSS_SKIP_ALL);
        assert_eq!(loss_for_skip_cause(SKIP_ENTRY_COOKIE), LOSS_ENTRY_COOKIE);
        // CALL flags: hint bit + cause nibble roundtrip.
        assert_eq!(
            split_call_flags(make_call_flags(true, SKIP_SEQ_FULL)),
            (true, SKIP_SEQ_FULL)
        );
        assert_eq!(
            split_call_flags(make_call_flags(false, SKIP_ADMITTED)),
            (false, SKIP_ADMITTED)
        );
    }

    #[test]
    fn scan_event_parse_strict() {
        // Roundtrips.
        let call = ScanCallEvent {
            kind: KIND_SCAN_CALL,
            op: 3,
            tid: 4242,
            flags: make_call_flags(true, SKIP_RING_PRESSURE),
            seq: make_seq(7, 9),
        };
        let cb = struct_bytes::<_, 24>(&call);
        assert_eq!(parse_scan_call_event(&cb), Ok(call));
        let ret = ScanRetEvent {
            kind: KIND_SCAN_RET,
            op: 3,
            flags: RET_FLAG_EMPTY,
            _pad: 0,
            arr: 0x5000,
            generation: 0,
        };
        let rb = struct_bytes::<_, 32>(&ret);
        assert_eq!(parse_scan_ret_event(&rb), Ok(ret));
        let guard = GuardEvent {
            kind: KIND_GUARD,
            op: 3,
            verdict: GUARD_VALID,
            _pad: 0,
            arr: 0x5000,
            generation: 0,
        };
        let gb = struct_bytes::<_, 32>(&guard);
        assert_eq!(parse_guard_event(&gb), Ok(guard));
        // Rejections: short, wrong kind, out-of-range cause /
        // verdict, nonzero reserved flag bits.
        assert_eq!(parse_scan_call_event(&cb[..8]), Err(WireErr::Length));
        let mut bad = cb;
        bad[0..4].copy_from_slice(&KIND_ROW.to_le_bytes());
        assert_eq!(parse_scan_call_event(&bad), Err(WireErr::Kind));
        let mut bad = cb;
        bad[12..16].copy_from_slice(&make_call_flags(false, 7).to_le_bytes());
        assert_eq!(parse_scan_call_event(&bad), Err(WireErr::StatusRange));
        let mut bad = cb;
        bad[12..16].copy_from_slice(&0x02u32.to_le_bytes());
        assert_eq!(parse_scan_call_event(&bad), Err(WireErr::StatusRange));
        let mut bad = rb;
        bad[8..12].copy_from_slice(&0x02u32.to_le_bytes());
        assert_eq!(parse_scan_ret_event(&bad), Err(WireErr::StatusRange));
        let mut bad = gb;
        bad[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(parse_guard_event(&bad), Err(WireErr::StatusRange));
    }

    /// Native-endian struct bytes (same-host wire, like the ring).
    fn struct_bytes<T: Copy, const N: usize>(v: &T) -> [u8; N] {
        assert_eq!(size_of::<T>(), N);
        let mut b = [0u8; N];
        unsafe { b.as_mut_ptr().cast::<T>().write_unaligned(*v) };
        b
    }
}
