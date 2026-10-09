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

/// Trip classes (u16 wire). Engine and load taxonomies share the
/// numeric space; the probe program (cookie context) selects the
/// decoder, so the values never mix.
pub const TRIP_OTHER: u16 = 0;
pub const ENGINE_DYNAMIC: u16 = 1;
pub const ENGINE_BUILTIN: u16 = 2;
pub const LOAD_LEGACY: u16 = 1;
pub const LOAD_DEFAULT: u16 = 2;
pub const LOAD_FIPS: u16 = 3;

/// Classified algorithm record: 32 bytes. `arr`/`idx` are the
/// internal structural join keys (array base + alg index) consumed
/// at relocation/attribution and never serialized.
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
}

const _: () = assert!(size_of::<AlgEvent>() == 32);
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

/// Dispatch row: 40 bytes, unchanged shape (no strings by
/// construction). Shared here so BPF cannot drift the layout.
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
}

const _: () = assert!(size_of::<RowEvent>() == 40);
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

/// `ALG_CLASS` map value, keyed by FNV-1a-64 of the exact registry
/// spelling: 40 bytes. `name`/`len` exist so the kernel can confirm
/// an exact byte match after the hash prefilter (a hash hit alone
/// never establishes membership). `weak` is 0/1.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgClassValue {
    pub class: u16,
    pub weak: u8,
    pub len: u8,
    pub name: [u8; MAX_ALG_NAME],
}

const _: () = assert!(size_of::<AlgClassValue>() == 40);
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
pub fn alg_value_bytes(v: &AlgClassValue) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..2].copy_from_slice(&v.class.to_le_bytes());
    b[2] = v.weak;
    b[3] = v.len;
    b[4..4 + MAX_ALG_NAME].copy_from_slice(&v.name);
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

/// FNV-1a-64 (IETF draft-eastlake-fnv, non-cryptographic): a hash
/// prefilter only. Membership always requires the exact byte
/// confirm, so adversarial preimages cannot forge a class (and a
/// hostile provider can already claim any name directly).
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

// Verifier-shape contract for every loop below: bounds are
// compile-time constants, iteration breaks on runtime lengths, and
// every byte load carries its own dominating `.get()` check (no
// bare indexing off reloaded positions, no intermediate sub-slices
// whose validity the verifier must carry across calls). Any check
// failure fails closed to "unknown segment", never to a partial
// decode.

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
/// `lookup` resolves a segment hash to its populated table entry;
/// BPF passes map lookups, host tests pass `HashMap` lookups. Every
/// loop bound is a compile-time constant (verifier-safe); every
/// byte access is bounds-checked (`.get`, never bare indexing off a
/// runtime position).
pub fn classify_alg_with<F>(name: &[u8], saturated: bool, lookup: F) -> AlgVerdict
where
    F: Fn(u64) -> Option<AlgClassValue>,
{
    if saturated || name.len() >= ALG_WINDOW {
        return AlgVerdict {
            class: OTHER_CLASS,
            weak: false,
            status: ALG_OVERLONG,
        };
    }
    // Phase 1: single bounded pass — split on ':' while hashing each
    // segment (FNV streams byte by byte). Store (hash, start, len)
    // for the first segments; count the total for truncation.
    let mut hashes = [0u64; MAX_ALG_SEGMENTS];
    let mut starts = [0u8; MAX_ALG_SEGMENTS];
    let mut lens = [0u8; MAX_ALG_SEGMENTS];
    let mut total: usize = 0;
    let mut h = FNV1A64_BASIS;
    let mut seg_start: usize = 0;
    let mut i: usize = 0;
    while i < ALG_WINDOW {
        let b = match name.get(i) {
            Some(b) => *b,
            None => break,
        };
        if b == b':' {
            if total < MAX_ALG_SEGMENTS {
                hashes[total] = h;
                starts[total] = seg_start as u8;
                lens[total] = (i - seg_start) as u8;
            }
            total += 1;
            h = FNV1A64_BASIS;
            seg_start = i + 1;
        } else {
            h = fnv1a64_step(h, b);
        }
        i += 1;
    }
    // Trailing segment (also the sole empty segment of empty input,
    // matching `str::split(':')` semantics incl. edge splits).
    if total < MAX_ALG_SEGMENTS {
        hashes[total] = h;
        starts[total] = seg_start as u8;
        lens[total] = (i - seg_start) as u8;
    }
    total += 1;
    // Look one segment up: hash prefilter + exact byte confirm.
    // `None` (hash miss, length mismatch, byte mismatch, or any
    // bounds-check failure) is an unknown segment — never a partial
    // decode. Segments longer than any possible pattern cannot match
    // (population caps pattern length), so they skip the lookup.
    let resolve = |s: usize| -> Option<(u16, bool)> {
        let st = *starts.get(s)? as usize;
        let ln = *lens.get(s)? as usize;
        if ln > MAX_ALG_NAME {
            return None;
        }
        let v = lookup(*hashes.get(s)?)?;
        if v.len as usize != ln {
            return None;
        }
        let mut i = 0usize;
        while i < MAX_ALG_NAME {
            if i >= ln {
                break;
            }
            if name.get(st.saturating_add(i)) != v.name.get(i) {
                return None;
            }
            i += 1;
        }
        Some((v.class, v.weak != 0))
    };
    if total > MAX_ALG_SEGMENTS {
        // Pathological alias list: the primary (fully observed and
        // confirmed) is kept, but weak fails closed — unseen tail
        // segments may be weak — and the status stays explicit.
        let class = resolve(0).map(|(c, _)| c).unwrap_or(OTHER_CLASS);
        return AlgVerdict {
            class,
            weak: true,
            status: ALG_TRUNCATED,
        };
    }
    let mut class = OTHER_CLASS;
    let mut weak = false;
    let mut s = 0;
    while s < MAX_ALG_SEGMENTS {
        if s >= total {
            break;
        }
        if let Some((c, w)) = resolve(s) {
            if s == 0 {
                class = c;
            }
            weak |= w;
        }
        s += 1;
    }
    AlgVerdict {
        class,
        weak,
        status: if class == OTHER_CLASS {
            ALG_UNKNOWN
        } else {
            ALG_OK
        },
    }
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
        ALG_OK | ALG_UNKNOWN | ALG_OVERLONG | ALG_TRUNCATED | ALG_UNREADABLE => {}
        _ => return Err(WireErr::StatusRange),
    }
    if e.weak > 1 {
        return Err(WireErr::WeakRange);
    }
    let combo_ok = match e.status {
        ALG_OK => e.class != OTHER_CLASS,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let (c, g) = (0xDEAD_BEEF, 0x1234_5678);
        assert_eq!(split_key(make_key(c, g)), (c, g));
        assert_eq!(make_key(1, 0), 1 << 32);
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
}
