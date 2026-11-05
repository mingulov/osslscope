//! SPDX-License-Identifier: GPL-2.0-only
//! Namespace-aware retained learned-site execution counter.
//!
//! One program, `count_entry`, attached via `uprobe_multi` to every
//! retained callback object/offset with an observer lifetime cookie.
//! Each hit records cookie+`GEN[0]` into the per-cpu `COUNTS` hash
//! (userspace sums across CPUs at drain). The `TARGET` tgid guard
//! resolves tasks through the public helper in the observer PID
//! coordinate and rejects foreign tasks. `TARGET[0] == 0` closes the
//! window in-kernel (`--duration` expiry). The `WINDOW` monotonic
//! interval admits hits only inside the declared `[start, deadline)`
//! (`bpf_ktime_get_ns`): pre-window and late hits drop even when
//! userspace stalls, so blocked discovery cannot extend counting.
//! Insert failures (map full) increment `DROPFAIL` — no eviction
//! EVER (fail loud, never misattribute). Capture reads NOTHING from
//! target memory: the cookie is an attach-time constant, counts are
//! kernel-side.
//!
//! BPF wire records and `WINDOW` cells use `osslscope-bpf-contract`.
//! Userspace retains separate ABI-compatible common types.
//!
//! The same handler also assigns at most one attribution partition per
//! stored physical hit through the shared typed producer maps (injected by
//! the host from the same FDs as the observation program). The partition
//! write runs only for admitted operational sites; every other hit keeps
//! exactly its physical behavior.
#![no_std]
#![no_main]
// BPF exposes no core AtomicU64 type; the pinned compiler intrinsics emit the
// actual 64-bit BPF atomic instructions for the shared sequence capture.
#![feature(core_intrinsics)]
#![allow(internal_features)]
#[path = "../shared_maps.rs"]
mod shared_maps;
// Only the same-handler operational check is live in this object; the typed
// entry/return state machine compiles out per object (verified by the
// per-object program/map manifest).
#[allow(dead_code)]
#[path = "../source_state.rs"]
mod source_state;
#[allow(dead_code)]
#[path = "../typed_producer.rs"]
mod typed_producer;
// The same-handler operational join resolves the firing callback through
// the current-VMA join; only the Code policy path links into this object.
#[allow(dead_code)]
#[path = "../source_vma.rs"]
mod source_vma;
#[path = "../writer_gate.rs"]
mod writer_gate;

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers,
    macros::{map, uprobe},
    maps::{Array, PerCpuArray, PerCpuHashMap},
    programs::ProbeContext,
    EbpfContext as _,
};
use osslscope_bpf_contract::{
    focused_namespace_admits, lat_bucket, make_key, BoundSlot, CountNamespace, CountValue,
    WINDOW_CELLS, WINDOW_DEADLINE, WINDOW_START,
};

/// `BPF_NOEXIST` for `insert` (kernel UAPI; aya-ebpf exposes no const).
const BPF_NOEXIST: u64 = 1;

/// Native observer namespace; target PID is numbered in this coordinate.
#[map]
static NS_CONFIG: Array<CountNamespace> = Array::with_max_entries(1, 0);
/// Public namespace-helper failures, independent of count admission.
#[map]
static NSFAIL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU keyed counts, bounded at 8192 lifetime keys.
#[map]
static COUNTS: PerCpuHashMap<u64, CountValue> = PerCpuHashMap::with_max_entries(8192, 0);

/// Generation epoch: userspace-bumped at every fence; BPF keys
/// every insert with `GEN[0]` so pre/post-fence counts never merge.
#[map]
static GEN: Array<u32> = Array::with_max_entries(1, 0);

/// Observed TGID guard (0 = closed, drop-all).
#[map]
static TARGET: Array<u64> = Array::with_max_entries(1, 0);

/// Monotonic admission interval `[start, deadline)` (cells
/// `WINDOW_START`/`WINDOW_DEADLINE`, `bpf_ktime_get_ns` time),
/// programmed once by userspace at window open. The zeroed map
/// admits nothing: hits before the declared start or at/after the
/// deadline drop in-BPF even when userspace stalls. Read-only to BPF.
#[map]
static WINDOW: Array<u64> = Array::with_max_entries(WINDOW_CELLS, 0);

/// BPF-side insert-fail count (map-full). Userspace sums across CPUs.
#[map]
static DROPFAIL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// BPF-side admitted-hits ledger (independent of `COUNTS`): one
/// per-CPU u64 bumped once per admitted hit (passed `TARGET` +
/// window), including `DROPFAIL` hits. Invariant (checked
/// userspace-side on every drain):
/// `ADMITTED == sum(COUNTS.count) + DROPFAIL`.
/// A second map drained through a second read path — shared
/// aggregation bugs cannot hide in both.
#[map]
static ADMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-hit admitted-path probe-body latency histogram (per-CPU
/// log2-ns buckets, `lat_bucket`), preserving the legacy slow-path
/// sampling semantics. This diagnostic is not performance qualification.
#[map]
static LATC: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

/// 6B sealed-bound slots: one per CPU per counted key (the
/// `COUNTS` key space, capacity-bounded below), two bound pairs
/// under one sequence word + the L1 generation tag. Every counted
/// hit also tags its bounds here; the host flips the epoch at
/// each window seal and consumes the sealed pair. Counts NEVER
/// depend on this map (a full `BOUNDS` loses bounds, never
/// counts).
#[map]
static BOUNDS: PerCpuHashMap<u64, BoundSlot> = PerCpuHashMap::with_max_entries(1024, 0);

/// 6B per-key per-CPU bound epoch (host-owned: BPF READS ONLY —
/// the host is the sole writer, so epoch flips never race BPF
/// count updates). Absent ⟺ `EPOCH_CUR` (below).
#[map]
static EPOCH: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(1024, 0);

/// 6B global epoch (host-owned, BPF-read-only): the currently
/// accumulating window generation. The host bumps this FIRST at
/// each seal, then sets every known key's per-CPU epoch; BPF tags
/// `EPOCH.get(key).unwrap_or(EPOCH_CUR)` so fresh keys always tag
/// the current generation.
#[map]
static EPOCH_CUR: Array<u64> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn count_entry(ctx: ProbeContext) -> u32 {
    let t0 = unsafe { helpers::bpf_ktime_get_ns() };
    if !writer_gate::admitted() {
        return 0;
    }
    let target = match TARGET.get(0) {
        Some(t) if *t != 0 => *t,
        _ => return 0,
    };
    let Some(ns) = NS_CONFIG.get(0) else {
        return 0;
    };
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let result = unsafe { helpers::bpf_get_ns_current_pid_tgid(ns.device, ns.inode, &mut ids, 8) };
    if result != 0 {
        if let Some(slot) = NSFAIL.get_ptr_mut(0) {
            unsafe {
                *slot = (*slot).saturating_add(1);
            }
        }
    }
    if !focused_namespace_admits(result, ids.tgid, target) {
        return 0;
    }
    // Declared-interval admission: the zeroed (unprogrammed) window
    // admits nothing; the deadline edge excludes. Cheap rejects run
    // before the attach-cookie fetch and map insert.
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    let start = WINDOW.get(WINDOW_START).copied().unwrap_or(0);
    let deadline = WINDOW.get(WINDOW_DEADLINE).copied().unwrap_or(0);
    if now < start || now >= deadline {
        return 0;
    }
    // Attribution snapshot, captured before the ledger, the physical store
    // and any attribution decision: selected owners and dependencies must
    // already be published in this snapshot.
    let entry_seq = typed_producer::capture_entry_seq();
    // Independent ledger: every hit admitted past TARGET + window,
    // including cookie-wide and map-full drops below.
    admitted();
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    // Lifetime cookies are u32 by construction; a wider cookie is a
    // userspace bug — counted in DROPFAIL, never truncated silently.
    if cookie > u32::MAX as u64 {
        dropfail();
        return 0;
    }
    let gen = match GEN.get(0) {
        Some(g) => *g,
        None => return 0,
    };
    let key = make_key(cookie as u32, gen);
    if let Some(slot) = COUNTS.get_ptr_mut(&key) {
        bump(slot, now);
        // 6B: tag the sealed-bound pair (bounds only — counts are
        // already kept above and never depend on this call).
        tag_bounds(&key, now);
        // At most one eligible partition in this same generation. A failed
        // attribution leaves the stored physical hit unresolved.
        let params = typed_producer::OpParams {
            cookie,
            tgid: ids.tgid,
            generation: gen,
            now_ns: now,
            entry_seq,
        };
        typed_producer::operational_check(&ctx, &params);
        return 0;
    }
    // Fresh-key slow path (F05/R04): bounded zero-seed + relookup.
    // Two CPUs can miss the same fresh key concurrently: both
    // insert here, one wins and the other takes EEXIST — but the
    // loser's per-CPU slot exists either way (a per-CPU hash
    // shares keys across CPUs; the winner's entry is already
    // visible), so the collision is recoverable: ignore the
    // insert result and resolve through one ordinary relookup. A
    // present slot counts this hit exactly once via the same
    // single bump as the fast path; a still-absent slot is
    // genuine exhaustion (map full) and stays DROPFAIL. No retry
    // loop: one insert + one lookup per miss, then done. (Per-CPU
    // keys are never removed, so a slot seen present cannot
    // vanish before the bump below.)
    let zero = CountValue {
        count: 0,
        first_ns: 0,
        last_ns: 0,
    };
    let _ = COUNTS.insert(&key, &zero, BPF_NOEXIST);
    if let Some(slot) = COUNTS.get_ptr_mut(&key) {
        bump(slot, now);
        // 6B slow path tags too (same single-tag rule as fast).
        tag_bounds(&key, now);
        // Same-generation partition assignment on the slow path too: the
        // physical store succeeded, so this hit is eligible exactly once.
        let params = typed_producer::OpParams {
            cookie,
            tgid: ids.tgid,
            generation: gen,
            now_ns: now,
            entry_seq,
        };
        typed_producer::operational_check(&ctx, &params);
    } else {
        dropfail();
    }
    let dt = unsafe { helpers::bpf_ktime_get_ns() }.saturating_sub(t0);
    if let Some(slot) = LATC.get_ptr_mut(lat_bucket(dt) as u32) {
        let c = unsafe { &mut *slot };
        *c = c.saturating_add(1);
    }
    0
}

/// The one ordinary per-CPU increment, shared by the fast path
/// and the slow-path relookup: stamp first touch (an ever-zero
/// first_ns poisons the userspace min-fold — including a fresh
/// zero-seeded slot), saturating-add one, stamp last.
#[inline(always)]
fn bump(slot: *mut CountValue, now: u64) {
    let v = unsafe { &mut *slot };
    if v.count == 0 {
        v.first_ns = now;
    }
    v.count = v.count.saturating_add(1);
    v.last_ns = now;
}

/// 6B bound tagging (one call per counted hit, both paths): tag
/// this hit's bounds into the pair selected by the slot's epoch.
/// Seqlock: odd before, even after. L1: bank writes apply only
/// when the updater epoch matches the tag (a mismatched tag
/// reinitializes — empties both pairs, adopts the generation —
/// before the write, so stale bounds never pollute a new window).
/// A missing `BOUNDS` slot (map full) drops the BOUNDS ONLY —
/// counts are already kept and `DROPFAIL` stays count-scoped.
#[inline(always)]
fn tag_bounds(key: &u64, now: u64) {
    // `EPOCH.get` reads THIS CPU's epoch (per-CPU semantics —
    // exactly the updater epoch for this slot); absent ⟺ the
    // global default. Sound: the returned reference borrows
    // map memory for the statement only, copied out immediately.
    let gen = match unsafe { EPOCH.get(key) } {
        Some(e) => *e,
        None => EPOCH_CUR.get(0).copied().unwrap_or(0),
    };
    let slot = match BOUNDS.get_ptr_mut(key) {
        Some(s) => s,
        None => {
            let zero = BoundSlot {
                seq: 0,
                tag: 0,
                pairs: [[0; 2]; 2],
            };
            let _ = BOUNDS.insert(key, &zero, BPF_NOEXIST);
            match BOUNDS.get_ptr_mut(key) {
                Some(s) => s,
                None => return,
            }
        }
    };
    let v = unsafe { &mut *slot };
    // Plain in-order stores (BPF executes in order; the existing
    // `bump` relies on the same — no fence instruction exists for
    // this target).
    v.seq = v.seq.wrapping_add(1);
    if v.tag != gen {
        v.pairs = [[0; 2]; 2];
        v.tag = gen;
    }
    let pair = &mut v.pairs[(gen & 1) as usize];
    if pair[0] == 0 {
        pair[0] = now;
    }
    pair[1] = now;
    v.seq = v.seq.wrapping_add(1);
}

fn dropfail() {
    if let Some(slot) = DROPFAIL.get_ptr_mut(0) {
        let c = unsafe { &mut *slot };
        *c = c.saturating_add(1);
    }
}

fn admitted() {
    if let Some(slot) = ADMITTED.get_ptr_mut(0) {
        let c = unsafe { &mut *slot };
        *c = c.saturating_add(1);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
