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
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers,
    macros::{map, uprobe},
    maps::{Array, PerCpuArray, PerCpuHashMap},
    programs::ProbeContext,
    EbpfContext as _,
};
use osslscope_bpf_contract::{
    focused_namespace_admits, lat_bucket, make_key, CountNamespace, CountValue, WINDOW_CELLS,
    WINDOW_DEADLINE, WINDOW_START,
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

#[uprobe]
pub fn count_entry(ctx: ProbeContext) -> u32 {
    let t0 = unsafe { helpers::bpf_ktime_get_ns() };
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
