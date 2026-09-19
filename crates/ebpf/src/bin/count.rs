//! SPDX-License-Identifier: GPL-2.0-only
//! Keyed execution-count probe (P2 capture; entry-only v1).
//!
//! One program, `count_entry`, attached via `uprobe_multi` to every
//! planned (path, offset) with the plan index as the attach cookie.
//! Each hit records cookie+`GEN[0]` into the per-cpu `COUNTS` hash
//! (userspace sums across CPUs at drain). The `TARGET` tgid guard
//! drops foreign tasks in-BPF (misattribution impossible — the
//! guard proof predates this file); `TARGET[0] == 0` closes the
//! window in-kernel (`--duration` expiry). Insert failures (map
//! full) increment `DROPFAIL` — no eviction EVER (fail loud, never
//! misattribute). Capture reads NOTHING from target memory: the
//! cookie is an attach-time constant, counts are kernel-side.
//!
//! Wire format (key/value structs) is owned by
//! `osslscope-ebpf-common` — shared with userspace, drift-proof.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, uprobe},
    maps::{Array, PerCpuArray, PerCpuHashMap},
    programs::ProbeContext,
    EbpfContext as _,
};
use osslscope_ebpf_common::{CountValue, make_key};

/// `BPF_NOEXIST` for `insert` (kernel UAPI; aya-ebpf exposes no const).
const BPF_NOEXIST: u64 = 1;

/// Per-cpu keyed counts. 8192 entries (8× the observed ~1K keys).
#[map]
static COUNTS: PerCpuHashMap<u64, CountValue> = PerCpuHashMap::with_max_entries(8192, 0);

/// Generation epoch: userspace-bumped at every fence; BPF keys
/// every insert with `GEN[0]` so pre/post-fence counts never merge.
#[map]
static GEN: Array<u32> = Array::with_max_entries(1, 0);

/// Observed TGID guard (0 = closed, drop-all).
#[map]
static TARGET: Array<u64> = Array::with_max_entries(1, 0);

/// BPF-side insert-fail count (map-full). Userspace sums across CPUs.
#[map]
static DROPFAIL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn count_entry(ctx: ProbeContext) -> u32 {
    let target = match TARGET.get(0) {
        Some(t) if *t != 0 => *t,
        _ => return 0,
    };
    let tgid = helpers::bpf_get_current_pid_tgid() >> 32;
    if tgid != target {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    // Plan indices are u32 by construction; a wider cookie is a
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
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    if let Some(slot) = COUNTS.get_ptr_mut(&key) {
        let v = unsafe { &mut *slot };
        // Fresh CPU slot (post-migration): stamp first touch — an
        // ever-zero first_ns poisons the userspace min-fold.
        if v.count == 0 {
            v.first_ns = now;
        }
        v.count = v.count.saturating_add(1);
        v.last_ns = now;
        return 0;
    }
    let fresh = CountValue { count: 1, first_ns: now, last_ns: now };
    if COUNTS.insert(&key, &fresh, BPF_NOEXIST).is_err() {
        dropfail();
    }
    0
}

fn dropfail() {
    if let Some(slot) = DROPFAIL.get_ptr_mut(0) {
        let c = unsafe { &mut *slot };
        *c = c.saturating_add(1);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
