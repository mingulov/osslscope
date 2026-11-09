// SPDX-License-Identifier: GPL-2.0-only
//! Public ABI producer. Target strings only exist in stack classifier scratch.
#![no_std]
#![no_main]
// BPF exposes no core AtomicU64 type; the pinned compiler intrinsics emit the
// actual 64-bit BPF atomic instructions, checked in the object receipt.
#![feature(core_intrinsics)]
#![allow(internal_features)]
#[path = "../shared_maps.rs"]
mod shared_maps;
#[path = "../source_registration.rs"]
mod source_registration;
#[path = "../source_state.rs"]
mod source_state;
#[path = "../typed_producer.rs"]
mod typed_producer;
// Code policy is retained unchanged for the subsequent copied callback join.
#[allow(dead_code)]
#[path = "../source_vma.rs"]
mod source_vma;
#[path = "../writer_gate.rs"]
mod writer_gate;
use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use osslscope_bpf_contract::{provider_observation::*, AlgClassValue, TripClassValue};
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);
#[map]
static CONFIG: HashMap<u64, Config> = HashMap::with_max_entries(1024, 0);
#[map]
static MEMBERS: HashMap<u32, Member> = HashMap::with_max_entries(64, 0);
#[map]
static NAMESPACE: Array<Namespace> = Array::with_max_entries(1, 0);
#[map]
static RANGES: HashMap<RangeKey, Range> = HashMap::with_max_entries(8192, 0);
#[map]
static THREADS: HashMap<ThreadKey, Thread> = HashMap::with_max_entries(4096, 0);
#[map]
static PENDING: HashMap<PendingKey, Pending> = HashMap::with_max_entries(4096, 0);
#[map]
static LOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);
#[map]
static ALG_CLASS: HashMap<u64, AlgClassValue> = HashMap::with_max_entries(1024, 0);
#[map]
static TRIP_CLASS: HashMap<u64, TripClassValue> = HashMap::with_max_entries(64, 0);
#[map]
static API_WINDOW: Array<Range> = Array::with_max_entries(1, 0);
#[map]
static TRACE_MODE: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static API_TOTALS: PerCpuHashMap<u64, ApiAggregate> = PerCpuHashMap::with_max_entries(1024, 0);
#[map]
static API_THREADS: HashMap<ApiThreadKey, Thread> = HashMap::with_max_entries(4096, 0);
// fix6 (R6-1): process-global creation-seed counter. THREADS-miss
// mints the row's identity here — the seed is STORED on the row
// (`Thread.seed`) and STAMPED on every record, joining the pairing
// key. (The fix5 design seeded `next` from this counter and claimed
// "never restarts" — R6-1 refuted it: unique seeds with OVERLAPPING
// ranges still mispair. Invocations restart at 1 per row BY DESIGN
// now, scoped by the seed: identity, not arithmetic.) BPF-internal;
// the host never reads or writes this map (it appears in the loader
// spec only so the object shape stays exact).
#[map]
static INV_SEQ: Array<u64> = Array::with_max_entries(1, 0);
// fix6 (R6-1): mint the next creation seed. Returns the PRE-add
// value (0 for the first-ever creation — legitimate, never gated).
// Implemented as a bounded CAS loop (the same `atomic_cxchg`
// pattern `source_state::claim_pending` already ships): a
// single-instruction fetch-add (`atomic_xadd` → XADD-with-fetch) is
// not expressible at the pinned `--cpu generic` (LLVM rejects use of
// the XADD return value), while cmpxchg on a 1-elem array value is
// already proven in this object. Each successful CAS hands out a
// unique seed, so issuance is strictly monotonic. Exhaustion (8
// consecutive races) or a saturated counter returns u64::MAX, which
// the entry path refuses WITHOUT creating a row (LOSS_DEPTH) —
// fail-closed, never a reused or sentinel seed. Wraparound past MAX
// is impossible: the CAS never advances a saturated counter.
#[inline(always)]
fn seed_next() -> u64 {
    use core::intrinsics::{atomic_cxchg, AtomicOrdering::SeqCst};
    let Some(cell) = INV_SEQ.get_ptr_mut(0) else {
        return u64::MAX;
    };
    let mut current = unsafe { atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(cell, 0, 0).0 };
    for _ in 0..8 {
        if current == u64::MAX {
            return u64::MAX;
        }
        let (observed, claimed) =
            unsafe { atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(cell, current, current + 1) };
        if claimed {
            return current;
        }
        current = observed;
    }
    u64::MAX
}
#[inline(always)]
fn api_increment(pointer: *mut u64) {
    // This non-preemptible program owns its CPU cell; no ring or raw operands.
    unsafe {
        *pointer = (*pointer).saturating_add(1);
    }
}
#[inline(never)]
#[no_mangle]
pub fn operational_entry(cookie: u64, key: &ThreadKey) {
    let Some(total) = API_TOTALS.get_ptr_mut(&cookie) else {
        loss(LOSS_MAP);
        return;
    };
    unsafe {
        api_increment(core::ptr::addr_of_mut!((*total).entries));
    }
    let ak = ApiThreadKey {
        thread: *key,
        cookie,
    };
    let mut state = unsafe { API_THREADS.get(&ak).copied() }.unwrap_or_default();
    if state.enter().is_none() {
        unsafe {
            api_increment(core::ptr::addr_of_mut!((*total).depth));
        }
    }
    if API_THREADS.insert(ak, state, 0).is_err() {
        unsafe {
            api_increment(core::ptr::addr_of_mut!((*total).map));
        }
    }
}
#[inline(never)]
#[no_mangle]
pub fn operational_return(cookie: u64, key: &ThreadKey, api: u32, rv: u64) {
    let Some(total) = API_TOTALS.get_ptr_mut(&cookie) else {
        loss(LOSS_MAP);
        return;
    };
    let ak = ApiThreadKey {
        thread: *key,
        cookie,
    };
    let Some(mut state) = (unsafe { API_THREADS.get(&ak).copied() }) else {
        unsafe {
            api_increment(core::ptr::addr_of_mut!((*total).unpaired));
        }
        return;
    };
    if state.skip_return() {
        if API_THREADS.insert(ak, state, 0).is_err() {
            unsafe {
                api_increment(core::ptr::addr_of_mut!((*total).map));
            }
        }
        return;
    }
    if state.depth == 0 {
        unsafe {
            api_increment(core::ptr::addr_of_mut!((*total).unpaired));
        }
        return;
    }
    state.depth -= 1;
    let changed = if state.depth == 0 {
        API_THREADS.remove(&ak)
    } else {
        API_THREADS.insert(ak, state, 0)
    };
    if changed.is_err() {
        unsafe {
            api_increment(core::ptr::addr_of_mut!((*total).map));
        }
        return;
    }
    unsafe {
        match operational_outcome(api, rv) {
            1 => api_increment(core::ptr::addr_of_mut!((*total).success)),
            2 => api_increment(core::ptr::addr_of_mut!((*total).failure)),
            3 => {
                api_increment(core::ptr::addr_of_mut!((*total).failure));
                api_increment(core::ptr::addr_of_mut!((*total).mismatch));
            }
            4 => {
                api_increment(core::ptr::addr_of_mut!((*total).failure));
                api_increment(core::ptr::addr_of_mut!((*total).unsupported));
            }
            _ => api_increment(core::ptr::addr_of_mut!((*total).unsupported_return)),
        }
    }
}
/// §6D-0 D0-1 mode gate: unreadable/missing entry reads as off (fail-closed).
#[inline(always)]
fn trace_operational() -> bool {
    trace_edge_bearing(TRACE_MODE.get(0).copied().unwrap_or(TRACE_MODE_OFF))
}
#[inline(always)]
fn loss(n: u32) {
    if let Some(p) = LOSS.get_ptr_mut(n) {
        unsafe { *p = (*p).saturating_add(1) }
    }
}
#[inline(always)]
fn identity(cookie: u64) -> Option<(Config, ThreadKey)> {
    identity_inner(cookie, true)
}
/// fix7 (R7-3): closed-window probe — `Some` IFF the identity
/// resolves fully EXCEPT the operational window is closed. The
/// window arm is the ONLY rejection that keeps the call on this
/// row (every other arm — CONFIG/ns/task/tgid/member/
/// generation — means a different task or row and must not touch
/// it). Non-operational APIs never resolve here (their identity
/// has no window arm, so a failed `identity()` fails here too).
/// Never fires loss (the failed `identity()` already did, if the
/// task query failed). The window never reopens (programmed once
/// per capture), so a call rejected here stays rejected.
#[inline(always)]
fn identity_closed_window(cookie: u64) -> Option<(Config, ThreadKey)> {
    identity_inner(cookie, false)
}
#[inline(always)]
fn identity_inner(cookie: u64, enforce_window: bool) -> Option<(Config, ThreadKey)> {
    let cfg = unsafe { *CONFIG.get(&cookie)? };
    let ns = NAMESPACE.get(0)?;
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let rv = unsafe { helpers::bpf_get_ns_current_pid_tgid(ns.device, ns.inode, &mut ids, 8) };
    if rv != 0 {
        if enforce_window {
            loss(LOSS_NAMESPACE);
        }
        return None;
    }
    if ids.tgid != cfg.pid {
        return None;
    }
    let member = unsafe { *MEMBERS.get(&ids.tgid)? };
    if operational_api(cfg.api) {
        let window = API_WINDOW.get(0)?;
        let now = unsafe { helpers::bpf_ktime_get_ns() };
        let closed = now < window.start || now >= window.end;
        if enforce_window && closed {
            return None;
        }
        if !enforce_window && !closed {
            return None;
        }
    }
    if member.generation != cfg.generation {
        return None;
    }
    Some((
        cfg,
        ThreadKey {
            pid: ids.tgid,
            tid: ids.pid,
            generation: cfg.generation,
        },
    ))
}
/// fix7 (R7-3): arm one blind tombstone for a closed-window
/// entry (out-of-line: the entry frame is stack-pressured and
/// this runs only on the cold reject path). fix8 (R8-2): the arm
/// is positional first — a blind marker slotted at the current
/// depth, LIFO-matched by the rejecting return (skip-safe: a
/// longjmp'd marker is discarded, never shifting frames). Marker
/// refusal (same-kind collision, quota, map) arms the fungible
/// tombstone — exactly the old arm. No row ⟹ no arm (a balanced
/// no-op: the return will find no row — or a fresh one with no
/// units — and likewise consume nothing).
#[inline(never)]
#[no_mangle]
pub fn blind_arm_entry(cookie: u64) {
    let Some((_, key)) = identity_closed_window(cookie) else {
        return;
    };
    let Some(mut thread) = (unsafe { THREADS.get(&key).copied() }) else {
        return;
    };
    let claimed = source_state::claim_pending();
    let placed = claimed
        && PENDING
            .insert(
                PendingKey {
                    thread: key,
                    depth: thread.depth,
                    reserved: PENDING_BLIND_MARKER,
                },
                Pending::marker(cookie),
                1,
            )
            .is_ok();
    if placed {
        return;
    }
    if claimed && !source_state::release_pending() {
        loss(LOSS_MAP);
    }
    thread.blind_entry();
    if THREADS.insert(key, thread, 0).is_err() {
        loss(LOSS_MAP);
    }
}
// Explicit output avoids aggregate-return ABI and keeps construction spills
// out of the query frame on kernels with a combined 512-byte stack limit.
// fix4: stamps the emitting task's incarnation (`task_struct.start_time`
// at the load-time-resolved `CONFIG.task_off`) into every record. Host
// pairing namespaces on the stamp, so recycled-tid edges never pair
// across incarnations in either recycle order. An unprogrammed or
// out-of-range offset stamps 0, which the host decoder rejects
// (fail-closed); the loader refuses to run with such an offset.
//
// The stamp is computed ONCE per program at the top level and threaded
// down: inlining the task-read CFG into `base` re-verifies it at every
// emission site and doubles program-load time (verifier state explosion).
#[inline(never)]
#[no_mangle]
pub fn base(p: &Pending, t: &ThreadKey, kind: u32, out: &mut Record, stamp: u64) {
    *out = Record {
        version: VERSION,
        kind,
        size: EVENT_SIZE as u32,
        api: p.api,
        pid: t.pid,
        tid: t.tid,
        cookie: p.cookie,
        generation: t.generation,
        monotonic_ns: unsafe { helpers::bpf_ktime_get_ns() },
        invocation: p.invocation,
        ..Record::default()
    };
    out.start_time_ns = stamp;
    // fix6 (R6-1): the seed is NOT set here — BPF subprograms take
    // at most 5 arguments, so every `base` call site assigns
    // `r.seed` itself (entry: its row's seed; returns:
    // `pop_return`'s live row seed, threaded like the stamp).
    // Derived emissions (INIT/QUERY/IMPLEMENTATION/ALIAS walks)
    // inherit it from the `base`-built record they reuse.
}
#[inline(always)]
fn incarnation_stamp(cookie: u64) -> u64 {
    let off = unsafe { CONFIG.get(&cookie).map(|c| c.task_off).unwrap_or(0) };
    // The bound is load-bearing for the verifier (an unbounded
    // scalar added to the task pointer is rejected) as well as
    // defense in depth (the loader validates first).
    if off == 0 || off > TASK_OFF_MAX {
        return 0;
    }
    let task = unsafe { helpers::generated::bpf_get_current_task_btf() };
    if task.is_null() {
        return 0;
    }
    let addr = (task as u64).wrapping_add(off);
    unsafe { helpers::bpf_probe_read_kernel(addr as *const u64) }.unwrap_or(0)
}
#[inline(never)]
#[no_mangle]
pub fn emit(r: &Record) {
    if let Some(mut slot) = EVENTS.reserve::<Record>(0) {
        slot.write(*r);
        slot.submit(0)
    } else {
        loss(LOSS_RING)
    }
}
#[inline(never)]
#[no_mangle]
pub fn code_ok(pid: u32, address: u64) -> bool {
    let Some(member) = (unsafe { MEMBERS.get(&pid) }) else {
        return false;
    };
    code_in_ranges(address, member.range_count, |index| unsafe {
        RANGES.get(&RangeKey { pid, index }).copied()
    })
}
#[inline(never)]
#[no_mangle]
pub fn provider_name(pointer: u64) -> u32 {
    let mut buf = [0u8; 32];
    let len =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(pointer as *const u8, &mut buf) } {
            Ok(v) => v.len(),
            Err(_) => return 4,
        };
    provider_name_class(&buf, len)
}
/// Typed producer entry: normalize the caller into the observer namespace
/// and stage/invalidate through the typed state machine. Never attached
/// unless the host programmed typed admission for this site.
#[uprobe]
pub fn typed_entry(ctx: ProbeContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let Some(ns) = NAMESPACE.get(0) else {
        return 0;
    };
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    if unsafe { helpers::bpf_get_ns_current_pid_tgid(ns.device, ns.inode, &mut ids, 8) } != 0 {
        return 0;
    }
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    typed_producer::typed_entry(&ctx, cookie, ids.tgid, ids.pid, now)
}

/// Typed producer return: pair the staged frame and publish or stage the
/// role's evidence. Never attached unless the host programmed typed
/// admission for this site.
#[uretprobe]
pub fn typed_return(ctx: RetProbeContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let Some(ns) = NAMESPACE.get(0) else {
        return 0;
    };
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    if unsafe { helpers::bpf_get_ns_current_pid_tgid(ns.device, ns.inode, &mut ids, 8) } != 0 {
        return 0;
    }
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    typed_producer::typed_return(&ctx, cookie, ids.tgid, ids.pid, now)
}
#[uprobe]
pub fn observation_entry(ctx: ProbeContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let Some((cfg, key)) = identity(cookie) else {
        // fix7 (R7-3): a closed-window entry arms its blind unit
        // (fix8: a positional T-marker first, the fungible
        // tombstone on marker refusal; no-op for every other
        // rejection arm); the call still executes unobserved.
        blind_arm_entry(cookie);
        return 0;
    };
    // fix4: single stamp per program, threaded to every emission site.
    // The return probe's cookie always equals the stored entry cookie
    // (`pop_return` rejects mismatches), so this is the same CONFIG
    // lookup `base` used to do — without re-verifying the task-read
    // CFG at each of the eight emission sites.
    let stamp = incarnation_stamp(cookie);
    if operational_api(cfg.api) {
        operational_entry(cookie, &key);
        if !trace_operational() {
            return 0;
        }
        // Edge-bearing: fall through to the shared Pending/emit path (D0-2/D0-3).
    }
    // fix6 (R6-1 + R6-4 primary): the row remembers its creation
    // seed. `seed_next()` mints a fresh identity; MAX (CAS
    // exhaustion or a saturated counter) REFUSES without creating
    // any row (LOSS_DEPTH) — no row, no record, never a sentinel
    // seed. Otherwise the row is born `{ seed: s, next: 0, ... }`:
    // invocations restart at 1 per row BY DESIGN (scoped by the
    // seed — the fix5 "never restarts" claim INVERTS). `depth`/
    // `overflow`/`blind` keep resetting: the old incarnation's
    // nesting died with its row (outstanding blind tombstones die
    // with it too — their returns find a fresh row with no units
    // and consume nothing, a balanced no-op), and depth overflow
    // reports LOSS_DEPTH at enter time (the None arm below) rather
    // than inheriting a stale counter.
    let mut thread = match unsafe { THREADS.get(&key).copied() } {
        Some(thread) => thread,
        None => {
            let s = seed_next();
            if s == u64::MAX {
                loss(LOSS_DEPTH);
                return 0;
            }
            Thread {
                seed: s,
                next: 0,
                depth: 0,
                overflow: 0,
                blind: 0,
                counter_known: 0,
                counter_owner: 0,
            }
        }
    };
    let old_depth = thread.depth;
    let Some(invocation) = thread.enter_frame() else {
        // fix6 (R6-4 backstop): a None with `next == MAX` DELETES
        // the row instead of inserting it — persisting a MAX row
        // would wedge every later entry (returns clear only
        // `overflow`/`blind`, never `next`), turning transient CAS
        // exhaustion into permanent per-thread blindness.
        // Creation-time refusal (above) makes fresh MAX rows
        // unreachable; a pre-existing MAX row needs 2^64 emits
        // (unreachable) — the delete is pure defense in depth,
        // distinguished by `next`, not freshness. fix8 (R8-2):
        // every other None slots a positional overflow marker when
        // it can (LIFO-matched pops, skip-safe); marker refusal
        // (same-kind collision, quota, map) arms the fungible
        // counter — exactly the old Insert arm. The row is
        // pre-existing here (a fresh row never refuses a frame),
        // so a placed marker writes no row.
        if enter_none_disposition(thread.next) == EnterNoneDisposition::Delete {
            if THREADS.remove(&key).is_err() {
                loss(LOSS_MAP)
            }
            loss(LOSS_DEPTH);
            return 0;
        }
        let claimed = source_state::claim_pending();
        let placed = claimed
            && PENDING
                .insert(
                    PendingKey {
                        thread: key,
                        depth: old_depth,
                        reserved: PENDING_OVERFLOW_MARKER,
                    },
                    Pending::marker(cookie),
                    1,
                )
                .is_ok();
        if !placed {
            if claimed && !source_state::release_pending() {
                loss(LOSS_MAP);
            }
            thread.overflow = thread.overflow.saturating_add(1);
            // R10 1b: record fallback OWNERSHIP with the unit
            // (ownership subsumes the R9 position probe: only
            // the recorded owner's return consumes before
            // popping; every other return pops its own slot
            // first). Covers collision, quota, and map refusal
            // uniformly — the record names the armer, not the
            // refusal cause.
            thread.record_counter_owner(cookie);
            if THREADS.insert(key, thread, 0).is_err() {
                loss(LOSS_MAP)
            }
        }
        loss(LOSS_DEPTH);
        return 0;
    };
    let mut p = Pending {
        cookie,
        invocation,
        object: cfg.object,
        arg0: ctx.arg(0).unwrap_or(0),
        arg2: ctx.arg(2).unwrap_or(0),
        api: cfg.api,
        ..Pending::default()
    };
    if query_api(p.api) {
        p.operation = known_operation(ctx.arg::<u32>(1).unwrap_or(0));
    }
    if load_api(p.api) || p.api == ADD_BUILTIN {
        p.name = provider_name(ctx.arg(1).unwrap_or(0));
    }
    if old_depth > 0 && load_api(p.api) {
        let parent = unsafe {
            PENDING.get(&PendingKey {
                thread: key,
                depth: old_depth - 1,
                reserved: PENDING_FRAME,
            })
        };
        if let Some(parent) = parent {
            // Same-API recursion remains distinct. Different wrapper API collapses only
            // for the same object and library context; pointer stays inside this map.
            if suppress_wrapper(parent, &p) {
                p.suppressed = 1;
            }
        }
    }
    let pk = PendingKey {
        thread: key,
        depth: old_depth,
        reserved: PENDING_FRAME,
    };
    if !source_state::claim_pending() {
        thread.failed_entry();
        // R10 1b: the failed call's counter unit records its
        // owner like any fallback.
        thread.record_counter_owner(cookie);
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        loss(LOSS_MAP);
        return 0;
    }
    if PENDING.insert(pk, p, 1).is_err() {
        // No new frame exists. Refund only our successful quota claim.
        if !source_state::release_pending() {
            loss(LOSS_MAP);
        }
        thread.failed_entry();
        // R10 1b: same owner recording as the claim-failure arm
        // above.
        thread.record_counter_owner(cookie);
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        loss(LOSS_MAP);
        return 0;
    }
    if THREADS.insert(key, thread, 0).is_err() {
        if PENDING.remove(&pk).is_ok() && !source_state::release_pending() {
            loss(LOSS_MAP);
        }
        loss(LOSS_MAP);
        return 0;
    }
    if p.suppressed == 0
        && !matches!(
            p.api,
            PROVIDER_INIT
                | GET_DISPATCH
                | PUBLIC_QUERY
                | QUERY_CALLBACK
                | PUBLIC_UNQUERY
                | TEARDOWN
                | UNQUERY_CALLBACK
        )
    {
        let mut r = Record::default();
        base(&p, &key, ATTEMPT, &mut r, stamp);
        r.seed = thread.seed;
        r.status = p.name;
        emit(&r)
    }
    if matches!(p.api, PUBLIC_UNQUERY | TEARDOWN | UNQUERY_CALLBACK) {
        invalidate(
            &p,
            &key,
            if p.api == TEARDOWN { 3 } else { 2 },
            stamp,
            thread.seed,
        );
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn invalidate(p: &Pending, key: &ThreadKey, status: u32, stamp: u64, seed: u64) {
    // Invalidate advertisement leases, independently of retained code lifetimes.
    if let Some(member) = MEMBERS.get_ptr_mut(&key.pid) {
        unsafe { (*member).epoch = 0 }
    }
    let mut r = Record::default();
    base(p, key, INVALIDATION, &mut r, stamp);
    r.seed = seed;
    r.status = status;
    emit(&r);
}
#[inline(never)]
#[no_mangle]
pub fn init_return(p: &Pending, key: &ThreadKey, rv: u64, stamp: u64, seed: u64) {
    let mut r = Record::default();
    base(p, key, INIT, &mut r, stamp);
    r.seed = seed;
    r.outcome = int_outcome(rv);
    emit(&r);
    if r.outcome != 1 {
        return;
    }
    let table = match unsafe { helpers::bpf_probe_read_user(p.arg2 as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            return;
        }
    };
    walk_provider_dispatch(table, &mut r);
}
#[inline(never)]
#[no_mangle]
pub fn getter_return(p: &Pending, key: &ThreadKey, table: u64, stamp: u64, seed: u64) {
    let mut r = Record::default();
    base(p, key, INIT, &mut r, stamp);
    r.seed = seed;
    r.outcome = if table == 0 { 2 } else { 1 };
    emit(&r);
    if table != 0 {
        walk_provider_dispatch(table, &mut r);
    }
}
#[inline(never)]
#[no_mangle]
pub fn walk_provider_dispatch(table: u64, r: &mut Record) {
    let mut query = false;
    for i in 0..16u64 {
        let Some(base) = table.checked_add(i * 16) else {
            loss(LOSS_READ);
            return;
        };
        let fid = match unsafe { helpers::bpf_probe_read_user(base as *const u32) } {
            Ok(v) => v,
            Err(_) => {
                loss(LOSS_READ);
                return;
            }
        };
        if fid == 0 {
            if !query {
                loss(LOSS_TRUNC)
            }
            return;
        }
        if matches!(fid, 1024 | 1027 | 1028) {
            let address = match unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) } {
                Ok(v) => v,
                Err(_) => {
                    loss(LOSS_READ);
                    return;
                }
            };
            if !code_ok(r.pid, address) {
                loss(LOSS_RANGE);
                continue;
            }
            r.function = fid;
            r.code = address;
            emit(r);
            if fid == 1027 {
                query = true
            }
        }
    }
    loss(LOSS_TRUNC);
}
#[inline(never)]
#[no_mangle]
pub fn alias(hash: u64, len: u64, index: u32, r: &mut Record) {
    r.kind = ALIAS;
    r.algorithm = OTHER;
    r.function = OTHER;
    r.outcome = 0;
    r.status = index;
    if len <= 36 {
        if let Some(entry) = unsafe { ALG_CLASS.get(&hash) } {
            if entry.len as u64 == len {
                r.algorithm = entry.class as u32;
                r.function = entry.canon as u32;
                r.outcome = entry.weak as u32;
            }
        }
    }
    emit(r);
    // Do not carry map-derived alias identities into the next byte or dispatch.
    r.algorithm = OTHER;
    r.function = 0;
    r.outcome = 0;
    r.status = 0;
}
#[repr(C)]
struct AliasScan {
    // Synchronous own-stack borrow; no target address or transport field.
    record: *mut Record,
    input: [u8; 128],
    len: usize,
    hash: u64,
    segment_len: u64,
    completed: u32,
    reserved: u32,
}
const _: () = assert!(core::mem::size_of::<AliasScan>() == 168);
#[inline(never)]
#[no_mangle]
pub extern "C" fn alias_byte(index: u64, context: u64) -> u64 {
    // SAFETY: synchronous bpf_loop receives this initialized own-stack context.
    let scan = unsafe { &mut *(context as *mut AliasScan) };
    if index < 128 && index < scan.len as u64 && scan.completed < 8 {
        let octet = scan.input[index as usize];
        if octet == b':' {
            // SAFETY: classify keeps this caller-owned Record alive for bpf_loop.
            alias(scan.hash, scan.segment_len, scan.completed, unsafe {
                &mut *scan.record
            });
            scan.completed += 1;
            scan.hash = 14_695_981_039_346_656_037;
            scan.segment_len = 0;
        } else {
            scan.hash = (scan.hash ^ octet as u64).wrapping_mul(1_099_511_628_211);
            scan.segment_len += 1;
        }
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn classify(pointer: u64, r: &mut Record) {
    r.algorithm = OTHER;
    r.function = 0;
    r.outcome = 0;
    r.status = 0;
    let mut scan = AliasScan {
        record: r,
        input: [0; 128],
        len: 0,
        hash: 14_695_981_039_346_656_037,
        segment_len: 0,
        completed: 0,
        reserved: 0,
    };
    scan.len = match unsafe {
        helpers::bpf_probe_read_user_str_bytes(pointer as *const u8, &mut scan.input)
    } {
        Ok(v) => v.len(),
        Err(_) => {
            loss(LOSS_READ);
            r.kind = ALIAS_END;
            r.status = 4;
            emit(r);
            r.status = 0;
            return;
        }
    };
    if scan.len >= 127 {
        r.kind = ALIAS_END;
        r.status = 2;
        emit(r);
        r.status = 0;
        return;
    }
    // Callback only reads captured scratch and the frozen classifier LUT.
    let result = unsafe {
        helpers::bpf_loop(
            128,
            alias_byte as *mut core::ffi::c_void,
            (&mut scan as *mut AliasScan).cast(),
            0,
        )
    };
    if result != 128 {
        loss(LOSS_READ);
        r.kind = ALIAS_END;
        r.status = 4;
        emit(r);
        r.status = 0;
        return;
    }
    if scan.completed == 8 {
        r.status = 3;
    } else {
        alias(scan.hash, scan.segment_len, scan.completed, r);
        scan.completed += 1;
    }
    r.kind = ALIAS_END;
    r.function = scan.completed;
    emit(r);
    r.function = 0;
    r.status = 0;
}
#[repr(C)]
struct DispatchScan {
    record: *mut Record,
    table: u64,
    stopped: u32,
    reserved: u32,
}
#[inline(never)]
#[no_mangle]
pub fn walk_dispatch(imp: u64, r: &mut Record) {
    let mut scan = DispatchScan {
        record: r,
        table: imp,
        stopped: 0,
        reserved: 0,
    };
    let result = unsafe {
        helpers::bpf_loop(
            128,
            dispatch_slot as *mut core::ffi::c_void,
            (&mut scan as *mut DispatchScan).cast(),
            0,
        )
    };
    if result < 0 {
        loss(LOSS_READ);
    } else if scan.stopped == 0 {
        loss(LOSS_TRUNC);
    }
}
#[inline(never)]
#[no_mangle]
pub extern "C" fn dispatch_slot(index: u64, context: u64) -> u64 {
    let scan = unsafe { &mut *(context as *mut DispatchScan) };
    if index >= 128 {
        return 1;
    }
    let Some(base) = scan.table.checked_add(index * 16) else {
        loss(LOSS_READ);
        scan.stopped = 1;
        return 1;
    };
    let id = match unsafe { helpers::bpf_probe_read_user(base as *const u32) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            scan.stopped = 1;
            return 1;
        }
    };
    if id == 0 {
        scan.stopped = 1;
        return 1;
    }
    if id > i32::MAX as u32 {
        loss(LOSS_TRUNC);
        scan.stopped = 1;
        return 1;
    }
    let r = unsafe { &mut *scan.record };
    r.function = id;
    r.code = 0;
    // Volatile returned tables supply synchronous advertisement metadata only.
    if r.cacheability == 1 {
        let address = match unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) } {
            Ok(v) => v,
            Err(_) => {
                loss(LOSS_READ);
                scan.stopped = 1;
                return 1;
            }
        };
        if code_ok(r.pid, address) {
            r.code = address
        } else {
            loss(LOSS_RANGE)
        }
    }
    r.kind = IMPLEMENTATION;
    emit(r);
    0
}
#[inline(never)]
#[no_mangle]
pub fn query_return(p: &Pending, key: &ThreadKey, table: u64, stamp: u64, seed: u64) {
    let cacheability = query_result(p, key, table, stamp, seed);
    if table == 0 {
        return;
    }
    let mut scan = AlgorithmScan {
        pending: p,
        thread: key,
        table,
        cacheability,
        stopped: 0,
        stamp,
        seed,
    };
    let result = unsafe {
        helpers::bpf_loop(
            MAX_ALGORITHMS,
            algorithm_slot as *mut core::ffi::c_void,
            (&mut scan as *mut AlgorithmScan).cast(),
            0,
        )
    };
    if result < 0 {
        loss(LOSS_READ);
    } else if scan.stopped == 0 {
        loss(LOSS_TRUNC);
    }
}
#[inline(never)]
#[no_mangle]
pub fn query_result(p: &Pending, key: &ThreadKey, table: u64, stamp: u64, seed: u64) -> u32 {
    let mut r = Record::default();
    base(p, key, QUERY, &mut r, stamp);
    r.seed = seed;
    r.operation = p.operation;
    r.outcome = if table == 0 { 2 } else { 1 };
    r.cacheability = match unsafe { helpers::bpf_probe_read_user(p.arg2 as *const u32) } {
        Ok(0) => 1,
        Ok(_) => 2,
        Err(_) => {
            loss(LOSS_READ);
            0
        }
    };
    emit(&r);
    if r.cacheability != 1 {
        if let Some(member) = MEMBERS.get_ptr_mut(&key.pid) {
            unsafe { (*member).epoch = 0 }
        }
    }
    r.cacheability
}
/// Synchronous own-stack context, never persisted or emitted. No returned table
/// address survives this uretprobe, including no-store and failed-read paths.
#[repr(C)]
struct AlgorithmScan {
    pending: *const Pending,
    thread: *const ThreadKey,
    table: u64,
    cacheability: u32,
    stopped: u32,
    stamp: u64,
    seed: u64,
}
#[inline(never)]
#[no_mangle]
pub extern "C" fn algorithm_slot(index: u64, context: u64) -> u64 {
    let scan = unsafe { &mut *(context as *mut AlgorithmScan) };
    if index >= MAX_ALGORITHMS as u64 {
        return 1;
    }
    let Some(slot) = scan.table.checked_add(index * 32) else {
        loss(LOSS_READ);
        scan.stopped = 1;
        return 1;
    };
    let names = match unsafe { helpers::bpf_probe_read_user(slot as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            scan.stopped = 1;
            return 1;
        }
    };
    if names == 0 {
        scan.stopped = 1;
        return 1;
    }
    let imp = match unsafe { helpers::bpf_probe_read_user((slot + 16) as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            scan.stopped = 1;
            return 1;
        }
    };
    let mut record = Record::default();
    let p = unsafe { &*scan.pending };
    base(
        p,
        unsafe { &*scan.thread },
        ALGORITHM_BEGIN,
        &mut record,
        scan.stamp,
    );
    record.seed = scan.seed;
    record.operation = p.operation;
    record.cacheability = scan.cacheability;
    let r = &mut record;
    r.kind = ALGORITHM_BEGIN;
    r.algorithm_index = index as u32;
    r.outcome = 1;
    r.algorithm = 0;
    r.function = 0;
    r.status = 0;
    r.code = 0;
    emit(r);
    classify(names, r);
    if imp != 0 {
        walk_dispatch(imp, r)
    } else {
        loss(LOSS_TRUNC)
    }
    0
}
// Keep pairing temporaries out of the frame that classifies a query return.
//
// fix6 (R6-1) orphaned-return seed rule: the RESULT carries the LIVE
// row's seed (`*out_seed`, set only on success). A row recreated
// mid-call (numeric cleanup deleted the pre-delete row — legal)
// hands the return its FRESH seed, so the RESULT can never pair with
// the pre-delete ATTEMPT (conservative no-pair, both visible
// unpaired — never a shared sentinel two orphans could pair
// through). A pure THREADS-miss (row deleted, not recreated) emits
// NOTHING (LOSS_PAIR + false; every caller returns without
// emitting), so no seed choice arises there — the pre-delete ATTEMPT
// expires unpaired-visible. `*out_seed` is untouched on every
// failure path (callers only read it after `true`).
/// fix8 (R8-2): discard slots strictly deeper than `mine_level`
/// (stale skipped inners — deeper is strictly inner: an outer
/// slot at level L proves L outers outstanding, so depth would
/// exceed any shallower entry — and an outstanding inner with me
/// returning is execution-impossible). Both paths discard all
/// kinds (a deeper T slot is stale-proven the same way; only the
/// ownership SEARCH excludes T for accepted returns — an
/// accepted return provably owns no blind marker, but still reaps
/// deeper blind garbage). Absent slots skip silent; a refused
/// batched quota release fires LOSS_MAP once (as on the pop path).
/// Task 0 verifier fix: the discard scan runs as a `bpf_loop`
/// callback (one level per invocation) instead of an inline Rust
/// loop. Bisected: an inline loop with one loop-carried counter
/// verifies, but adding the second counter (`unwound` beside
/// `freed`) blows the jump budget — the verifier stops merging
/// loop states (21K states, sequence trip) — and the post-loop
/// quota-release call multiplies the unmerged caller states past
/// the budget. The `bpf_loop` callback is verified ONCE (index as
/// a range, not per-iteration states), so the single-pass body
/// with both counters fits comfortably; the batched release and
/// the depth unwinding stay hoisted after (net-identical).
/// Deletes/visits unchanged (levels top→0, all kinds).
/// R10 1b: the callback additionally counts discarded O-markers
/// so the hoisted tail can retire the counter-owner record.
struct DiscardCtx {
    key: ThreadKey,
    top: u32,
    mine_level: u32,
    include_t: u32,
    unwound: u32,
    markers_freed: u32,
    o_freed: u32,
}
/// One discard level (see `discard_deeper`): returns 0 to continue
/// the scan, 1 to break (mine reached or index beyond `top`).
#[inline(never)]
#[no_mangle]
pub extern "C" fn discard_level_cb(index: u64, context: u64) -> u64 {
    // SAFETY: synchronous bpf_loop receives this initialized own-stack context.
    let ctx = unsafe { &mut *(context as *mut DiscardCtx) };
    if index > ctx.top as u64 {
        return 1;
    }
    let level = ctx.top - index as u32;
    if level <= ctx.mine_level {
        return 1;
    }
    let frame_key = PendingKey {
        thread: ctx.key,
        depth: level,
        reserved: PENDING_FRAME,
    };
    if PENDING.remove(&frame_key).is_ok() {
        ctx.unwound += 1;
    }
    if ctx.include_t != 0 {
        let t_key = PendingKey {
            thread: ctx.key,
            depth: level,
            reserved: PENDING_BLIND_MARKER,
        };
        if PENDING.remove(&t_key).is_ok() {
            ctx.markers_freed += 1;
        }
    }
    let o_key = PendingKey {
        thread: ctx.key,
        depth: level,
        reserved: PENDING_OVERFLOW_MARKER,
    };
    if PENDING.remove(&o_key).is_ok() {
        ctx.markers_freed += 1;
        ctx.o_freed += 1;
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn discard_deeper(
    key: &ThreadKey,
    depth: u32,
    mine_level: u32,
    include_t: u32,
    thread: &mut Thread,
) {
    let top = if depth > MAX_DEPTH { MAX_DEPTH } else { depth };
    let mut ctx = DiscardCtx {
        key: *key,
        top,
        mine_level,
        include_t,
        unwound: 0,
        markers_freed: 0,
        o_freed: 0,
    };
    // Callback only touches captured scratch (levels top→0) and
    // PENDING deletes; counts stay exact even on early break.
    let result = unsafe {
        helpers::bpf_loop(
            9,
            discard_level_cb as *mut core::ffi::c_void,
            (&mut ctx as *mut DiscardCtx).cast(),
            0,
        )
    };
    if result < 0 {
        // Unreachable (nr=9 + flags=0 + verified callback cannot
        // fail); signal LOUD and proceed with the actual counts
        // (sound: the release/depth below consume exactly what the
        // callback deleted, partial or full).
        loss(LOSS_MAP);
    }
    thread.depth = thread.depth.saturating_sub(ctx.unwound);
    let freed = ctx.unwound + ctx.markers_freed;
    if freed != 0 && !source_state::release_pending_n(freed) {
        loss(LOSS_MAP);
    }
    // R10 1b: a discarded O-marker retires the counter-owner
    // record (its reference marker is gone — the finding-1
    // staleness must not reach a later marker).
    if ctx.o_freed != 0 {
        thread.retire_counter_owner();
    }
}
/// fix8 (R8-2): fast-path guard — whether any marker (either
/// kind, any cookie) sits at `level`. A same-cookie owner must
/// take the slow path to its own deeper marker; a foreign deeper
/// marker is a skipped inner the slow path discards.
#[inline(always)]
fn marker_at(key: &ThreadKey, level: u32) -> bool {
    let o_key = PendingKey {
        thread: *key,
        depth: level,
        reserved: PENDING_OVERFLOW_MARKER,
    };
    if unsafe { PENDING.get(&o_key) }.is_some() {
        return true;
    }
    let t_key = PendingKey {
        thread: *key,
        depth: level,
        reserved: PENDING_BLIND_MARKER,
    };
    unsafe { PENDING.get(&t_key) }.is_some()
}
/// fix8 (R8-2): slow pop search — the deepest slot owned by
/// `cookie` (fetch-only; `*out` packs level << 32 | kind). Frames
/// sort before their lateral markers (a frame is always inner to
/// same-level markers: it wounded past them), T before O (the
/// reverse nesting — an accepted overflow inside a closed blind —
/// needs a window reopen). Accepted returns exclude T (an
/// accepted return provably owns a frame or an overflow marker:
/// its entry was accepted, and the window never reopens).
#[inline(never)]
#[no_mangle]
pub fn find_mine(
    key: &ThreadKey,
    depth: u32,
    cookie: u64,
    include_t: u32,
    out: &mut u64,
) -> bool {
    let top = if depth > MAX_DEPTH { MAX_DEPTH } else { depth };
    // Task 0 verifier fix: count DOWN from `top` (no `top - step`
    // subtraction — the up-counting range confused the verifier's
    // bound tracking). Visit order unchanged (levels top→0).
    let mut level = top;
    for _ in 0..9u32 {
        let frame_key = PendingKey {
            thread: *key,
            depth: level,
            reserved: PENDING_FRAME,
        };
        if let Some(p) = unsafe { PENDING.get(&frame_key).copied() } {
            if p.cookie == cookie {
                *out = (level as u64) << 32 | PENDING_FRAME as u64;
                return true;
            }
        }
        if include_t != 0 {
            let t_key = PendingKey {
                thread: *key,
                depth: level,
                reserved: PENDING_BLIND_MARKER,
            };
            if let Some(p) = unsafe { PENDING.get(&t_key).copied() } {
                if p.cookie == cookie {
                    *out = (level as u64) << 32 | PENDING_BLIND_MARKER as u64;
                    return true;
                }
            }
        }
        let o_key = PendingKey {
            thread: *key,
            depth: level,
            reserved: PENDING_OVERFLOW_MARKER,
        };
        if let Some(p) = unsafe { PENDING.get(&o_key).copied() } {
            if p.cookie == cookie {
                *out = (level as u64) << 32 | PENDING_OVERFLOW_MARKER as u64;
                return true;
            }
        }
        if level == 0 {
            break;
        }
        level -= 1;
    }
    false
}
#[inline(never)]
#[no_mangle]
pub fn pop_return(
    cookie: u64,
    out_key: &mut ThreadKey,
    out_pending: &mut Pending,
    out_seed: &mut u64,
) -> bool {
    let Some((_, key)) = identity(cookie) else {
        // fix8 (R8-2): a return rejected by the OPERATIONAL WINDOW
        // pops its OWN slot (frame or either marker — always
        // suppressed, never emitted) after discarding deeper stale
        // slots (a deeper slot with me returning is a skipped inner
        // — execution-impossible otherwise). fix7's
        // consume-T-first survives only for counter-owned returns
        // (marker refusal was rare and is now rarer). Every other
        // rejection arm cannot attribute (different task/row):
        // consume nothing, as before.
        if let Some((_, key)) = identity_closed_window(cookie) {
            if let Some(mut thread) = unsafe { THREADS.get(&key).copied() } {
                if thread.depth > 0 {
                    let pk = PendingKey {
                        thread: key,
                        depth: thread.depth - 1,
                        reserved: PENDING_FRAME,
                    };
                    if let Some(p) = unsafe { PENDING.get(&pk).copied() } {
                        if p.cookie == cookie && !marker_at(&key, thread.depth) {
                            if PENDING.remove(&pk).is_err() {
                                loss(LOSS_MAP);
                                return false;
                            }
                            if !source_state::release_pending() {
                                loss(LOSS_MAP);
                            }
                            thread.depth -= 1;
                            if THREADS.insert(key, thread, 0).is_err() {
                                loss(LOSS_MAP);
                            }
                            return false;
                        }
                    }
                }
                let mut found = 0u64;
                if find_mine(&key, thread.depth, cookie, 1, &mut found) {
                    let mine_level = (found >> 32) as u32;
                    let mine_kind = (found & 0xffff_ffff) as u32;
                    // Task 0 verifier fix: bound `mine_level` for the
                    // discard loop (`find_mine` only ever writes
                    // 0..=top, but the verifier joins its exit states
                    // imprecisely — an unbounded level blows the jump
                    // budget). Out-of-range is unreachable; fail LOUD
                    // (never pop a wild slot) if hit.
                    if mine_level > MAX_DEPTH {
                        loss(LOSS_PAIR);
                        return false;
                    }
                    discard_deeper(&key, thread.depth, mine_level, 1, &mut thread);
                    let mk = PendingKey {
                        thread: key,
                        depth: mine_level,
                        reserved: mine_kind,
                    };
                    let Some(_p) = (unsafe { PENDING.get(&mk).copied() }) else {
                        loss(LOSS_PAIR);
                        return false;
                    };
                    if PENDING.remove(&mk).is_err() {
                        loss(LOSS_MAP);
                        return false;
                    }
                    if !source_state::release_pending() {
                        loss(LOSS_MAP);
                    }
                    if mine_kind == PENDING_FRAME {
                        thread.depth = thread.depth.saturating_sub(1);
                    }
                    // R10 1b: a popped O-marker retires the
                    // counter-owner record (the only rejected-arm
                    // change; slot-first + T-first preserved).
                    if mine_kind == PENDING_OVERFLOW_MARKER {
                        thread.retire_counter_owner();
                    }
                    if THREADS.insert(key, thread, 0).is_err() {
                        loss(LOSS_MAP);
                    }
                } else if thread.blind_return() {
                    if THREADS.insert(key, thread, 0).is_err() {
                        loss(LOSS_MAP);
                    }
                }
            }
        }
        return false;
    };
    // fix6 (R6-4 return-miss audit): userspace numeric cleanup may
    // delete this row mid-call — the miss emits NOTHING (LOSS_PAIR
    // + false; both `observation_return` callers return without
    // emitting) and no return path dereferences a missing row.
    let Some(mut thread) = (unsafe { THREADS.get(&key).copied() }) else {
        loss(LOSS_PAIR);
        return false;
    };
    // fix8 (R8-2) fast path: the framed return pops its own frame
    // directly (the common case) — but ONLY when no marker sits at
    // the current depth (a same-cookie marker-owner's return must
    // NOT hijack the outer frame; a deeper marker of any cookie is
    // a skipped inner the slow path discards). R10 1b: and ONLY
    // when the returning call is NOT the recorded counter owner
    // (a cookie match is not ownership — the owner's return must
    // consume its counter unit via the slow path instead).
    // Anything else falls to the slow positional search.
    if thread.depth > 0 {
        let pk = PendingKey {
            thread: key,
            depth: thread.depth - 1,
            reserved: PENDING_FRAME,
        };
        if let Some(p) = unsafe { PENDING.get(&pk).copied() } {
            if p.cookie == cookie
                && !marker_at(&key, thread.depth)
                && !thread.counter_owned_by(cookie)
            {
                if PENDING.remove(&pk).is_err() {
                    loss(LOSS_MAP);
                    return false;
                }
                if !source_state::release_pending() {
                    loss(LOSS_MAP);
                }
                thread.depth -= 1;
                if THREADS.insert(key, thread, 0).is_err() {
                    loss(LOSS_MAP);
                    return false;
                }
                *out_key = key;
                *out_pending = p;
                *out_seed = thread.seed;
                return p.suppressed == 0;
            }
        }
    }
    let mut found = 0u64;
    if find_mine(&key, thread.depth, cookie, 0, &mut found) {
        let mine_level = (found >> 32) as u32;
        let mine_kind = (found & 0xffff_ffff) as u32;
        // Task 0 verifier fix: bound `mine_level` for the discard
        // loop (see the rejected arm above — same join imprecision).
        // Out-of-range is unreachable; fail LOUD if hit.
        if mine_level > MAX_DEPTH {
            loss(LOSS_PAIR);
            return false;
        }
        // R10 1b: a cookie match is not ownership — an ambiguous
        // match consumes instead of popping ONLY when the
        // returning call is the recorded counter owner
        // (`counter_owned_by`, kind-independent — O-slot and
        // frame matches alike, since same-cookie units are
        // fungible suppressions); every other match pops its own
        // slot first (`d7c431a` order). A consume pops and
        // discards nothing (a deeper marker may be outer-live,
        // not skipped). The guard guarantees a unit
        // (`skip_return` cannot fail here).
        if thread.counter_owned_by(cookie) {
            thread.skip_return();
            if THREADS.insert(key, thread, 0).is_err() {
                loss(LOSS_MAP);
            }
            return false;
        }
        discard_deeper(&key, thread.depth, mine_level, 1, &mut thread);
        let mk = PendingKey {
            thread: key,
            depth: mine_level,
            reserved: mine_kind,
        };
        let Some(p) = (unsafe { PENDING.get(&mk).copied() }) else {
            loss(LOSS_PAIR);
            return false;
        };
        if PENDING.remove(&mk).is_err() {
            loss(LOSS_MAP);
            return false;
        }
        if !source_state::release_pending() {
            loss(LOSS_MAP);
        }
        if mine_kind == PENDING_FRAME {
            thread.depth = thread.depth.saturating_sub(1);
        }
        // R10 1b: a popped O-marker retires the counter-owner
        // record (T pops and frame pops never retire).
        if mine_kind == PENDING_OVERFLOW_MARKER {
            thread.retire_counter_owner();
        }
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP);
            return false;
        }
        *out_key = key;
        *out_pending = p;
        // The live row's seed (immutable since creation — `enter`/
        // depth bookkeeping never touches it). On a recreated row this
        // is the FRESH seed (orphaned-return rule above).
        *out_seed = thread.seed;
        return p.suppressed == 0;
    }
    // No slot of mine: a counter-owned return consumes its overflow
    // unit (an accepted return provably owns no blind unit); a
    // unit-less return is unpaired (fail-closed, as before).
    if thread.skip_return() {
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        return false;
    }
    loss(LOSS_PAIR);
    false
}
#[uretprobe]
pub fn observation_return(ctx: RetProbeContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    // fix4: single stamp per program (see `observation_entry`).
    let stamp = incarnation_stamp(cookie);
    if let Some((cfg, key)) = identity(cookie) {
        if operational_api(cfg.api) {
            let rv = ctx.ret();
            operational_return(cookie, &key, cfg.api, rv);
            if trace_operational() {
                let mut tkey = ThreadKey::default();
                let mut pend = Pending::default();
                let mut seed = 0;
                if pop_return(cookie, &mut tkey, &mut pend, &mut seed) {
                    let mut r = Record::default();
                    base(&pend, &tkey, RESULT, &mut r, stamp);
                    r.seed = seed;
                    r.status = 0;
                    r.outcome = operational_outcome(pend.api, rv);
                    emit(&r);
                }
            }
            return 0;
        }
    }
    let mut key = ThreadKey::default();
    let mut p = Pending::default();
    let mut seed = 0;
    if !pop_return(cookie, &mut key, &mut p, &mut seed) {
        return 0;
    }
    let rv: u64 = ctx.ret();
    if p.api == PROVIDER_INIT {
        init_return(&p, &key, rv, stamp, seed)
    } else if p.api == GET_DISPATCH {
        getter_return(&p, &key, rv, stamp, seed)
    } else if query_api(p.api) {
        query_return(&p, &key, rv, stamp, seed)
    } else if !matches!(p.api, PUBLIC_UNQUERY | TEARDOWN | UNQUERY_CALLBACK) {
        api_return(&p, &key, rv, stamp, seed);
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn api_return(p: &Pending, key: &ThreadKey, rv: u64, stamp: u64, seed: u64) {
    let mut r = Record::default();
    base(p, key, RESULT, &mut r, stamp);
    r.seed = seed;
    r.status = p.name;
    r.outcome = if matches!(p.api, UNLOAD | ADD_BUILTIN) {
        int_outcome(rv)
    } else if rv != 0 {
        1
    } else {
        2
    };
    emit(&r);
    if p.api == UNLOAD && r.outcome == 1 {
        invalidate(p, key, 1, stamp, seed)
    }
    if p.api == ADD_BUILTIN && r.outcome == 1 {
        if code_ok(key.pid, p.arg2) {
            r.kind = INIT;
            r.status = 0;
            r.function = 1;
            r.code = p.arg2;
            emit(&r)
        } else {
            loss(LOSS_RANGE)
        }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
