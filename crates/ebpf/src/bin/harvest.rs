//! SPDX-License-Identifier: GPL-2.0-only
//! Harvest probes: two-stage provider table walk in BPF (promoted
//! from the P0-4 spike at P1 exit 1; P1 exit 2 raises the walk bounds
//! for the built-in default provider: 241-encoder census).
//!
//! Stage 1 anchors on the load-mandated `OSSL_provider_init` export (found
//! via disk-ELF .dynsym by userspace; present even in stripped modules).
//! At init-return the BPF walks the returned provider dispatch table for
//! OSSL_FUNC_PROVIDER_QUERY_OPERATION (1027) and reports its address.
//! Stage 2 (attached by userspace at that address) walks each query-return
//! OSSL_ALGORITHM array plus per-alg dispatch tables, emitting one ROW
//! event per (op, class, funcid, addr). No symbols are used past the init
//! anchor; userspace never reads target memory.
//!
//! Walk bounds (P1 exit 2, default-provider census 4.0.2: 241 algs/op
//! max, 115 dispatch entries/alg max, 81-char names max): each
//! query-return hit walks exactly ONE alg — index = per-(thread, op)
//! query count mod 512 — so an op queried N times covers algs 0..N
//! (order-independent; single-shot triggers walk alg 0). The 512-call
//! inventory trigger covers 512 algs/op; array overrun is detected by
//! reading one past the last slot (sets TRUNC[op] bit 1) and dispatch
//! tables past 128 entries set bit 2 — userspace degrades to PARTIAL,
//! so growth fails closed, never truncates silently. The single-alg
//! shape is deliberate: nested slice loops blow the verifier's 1M
//! processed-insn ceiling via state explosion (bisected 2026-09-17),
//! while one loop (dispatch walk, as a subprogram) verifies with wide
//! margin.
//!
//! P5a-C1 chain probe: the entry program walks slot j, then tail-calls
//! the `c_slot` callee (via the `JUMPS` prog-array) to walk slot j+1,
//! advancing the cursor by 2 per query. The handoff rides the
//! existing maps (the entry re-inserts its `PENDING_QUERY` record;
//! the callee takes it and re-derives count from `QUERY_NEXT`) — a
//! dedicated stash array breaks the classifier's loop-state merging,
//! and the kernel forbids tail calls from subprograms without BTF.
//! The slot-walk body is duplicated in entry and callee (a shared
//! subprogram would nest the loop-calls at depth 2 and blow the
//! verifier's 1M processed-insn ceiling — observed 2026-10-12);
//! same honesty rules, only the advance diagonal differs (see
//! `c_slot`). An unpopulated `JUMPS` slot or a failed re-stash
//! degrades to the sampler (advance by 1) — the loader populates
//! before any attach and fails the attach when population fails, so
//! the fallback is unreachable in practice, and any live fallback
//! is observable in the doc's rows-per-query ratio (14 chained vs 7
//! sampled).
//!
//! T03 honesty: a prefix is never COMPLETE. The walker records
//! termination proof (`TERMD[arr] = (op, len)`) on reading the
//! terminator, flags walk aborts at every slot, advances past
//! implementation-less slots (stable: freezing would stall), counts
//! every ring/map failure in `LOSS[src]`, and samples `no_store`
//! arrays once (slot 0, `TRUNC_NO_STORE`, never proven). TRUNC bits
//! and LOSS ids are frozen in the shared crate.
//!
//! Classify-before-emission (T02, wire ABI v2): target strings are
//! read into kernel stack scratch (128B alg window, 32B trip window)
//! and classified in-kernel against the observer-populated
//! `ALG_CLASS`/`TRIP_CLASS` tables. The ring carries finite
//! `(class, status)` numerics plus internal structural join
//! addresses only — no name/argument bytes. All event shapes come
//! from the shared crate (this program defines no wire structs of
//! its own); userspace decodes ids to table labels. Saturated
//! windows (helper filled the whole window — exact-fit and
//! truncation are indistinguishable) fail closed to overlong with no
//! retained prefix. String-read failures emit explicit unreadable
//! verdicts; the alg-slot counter still freezes so the next query
//! re-walks the slot. Walk-abort forensics left the ring (TRUNC bits
//! keep the abort signal).
//!
//! Layout constants mirror `kinds::SHAPES` (R12; asserted fail-closed by
//! `layout_assert.c` against real headers): OSSL_DISPATCH = {u32, pad,
//! u64} @16B; OSSL_ALGORITHM = 4×u64 @32B.
//!
//! P1 exit 3 adds legacy tripwires: `trip_count` (cookie++ only, hot
//! symbols) and `trip_str0`/`trip_str1` (cookie++ plus the classified
//! arg verdict, cold string-bearing entrypoints) share one `TRIP` map
//! keyed by attach cookie (userspace-defined id space; kernels
//! ≥5.15). Query programs read their own cookie to count `CALLS` (0)
//! vs `LGCALLS` (1): the legacy provider's query fn is stage-attached
//! alongside the target provider's, and userspace partitions rows by
//! array mapping.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuHashMap, ProgramArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext as _,
};
use osslscope_ebpf_common::{
    AlgClassValue, AlgEvent, InitRetEvent, PendQuery, RowEvent, TripClassValue, TripEvent,
    TripTaxonomy, ALG_UNREADABLE, ALG_WINDOW, KIND_ALG, KIND_INIT_RET, KIND_QUERY_RET, KIND_ROW,
    KIND_TRIP, LOSS_INIT_SCAN, LOSS_MAP_CALLS, LOSS_MAP_LGCALLS, LOSS_MAP_QUERY_NEXT,
    LOSS_MAP_TERMD, LOSS_MAP_TRIP, LOSS_MAP_TRUNC, LOSS_PENDING_INIT_FULL, LOSS_PENDING_INIT_MISS,
    LOSS_PENDING_QUERY_FULL, LOSS_PENDING_QUERY_MISS, LOSS_RING_ALG, LOSS_RING_INIT,
    LOSS_RING_ROW, LOSS_RING_TRIP, OTHER_CLASS, TRIP_OTHER, TRIP_UNREADABLE, TRIP_WINDOW,
    TRUNC_ALGS, TRUNC_DISPATCH, TRUNC_NO_STORE, TRUNC_WALK_EMPTY, TRUNC_WALK_NAME,
    TRUNC_WALK_NOIMP, TRUNC_WALK_READ, classify_alg_with, classify_trip_with, make_termd,
};

/// core_dispatch.h: provider codes live at 1024+; verified 2026-09-16.
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: u32 = 1027;

/// `BPF_NOEXIST` for `insert` (kernel UAPI; aya-ebpf exposes no const).
const BPF_NOEXIST: u64 = 1;

/// Alg-array bound per op (measured max 364, oqsprovider encoder;
/// 512 is the next power of two with headroom). No BPF loop runs
/// on this bound — one alg slot per query-return hit — so the
/// raise costs the verifier nothing. LOCKSTEP: the inventory
/// trigger rounds (SPIKE_QUERY_ROUNDS, fixture default) must stay
/// >= this bound, or arrays past the round count go silently
/// unflagged (the overrun guard only fires at the last slot).
const MAX_ALGS: u64 = 512;
/// Dispatch-table bound per alg (measured max 115, RSA encoder, stable
/// across 3.0/3.5/4.0; 128 keeps the verifier under its 1M processed-insn
/// ceiling with ~2x margin — overflow fails closed via TRUNC).
const MAX_DISPATCH: u64 = 128;
/// `QUERY_NEXT` sentinel for `no_store` arrays: the persistent
/// counter is meaningless for uncacheable tables (T03: sampled once,
/// never advanced). Unreachable by real query counts.
const NS_FROZEN: u64 = u64::MAX;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 21, 0);
#[map]
static PENDING_INIT: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
/// Entry→return pairs: op + caller `no_store` out-pointer (16-byte
/// values; T03 widens the shape to honor provider lifetimes).
#[map]
static PENDING_QUERY: HashMap<u64, PendQuery> = HashMap::with_max_entries(1024, 0);
/// Termination proofs: array base → packed (op, live-slot count)
/// (T03: a table without proof is a prefix, never COMPLETE).
#[map]
static TERMD: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Per-array incarnation generation (F-H/H1): the host installs
/// `GEN[arr]` when an array's epoch is born or reborn and deletes
/// it when the array unloads. Every ROW/ALG/QUERY_RET record
/// carries the value read here at emit time (0 on miss — the
/// array's first observation, before the host's bootstrap install
/// lands), so the host can drop ring-queued stragglers from a
/// retired incarnation instead of attributing them against newer
/// mappings. Same shape as the count side's global `GEN[0]`, but
/// keyed per array: replacements are per-object, and a global
/// bump would drop unrelated arrays' in-flight records.
#[map]
static GEN: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
/// Source-tagged failure counters (T03: every ring-reserve and
/// map-update failure lands here; keys are the `LOSS_*` ids).
/// Per-CPU (F-C/A8): shared-map lookup–increment–replace loses
/// concurrent increments across CPUs; per-CPU slots are
/// single-writer (no migration mid-BPF), so a plain add is
/// exact. Userspace sums across CPUs at drain.
#[map]
static LOSS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(32, 0);
/// Per-(thread, array) query count; walked index = count % MAX_ALGS.
/// Keyed by the composite (pid_tgid, array address) pair — each
/// provider-op array is a distinct static, so different providers'
/// same-op arrays must NOT share a counter, and an XOR-folded key
/// could collide across threads (T03: composite, never folded). The
/// counter freezes at the first terminator (see query_return), so
/// short arrays never walk past their end into adjacent tables.
#[map]
static QUERY_NEXT: HashMap<u128, u64> = HashMap::with_max_entries(4096, 0);
/// Walk-overflow flags per op id; userspace degrades to PARTIAL.
/// Per-CPU (F-C/A8, same race as the counters); userspace ORs
/// across CPUs at drain.
#[map]
static TRUNC: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(64, 0);
/// Non-null query calls per op id. The 512-round inventory trigger
/// fires ~68K calls in milliseconds; counting in-map (instead of a
/// ring event per call) keeps the ring burst under 1MB. QUERY_RET is
/// emitted on the first hit per array only (liveness + ops-hit).
/// Per-CPU (F-C/A8); userspace sums at drain.
#[map]
static CALLS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(64, 0);
/// Tripwire hits per attach cookie (userspace id space: ENGINE /
/// meth_new / provider-load / low-level-family probes).
/// Per-CPU (F-C/A8); userspace sums at drain.
#[map]
static TRIP: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(128, 0);
/// Non-null query calls per op id on the legacy attachment
/// (cookie 1); the target provider's stay in CALLS.
/// Per-CPU (F-C/A8); userspace sums at drain.
#[map]
static LGCALLS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(64, 0);
/// Kernel classifier table: FNV-1a-64 of exact registry spelling →
/// (class, weak, len-checked; name reserved). Observer-populated
/// before any attach; no target bytes at rest.
#[map]
static ALG_CLASS: HashMap<u64, AlgClassValue> = HashMap::with_max_entries(1024, 0);
/// Kernel trip table: FNV-1a-64 of exact taxonomy pattern →
/// (engine class, load class, name for exact confirm). Same
/// observer-populated discipline.
#[map]
static TRIP_CLASS: HashMap<u64, TripClassValue> = HashMap::with_max_entries(64, 0);
/// Chain jump table (P5a-C1): prog-array, slot 0 = the `c_slot` tail
/// callee. Populated by the loader before any attach (fail-closed);
/// 8 slots for the P7 multi-callee protocol. The handoff rides the
/// existing maps (zero new state): the entry re-inserts its
/// `PENDING_QUERY` record before tailing, and the callee takes it
/// back and re-derives (count, j+1) from `QUERY_NEXT`. (A dedicated
/// 72-byte `CURSOR` map was prototyped and rejected: its stack
/// materialization breaks the classifier's loop-state merging, and
/// the kernel forbids tail calls from subprograms without BTF, so
/// the tail site must live in the main scope.)
#[map]
static JUMPS: ProgramArray = ProgramArray::with_max_entries(8, 0);

/// Per-CPU counter add (F-C/A8): shared-map lookup–increment–
/// replace loses concurrent increments across CPUs, and `core`
/// atomics are unavailable on this target — so the counters live
/// in per-CPU slots (single-writer: no migration mid-BPF) and a
/// plain wrapping add is exact. Absent keys plant 0 with NOEXIST
/// first (a lost plant race still lands on the winner's slot);
/// only a full map fails. Userspace sums across CPUs at drain.
fn percpu_add<K>(map: &PerCpuHashMap<K, u64>, key: &K) -> Result<(), ()> {
    if map.get_ptr_mut(key).is_none() {
        // Stack local, never `&0u64`: a literal reference folds
        // into .rodata with an R_BPF_64_64 reloc, which the
        // fail-closed loader rejects (non-map 64-bit reloc).
        let zero = 0u64;
        let _ = map.insert(key, &zero, BPF_NOEXIST);
    }
    match map.get_ptr_mut(key) {
        Some(slot) => {
            unsafe { *slot = (*slot).wrapping_add(1) };
            Ok(())
        }
        None => Err(()),
    }
}

/// Per-CPU flag-OR (F-C/A8): same lost-update race as the
/// counters, same fix; userspace ORs across CPUs at drain.
fn percpu_or<K>(map: &PerCpuHashMap<K, u64>, key: &K, bit: u64) -> Result<(), ()> {
    if map.get_ptr_mut(key).is_none() {
        // Stack local (see percpu_add): `&0u64` emits a
        // loader-rejected .rodata R_BPF_64_64 reloc.
        let zero = 0u64;
        let _ = map.insert(key, &zero, BPF_NOEXIST);
    }
    match map.get_ptr_mut(key) {
        Some(slot) => {
            unsafe { *slot |= bit };
            Ok(())
        }
        None => Err(()),
    }
}

/// Source-tagged loss bump (T03: ring-exhaustion and map-update
/// failures are counted, never silent). A full LOSS map is the one
/// uncounted residual (15 keys in 32 slots: effectively never
/// full).
fn bump_loss(src: u32) {
    let _ = percpu_add(&LOSS, &src);
}

fn emit_alg(ev: &AlgEvent) {
    if let Some(mut e) = EVENTS.reserve::<AlgEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_ALG);
    }
}

fn emit_row(ev: &RowEvent) {
    if let Some(mut e) = EVENTS.reserve::<RowEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_ROW);
    }
}

fn emit_trip(ev: &TripEvent) {
    if let Some(mut e) = EVENTS.reserve::<TripEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_TRIP);
    }
}

fn emit_init_ret(ev: &InitRetEvent) {
    if let Some(mut e) = EVENTS.reserve::<InitRetEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_INIT);
    }
}

/// Current incarnation cookie for one array: the installed
/// generation, or 0 when the host has not bootstrapped this array
/// yet. Zero-stamped records are pre-install genuine (emitted
/// before the bootstrap install lands): the host accepts them for
/// novel arrays and for never-reborn tracked arrays, and requires
/// the installed value otherwise (see `check_gen`).
fn gen_of(arr: u64) -> u64 {
    // Same copy-out as `lookup_alg`: the value is small and the
    // borrow must not escape into the emit below.
    unsafe { GEN.get_ptr(&arr).map(|p| *p).unwrap_or(0) }
}

/// Table lookups behind the shared classifiers (copied out: values
/// are small, and the trip confirm step borrows the copy).
fn lookup_alg(h: u64) -> Option<AlgClassValue> {
    unsafe { ALG_CLASS.get_ptr(&h).map(|p| *p) }
}

fn lookup_trip(h: u64) -> Option<TripClassValue> {
    unsafe { TRIP_CLASS.get_ptr(&h).map(|p| *p) }
}

/// Algorithm classification as a BPF subprogram (separate
/// verification scope, like the dispatch walk below).
#[inline(never)]
fn classify_alg(
    buf: &[u8; ALG_WINDOW],
    len: usize,
    saturated: bool,
) -> osslscope_ebpf_common::AlgVerdict {
    classify_alg_with(buf, len, saturated, lookup_alg)
}

fn cookie_of(ctx: &ProbeContext) -> u64 {
    unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }
}

fn bump_trip(cookie: u64) {
    if percpu_add(&TRIP, &cookie).is_err() {
        bump_loss(LOSS_MAP_TRIP);
    }
}

fn take_key<V: Copy>(map: &HashMap<u64, V>, key: u64) -> Option<V> {
    let val = unsafe { *map.get_ptr(&key)? };
    let _ = map.remove(&key);
    Some(val)
}

/// PENDING key namespaced by attach cookie: primary (0) and legacy
/// (1) attachments share the maps. Bits 56+ carry the namespace,
/// which is collision-free only while pid_tgid leaves them clear —
/// true under default pid_max (2^22); a >2^24 TGID namespace would
/// need a wider key (P5 stretch, never observed).
fn pend_key(cookie: u64) -> u64 {
    helpers::bpf_get_current_pid_tgid() ^ ((cookie + 1) << 56)
}

fn flag_trunc(op: u32, bit: u64) {
    if percpu_or(&TRUNC, &op, bit).is_err() {
        bump_loss(LOSS_MAP_TRUNC);
    }
}

/// Record termination proof for an array (T03). Insert failures are
/// counted — a lost proof must read as a gap, never as COMPLETE.
fn record_termd(arr: u64, op: u32, len: u64) {
    if TERMD.insert(arr, make_termd(op, len as u32), 0).is_err() {
        bump_loss(LOSS_MAP_TERMD);
    }
}

/// Advance the per-(thread, array) counter past a fully-observed
/// slot. Insert failures freeze the counter (retry next query) and
/// are counted.
fn advance_next(key: u128, count: u64) {
    if QUERY_NEXT.insert(key, count.wrapping_add(1), 0).is_err() {
        bump_loss(LOSS_MAP_QUERY_NEXT);
    }
}

/// Store an explicit per-(thread, array) counter value (the chain
/// callee's advance-by-2 and freeze-at-terminator diagonals). Same
/// freeze-on-failure honesty as `advance_next`.
fn store_next(key: u128, val: u64) {
    if QUERY_NEXT.insert(key, val, 0).is_err() {
        bump_loss(LOSS_MAP_QUERY_NEXT);
    }
}

/// OSSL_provider_init(handle, in, out, provctx): stash arg2 (out).
#[uprobe]
pub fn init_entry(ctx: ProbeContext) -> u32 {
    let out: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    if PENDING_INIT
        .insert(pend_key(cookie_of(&ctx)), out, 0)
        .is_err()
    {
        bump_loss(LOSS_PENDING_INIT_FULL);
    }
    0
}

/// At init-return walk *out for the query op; report its address.
/// `aux` carries the attach cookie (0 = target provider, 1 = legacy)
/// so userspace routes stage-2 attaches with the matching cookie.
#[uretprobe]
pub fn init_return(ctx: RetProbeContext) -> u32 {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let out = match take_key(&PENDING_INIT, pend_key(cookie)) {
        Some(v) => v,
        // Return without entry (in flight during attach, or the
        // entry insert failed): the init is unobservable — a gap.
        None => {
            bump_loss(LOSS_PENDING_INIT_MISS);
            return 0;
        }
    };
    let rv: u64 = ctx.ret();
    if rv != 1 || out == 0 {
        return 0;
    }
    let table = match unsafe { helpers::bpf_probe_read_user(out as *const u64) } {
        Ok(v) => v,
        // The stage-1 anchor read failed (cold page on a fresh
        // mapping): no INIT_RET event follows, so the miss is
        // counted here or the blind stage-2 has no cause.
        Err(_) => {
            bump_loss(LOSS_INIT_SCAN);
            return 0;
        }
    };
    if table == 0 {
        return 0;
    }
    // OSSL_DISPATCH = { u32 id; u32 pad; fnptr u64 } = 16 bytes.
    for i in 0..16u64 {
        let base = table + i * 16;
        let fid = unsafe { helpers::bpf_probe_read_user(base as *const u32) };
        let fptr = unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) };
        let (Ok(fid), Ok(fptr)) = (fid, fptr) else {
            bump_loss(LOSS_INIT_SCAN);
            return 0;
        };
        if fid == 0 {
            // Clean terminator without a query operation: a
            // definitive (broken-provider) shape, loud downstream
            // via the blind stage-2 — not scan loss.
            return 0;
        }
        if fid == OSSL_FUNC_PROVIDER_QUERY_OPERATION && fptr != 0 {
            emit_init_ret(&InitRetEvent {
                kind: KIND_INIT_RET,
                op: 0,
                funcid: fid,
                _pad: 0,
                addr: fptr,
                aux: cookie,
            });
            return 0;
        }
    }
    // Sixteen entries without a terminator or a query operation: a
    // truncated scan, counted or the blind stage-2 has no cause.
    bump_loss(LOSS_INIT_SCAN);
    0
}

/// Hot tripwire: count the hit, no ring traffic.
#[uprobe]
pub fn trip_count(ctx: ProbeContext) -> u32 {
    bump_trip(cookie_of(&ctx));
    0
}

fn trip_unreadable(cookie: u64) {
    emit_trip(&TripEvent {
        kind: KIND_TRIP,
        cookie: cookie as u32,
        class: TRIP_OTHER,
        status: TRIP_UNREADABLE,
        _pad: 0,
        _pad2: 0,
    });
}

/// Always inlined: the probe-arg index `n` must be a per-program
/// constant (a runtime `n` lowers to `ctx - n*8 + 112`, whose
/// negative intermediate the verifier rejects — F-BPF-1 trip half:
/// `trip_str1` insn 54 on 6.12).
#[inline(always)]
fn trip_str_at(ctx: &ProbeContext, n: usize, taxonomy: TripTaxonomy) {
    let c = cookie_of(ctx);
    bump_trip(c);
    let s: u64 = match ctx.arg(n) {
        Some(v) => v,
        None => return,
    };
    // NULL argument: an explicit unreadable verdict (the call
    // happened; userspace counts it, never a silent undercount).
    if s == 0 {
        trip_unreadable(c);
        return;
    }
    // Kernel scratch only: classified below, never emitted.
    let mut arg_buf = [0u8; 32];
    let slice =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(s as *const u8, &mut arg_buf) } {
            Ok(s) => s,
            Err(_) => {
                trip_unreadable(c);
                return;
            }
        };
    let saturated = slice.len() == TRIP_WINDOW - 1;
    let v = classify_trip_with(slice, saturated, taxonomy, lookup_trip);
    emit_trip(&TripEvent {
        kind: KIND_TRIP,
        cookie: c as u32,
        class: v.class,
        status: v.status,
        _pad: 0,
        _pad2: 0,
    });
}

/// Cold string-bearing tripwire, arg0 flavor (`ENGINE_by_id(id)`).
#[uprobe]
pub fn trip_str0(ctx: ProbeContext) -> u32 {
    trip_str_at(&ctx, 0, TripTaxonomy::Engine);
    0
}

/// Cold string-bearing tripwire, arg1 flavor
/// (`OSSL_PROVIDER_load(libctx, name)`).
#[uprobe]
pub fn trip_str1(ctx: ProbeContext) -> u32 {
    trip_str_at(&ctx, 1, TripTaxonomy::Load);
    0
}

/// query_operation(provctx, operation_id, no_store): stash arg1
/// (op) plus arg2 (the caller's `no_store` out-pointer, read back
/// at return). Same arg positions for the core wrapper
/// ossl_provider_query_operation(prov, op, no_cache) on 3.0/3.5/4.0,
/// which passes the provider's verdict straight through; a missed
/// or misread pointer fails closed to `no_store` (loud PARTIAL, and
/// the live lane confirms the wrapper shape on the default
/// provider).
#[uprobe]
pub fn query_entry(ctx: ProbeContext) -> u32 {
    let op: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    // A missing arg2 stashes a NULL pointer: the return-side read
    // then fails and the array is treated as `no_store`.
    let ns_ptr: u64 = ctx.arg(2).unwrap_or(0);
    if PENDING_QUERY
        .insert(pend_key(cookie_of(&ctx)), PendQuery { op, ns_ptr }, 0)
        .is_err()
    {
        bump_loss(LOSS_PENDING_QUERY_FULL);
    }
    0
}

/// Dispatch-table walk as a BPF subprogram (separate verification
/// scope). Emits one ROW event per entry (`aux`/`idx` = array address
/// + alg index, the userspace ALG-join key); returns true when the
/// table runs past MAX_DISPATCH without a terminator (TRUNC).
/// Returns 0 (terminator), 1 (overflow), or 2 (read abort — the
/// caller freezes the counter so the next query re-walks).
#[inline(never)]
fn walk_dispatch(imp: u64, op: u32, arr: u64, j: u64) -> u64 {
    for k in 0..MAX_DISPATCH {
        let base = imp + k * 16;
        let fid = unsafe { helpers::bpf_probe_read_user(base as *const u32) };
        let fptr = unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) };
        let (Ok(fid), Ok(fptr)) = (fid, fptr) else {
            return 2;
        };
        if fid == 0 {
            return 0;
        }
        emit_row(&RowEvent {
            kind: KIND_ROW,
            op,
            funcid: fid,
            _pad: 0,
            addr: fptr,
            aux: arr,
            idx: j,
            generation: gen_of(arr),
        });
    }
    1
}

/// At query-return walk slot j of the OSSL_ALGORITHM array (index =
/// per-(thread, array) query count mod 512) plus its dispatch table,
/// then tail-call the `c_slot` callee for slot j+1 (P5a-C1 chain —
/// the cursor advances by 2 per query). Short arrays still never walk
/// past their end: the terminator freezes the counter (entry) or
/// freezes AT the terminator (callee). OSSL_ALGORITHM = { names,
/// props, impl, desc } @32B.
///
/// T03 honesty: the walker records termination proof (`TERMD`) when
/// it reads the terminator, flags walk aborts at EVERY slot (not
/// just slot 0), advances past implementation-less slots (they are
/// stable observations, not transient failures — freezing on them
/// stalls the op forever), counts every ring/map failure in `LOSS`,
/// and samples `no_store` arrays once (slot 0, no persistent
/// counter, never termination proof — and never chained).
#[uretprobe]
pub fn query_return(ctx: RetProbeContext) -> u32 {
    // Cookie 1 = legacy attachment: its calls stay out of CALLS.
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let pend = match take_key(&PENDING_QUERY, pend_key(cookie)) {
        Some(v) => v,
        // Return without entry (in flight during attach, or the
        // entry insert failed): the query is unobservable — a gap.
        None => {
            bump_loss(LOSS_PENDING_QUERY_MISS);
            return 0;
        }
    };
    let op = pend.op;
    let rv: u64 = ctx.ret();
    if rv == 0 {
        return 0;
    }
    let legacy = cookie == 1;
    if legacy {
        if percpu_add(&LGCALLS, &(op as u32)).is_err() {
            bump_loss(LOSS_MAP_LGCALLS);
        }
    } else if percpu_add(&CALLS, &(op as u32)).is_err() {
        bump_loss(LOSS_MAP_CALLS);
    }
    // The provider's lifetime verdict, read once from the caller's
    // out-pointer in this valid return context. Only an explicit 0
    // is cacheable; any nonzero verdict, NULL pointer, or read
    // failure fails closed to `no_store`.
    let no_store = match unsafe { helpers::bpf_probe_read_user(pend.ns_ptr as *const u32) } {
        Ok(0) => false,
        _ => true,
    };
    // Composite cursor key: pid_tgid in the high half, array base
    // in the low half. Never XOR-folded: two (thread, array) pairs
    // must never share a walk position.
    let key = ((helpers::bpf_get_current_pid_tgid() as u128) << 64) | (rv as u128);
    let stored = unsafe { QUERY_NEXT.get_ptr(&key).map(|p| *p) };
    if no_store {
        // Uncacheable table: the persistent counter is meaningless
        // (the array may be freed or mutated between queries), so
        // this path samples slot 0 exactly once per (thread,
        // array) — no advance, no termination proof, ever. Later
        // queries only refresh the call count and the sticky bit.
        // FULL slot-0 sampling (not just liveness) still runs
        // below on the first observation; transient sample aborts
        // fail closed to PARTIAL rather than spamming retries.
        flag_trunc(op as u32, TRUNC_NO_STORE);
        if stored.is_some() {
            // Poison any stale positional count (cacheable→no_store
            // flip): the array is uncacheable now, so a later flip
            // back to cacheable must restart the walk at slot 0
            // rather than resume a position across the gap.
            if stored != Some(NS_FROZEN)
                && QUERY_NEXT.insert(key, NS_FROZEN, 0).is_err()
            {
                bump_loss(LOSS_MAP_QUERY_NEXT);
            }
            return 0;
        }
        if QUERY_NEXT.insert(key, NS_FROZEN, 0).is_err() {
            bump_loss(LOSS_MAP_QUERY_NEXT);
        }
    }
    let mut count = stored.unwrap_or(0);
    // A `no_store`→cacheable flip (provider verdicts may change
    // across queries): the frozen sentinel is not a position, so
    // the walk restarts at slot 0.
    if !no_store && count == NS_FROZEN {
        count = 0;
    }
    // `no_store` first observations always sample slot 0.
    let j = if no_store { 0 } else { count % MAX_ALGS };
    if count == 0 {
        emit_row(&RowEvent {
            kind: KIND_QUERY_RET,
            op: op as u32,
            funcid: 0,
            _pad: 0,
            addr: rv,
            aux: j,
            idx: 0,
            generation: gen_of(rv),
        });
    }
    // Slot walk (P5a-C1: this body is duplicated in `c_slot`
    // below — a shared subprogram would nest loop-calls at depth 2
    // and blow the verifier's 1M processed-insn ceiling, so the two
    // mains each inline the walk and differ only in the advance
    // diagonal at the end. Keep the two copies in sync; the P7
    // protocol subsumes both).
    let base = rv + j * 32;
    let names = unsafe { helpers::bpf_probe_read_user(base as *const u64) };
    let imp = unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) };
    let (Ok(names), Ok(imp)) = (names, imp) else {
        // Unreadable slot at ANY position aborts this query's walk;
        // the counter freezes so the next query retries the slot.
        // Sticky: a later success does not clear the flag (fail
        // closed; pretouch keeps cold pages off this path).
        flag_trunc(op as u32, TRUNC_WALK_READ);
        return 0;
    };
    if names == 0 {
        // Terminator: freeze the counter (no insert), stop, and
        // record proof — unless `no_store` (uncacheable tables are
        // never proven). Slot 0 empty = the query returned a table
        // with no first alg (suspicious: flagged, still PARTIAL).
        if !no_store {
            record_termd(rv, op as u32, j);
        }
        if j == 0 {
            flag_trunc(op as u32, TRUNC_WALK_EMPTY);
        }
        return 0;
    }
    // Overrun guard on the last slot: entries 0..=511 all live means
    // the array may extend past the bound — slot 512 decides (live or
    // unreadable = TRUNC, terminator = clean + proof). Runs before
    // the impl-less skip so a bare slot 511 still guards the tail.
    if j == MAX_ALGS - 1 {
        let tail = unsafe { helpers::bpf_probe_read_user((rv + MAX_ALGS * 32) as *const u64) };
        match tail {
            Ok(0) => {
                if !no_store {
                    record_termd(rv, op as u32, MAX_ALGS);
                }
            }
            _ => flag_trunc(op as u32, TRUNC_ALGS),
        }
    }
    if imp == 0 {
        // Alg without implementation: a stable observation (the slot
        // read fine), so the walk ADVANCES past it — freezing here
        // would re-walk this slot on every future query and stall
        // the op forever. The skip is explicit via NOIMP.
        flag_trunc(op as u32, TRUNC_WALK_NOIMP);
        if !no_store {
            advance_next(key, count);
        }
        return 0;
    }
    // Kernel scratch only: classified below, never emitted.
    let mut name_buf = [0u8; 128];
    let slice =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(names as *const u8, &mut name_buf) }
        {
            Ok(s) => s,
            Err(_) => {
                flag_trunc(op as u32, TRUNC_WALK_NAME);
                // Explicit unreadable record (cold page or hostile
                // pointer): the counter still freezes so the next
                // query re-walks this slot instead of losing the alg.
                emit_alg(&AlgEvent {
                    kind: KIND_ALG,
                    op: op as u32,
                    class: OTHER_CLASS,
                    status: ALG_UNREADABLE,
                    weak: 0,
                    _pad: 0,
                    arr: rv,
                    idx: j,
                    generation: gen_of(rv),
                });
                return 0;
            }
        };
    // Copy the length out first: the window array is reborrowed
    // shared below, which ends `slice`'s mutable borrow.
    let len = slice.len();
    let saturated = len == ALG_WINDOW - 1;
    let v = classify_alg(&name_buf, len, saturated);
    // ALG first: userspace drops rows whose (array, index) has no
    // ALG record yet (orphan rule), so rows must follow their ALG.
    emit_alg(&AlgEvent {
        kind: KIND_ALG,
        op: op as u32,
        class: v.class,
        status: v.status,
        weak: u8::from(v.weak),
        _pad: 0,
        arr: rv,
        idx: j,
        generation: gen_of(rv),
    });
    // Entry diagonal: a fully-walked slot continues the chain (stash
    // + tail-call — the callee walks j+1 and advances by 2).
    // `no_store` first observations walk slot 0 and stop (sampled
    // once, never advanced, never chained); the chain ends at the
    // bound (slot 512 is the overrun decider, never a walked slot).
    // BPF probe reads are nofault, so a cold page aborts the walk
    // even though the table is valid — freezing the counter lets the
    // next query re-walk this slot instead of losing the alg forever
    // (the terminator path above still freezes too, and a dispatch
    // read-abort freezes as well: ALG/ROW re-emits dedupe userside
    // via the alg_names overwrite + rows seen-map).
    match walk_dispatch(imp, op as u32, rv, j) {
        // Overflow: rows 0..127 are kept, the rest is unwalkable —
        // the chain continues past like a success, but the
        // truncation is flagged.
        1 => {
            // V2 BISECT: branches only, no re-insert/tail.
            flag_trunc(op as u32, TRUNC_DISPATCH);
            if no_store {
                return 0;
            }
            if j == MAX_ALGS - 1 {
                advance_next(key, count);
                return 0;
            }
            advance_next(key, count);
        }
        0 => {
            if no_store {
                return 0;
            }
            if j == MAX_ALGS - 1 {
                advance_next(key, count);
                return 0;
            }
            advance_next(key, count);
        }
        // Read abort: flag (all slots) and freeze for re-walk.
        _ => {
            flag_trunc(op as u32, TRUNC_WALK_READ);
        }
    }
    0
}

/// Hand the query to `c_slot` and tail-call it (P5a-C1 entry
/// diagonal, shared by the full-walk arms above). The handoff is
/// the 16-byte `PENDING_QUERY` record the take at the top consumed:
/// re-insert it here (the callee takes it back) and re-derive
/// (count, j+1) from `QUERY_NEXT` there — no new maps, no stack
/// arrays (a 72-byte CURSOR stash breaks the classifier's
/// loop-state merging). Inlined: the kernel forbids tail calls from
/// subprograms without BTF, so the tail site must live in this main
/// scope — and the 16-byte re-insert perturbs the frame far less
/// than a stash array.
#[inline(always)]
#[allow(dead_code)]
fn chain_tail(ctx: &RetProbeContext, cookie: u64, pend: PendQuery, key: u128, count: u64) {
    if PENDING_QUERY.insert(pend_key(cookie), pend, 0).is_err() {
        // Unstashable (map full — effectively unreachable: one
        // entry per in-flight query): chain nothing rather than
        // chain a stale record; sampler fallback keeps the walk
        // progressing, and the fallback is observable in the doc's
        // rows-per-query ratio.
        advance_next(key, count);
        return;
    }
    unsafe { JUMPS.tail_call(ctx, 0) };
    // Tail-call failure (empty slot, OOB index, or tail budget —
    // indistinguishable, RET_VOID): take back the re-stash (else a
    // stale record lingers until the next query overwrites it) and
    // advance like the sampler. Unreachable in practice (the loader
    // populates before any attach and fails the attach otherwise);
    // observable in the ratio if it ever fires live.
    let _ = take_key(&PENDING_QUERY, pend_key(cookie));
    advance_next(key, count);
}

/// Chain tail callee (P5a-C1): walks slot j+1 after the entry walked
/// slot j. NEVER directly attached — reachable only via `JUMPS[0]`
/// from `query_return`. The handoff is the entry's `PENDING_QUERY`
/// record (re-inserted before the tail — taken back here); (count,
/// j+1) re-derive from `QUERY_NEXT`, which the entry has not
/// advanced yet. The slot-walk body duplicates the entry's (see the
/// sync note there — a shared subprogram nests loop-calls at depth
/// 2 and blows the verifier's 1M ceiling); only the advance
/// diagonal differs: full walks store count+2, a stable skip stores
/// count+2 past it, the terminator stores count+1 (frozen AT the
/// terminator — the next query's entry re-reads it once, exactly
/// like a sampler-frozen terminator), and aborts freeze (no store:
/// the next query re-walks BOTH slots). Runs cacheable-only (the
/// entry never chains `no_store`).
#[uretprobe]
pub fn c_slot(ctx: RetProbeContext) -> u32 {
    let rv: u64 = ctx.ret();
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let pend = match take_key(&PENDING_QUERY, pend_key(cookie)) {
        Some(v) => v,
        // No handoff (direct attach — impossible via the loader —
        // or a clobbered stash): chain nothing.
        None => return 0,
    };
    let op = pend.op as u32;
    let tgid = helpers::bpf_get_current_pid_tgid();
    let key = ((tgid as u128) << 64) | (rv as u128);
    // The entry has not advanced yet, so this is its count —
    // mirrored normalization: raw NS_FROZEN (a no_store→cacheable
    // flip) means the entry walked j=0 (same rule as the entry).
    // j+1 needs no bound guard: the entry chains only below slot
    // 511, and the modulo keeps every value in range regardless.
    let raw = unsafe { QUERY_NEXT.get_ptr(&key).map(|p| *p) };
    let norm = match raw {
        Some(c) if c != NS_FROZEN => c,
        _ => 0,
    };
    let j = norm.wrapping_add(1) % MAX_ALGS;
    let count = norm;
    // Slot-walk copy (see the entry's sync note): identical reads,
    // proofs, flags, and emissions — only the counter stores below
    // implement the callee diagonal.
    let base = rv + j * 32;
    let names = unsafe { helpers::bpf_probe_read_user(base as *const u64) };
    let imp = unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) };
    let (Ok(names), Ok(imp)) = (names, imp) else {
        flag_trunc(op, TRUNC_WALK_READ);
        return 0;
    };
    if names == 0 {
        // Terminator at j+1: proof + freeze AT the terminator
        // (count+1 — the next query's entry re-reads this slot
        // once, like a sampler-frozen terminator).
        record_termd(rv, op, j);
        store_next(key, count.wrapping_add(1));
        return 0;
    }
    // Overrun guard (mirrors the entry: j == 511 reads slot 512 as
    // the decider; the entry never chains INTO 512, but the callee
    // can walk 511 itself when the entry walked 510).
    if j == MAX_ALGS - 1 {
        let tail = unsafe { helpers::bpf_probe_read_user((rv + MAX_ALGS * 32) as *const u64) };
        match tail {
            Ok(0) => {
                record_termd(rv, op, MAX_ALGS);
            }
            _ => flag_trunc(op, TRUNC_ALGS),
        }
    }
    if imp == 0 {
        // Stable skip: advance past by 2 (both slots observed).
        flag_trunc(op, TRUNC_WALK_NOIMP);
        store_next(key, count.wrapping_add(2));
        return 0;
    }
    let mut name_buf = [0u8; 128];
    let slice =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(names as *const u8, &mut name_buf) }
        {
            Ok(s) => s,
            Err(_) => {
                flag_trunc(op, TRUNC_WALK_NAME);
                emit_alg(&AlgEvent {
                    kind: KIND_ALG,
                    op,
                    class: OTHER_CLASS,
                    status: ALG_UNREADABLE,
                    weak: 0,
                    _pad: 0,
                    arr: rv,
                    idx: j,
                    generation: gen_of(rv),
                });
                return 0;
            }
        };
    let len = slice.len();
    let saturated = len == ALG_WINDOW - 1;
    let v = classify_alg(&name_buf, len, saturated);
    emit_alg(&AlgEvent {
        kind: KIND_ALG,
        op,
        class: v.class,
        status: v.status,
        weak: u8::from(v.weak),
        _pad: 0,
        arr: rv,
        idx: j,
        generation: gen_of(rv),
    });
    match walk_dispatch(imp, op, rv, j) {
        1 => {
            flag_trunc(op, TRUNC_DISPATCH);
            store_next(key, count.wrapping_add(2));
        }
        0 => {
            store_next(key, count.wrapping_add(2));
        }
        _ => {
            flag_trunc(op, TRUNC_WALK_READ);
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
