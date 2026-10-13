//! SPDX-License-Identifier: GPL-2.0-only
//! Member chunk: one object, 512 baked-slot query-return programs
//! plus the shared entry (P7 item 3; criteria §6.3, §5.1/§5.3).
//!
//! Each `member_J` walks exactly slot J of the query-returned
//! OSSL_ALGORITHM array plus its dispatch table — the sampler's
//! proven slot-walk body (`harvest.rs query_return`) with the
//! cursor/chain/proof machinery removed (no cursor: every scan is
//! full; no tail calls; no TERMD: 512 writers would last-wins)
//! under the §5.1/§5.3 protocol layers (R18): SCAN peek (never
//! take — a taker would starve whichever members fire after it,
//! and attachment order must stay meaningless),
//! counter-first/retire-last, per-member T-cache peek with local
//! pointee-read eligibility, member-0 verdict-first QUERY_RET,
//! and the member-511 guard read. WALK-DONE + TRUE-T land with
//! the item-4 join; the harvest path's PENDING scaffold retires
//! in item 9 (members.o dropped its own PENDING in stage D).
//!
//! Stage-D honesty bounds (stated, tested): the T-gate skips
//! past-T members only on a warm cache entry with a
//! successfully-read zero pointee (cold/GEN-stale/unreadable
//! walks — v1 prefix reach); completion/termination proof is the
//! item-4 join's job (GUARD/RET/ALG/ROW carry (tid,seq) for it;
//! ALG/ROW keys land with that oracle).
//!
//! Helpers and the walk body are duplicated from `harvest.rs`
//! (not shared): the codebase's established pattern — the P5a
//! object already carries the walk 9×, and touching the proven
//! object would force its re-verification. `harvest.o` is
//! byte-untouched by this bin.
//!
//! Layout constants mirror `kinds::SHAPES` (R12): OSSL_DISPATCH =
//! {u32, pad, u64} @16B; OSSL_ALGORITHM = 4×u64 @32B.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext as _,
};
use osslscope_ebpf_common::{
    classify_alg_with, loss_for_skip_cause, make_bucket, make_call_flags, make_rcount, make_seq,
    split_bucket, split_rcount, split_seq, AlgClassValue, CtrlValue, GuardEvent, ScanAlgEvent,
    ScanCallEvent, ScanRec, ScanRetEvent, ScanRowEvent, TCacheValue, ALG_UNREADABLE, ALG_WINDOW,
    BIRTH_FROZEN, BUCKET_BURST, BUCKET_PERIOD_SHIFTED, GUARD_EMPTY, GUARD_ERROR, GUARD_VALID,
    KIND_GUARD, KIND_SCAN_ALG, KIND_SCAN_CALL, KIND_SCAN_RET, KIND_SCAN_ROW, LOSS_GUARD_READ_ABORT,
    LOSS_MAP_CALLS, LOSS_MAP_TRUNC, LOSS_MEMBER_COOKIE, LOSS_RETIRE_FAIL, LOSS_RING_ALG,
    LOSS_RING_CALL, LOSS_RING_GUARD, LOSS_RING_RET, LOSS_RING_ROW, LOSS_SCAN_CHURNED,
    LOSS_SCAN_EVICTED, LOSS_STALE_REPAIRED, MEMBER_ENTRY_COOKIE, OTHER_CLASS, RCOUNT_STATE_ACTIVE,
    RCOUNT_STATE_IDLE, RET_FLAG_EMPTY, RINGBUF_AVAIL_DATA, SEQ_CTR_MAX, SKIP_ADMITTED,
    SKIP_ADMIT_STORE_FAIL, SKIP_ALL, SKIP_BIRTH_PENDING, SKIP_BIRTH_WRAP, SKIP_BUCKET_EMPTY,
    SKIP_CTRL_UNPROGRAMMED, SKIP_ENTRY_COOKIE, SKIP_RING_PRESSURE, SKIP_SEQ_FULL,
    SKIP_SEQ_SATURATED, TRUNC_ALGS, TRUNC_DISPATCH, TRUNC_NO_STORE, TRUNC_WALK_EMPTY,
    TRUNC_WALK_NAME, TRUNC_WALK_NOIMP, TRUNC_WALK_READ,
};

/// `BPF_NOEXIST` for `insert` (kernel UAPI; aya-ebpf exposes no const).
const BPF_NOEXIST: u64 = 1;

/// Kernel errno ENOENT (UAPI asm-generic/errno.h): aya-ebpf
/// `remove` surfaces raw negative errnos, so ENOENT is
/// distinguishable from real cleanup failures (R18 §3/§6.16
/// ENOENT-as-absent).
const ENOENT: i32 = 2;

/// Alg-array bound per op (measured max 364, oqsprovider encoder;
/// 512 is the next power of two with headroom). Members are
/// indexed 0..512; slot 512 exists only as member 511's guard read.
const MAX_ALGS: u64 = 512;
/// Dispatch-table bound per alg (measured max 115, RSA encoder,
/// stable across 3.0/3.5/4.0; 128 keeps the verifier under its 1M
/// processed-insn ceiling with ~2x margin — overflow fails closed
/// via TRUNC). Matches criteria §2.2 E_bound.
const MAX_DISPATCH: u64 = 128;

/// Item-7 ring (16MiB — the 2MiB ring cannot hold one worst-case
/// scan; criterion §5.6, re-verified with item-4 sizes in
/// `src/scan/oracle.rs`).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

/// Per-array incarnation generation (F-H/H1): the host installs
/// `GEN[arr]` when an array's epoch is born or reborn and deletes
/// it when the array unloads. Every ROW/ALG record carries the
/// value read here at emit time (0 on miss), so the host can drop
/// ring-queued stragglers from a retired incarnation.
#[map]
static GEN: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
/// Source-tagged failure counters. Per-CPU (F-C/A8): shared-map
/// lookup–increment–replace loses concurrent increments across
/// CPUs; per-CPU slots are single-writer, so a plain add is exact.
/// Userspace sums across CPUs at drain.
#[map]
static LOSS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(32, 0);
/// Walk-overflow flags per op id; userspace degrades to PARTIAL.
/// Per-CPU (F-C/A8); userspace ORs across CPUs at drain.
#[map]
static TRUNC: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(64, 0);
/// Non-null query calls per op id, counted by member 0 (once per
/// query — every member fires every hit, so member 0's bump is the
/// per-query count; all-members bumping would inflate 512x).
/// Single-site in v1: the cookie rides the slot, so the sampler's
/// `cookie == 1` legacy partition cannot apply; it rides item-3
/// membership. Per-CPU (F-C/A8); userspace sums at drain.
#[map]
static CALLS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(64, 0);
/// Kernel classifier table: FNV-1a-64 of exact registry spelling →
/// (class, weak, len-checked; name reserved). Observer-populated
/// before any attach; no target bytes at rest.
#[map]
static ALG_CLASS: HashMap<u64, AlgClassValue> = HashMap::with_max_entries(1024, 0);
/// One in-flight scan per thread (§5.1): the entry's take record,
/// peeked by members. LRU: orphans from never-returning hits evict
/// instead of leaking (eviction ⟺ NULL + ACTIVE — the NULL+SEQ
/// rule misclassified retirement AND first queries, R18 §2).
#[map]
static SCAN: LruHashMap<u32, ScanRec> = LruHashMap::with_max_entries(1024, 0);
/// Invocation sequences (§5.1): tid → birth:16|ctr:48.
/// Non-evictable (never reused across eviction or tid-reuse);
/// insert-fail skips the query (LOSS_SEQ_FULL).
#[map]
static SEQ: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);
/// Thread birth registry (§5.1): tid → u16 birth,
/// userspace-superseded, never deleted (dead tids orphan; a later
/// incarnation supersedes).
#[map]
static BIRTH: HashMap<u32, u16> = HashMap::with_max_entries(4096, 0);
/// Per-thread member return counter + scan lifecycle (§5.1, R18
/// §2/§6.9): count:32|state:32 fold. Bumped by every admitted-scan
/// exit (members, D), reset to ACTIVE|0 by every admit, IDLEd by
/// every skip/retire. 4k lifecycle (never created by the SKIP path;
/// insert-fail unreachable — RCOUNT keys ⊆ SEQ keys, and the admit
/// order inserts SEQ first).
#[map]
static RCOUNT: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);
/// Terminator cache (§5.3): array → (T, GEN),
/// single-userspace-writer. Members peek + validate GEN and
/// skip-silent past T.
#[map]
static T_CACHE: HashMap<u64, TCacheValue> = HashMap::with_max_entries(1024, 0);
/// Tier-1 token bucket (item 5, §5.4): tid → tokens:8 |
/// last-refill(ns>>8):56. 40/s sustained, burst 4 — single-writer
/// (one tid = one thread), race-free. Charged by the entry after
/// all other gates (tokens meter admitted scans, not attempts);
/// kept separate from BIRTH (userspace overwrites BIRTH rows on
/// poll — folding would clobber rate state).
#[map]
static BUCKET: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);
/// Session control (§5.1/§5.4/§5.5): EXPECTED / epoch / SKIP-ALL /
/// governor (max admittable ring OCCUPANCY in bytes — admit iff
/// occupancy <= threshold, R18 §2/§6.6). Loader-programmed at
/// attach.
#[map]
static CTRL: Array<CtrlValue> = Array::with_max_entries(1, 0);
/// Entry-hit attempts (§5.5): every hit including skips. Per-CPU
/// array; userspace sums. ATTEMPT − CALLS = skipped queries.
#[map]
static ATTEMPT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
/// failures are counted, never silent).
fn bump_loss(src: u32) {
    let _ = percpu_add(&LOSS, &src);
}

fn emit_scan_alg(ev: &ScanAlgEvent) {
    if let Some(mut e) = EVENTS.reserve::<ScanAlgEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_ALG);
    }
}

fn emit_scan_row(ev: &ScanRowEvent) {
    if let Some(mut e) = EVENTS.reserve::<ScanRowEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_ROW);
    }
}

/// Current incarnation cookie for one array: the installed
/// generation, or 0 when the host has not bootstrapped this array
/// yet (see `check_gen` host-side).
fn gen_of(arr: u64) -> u64 {
    unsafe { GEN.get_ptr(&arr).map(|p| *p).unwrap_or(0) }
}

/// Table lookup behind the shared classifier (copied out: the
/// value is small, and the borrow must not escape into emit).
fn lookup_alg(h: u64) -> Option<AlgClassValue> {
    unsafe { ALG_CLASS.get_ptr(&h).map(|p| *p) }
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

fn flag_trunc(op: u32, bit: u64) {
    if percpu_or(&TRUNC, &op, bit).is_err() {
        bump_loss(LOSS_MAP_TRUNC);
    }
}

/// Dispatch-walk context (BPF calls take ≤5 args — r1..r5 — so
/// the scan-keyed ROW emission packs its context into one stack
/// struct passed by pointer).
struct WalkCtx {
    op: u32,
    tid: u32,
    arr: u64,
    j: u64,
    seq: u64,
}

/// Dispatch-table walk as a BPF subprogram (separate verification
/// scope). Emits one ROW event per entry (`aux`/`idx` = array address
/// + alg index, the userspace ALG-join key); returns true when the
/// table runs past MAX_DISPATCH without a terminator (TRUNC).
/// Returns 0 (terminator), 1 (overflow), or 2 (read abort — the
/// caller flags; re-cover semantics land with item 4).
#[inline(never)]
fn walk_dispatch(imp: u64, ctx: &WalkCtx) -> u64 {
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
        emit_scan_row(&ScanRowEvent {
            kind: KIND_SCAN_ROW,
            op: ctx.op,
            funcid: fid,
            _pad: 0,
            addr: fptr,
            aux: ctx.arr,
            idx: ctx.j,
            generation: gen_of(ctx.arr),
            tid: ctx.tid,
            _pad2: 0,
            seq: ctx.seq,
        });
    }
    1
}

/// ATTEMPT-first (R18 §3 step 1): every entry hit, admitted or
/// skipped, no exceptions — the SINGLE count (`skip` performs no
/// bump; ATTEMPT − CALLS = skipped queries, exactly).
/// PerCpuArray cells pre-exist, so the slot cannot miss.
fn bump_attempt() {
    if let Some(slot) = ATTEMPT.get_ptr_mut(0) {
        unsafe { *slot = (*slot).wrapping_add(1) };
    }
}

fn emit_call(ev: &ScanCallEvent) {
    if let Some(mut e) = EVENTS.reserve::<ScanCallEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_CALL);
    }
}

fn emit_ret(ev: &ScanRetEvent) {
    if let Some(mut e) = EVENTS.reserve::<ScanRetEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_RET);
    }
}

fn emit_guard(ev: &GuardEvent) {
    if let Some(mut e) = EVENTS.reserve::<GuardEvent>(0) {
        e.write(*ev);
        e.submit(0);
    } else {
        bump_loss(LOSS_RING_GUARD);
    }
}

/// Retire primitive (R18 §3, shared entry-recovery + member-
/// epilogue paths): RCOUNT = IDLE|0 FIRST, then SCAN delete
/// (non-ENOENT → LOSS_RETIRE_FAIL promptly via `absent_ok` —
/// never delay a failure count to take time, or a never-coming
/// take silences it; IDLE+record is the marker that take-time
/// recovery must NOT recount; ENOENT → absent-ok).
fn retire(tid: &u32) {
    // The cell exists (the epilogue read it pre-bump in this same
    // invocation — no same-tid interleaving), so BPF_ANY cannot
    // fail; ignored regardless — retirement is best-effort, and a
    // stale record is take-time LOUD (LOSS 31), never silent.
    let _ = RCOUNT.insert(tid, make_rcount(0, RCOUNT_STATE_IDLE), 0);
    absent_ok(SCAN.remove(tid));
}

/// Gated epilogue (R18 §4 — one epilogue, every path): retires iff
/// the peek hit AND ACTIVE AND the EXPLICIT pre-bump read reaches
/// the frozen expected (`old_count + 1 == expected` — comparing
/// post-bump would retire after 511 firings).
fn epilogue(gated: bool, old: Option<u32>, expected: u32, tid: &u32) {
    if !gated {
        return;
    }
    if let Some(c) = old {
        // Wrapping: a corrupt count (u32::MAX) wraps to 0, which
        // never equals the validated expected (1..=512) — no
        // accidental retire.
        if c.wrapping_add(1) == expected {
            retire(tid);
        }
    }
}

/// Absent-ok delete (R18 §6.16 ENOENT-as-absent): `Ok`/`-ENOENT`
/// mean the desired state is achieved (no LOSS); any other error
/// is a cleanup failure (LOSS_RETIRE_FAIL now — a failure count is
/// never delayed to take time, or a never-coming take silences
/// it) and the cell is retained.
fn absent_ok(r: Result<(), i32>) {
    match r {
        Ok(()) => {}
        Err(e) if e == -ENOENT => {}
        Err(_) => bump_loss(LOSS_RETIRE_FAIL),
    }
}

/// Uniform skip path (R18 §3, sol F1): every cause, including
/// post-SEQ publication failures. Deletes SCAN[tid] (D — the C
/// PENDING delete is gone with the map), RCOUNT→IDLE|0 iff
/// present (never create — the SKIP path never creates cells),
/// LOSS[cause], CALL(skipped, cause, seq 0). The RCOUNT→IDLE step
/// runs REGARDLESS of delete outcomes, so a retained cell is
/// always paired with IDLE-or-missing.
fn skip(tid: u32, op: u64, cause: u8) {
    absent_ok(SCAN.remove(&tid));
    if RCOUNT.get_ptr(&tid).is_some() {
        // Existing-key update: cannot fail; ignored regardless —
        // the skip disposition is already decided.
        let _ = RCOUNT.insert(&tid, make_rcount(0, RCOUNT_STATE_IDLE), 0);
    }
    bump_loss(loss_for_skip_cause(cause));
    emit_call(&ScanCallEvent {
        kind: KIND_SCAN_CALL,
        op: op as u32,
        tid,
        flags: make_call_flags(false, cause),
        seq: 0,
    });
}

/// query_operation(provctx, operation_id, no_store): the entry
/// plane (R18 §3, stage D: the C-interim PENDING write is gone —
/// members read SCAN; item 5 adds the tier-1 token bucket).
/// Fail-fast gates (cookie → CTRL → SKIP_ALL → BIRTH → wrap →
/// governor → bucket), SEQ mint, SCAN take (snapshot-then-classify),
/// RCOUNT reset, SCAN publish, then admit effects (CALLS bump +
/// CALL). Every gate skips with its cause + LOSS + CALL(skipped,
/// seq 0); admits freeze EXPECTED+epoch from CTRL into the record.
/// Same arg positions for the core wrapper
/// ossl_provider_query_operation(prov, op, no_cache) on
/// 3.0/3.5/4.0. Straight-line: zero loops (R18 §10.3).
#[uprobe]
pub fn member_entry(ctx: ProbeContext) -> u32 {
    // 1. ATTEMPT bump FIRST (before every exit incl. legacy).
    bump_attempt();
    let op: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    // A missing arg2 stashes a NULL pointer: the return-side read
    // then fails and the array is treated as `no_store`.
    let ns_ptr: u64 = ctx.arg(2).unwrap_or(0);
    let tid = helpers::bpf_get_current_pid_tgid() as u32;
    // 2. Cookie fail-fast, before any map read (loader bug).
    if cookie_of(&ctx) != MEMBER_ENTRY_COOKIE {
        skip(tid, op, SKIP_ENTRY_COOKIE);
        return 0;
    }
    // 3. CTRL: missing/unreadable/invalid → cause 7 (defense in
    // depth — the loader always programs it; zero EXPECTED/epoch =
    // never programmed, EXPECTED > 512 = loader bug — v1 attaches
    // exactly 512, item 6 programs fewer legitimately).
    let ctrl = match unsafe { CTRL.get_ptr(0).map(|p| *p) } {
        Some(c) => c,
        None => {
            skip(tid, op, SKIP_CTRL_UNPROGRAMMED);
            return 0;
        }
    };
    if ctrl.expected == 0 || ctrl.expected > MAX_ALGS as u32 || ctrl.epoch == 0 {
        skip(tid, op, SKIP_CTRL_UNPROGRAMMED);
        return 0;
    }
    // 4. SKIP_ALL.
    if ctrl.skip_all != 0 {
        skip(tid, op, SKIP_ALL);
        return 0;
    }
    // 5-6. BIRTH: missing → pending; MAX → frozen (freeze is
    // enforced by keeping BIRTH at MAX and checking every hit —
    // NO future admits for this tid).
    let birth = match unsafe { BIRTH.get_ptr(&tid).map(|p| *p) } {
        Some(b) => b,
        None => {
            skip(tid, op, SKIP_BIRTH_PENDING);
            return 0;
        }
    };
    if birth == BIRTH_FROZEN {
        skip(tid, op, SKIP_BIRTH_WRAP);
        return 0;
    }
    // 7. Governor: occupancy > GOVERNOR → cause 4 (occupancy
    // semantics — GOVERNOR is max admittable OCCUPANCY, R18 §2).
    if EVENTS.query(RINGBUF_AVAIL_DATA) > ctrl.governor {
        skip(tid, op, SKIP_RING_PRESSURE);
        return 0;
    }
    // 7b. Tier-1 token bucket (item 5, §5.4): charged AFTER all
    // other gates (tokens meter admitted scans, not attempts).
    // Missing cell → full burst (a tid's first query starts
    // untaxed); insert-fail → cause 8 (admit-store class).
    // Refill math runs in bucket-shifted space (ns>>8); last is
    // reset to now (dropping the remainder is conservative —
    // sustained admits stay ≥25ms apart, exactly 40/s).
    let now_shifted = unsafe { helpers::bpf_ktime_get_ns() } >> 8;
    let (tok, last) = match unsafe { BUCKET.get_ptr(&tid).map(|p| *p) } {
        Some(v) => split_bucket(v),
        None => (BUCKET_BURST as u8, now_shifted),
    };
    let elapsed = now_shifted.wrapping_sub(last);
    let refill = (elapsed / BUCKET_PERIOD_SHIFTED).min(BUCKET_BURST);
    let mut tokens = (tok as u64 + refill).min(BUCKET_BURST);
    if tokens == 0 {
        skip(tid, op, SKIP_BUCKET_EMPTY);
        return 0;
    }
    tokens -= 1;
    if BUCKET
        .insert(&tid, make_bucket(tokens as u8, now_shifted), 0)
        .is_err()
    {
        skip(tid, op, SKIP_ADMIT_STORE_FAIL);
        return 0;
    }
    // 8. SEQ step: missing → insert (birth,0) (fail → cause 2);
    // birth mismatch → reset (birth_new,0); match → ctr+1
    // saturating, re-issuing MAX skips (cause 9, sol F10 — never
    // reissue). `split_seq` masks to 48 bits, so ctr > MAX is
    // impossible and `== MAX` is the exact saturation test.
    // (SEQ-update of an existing key cannot fail — plain HASH
    // update.)
    let seq = match unsafe { SEQ.get_ptr(&tid).map(|p| *p) } {
        None => {
            let fresh = make_seq(birth, 0);
            if SEQ.insert(&tid, fresh, BPF_NOEXIST).is_err() {
                skip(tid, op, SKIP_SEQ_FULL);
                return 0;
            }
            fresh
        }
        Some(cur) => {
            let (cur_birth, ctr) = split_seq(cur);
            if cur_birth != birth {
                let fresh = make_seq(birth, 0);
                let _ = SEQ.insert(&tid, fresh, 0);
                fresh
            } else if ctr == SEQ_CTR_MAX {
                skip(tid, op, SKIP_SEQ_SATURATED);
                return 0;
            } else {
                let next = make_seq(birth, ctr + 1);
                let _ = SEQ.insert(&tid, next, 0);
                next
            }
        }
    };
    // 9. (D: the C-interim PENDING write is gone with the map —
    // members read SCAN now. Cause-8/LOSS-32 still cover the
    // RCOUNT-reset + SCAN-publish failures below.)
    // 10. SCAN take: SNAPSHOT old SCAN + old RCOUNT into stack
    // FIRST, classify the snapshot (R18 §3 table), run the row's
    // effects. The repair rows' "delete" is subsumed by the step-12
    // BPF_ANY overwrite (single-writer serial context: identical
    // end state), and a failed publish runs the uniform skip path
    // whose SCAN delete preserves the loss accounting — so no
    // explicit delete here.
    let old_scan: Option<ScanRec> = unsafe { SCAN.get_ptr(&tid).map(|p| *p) };
    let old_rc: Option<u64> = unsafe { RCOUNT.get_ptr(&tid).map(|p| *p) };
    let mut hint = false;
    match (old_scan, old_rc) {
        (None, Some(rc)) if split_rcount(rc).1 == RCOUNT_STATE_ACTIVE => {
            // LRU-evicted in-flight (NULL + ACTIVE ⟺ evicted).
            bump_loss(LOSS_SCAN_EVICTED);
        }
        (None, _) => {
            // First query, retired, or prior skip: fresh-silent.
        }
        (Some(rec), _) if rec.epoch != ctrl.epoch => {
            // Membership churned mid-flight: never a hint.
            bump_loss(LOSS_SCAN_CHURNED);
        }
        (Some(_), None) => {
            // Corrupt (unreachable: step 11 precedes 12).
            bump_loss(LOSS_STALE_REPAIRED);
        }
        (Some(rec), Some(rc)) => {
            let (count, state) = split_rcount(rc);
            if state == RCOUNT_STATE_IDLE {
                // Failed-delete marker: already counted at retire —
                // silent recovery (recounting would double-count).
            } else if count >= rec.expected {
                // Unretired complete (structurally unreachable):
                // loud repair.
                bump_loss(LOSS_STALE_REPAIRED);
            } else {
                // Nested (fresh in-flight has count 0).
                hint = true;
            }
        }
    }
    // 11. RCOUNT-reset (insert-or-create ACTIVE|0; logically
    // unreachable by the §2 invariant — leg via synthetic
    // violation).
    if RCOUNT
        .insert(&tid, make_rcount(0, RCOUNT_STATE_ACTIVE), 0)
        .is_err()
    {
        skip(tid, op, SKIP_ADMIT_STORE_FAIL);
        return 0;
    }
    // 12. SCAN-publish (the minted seq is spent on failure —
    // monotonicity preserved, the id simply never observed).
    let rec = ScanRec {
        op,
        ns_ptr,
        seq,
        expected: ctrl.expected,
        _pad: 0,
        epoch: ctrl.epoch,
    };
    if SCAN.insert(&tid, rec, 0).is_err() {
        skip(tid, op, SKIP_ADMIT_STORE_FAIL);
        return 0;
    }
    // 13. Admit effects: CALLS bump (admitted-once — NULL included,
    // the entry cannot see rv) + CALL(admitted, seq, hint?).
    if percpu_add(&CALLS, &(op as u32)).is_err() {
        bump_loss(LOSS_MAP_CALLS);
    }
    emit_call(&ScanCallEvent {
        kind: KIND_SCAN_CALL,
        op: op as u32,
        tid,
        flags: make_call_flags(hint, SKIP_ADMITTED),
        seq,
    });
    0
}

/// Define one baked-slot member (`member_J` walks slot J and only
/// slot J). The slot index is a literal, so the address math folds
/// and the slot-0 / slot-511 specials compile out of every other
/// member. Each expansion is an independent `#[uretprobe]` main
/// (512 independent verifies — a member failure is a hole, never a
/// load failure once item 6 lands; v1 keeps abort-whole).
///
/// Stage-D body (R18 §4 — sampler-parity DECLARED broken, §6.5:
/// classifier/dispatch/cacheability/privacy logic stays verbatim,
/// the wrapper diverges): SCAN peek + bump-if-present + ACTIVE
/// gate + member-0 verdict-first RET + per-member T-cache
/// eligibility + 511 guard + uniform gated epilogue with retire.
/// CALLS counted by the entry (admit-bump — R18 §6.2); no
/// QUERY_NEXT cursor (every scan is full); no TERMD (512 writers
/// would last-wins — TRUE-T is the item-4 join's job); no tail
/// calls.
macro_rules! def_member {
    ($name:ident, $j:literal) => {
        #[uretprobe]
        pub fn $name(ctx: RetProbeContext) -> u32 {
            let tid = helpers::bpf_get_current_pid_tgid() as u32;
            // Loader self-check (recorded, not returned: a
            // mismatched member still bumps + runs the gated
            // epilogue — the scan completed, its slot evidence
            // holes — R18 §6.4).
            let cookie_ok =
                unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) } == $j;
            // SCAN peek (record kept for the epilogue).
            let peek: Option<ScanRec> = unsafe { SCAN.get_ptr(&tid).map(|p| *p) };
            // bump-if-present (never create — §2 invariant): the
            // EXPLICIT pre-bump read feeds the retire equation.
            // Single-threaded per cell (one tid = one thread, its
            // 512 members fire sequentially), so the read-modify-
            // write loses nothing.
            let mut old: Option<u32> = None;
            let mut was_active = false;
            if let Some(cell) = unsafe { RCOUNT.get_ptr(&tid).map(|p| *p) } {
                let (count, state) = split_rcount(cell);
                old = Some(count);
                was_active = state == RCOUNT_STATE_ACTIVE;
                let _ = RCOUNT.insert(&tid, make_rcount(count.wrapping_add(1), state), 0);
            }
            // ACTIVE gate (R18 §6.4): work + epilogue require
            // peek-hit AND RCOUNT ACTIVE.
            let gated = peek.is_some() && old.is_some() && was_active;
            if !cookie_ok {
                bump_loss(LOSS_MEMBER_COOKIE);
                if let (Some(rec), Some(c)) = (peek, old) {
                    if gated && c.wrapping_add(1) == rec.expected {
                        retire(&tid);
                    }
                }
                return 0;
            }
            let rec = match peek {
                Some(r) => r,
                // SCAN-miss: skipped scans emit nothing member-side
                // (no work, no RET, no guard).
                None => return 0,
            };
            if !gated {
                // IDLE+record (or RCOUNT-less): no work, no
                // epilogue — the record persists for take-time
                // silent recovery.
                return 0;
            }
            let op = rec.op;
            let ns_ptr = rec.ns_ptr;
            let seq = rec.seq;
            // Frozen expected from the PEEKED record (never live
            // CTRL — a membership change mid-scan must not move
            // the retire equation).
            let expected = rec.expected;
            let rv: u64 = ctx.ret();
            if $j == 0 {
                // (1) Member 0 reads ns_ptr FIRST and flags
                // TRUNC_NO_STORE (skip-proof cacheability — R18
                // §4: T-skips and EMPTY paths must never lose a
                // no_store verdict; member 0 always walks — j=0 ≤
                // T — so the flag is always evaluated). Only an
                // explicit 0 is cacheable; any nonzero verdict,
                // NULL pointer, or read failure fails closed to
                // `no_store` (flagged, still walked — never
                // proven).
                let no_store =
                    match unsafe { helpers::bpf_probe_read_user(ns_ptr as *const u32) } {
                        Ok(0) => false,
                        _ => true,
                    };
                if no_store {
                    flag_trunc(op as u32, TRUNC_NO_STORE);
                }
                // (2) Member 0 emits QUERY_RET early (a slot-0 read
                // abort must still present RET, else HOLE-0 is
                // indistinguishable from abort).
                emit_ret(&ScanRetEvent {
                    kind: KIND_SCAN_RET,
                    op: op as u32,
                    flags: if rv == 0 { RET_FLAG_EMPTY } else { 0 },
                    tid,
                    seq,
                    arr: rv,
                    generation: gen_of(rv),
                });
            }
            if rv == 0 {
                // EMPTY: all members run the gated epilogue and
                // return (the invocation still retires; count
                // reaches expected).
                epilogue(gated, old, expected, &tid);
                return 0;
            }
            // T-cache peek with LOCAL eligibility (R18 §6.12 — no
            // shared cell, order-independent; member 0 skips the
            // peek — it always walks). Miss OR GEN-mismatch →
            // COLD (GEN-mismatch is logical invalidation for
            // peek-only BPF; item 4 replaces the cache).
            let mut warm_t: Option<u64> = None;
            if $j != 0 {
                if let Some(tc) = unsafe { T_CACHE.get_ptr(&rv).map(|p| *p) } {
                    if tc.generation == gen_of(rv) {
                        warm_t = Some(tc.t);
                    }
                }
                if let Some(t) = warm_t {
                    if $j > t {
                        // Would-skip path: only a
                        // successfully-read zero pointee skips (a
                        // non-NULL pointer is NOT permission — the
                        // OpenSSL provider-base contract assigns
                        // cache permission to the integer
                        // out-value). Nonzero / NULL / unreadable
                        // → COLD walk.
                        match unsafe {
                            helpers::bpf_probe_read_user(ns_ptr as *const u32)
                        } {
                            Ok(0) => {
                                epilogue(gated, old, expected, &tid);
                                return 0;
                            }
                            _ => {}
                        }
                    }
                }
            }
            // Slot walk (OSSL_ALGORITHM = { names, props, impl,
            // desc } @32B; only names+impl are read here; v1
            // precedence: tuple-read-fail → TRUNC_WALK_READ;
            // names == 0 → EMPTY-silent (slot 0: TRUNC_WALK_EMPTY
            // flag); imp == 0 → NOIMP; pointed-to-name-read-fail →
            // TRUNC_WALK_NAME + ALG_UNREADABLE). Aborts/NOIMP/
            // name-fails record their TRUNC/LOSS and fall through
            // to the guard check, never skipping it.
            let base = rv + $j * 32;
            let names = unsafe { helpers::bpf_probe_read_user(base as *const u64) };
            let imp = unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) };
            let mut names_present = false;
            match (names, imp) {
                (Ok(names), Ok(imp)) => {
                    if names == 0 {
                        // Terminator at this slot: silent (no proof
                        // without the item-4 T-join). Slot 0 empty
                        // = the query returned a table with no
                        // first alg (flagged).
                        if $j == 0 {
                            flag_trunc(op as u32, TRUNC_WALK_EMPTY);
                        }
                    } else {
                        names_present = true;
                        if imp == 0 {
                            // Alg without implementation: a stable
                            // observation (the slot read fine),
                            // explicit via NOIMP.
                            flag_trunc(op as u32, TRUNC_WALK_NOIMP);
                        } else {
                            // Kernel scratch only: classified
                            // below, never emitted.
                            let mut name_buf = [0u8; 128];
                            match unsafe {
                                helpers::bpf_probe_read_user_str_bytes(
                                    names as *const u8,
                                    &mut name_buf,
                                )
                            } {
                                Ok(slice) => {
                                    // Copy the length out first:
                                    // the window array is
                                    // reborrowed shared below,
                                    // which ends `slice`'s mutable
                                    // borrow.
                                    let len = slice.len();
                                    let saturated = len == ALG_WINDOW - 1;
                                    let v = classify_alg(&name_buf, len, saturated);
                                    // ALG first: userspace drops
                                    // rows whose (array, index) has
                                    // no ALG record yet (orphan
                                    // rule), so rows must follow
                                    // their ALG.
                                    emit_scan_alg(&ScanAlgEvent {
                                        kind: KIND_SCAN_ALG,
                                        op: op as u32,
                                        class: v.class,
                                        status: v.status,
                                        weak: u8::from(v.weak),
                                        _pad: 0,
                                        arr: rv,
                                        idx: $j,
                                        generation: gen_of(rv),
                                        tid,
                                        _pad2: 0,
                                        seq,
                                    });
                                    let wctx = WalkCtx {
                                        op: op as u32,
                                        tid,
                                        arr: rv,
                                        j: $j,
                                        seq,
                                    };
                                    match walk_dispatch(imp, &wctx) {
                                        // Overflow: rows 0..127 are
                                        // kept, the rest is
                                        // unwalkable — flagged, not
                                        // silent.
                                        1 => {
                                            flag_trunc(op as u32, TRUNC_DISPATCH);
                                        }
                                        0 => {}
                                        // Read abort: flag (the
                                        // scan re-walks next
                                        // query).
                                        _ => {
                                            flag_trunc(op as u32, TRUNC_WALK_READ);
                                        }
                                    }
                                }
                                Err(_) => {
                                    flag_trunc(op as u32, TRUNC_WALK_NAME);
                                    // Explicit unreadable record
                                    // (cold page or hostile
                                    // pointer).
                                    emit_scan_alg(&ScanAlgEvent {
                                        kind: KIND_SCAN_ALG,
                                        op: op as u32,
                                        class: OTHER_CLASS,
                                        status: ALG_UNREADABLE,
                                        weak: 0,
                                        _pad: 0,
                                        arr: rv,
                                        idx: $j,
                                        generation: gen_of(rv),
                                        tid,
                                        _pad2: 0,
                                        seq,
                                    });
                                }
                            }
                        }
                    }
                }
                // Unreadable slot aborts this member's walk
                // (flagged; the next scan re-walks — every scan is
                // full).
                _ => {
                    flag_trunc(op as u32, TRUNC_WALK_READ);
                }
            }
            // 511-only guard (R18 §4): eligible iff (warm AND T ==
            // 512) OR ((cold OR GEN-miss) AND slot 511 read
            // live/names-present). Cold boundary scans need the
            // guard (else item 4 can never establish T = 512 or
            // publish the first warm entry). The guard is NOT part
            // of the walk: NOIMP/EMPTY/ERROR @511 still execute it
            // when eligible (eligibility ≠ walkability);
            // EMPTY@511 in cold means T ≤ 511 is established → no
            // guard (silence justified); rv == 0 and SCAN-miss
            // never guard (returned above). Folds out of members
            // 0..510.
            if $j == MAX_ALGS - 1 {
                let eligible = match warm_t {
                    Some(t) => t == MAX_ALGS,
                    None => names_present,
                };
                if eligible {
                    // Single positional read of slot 512.
                    let tail = unsafe {
                        helpers::bpf_probe_read_user((rv + MAX_ALGS * 32) as *const u64)
                    };
                    match tail {
                        // EMPTY: clean-full proof (event only).
                        Ok(0) => {
                            emit_guard(&GuardEvent {
                                kind: KIND_GUARD,
                                op: op as u32,
                                verdict: GUARD_EMPTY,
                                tid,
                                seq,
                                arr: rv,
                                generation: gen_of(rv),
                            });
                        }
                        // VALID: contract violation (event +
                        // TRUNC_ALGS — guard-VALID-exclusive in D;
                        // the v1 tail check's ERROR/VALID
                        // conflation is removed; members.o has no
                        // other TRUNC_ALGS producer).
                        Ok(_) => {
                            flag_trunc(op as u32, TRUNC_ALGS);
                            emit_guard(&GuardEvent {
                                kind: KIND_GUARD,
                                op: op as u32,
                                verdict: GUARD_VALID,
                                tid,
                                seq,
                                arr: rv,
                                generation: gen_of(rv),
                            });
                        }
                        // ERROR: read-abort/UNKNOWN-TERMINATOR
                        // (event + LOSS — re-covers on retry).
                        Err(_) => {
                            bump_loss(LOSS_GUARD_READ_ABORT);
                            emit_guard(&GuardEvent {
                                kind: KIND_GUARD,
                                op: op as u32,
                                verdict: GUARD_ERROR,
                                tid,
                                seq,
                                arr: rv,
                                generation: gen_of(rv),
                            });
                        }
                    }
                }
            }
            epilogue(gated, old, expected, &tid);
            0
        }
    };
}

def_member!(member_000, 0);
def_member!(member_001, 1);
def_member!(member_002, 2);
def_member!(member_003, 3);
def_member!(member_004, 4);
def_member!(member_005, 5);
def_member!(member_006, 6);
def_member!(member_007, 7);
def_member!(member_008, 8);
def_member!(member_009, 9);
def_member!(member_010, 10);
def_member!(member_011, 11);
def_member!(member_012, 12);
def_member!(member_013, 13);
def_member!(member_014, 14);
def_member!(member_015, 15);
def_member!(member_016, 16);
def_member!(member_017, 17);
def_member!(member_018, 18);
def_member!(member_019, 19);
def_member!(member_020, 20);
def_member!(member_021, 21);
def_member!(member_022, 22);
def_member!(member_023, 23);
def_member!(member_024, 24);
def_member!(member_025, 25);
def_member!(member_026, 26);
def_member!(member_027, 27);
def_member!(member_028, 28);
def_member!(member_029, 29);
def_member!(member_030, 30);
def_member!(member_031, 31);
def_member!(member_032, 32);
def_member!(member_033, 33);
def_member!(member_034, 34);
def_member!(member_035, 35);
def_member!(member_036, 36);
def_member!(member_037, 37);
def_member!(member_038, 38);
def_member!(member_039, 39);
def_member!(member_040, 40);
def_member!(member_041, 41);
def_member!(member_042, 42);
def_member!(member_043, 43);
def_member!(member_044, 44);
def_member!(member_045, 45);
def_member!(member_046, 46);
def_member!(member_047, 47);
def_member!(member_048, 48);
def_member!(member_049, 49);
def_member!(member_050, 50);
def_member!(member_051, 51);
def_member!(member_052, 52);
def_member!(member_053, 53);
def_member!(member_054, 54);
def_member!(member_055, 55);
def_member!(member_056, 56);
def_member!(member_057, 57);
def_member!(member_058, 58);
def_member!(member_059, 59);
def_member!(member_060, 60);
def_member!(member_061, 61);
def_member!(member_062, 62);
def_member!(member_063, 63);
def_member!(member_064, 64);
def_member!(member_065, 65);
def_member!(member_066, 66);
def_member!(member_067, 67);
def_member!(member_068, 68);
def_member!(member_069, 69);
def_member!(member_070, 70);
def_member!(member_071, 71);
def_member!(member_072, 72);
def_member!(member_073, 73);
def_member!(member_074, 74);
def_member!(member_075, 75);
def_member!(member_076, 76);
def_member!(member_077, 77);
def_member!(member_078, 78);
def_member!(member_079, 79);
def_member!(member_080, 80);
def_member!(member_081, 81);
def_member!(member_082, 82);
def_member!(member_083, 83);
def_member!(member_084, 84);
def_member!(member_085, 85);
def_member!(member_086, 86);
def_member!(member_087, 87);
def_member!(member_088, 88);
def_member!(member_089, 89);
def_member!(member_090, 90);
def_member!(member_091, 91);
def_member!(member_092, 92);
def_member!(member_093, 93);
def_member!(member_094, 94);
def_member!(member_095, 95);
def_member!(member_096, 96);
def_member!(member_097, 97);
def_member!(member_098, 98);
def_member!(member_099, 99);
def_member!(member_100, 100);
def_member!(member_101, 101);
def_member!(member_102, 102);
def_member!(member_103, 103);
def_member!(member_104, 104);
def_member!(member_105, 105);
def_member!(member_106, 106);
def_member!(member_107, 107);
def_member!(member_108, 108);
def_member!(member_109, 109);
def_member!(member_110, 110);
def_member!(member_111, 111);
def_member!(member_112, 112);
def_member!(member_113, 113);
def_member!(member_114, 114);
def_member!(member_115, 115);
def_member!(member_116, 116);
def_member!(member_117, 117);
def_member!(member_118, 118);
def_member!(member_119, 119);
def_member!(member_120, 120);
def_member!(member_121, 121);
def_member!(member_122, 122);
def_member!(member_123, 123);
def_member!(member_124, 124);
def_member!(member_125, 125);
def_member!(member_126, 126);
def_member!(member_127, 127);
def_member!(member_128, 128);
def_member!(member_129, 129);
def_member!(member_130, 130);
def_member!(member_131, 131);
def_member!(member_132, 132);
def_member!(member_133, 133);
def_member!(member_134, 134);
def_member!(member_135, 135);
def_member!(member_136, 136);
def_member!(member_137, 137);
def_member!(member_138, 138);
def_member!(member_139, 139);
def_member!(member_140, 140);
def_member!(member_141, 141);
def_member!(member_142, 142);
def_member!(member_143, 143);
def_member!(member_144, 144);
def_member!(member_145, 145);
def_member!(member_146, 146);
def_member!(member_147, 147);
def_member!(member_148, 148);
def_member!(member_149, 149);
def_member!(member_150, 150);
def_member!(member_151, 151);
def_member!(member_152, 152);
def_member!(member_153, 153);
def_member!(member_154, 154);
def_member!(member_155, 155);
def_member!(member_156, 156);
def_member!(member_157, 157);
def_member!(member_158, 158);
def_member!(member_159, 159);
def_member!(member_160, 160);
def_member!(member_161, 161);
def_member!(member_162, 162);
def_member!(member_163, 163);
def_member!(member_164, 164);
def_member!(member_165, 165);
def_member!(member_166, 166);
def_member!(member_167, 167);
def_member!(member_168, 168);
def_member!(member_169, 169);
def_member!(member_170, 170);
def_member!(member_171, 171);
def_member!(member_172, 172);
def_member!(member_173, 173);
def_member!(member_174, 174);
def_member!(member_175, 175);
def_member!(member_176, 176);
def_member!(member_177, 177);
def_member!(member_178, 178);
def_member!(member_179, 179);
def_member!(member_180, 180);
def_member!(member_181, 181);
def_member!(member_182, 182);
def_member!(member_183, 183);
def_member!(member_184, 184);
def_member!(member_185, 185);
def_member!(member_186, 186);
def_member!(member_187, 187);
def_member!(member_188, 188);
def_member!(member_189, 189);
def_member!(member_190, 190);
def_member!(member_191, 191);
def_member!(member_192, 192);
def_member!(member_193, 193);
def_member!(member_194, 194);
def_member!(member_195, 195);
def_member!(member_196, 196);
def_member!(member_197, 197);
def_member!(member_198, 198);
def_member!(member_199, 199);
def_member!(member_200, 200);
def_member!(member_201, 201);
def_member!(member_202, 202);
def_member!(member_203, 203);
def_member!(member_204, 204);
def_member!(member_205, 205);
def_member!(member_206, 206);
def_member!(member_207, 207);
def_member!(member_208, 208);
def_member!(member_209, 209);
def_member!(member_210, 210);
def_member!(member_211, 211);
def_member!(member_212, 212);
def_member!(member_213, 213);
def_member!(member_214, 214);
def_member!(member_215, 215);
def_member!(member_216, 216);
def_member!(member_217, 217);
def_member!(member_218, 218);
def_member!(member_219, 219);
def_member!(member_220, 220);
def_member!(member_221, 221);
def_member!(member_222, 222);
def_member!(member_223, 223);
def_member!(member_224, 224);
def_member!(member_225, 225);
def_member!(member_226, 226);
def_member!(member_227, 227);
def_member!(member_228, 228);
def_member!(member_229, 229);
def_member!(member_230, 230);
def_member!(member_231, 231);
def_member!(member_232, 232);
def_member!(member_233, 233);
def_member!(member_234, 234);
def_member!(member_235, 235);
def_member!(member_236, 236);
def_member!(member_237, 237);
def_member!(member_238, 238);
def_member!(member_239, 239);
def_member!(member_240, 240);
def_member!(member_241, 241);
def_member!(member_242, 242);
def_member!(member_243, 243);
def_member!(member_244, 244);
def_member!(member_245, 245);
def_member!(member_246, 246);
def_member!(member_247, 247);
def_member!(member_248, 248);
def_member!(member_249, 249);
def_member!(member_250, 250);
def_member!(member_251, 251);
def_member!(member_252, 252);
def_member!(member_253, 253);
def_member!(member_254, 254);
def_member!(member_255, 255);
def_member!(member_256, 256);
def_member!(member_257, 257);
def_member!(member_258, 258);
def_member!(member_259, 259);
def_member!(member_260, 260);
def_member!(member_261, 261);
def_member!(member_262, 262);
def_member!(member_263, 263);
def_member!(member_264, 264);
def_member!(member_265, 265);
def_member!(member_266, 266);
def_member!(member_267, 267);
def_member!(member_268, 268);
def_member!(member_269, 269);
def_member!(member_270, 270);
def_member!(member_271, 271);
def_member!(member_272, 272);
def_member!(member_273, 273);
def_member!(member_274, 274);
def_member!(member_275, 275);
def_member!(member_276, 276);
def_member!(member_277, 277);
def_member!(member_278, 278);
def_member!(member_279, 279);
def_member!(member_280, 280);
def_member!(member_281, 281);
def_member!(member_282, 282);
def_member!(member_283, 283);
def_member!(member_284, 284);
def_member!(member_285, 285);
def_member!(member_286, 286);
def_member!(member_287, 287);
def_member!(member_288, 288);
def_member!(member_289, 289);
def_member!(member_290, 290);
def_member!(member_291, 291);
def_member!(member_292, 292);
def_member!(member_293, 293);
def_member!(member_294, 294);
def_member!(member_295, 295);
def_member!(member_296, 296);
def_member!(member_297, 297);
def_member!(member_298, 298);
def_member!(member_299, 299);
def_member!(member_300, 300);
def_member!(member_301, 301);
def_member!(member_302, 302);
def_member!(member_303, 303);
def_member!(member_304, 304);
def_member!(member_305, 305);
def_member!(member_306, 306);
def_member!(member_307, 307);
def_member!(member_308, 308);
def_member!(member_309, 309);
def_member!(member_310, 310);
def_member!(member_311, 311);
def_member!(member_312, 312);
def_member!(member_313, 313);
def_member!(member_314, 314);
def_member!(member_315, 315);
def_member!(member_316, 316);
def_member!(member_317, 317);
def_member!(member_318, 318);
def_member!(member_319, 319);
def_member!(member_320, 320);
def_member!(member_321, 321);
def_member!(member_322, 322);
def_member!(member_323, 323);
def_member!(member_324, 324);
def_member!(member_325, 325);
def_member!(member_326, 326);
def_member!(member_327, 327);
def_member!(member_328, 328);
def_member!(member_329, 329);
def_member!(member_330, 330);
def_member!(member_331, 331);
def_member!(member_332, 332);
def_member!(member_333, 333);
def_member!(member_334, 334);
def_member!(member_335, 335);
def_member!(member_336, 336);
def_member!(member_337, 337);
def_member!(member_338, 338);
def_member!(member_339, 339);
def_member!(member_340, 340);
def_member!(member_341, 341);
def_member!(member_342, 342);
def_member!(member_343, 343);
def_member!(member_344, 344);
def_member!(member_345, 345);
def_member!(member_346, 346);
def_member!(member_347, 347);
def_member!(member_348, 348);
def_member!(member_349, 349);
def_member!(member_350, 350);
def_member!(member_351, 351);
def_member!(member_352, 352);
def_member!(member_353, 353);
def_member!(member_354, 354);
def_member!(member_355, 355);
def_member!(member_356, 356);
def_member!(member_357, 357);
def_member!(member_358, 358);
def_member!(member_359, 359);
def_member!(member_360, 360);
def_member!(member_361, 361);
def_member!(member_362, 362);
def_member!(member_363, 363);
def_member!(member_364, 364);
def_member!(member_365, 365);
def_member!(member_366, 366);
def_member!(member_367, 367);
def_member!(member_368, 368);
def_member!(member_369, 369);
def_member!(member_370, 370);
def_member!(member_371, 371);
def_member!(member_372, 372);
def_member!(member_373, 373);
def_member!(member_374, 374);
def_member!(member_375, 375);
def_member!(member_376, 376);
def_member!(member_377, 377);
def_member!(member_378, 378);
def_member!(member_379, 379);
def_member!(member_380, 380);
def_member!(member_381, 381);
def_member!(member_382, 382);
def_member!(member_383, 383);
def_member!(member_384, 384);
def_member!(member_385, 385);
def_member!(member_386, 386);
def_member!(member_387, 387);
def_member!(member_388, 388);
def_member!(member_389, 389);
def_member!(member_390, 390);
def_member!(member_391, 391);
def_member!(member_392, 392);
def_member!(member_393, 393);
def_member!(member_394, 394);
def_member!(member_395, 395);
def_member!(member_396, 396);
def_member!(member_397, 397);
def_member!(member_398, 398);
def_member!(member_399, 399);
def_member!(member_400, 400);
def_member!(member_401, 401);
def_member!(member_402, 402);
def_member!(member_403, 403);
def_member!(member_404, 404);
def_member!(member_405, 405);
def_member!(member_406, 406);
def_member!(member_407, 407);
def_member!(member_408, 408);
def_member!(member_409, 409);
def_member!(member_410, 410);
def_member!(member_411, 411);
def_member!(member_412, 412);
def_member!(member_413, 413);
def_member!(member_414, 414);
def_member!(member_415, 415);
def_member!(member_416, 416);
def_member!(member_417, 417);
def_member!(member_418, 418);
def_member!(member_419, 419);
def_member!(member_420, 420);
def_member!(member_421, 421);
def_member!(member_422, 422);
def_member!(member_423, 423);
def_member!(member_424, 424);
def_member!(member_425, 425);
def_member!(member_426, 426);
def_member!(member_427, 427);
def_member!(member_428, 428);
def_member!(member_429, 429);
def_member!(member_430, 430);
def_member!(member_431, 431);
def_member!(member_432, 432);
def_member!(member_433, 433);
def_member!(member_434, 434);
def_member!(member_435, 435);
def_member!(member_436, 436);
def_member!(member_437, 437);
def_member!(member_438, 438);
def_member!(member_439, 439);
def_member!(member_440, 440);
def_member!(member_441, 441);
def_member!(member_442, 442);
def_member!(member_443, 443);
def_member!(member_444, 444);
def_member!(member_445, 445);
def_member!(member_446, 446);
def_member!(member_447, 447);
def_member!(member_448, 448);
def_member!(member_449, 449);
def_member!(member_450, 450);
def_member!(member_451, 451);
def_member!(member_452, 452);
def_member!(member_453, 453);
def_member!(member_454, 454);
def_member!(member_455, 455);
def_member!(member_456, 456);
def_member!(member_457, 457);
def_member!(member_458, 458);
def_member!(member_459, 459);
def_member!(member_460, 460);
def_member!(member_461, 461);
def_member!(member_462, 462);
def_member!(member_463, 463);
def_member!(member_464, 464);
def_member!(member_465, 465);
def_member!(member_466, 466);
def_member!(member_467, 467);
def_member!(member_468, 468);
def_member!(member_469, 469);
def_member!(member_470, 470);
def_member!(member_471, 471);
def_member!(member_472, 472);
def_member!(member_473, 473);
def_member!(member_474, 474);
def_member!(member_475, 475);
def_member!(member_476, 476);
def_member!(member_477, 477);
def_member!(member_478, 478);
def_member!(member_479, 479);
def_member!(member_480, 480);
def_member!(member_481, 481);
def_member!(member_482, 482);
def_member!(member_483, 483);
def_member!(member_484, 484);
def_member!(member_485, 485);
def_member!(member_486, 486);
def_member!(member_487, 487);
def_member!(member_488, 488);
def_member!(member_489, 489);
def_member!(member_490, 490);
def_member!(member_491, 491);
def_member!(member_492, 492);
def_member!(member_493, 493);
def_member!(member_494, 494);
def_member!(member_495, 495);
def_member!(member_496, 496);
def_member!(member_497, 497);
def_member!(member_498, 498);
def_member!(member_499, 499);
def_member!(member_500, 500);
def_member!(member_501, 501);
def_member!(member_502, 502);
def_member!(member_503, 503);
def_member!(member_504, 504);
def_member!(member_505, 505);
def_member!(member_506, 506);
def_member!(member_507, 507);
def_member!(member_508, 508);
def_member!(member_509, 509);
def_member!(member_510, 510);
def_member!(member_511, 511);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
