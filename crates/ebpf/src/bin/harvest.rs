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
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext as _,
};
use osslscope_ebpf_common::{
    AlgClassValue, AlgEvent, InitRetEvent, RowEvent, TripClassValue, TripEvent, TripTaxonomy,
    ALG_UNREADABLE, ALG_WINDOW, KIND_ALG, KIND_INIT_RET, KIND_QUERY_RET, KIND_ROW, KIND_TRIP,
    OTHER_CLASS, TRIP_OTHER, TRIP_UNREADABLE, TRIP_WINDOW, classify_alg_with, classify_trip_with,
};

/// core_dispatch.h: provider codes live at 1024+; verified 2026-09-16.
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: u32 = 1027;

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
/// TRUNC[op] bits: alg-array overflow | dispatch-table overflow |
/// walk aborts (entry unreadable | empty table at slot 0 |
/// implementation-less alg at slot 0 | alg-name unreadable). The
/// slot-0 aborts are suspicious (a live query returning an
/// unwalkable first entry); later-slot terminators stay silent.
const TRUNC_ALGS: u64 = 1;
const TRUNC_DISPATCH: u64 = 2;
const TRUNC_WALK_READ: u64 = 4;
const TRUNC_WALK_EMPTY: u64 = 8;
const TRUNC_WALK_NOIMP: u64 = 16;
const TRUNC_WALK_NAME: u64 = 32;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 21, 0);
#[map]
static PENDING_INIT: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
#[map]
static PENDING_QUERY: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
/// Per-(thread, array) query count; walked index = count % MAX_ALGS.
/// Keyed by array address (each provider-op array is a distinct static):
/// different providers' same-op arrays must NOT share a counter, and
/// the counter freezes at the first terminator (see query_return), so
/// short arrays never walk past their end into adjacent tables.
#[map]
static QUERY_NEXT: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);
/// Walk-overflow flags per op id; userspace degrades to PARTIAL.
#[map]
static TRUNC: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);
/// Non-null query calls per op id. The 512-round inventory trigger
/// fires ~68K calls in milliseconds; counting in-map (instead of a
/// ring event per call) keeps the ring burst under 1MB. QUERY_RET is
/// emitted on the first hit per array only (liveness + ops-hit).
#[map]
static CALLS: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);
/// Tripwire hits per attach cookie (userspace id space: ENGINE /
/// meth_new / provider-load / low-level-family probes).
#[map]
static TRIP: HashMap<u64, u64> = HashMap::with_max_entries(128, 0);
/// Non-null query calls per op id on the legacy attachment
/// (cookie 1); the target provider's stay in CALLS.
#[map]
static LGCALLS: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);
/// Kernel classifier table: FNV-1a-64 of exact registry spelling →
/// (class, weak, name for exact confirm). Observer-populated before
/// any attach; no target bytes at rest.
#[map]
static ALG_CLASS: HashMap<u64, AlgClassValue> = HashMap::with_max_entries(1024, 0);
/// Kernel trip table: FNV-1a-64 of exact taxonomy pattern →
/// (engine class, load class, name for exact confirm). Same
/// observer-populated discipline.
#[map]
static TRIP_CLASS: HashMap<u64, TripClassValue> = HashMap::with_max_entries(64, 0);

fn emit_alg(ev: &AlgEvent) {
    if let Some(mut e) = EVENTS.reserve::<AlgEvent>(0) {
        e.write(*ev);
        e.submit(0);
    }
}

fn emit_row(ev: &RowEvent) {
    if let Some(mut e) = EVENTS.reserve::<RowEvent>(0) {
        e.write(*ev);
        e.submit(0);
    }
}

fn emit_trip(ev: &TripEvent) {
    if let Some(mut e) = EVENTS.reserve::<TripEvent>(0) {
        e.write(*ev);
        e.submit(0);
    }
}

fn emit_init_ret(ev: &InitRetEvent) {
    if let Some(mut e) = EVENTS.reserve::<InitRetEvent>(0) {
        e.write(*ev);
        e.submit(0);
    }
}

/// Table lookups behind the shared classifiers (copied out: values
/// are small, and the confirm step borrows the copy).
fn lookup_alg(h: u64) -> Option<AlgClassValue> {
    unsafe { ALG_CLASS.get_ptr(&h).map(|p| *p) }
}

fn lookup_trip(h: u64) -> Option<TripClassValue> {
    unsafe { TRIP_CLASS.get_ptr(&h).map(|p| *p) }
}

/// Algorithm classification as a BPF subprogram (separate
/// verification scope, like the dispatch walk below).
#[inline(never)]
fn classify_alg(name: &[u8], saturated: bool) -> osslscope_ebpf_common::AlgVerdict {
    classify_alg_with(name, saturated, lookup_alg)
}

fn cookie_of(ctx: &ProbeContext) -> u64 {
    unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }
}

fn bump_trip(cookie: u64) {
    let cur = unsafe { TRIP.get_ptr(&cookie).map(|p| *p).unwrap_or(0) };
    let _ = TRIP.insert(cookie, cur.wrapping_add(1), 0);
}

fn take_key(map: &HashMap<u64, u64>, key: u64) -> Option<u64> {
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
    let cur = unsafe { TRUNC.get_ptr(&op).map(|p| *p).unwrap_or(0) };
    let _ = TRUNC.insert(op, cur | bit, 0);
}

/// OSSL_provider_init(handle, in, out, provctx): stash arg2 (out).
#[uprobe]
pub fn init_entry(ctx: ProbeContext) -> u32 {
    let out: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    let _ = PENDING_INIT.insert(pend_key(cookie_of(&ctx)), out, 0);
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
        None => return 0,
    };
    let rv: u64 = ctx.ret();
    if rv != 1 || out == 0 {
        return 0;
    }
    let table = match unsafe { helpers::bpf_probe_read_user(out as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
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
            return 0;
        };
        if fid == 0 {
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

/// query_operation(provctx, operation_id, no_store): stash arg1 (op).
/// Same arg position for the core wrapper
/// ossl_provider_query_operation(prov, op, no_cache) on 3.0/3.5/4.0.
#[uprobe]
pub fn query_entry(ctx: ProbeContext) -> u32 {
    let op: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let _ = PENDING_QUERY.insert(pend_key(cookie_of(&ctx)), op, 0);
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
        });
    }
    1
}

/// At query-return walk exactly one alg of the OSSL_ALGORITHM array
/// (index = per-(thread, array) query count mod 512) plus its dispatch
/// table. The counter freezes at the first terminator (names == 0):
/// later hits re-read the terminator and stop, so short arrays never
/// walk past their end (impl-less algs still advance — they can sit
/// mid-array). OSSL_ALGORITHM = { names, props, impl, desc } @32B.
#[uretprobe]
pub fn query_return(ctx: RetProbeContext) -> u32 {
    // Cookie 1 = legacy attachment: its calls stay out of CALLS.
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let op = match take_key(&PENDING_QUERY, pend_key(cookie)) {
        Some(v) => v,
        None => return 0,
    };
    let rv: u64 = ctx.ret();
    if rv == 0 {
        return 0;
    }
    let legacy = cookie == 1;
    if legacy {
        let calls = unsafe { LGCALLS.get_ptr(&(op as u32)).map(|p| *p).unwrap_or(0) };
        let _ = LGCALLS.insert(op as u32, calls.wrapping_add(1), 0);
    } else {
        let calls = unsafe { CALLS.get_ptr(&(op as u32)).map(|p| *p).unwrap_or(0) };
        let _ = CALLS.insert(op as u32, calls.wrapping_add(1), 0);
    }
    let key = helpers::bpf_get_current_pid_tgid() ^ rv;
    let count = unsafe { QUERY_NEXT.get_ptr(&key).map(|p| *p).unwrap_or(0) };
    let j = count % MAX_ALGS;
    if count == 0 {
        emit_row(&RowEvent {
            kind: KIND_QUERY_RET,
            op: op as u32,
            funcid: 0,
            _pad: 0,
            addr: rv,
            aux: j,
            idx: 0,
        });
    }
    let base = rv + j * 32;
    let names = unsafe { helpers::bpf_probe_read_user(base as *const u64) };
    let imp = unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) };
    let (Ok(names), Ok(imp)) = (names, imp) else {
        if j == 0 {
            flag_trunc(op as u32, TRUNC_WALK_READ);
        }
        return 0;
    };
    if names == 0 {
        // Terminator: freeze the counter (no insert), stop. Slot 0
        // empty = the query returned a table with no first alg.
        if j == 0 {
            flag_trunc(op as u32, TRUNC_WALK_EMPTY);
        }
        return 0;
    }
    if imp == 0 {
        // Alg without implementation: skipped, like the dumper.
        // Counter NOT advanced (same as every abort below): the
        // next hit re-walks this slot instead of sliding past it.
        if j == 0 {
            flag_trunc(op as u32, TRUNC_WALK_NOIMP);
        }
        return 0;
    }
    // Overrun guard on the last slot: entries 0..=511 all live means
    // the array may extend past the bound — slot 512 decides (live or
    // unreadable = TRUNC, terminator = clean).
    if j == MAX_ALGS - 1 {
        let tail = unsafe { helpers::bpf_probe_read_user((rv + MAX_ALGS * 32) as *const u64) };
        match tail {
            Ok(0) => {}
            _ => flag_trunc(op as u32, TRUNC_ALGS),
        }
    }
    // Kernel scratch only: classified below, never emitted.
    let mut name_buf = [0u8; 128];
    let slice =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(names as *const u8, &mut name_buf) }
        {
            Ok(s) => s,
            Err(_) => {
                if j == 0 {
                    flag_trunc(op as u32, TRUNC_WALK_NAME);
                }
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
                });
                return 0;
            }
        };
    let saturated = slice.len() == ALG_WINDOW - 1;
    let v = classify_alg(slice, saturated);
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
    });
    // Advance past this slot ONLY on a fully-walked alg: BPF probe
    // reads are nofault, so a cold (never-touched) page aborts the
    // walk even though the table is valid — freezing the counter
    // lets the next query re-walk this slot instead of losing the
    // alg forever (the terminator path above still freezes too, and
    // a dispatch read-abort freezes as well: ALG/ROW re-emits
    // dedupe userside via the alg_names overwrite + rows seen-map).
    match walk_dispatch(imp, op as u32, rv, j) {
        // Overflow: rows 0..127 are kept, the rest is unwalkable —
        // advance past like a success, but flag the truncation.
        1 => {
            let _ = QUERY_NEXT.insert(key, count.wrapping_add(1), 0);
            flag_trunc(op as u32, TRUNC_DISPATCH);
        }
        0 => {
            let _ = QUERY_NEXT.insert(key, count.wrapping_add(1), 0);
        }
        // Read abort: no insert (freeze for re-walk).
        _ => {}
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
