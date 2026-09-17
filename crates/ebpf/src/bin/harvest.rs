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
//! event per (op, alg, funcid, addr). No symbols are used past the init
//! anchor; userspace never reads target memory.
//!
//! Walk bounds (P1 exit 2, default-provider census 4.0.2: 241 algs/op
//! max, 115 dispatch entries/alg max, 81-char names max): each
//! query-return hit walks exactly ONE alg — index = per-(thread, op)
//! query count mod 256 — so an op queried N times covers algs 0..N
//! (order-independent; single-shot triggers walk alg 0). The 256-call
//! inventory trigger covers 256 algs/op; array overrun is detected by
//! reading one past the last slot (sets TRUNC[op] bit 1) and dispatch
//! tables past 128 entries set bit 2 — userspace degrades to PARTIAL,
//! so growth fails closed, never truncates silently. The single-alg
//! shape is deliberate: nested slice loops blow the verifier's 1M
//! processed-insn ceiling via state explosion (bisected 2026-09-17),
//! while one loop (dispatch walk, as a subprogram) verifies with wide
//! margin. Name field 128B; ring 2MB. Event layout must match
//! `discovery::harvest` EVENT_LEN (160 bytes, 40 for ROW/QUERY_RET).
//!
//! Layout constants mirror `kinds::SHAPES` (R12; asserted fail-closed by
//! `layout_assert.c` against real headers): OSSL_DISPATCH = {u32, pad,
//! u64} @16B; OSSL_ALGORITHM = 4×u64 @32B.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};

/// Must match discovery::harvest Event. 160 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    kind: u32,
    op: u32,
    funcid: u32,
    _pad: u32,
    addr: u64,
    aux: u64,
    name: [u8; 128],
}

/// Hot-loop row: 40 bytes (no name copy — userspace joins
/// (`aux` = array address, `idx` = alg index) to the KIND_ALG record;
/// the array disambiguates providers sharing (op, index)). The 128B
/// name copy inside the dispatch loop blows the verifier's 1M
/// processed-insn ceiling; the normalized split keeps the inner body
/// small. Must match discovery::harvest RowEvent.
#[repr(C)]
#[derive(Clone, Copy)]
struct RowEvent {
    kind: u32,
    op: u32,
    funcid: u32,
    _pad: u32,
    addr: u64,
    aux: u64,
    idx: u64,
}

const KIND_INIT_RET: u32 = 1;
const KIND_QUERY_RET: u32 = 2;
const KIND_ROW: u32 = 3;
const KIND_ALG: u32 = 4;

/// core_dispatch.h: provider codes live at 1024+; verified 2026-09-16.
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: u32 = 1027;

/// Alg-array bound per op (measured max 241, 4.0.2 encoders).
const MAX_ALGS: u64 = 256;
/// Dispatch-table bound per alg (measured max 115, RSA encoder, stable
/// across 3.0/3.5/4.0; 128 keeps the verifier under its 1M processed-insn
/// ceiling with ~2x margin — overflow fails closed via TRUNC).
const MAX_DISPATCH: u64 = 128;
/// TRUNC[op] bits: alg-array overflow | dispatch-table overflow.
const TRUNC_ALGS: u64 = 1;
const TRUNC_DISPATCH: u64 = 2;

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
/// Non-null query calls per op id. The 256-round inventory trigger
/// fires ~34K calls in milliseconds; counting in-map (instead of a
/// ring event per call) keeps the ring burst under 1MB. QUERY_RET is
/// emitted on the first hit per array only (liveness + ops-hit).
#[map]
static CALLS: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

fn emit(ev: &Event) {
    if let Some(mut e) = EVENTS.reserve::<Event>(0) {
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

fn take(map: &HashMap<u64, u64>) -> Option<u64> {
    let key = helpers::bpf_get_current_pid_tgid();
    let val = unsafe { *map.get_ptr(&key)? };
    let _ = map.remove(&key);
    Some(val)
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
    let _ = PENDING_INIT.insert(helpers::bpf_get_current_pid_tgid(), out, 0);
    0
}

/// At init-return walk *out for the query op; report its address.
#[uretprobe]
pub fn init_return(ctx: RetProbeContext) -> u32 {
    let out = match take(&PENDING_INIT) {
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
            emit(&Event {
                kind: KIND_INIT_RET,
                op: 0,
                funcid: fid,
                _pad: 0,
                addr: fptr,
                aux: 0,
                name: [0; 128],
            });
            return 0;
        }
    }
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
    let _ = PENDING_QUERY.insert(helpers::bpf_get_current_pid_tgid(), op, 0);
    0
}

/// Dispatch-table walk as a BPF subprogram (separate verification
/// scope). Emits one ROW event per entry (`aux`/`idx` = array address
/// + alg index, the userspace ALG-join key); returns true when the
/// table runs past MAX_DISPATCH without a terminator (TRUNC).
#[inline(never)]
fn walk_dispatch(imp: u64, op: u32, arr: u64, j: u64) -> bool {
    for k in 0..MAX_DISPATCH {
        let base = imp + k * 16;
        let fid = unsafe { helpers::bpf_probe_read_user(base as *const u32) };
        let fptr = unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) };
        let (Ok(fid), Ok(fptr)) = (fid, fptr) else {
            return false;
        };
        if fid == 0 {
            return false;
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
    true
}

/// At query-return walk exactly one alg of the OSSL_ALGORITHM array
/// (index = per-(thread, array) query count mod 256) plus its dispatch
/// table. The counter freezes at the first terminator (names == 0):
/// later hits re-read the terminator and stop, so short arrays never
/// walk past their end (impl-less algs still advance — they can sit
/// mid-array). OSSL_ALGORITHM = { names, props, impl, desc } @32B.
#[uretprobe]
pub fn query_return(ctx: RetProbeContext) -> u32 {
    let op = match take(&PENDING_QUERY) {
        Some(v) => v,
        None => return 0,
    };
    let rv: u64 = ctx.ret();
    if rv == 0 {
        return 0;
    }
    let calls = unsafe { CALLS.get_ptr(&(op as u32)).map(|p| *p).unwrap_or(0) };
    let _ = CALLS.insert(op as u32, calls.wrapping_add(1), 0);
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
        return 0;
    };
    if names == 0 {
        // Terminator: freeze the counter (no insert), stop.
        return 0;
    }
    let _ = QUERY_NEXT.insert(key, count.wrapping_add(1), 0);
    if imp == 0 {
        // Alg without implementation: skipped, like the dumper.
        return 0;
    }
    // Overrun guard on the last slot: entries 0..=255 all live means
    // the array may extend past the bound — slot 256 decides (live or
    // unreadable = TRUNC, terminator = clean).
    if j == MAX_ALGS - 1 {
        let tail = unsafe { helpers::bpf_probe_read_user((rv + MAX_ALGS * 32) as *const u64) };
        match tail {
            Ok(0) => {}
            _ => flag_trunc(op as u32, TRUNC_ALGS),
        }
    }
    let mut name = [0u8; 128];
    if unsafe { helpers::bpf_probe_read_user_str_bytes(names as *const u8, &mut name) }.is_err() {
        return 0;
    }
    emit(&Event {
        kind: KIND_ALG,
        op: op as u32,
        funcid: 0,
        _pad: 0,
        addr: rv,
        aux: j,
        name,
    });
    if walk_dispatch(imp, op as u32, rv, j) {
        flag_trunc(op as u32, TRUNC_DISPATCH);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
