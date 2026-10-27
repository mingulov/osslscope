// SPDX-License-Identifier: GPL-2.0-only
//! Public ABI producer. Target strings only exist in stack classifier scratch.
#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
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
static CURSORS: HashMap<CursorKey, u32> = HashMap::with_max_entries(4096, 0);
#[map]
static LOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);
#[map]
static ALG_CLASS: HashMap<u64, AlgClassValue> = HashMap::with_max_entries(1024, 0);
#[map]
static TRIP_CLASS: HashMap<u64, TripClassValue> = HashMap::with_max_entries(64, 0);
#[map]
static FUNCTIONS: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);
#[inline(always)]
fn loss(n: u32) {
    if let Some(p) = LOSS.get_ptr_mut(n) {
        unsafe { *p = (*p).saturating_add(1) }
    }
}
#[inline(always)]
fn identity(cookie: u64) -> Option<(Config, ThreadKey)> {
    let cfg = unsafe { *CONFIG.get(&cookie)? };
    let ns = NAMESPACE.get(0)?;
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let rv = unsafe { helpers::bpf_get_ns_current_pid_tgid(ns.device, ns.inode, &mut ids, 8) };
    if rv != 0 {
        loss(LOSS_NAMESPACE);
        return None;
    }
    if ids.tgid != cfg.pid {
        return None;
    }
    let member = unsafe { *MEMBERS.get(&ids.tgid)? };
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
// Explicit output avoids aggregate-return ABI and keeps construction spills
// out of the query frame on kernels with a combined 512-byte stack limit.
#[inline(never)]
#[no_mangle]
pub fn base(p: &Pending, t: &ThreadKey, kind: u32, out: &mut Record) {
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
#[uprobe]
pub fn observation_entry(ctx: ProbeContext) -> u32 {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let Some((cfg, key)) = identity(cookie) else {
        return 0;
    };
    let mut thread = unsafe { THREADS.get(&key).copied() }.unwrap_or_default();
    let old_depth = thread.depth;
    let Some(invocation) = thread.enter() else {
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
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
                reserved: 0,
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
        reserved: 0,
    };
    if PENDING.insert(pk, p, 1).is_err() {
        thread.failed_entry();
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        loss(LOSS_MAP);
        return 0;
    }
    if THREADS.insert(key, thread, 0).is_err() {
        let _ = PENDING.remove(&pk);
        loss(LOSS_MAP);
        return 0;
    }
    if p.suppressed == 0
        && !matches!(
            p.api,
            PROVIDER_INIT
                | PUBLIC_QUERY
                | QUERY_CALLBACK
                | PUBLIC_UNQUERY
                | TEARDOWN
                | UNQUERY_CALLBACK
        )
    {
        let mut r = Record::default();
        base(&p, &key, ATTEMPT, &mut r);
        r.status = p.name;
        emit(&r)
    }
    if matches!(p.api, PUBLIC_UNQUERY | TEARDOWN | UNQUERY_CALLBACK) {
        invalidate(&p, &key, if p.api == TEARDOWN { 3 } else { 2 });
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn invalidate(p: &Pending, key: &ThreadKey, status: u32) {
    // Kernel-only epoch invalidation: no host enumeration of cursor/opaque keys.
    if let Some(member) = MEMBERS.get_ptr_mut(&key.pid) {
        unsafe { (*member).epoch = 0 }
    }
    let mut r = Record::default();
    base(p, key, INVALIDATION, &mut r);
    r.status = status;
    emit(&r);
}
#[inline(never)]
#[no_mangle]
pub fn init_return(p: &Pending, key: &ThreadKey, rv: u64) {
    let mut r = Record::default();
    base(p, key, INIT, &mut r);
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
            if !code_ok(key.pid, address) {
                loss(LOSS_RANGE);
                continue;
            }
            r.function = fid;
            r.code = address;
            emit(&r);
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
#[inline(always)]
fn classify(pointer: u64, r: &mut Record) {
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
#[inline(never)]
#[no_mangle]
pub fn walk_dispatch(imp: u64, r: &mut Record) {
    for index in 0..128u64 {
        let Some(base) = imp.checked_add(index * 16) else {
            loss(LOSS_READ);
            return;
        };
        let id = match unsafe { helpers::bpf_probe_read_user(base as *const u32) } {
            Ok(v) => v,
            Err(_) => {
                loss(LOSS_READ);
                return;
            }
        };
        if id == 0 {
            return;
        }
        // Unknown function IDs are finite OTHER and cannot authorize a site.
        let function = unsafe {
            FUNCTIONS
                .get(&(((r.operation as u64) << 32) | id as u64))
                .copied()
        }
        .unwrap_or(0);
        r.function = function;
        r.code = 0;
        if function != 0 && r.cacheability == 1 {
            let address = match unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) } {
                Ok(v) => v,
                Err(_) => {
                    loss(LOSS_READ);
                    return;
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
    }
    loss(LOSS_TRUNC);
}
#[inline(never)]
#[no_mangle]
pub fn query_return(p: &Pending, key: &ThreadKey, table: u64) {
    let mut r = Record::default();
    base(p, key, QUERY, &mut r);
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
        // Once lifetime is uncertain, never revive a cursor in this mapping
        // generation. This idempotent invalidation cannot lose racing updates.
        if let Some(member) = MEMBERS.get_ptr_mut(&key.pid) {
            unsafe { (*member).epoch = 0 }
        }
    }
    if table == 0 {
        return;
    }
    let epoch = match unsafe { MEMBERS.get(&key.pid) } {
        Some(v) => v.epoch,
        None => return,
    };
    if epoch == u64::MAX {
        loss(LOSS_MAP);
        return;
    }
    let cursor = CursorKey {
        generation: key.generation,
        epoch,
        cookie: p.cookie,
        context: p.arg0,
        table,
        pid: key.pid,
        operation: p.operation,
    };
    let index = if r.cacheability == 1 && epoch != 0 {
        unsafe { CURSORS.get(&cursor).copied() }.unwrap_or(0)
    } else {
        0
    };
    let Some(index) = sample_index(r.cacheability, index) else {
        loss(LOSS_TRUNC);
        return;
    };
    let Some(slot) = table.checked_add(index as u64 * 32) else {
        loss(LOSS_READ);
        return;
    };
    let names = match unsafe { helpers::bpf_probe_read_user(slot as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            return;
        }
    };
    if names == 0 {
        return;
    }
    let imp = match unsafe { helpers::bpf_probe_read_user((slot + 16) as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            loss(LOSS_READ);
            return;
        }
    };
    classify(names, &mut r);
    if imp != 0 {
        walk_dispatch(imp, &mut r)
    } else {
        loss(LOSS_TRUNC)
    }
    if r.cacheability == 1 && epoch != 0 {
        if CURSORS.insert(cursor, index + 1, 0).is_err() {
            loss(LOSS_MAP)
        }
    }
}
// Keep pairing temporaries out of the frame that classifies a query return.
#[inline(never)]
#[no_mangle]
pub fn pop_return(cookie: u64, out_key: &mut ThreadKey, out_pending: &mut Pending) -> bool {
    let Some((_, key)) = identity(cookie) else {
        return false;
    };
    let Some(mut thread) = (unsafe { THREADS.get(&key).copied() }) else {
        loss(LOSS_PAIR);
        return false;
    };
    if thread.skip_return() {
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        return false;
    }
    if thread.depth == 0 {
        loss(LOSS_PAIR);
        return false;
    }
    let pk = PendingKey {
        thread: key,
        depth: thread.depth - 1,
        reserved: 0,
    };
    let Some(p) = (unsafe { PENDING.get(&pk).copied() }) else {
        loss(LOSS_PAIR);
        return false;
    };
    if p.cookie != cookie {
        loss(LOSS_PAIR);
        return false;
    }
    if PENDING.remove(&pk).is_err() {
        loss(LOSS_MAP);
        return false;
    }
    thread.depth -= 1;
    if THREADS.insert(key, thread, 0).is_err() {
        loss(LOSS_MAP);
        return false;
    }
    *out_key = key;
    *out_pending = p;
    p.suppressed == 0
}
#[uretprobe]
pub fn observation_return(ctx: RetProbeContext) -> u32 {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let mut key = ThreadKey::default();
    let mut p = Pending::default();
    if !pop_return(cookie, &mut key, &mut p) {
        return 0;
    }
    let rv: u64 = ctx.ret();
    if p.api == PROVIDER_INIT {
        init_return(&p, &key, rv)
    } else if query_api(p.api) {
        query_return(&p, &key, rv)
    } else if !matches!(p.api, PUBLIC_UNQUERY | TEARDOWN | UNQUERY_CALLBACK) {
        api_return(&p, &key, rv);
    }
    0
}
#[inline(never)]
#[no_mangle]
pub fn api_return(p: &Pending, key: &ThreadKey, rv: u64) {
    let mut r = Record::default();
    base(p, key, RESULT, &mut r);
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
        invalidate(p, key, 1)
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
