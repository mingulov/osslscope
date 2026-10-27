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
use osslscope_bpf_contract::{
    classify_alg_with, provider_observation::*, AlgClassValue, TripClassValue,
};
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
#[inline(always)]
fn base(p: &Pending, t: &ThreadKey, kind: u32) -> Record {
    Record {
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
    }
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
    if !(4096..=0x0000_ffff_ffff_ffff).contains(&address) {
        return false;
    }
    for index in 0..MAX_RANGES {
        if let Some(r) = unsafe { RANGES.get(&RangeKey { pid, index }) } {
            if address >= r.start && address < r.end {
                return true;
            }
        }
    }
    false
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
        let mut r = base(&p, &key, ATTEMPT);
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
    let mut r = base(p, key, INVALIDATION);
    r.status = status;
    emit(&r);
}
#[inline(never)]
#[no_mangle]
pub fn init_return(p: &Pending, key: &ThreadKey, rv: u64) {
    let mut r = base(p, key, INIT);
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
pub fn classify(pointer: u64) -> u64 {
    let mut buf = [0u8; 128];
    let len =
        match unsafe { helpers::bpf_probe_read_user_str_bytes(pointer as *const u8, &mut buf) } {
            Ok(v) => v.len(),
            Err(_) => {
                loss(LOSS_READ);
                return (OTHER as u64) | (4u64 << 32);
            }
        };
    let v = classify_alg_with(&buf, len, len == 127, |h| unsafe {
        ALG_CLASS.get(&h).copied()
    });
    (v.class as u64) | ((v.status as u64) << 32)
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
    let mut r = base(p, key, QUERY);
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
    let classified = classify(names);
    let algorithm = classified as u32;
    let status = (classified >> 32) as u32;
    r.kind = ALGORITHM;
    r.algorithm = algorithm;
    r.status = status;
    r.outcome = 0;
    emit(&r);
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
#[uretprobe]
pub fn observation_return(ctx: RetProbeContext) -> u32 {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let Some((_, key)) = identity(cookie) else {
        return 0;
    };
    let Some(mut thread) = (unsafe { THREADS.get(&key).copied() }) else {
        loss(LOSS_PAIR);
        return 0;
    };
    if thread.skip_return() {
        if THREADS.insert(key, thread, 0).is_err() {
            loss(LOSS_MAP)
        }
        return 0;
    }
    if thread.depth == 0 {
        loss(LOSS_PAIR);
        return 0;
    }
    let pk = PendingKey {
        thread: key,
        depth: thread.depth - 1,
        reserved: 0,
    };
    let Some(p) = (unsafe { PENDING.get(&pk).copied() }) else {
        loss(LOSS_PAIR);
        return 0;
    };
    if p.cookie != cookie {
        loss(LOSS_PAIR);
        return 0;
    }
    if PENDING.remove(&pk).is_err() {
        loss(LOSS_MAP);
        return 0;
    }
    thread.depth -= 1;
    if THREADS.insert(key, thread, 0).is_err() {
        loss(LOSS_MAP);
        return 0;
    }
    if p.suppressed != 0 {
        return 0;
    }
    let rv: u64 = ctx.ret();
    if p.api == PROVIDER_INIT {
        init_return(&p, &key, rv)
    } else if query_api(p.api) {
        query_return(&p, &key, rv)
    } else if !matches!(p.api, PUBLIC_UNQUERY | TEARDOWN | UNQUERY_CALLBACK) {
        let mut r = base(&p, &key, RESULT);
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
            invalidate(&p, &key, 1)
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
    0
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
