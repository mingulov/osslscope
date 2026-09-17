//! Harvest probes: two-stage provider table walk in BPF (promoted
//! from the P0-4 spike at P1 exit 1; behavior-identical).
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
//! Layout constants mirror `kinds::SHAPES` (R12; asserted fail-closed by
//! `layout_assert.c` against real headers): OSSL_DISPATCH = {u32, pad,
//! u64} @16B; OSSL_ALGORITHM = 4×u64 @32B. Event layout must match
//! `discovery::harvest` EVENT_LEN (96 bytes).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};

/// Must match spike/src/bin/harvest.rs Event. 96 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    kind: u32,
    op: u32,
    funcid: u32,
    _pad: u32,
    addr: u64,
    aux: u64,
    name: [u8; 64],
}

const KIND_INIT_RET: u32 = 1;
const KIND_QUERY_RET: u32 = 2;
const KIND_ROW: u32 = 3;

/// core_dispatch.h: provider codes live at 1024+; verified 2026-09-16.
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: u32 = 1027;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(65536, 0);
#[map]
static PENDING_INIT: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
#[map]
static PENDING_QUERY: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

fn emit(ev: &Event) {
    if let Some(mut e) = EVENTS.reserve::<Event>(0) {
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
                name: [0; 64],
            });
            return 0;
        }
    }
    0
}

/// query_operation(provctx, operation_id, no_store): stash arg1 (op).
#[uprobe]
pub fn query_entry(ctx: ProbeContext) -> u32 {
    let op: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let _ = PENDING_QUERY.insert(helpers::bpf_get_current_pid_tgid(), op, 0);
    0
}

/// At query-return walk the OSSL_ALGORITHM array + dispatch tables.
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
    emit(&Event {
        kind: KIND_QUERY_RET,
        op: op as u32,
        funcid: 0,
        _pad: 0,
        addr: rv,
        aux: 0,
        name: [0; 64],
    });
    // OSSL_ALGORITHM = { names u64; props u64; impl u64; desc u64 } = 32 B.
    for j in 0..8u64 {
        let base = rv + j * 32;
        let names = unsafe { helpers::bpf_probe_read_user(base as *const u64) };
        let imp = unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) };
        let (Ok(names), Ok(imp)) = (names, imp) else {
            return 0;
        };
        if names == 0 {
            return 0;
        }
        let mut name = [0u8; 64];
        if unsafe { helpers::bpf_probe_read_user_str_bytes(names as *const u8, &mut name) }
            .is_err()
            || imp == 0
        {
            continue;
        }
        // Bound 64: the P0-6 scaled provider packs 63 entries per alg.
        for k in 0..64u64 {
            let base = imp + k * 16;
            let fid = unsafe { helpers::bpf_probe_read_user(base as *const u32) };
            let fptr = unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) };
            let (Ok(fid), Ok(fptr)) = (fid, fptr) else {
                return 0;
            };
            if fid == 0 {
                break;
            }
            emit(&Event {
                kind: KIND_ROW,
                op: op as u32,
                funcid: fid,
                _pad: 0,
                addr: fptr,
                aux: j,
                name,
            });
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
