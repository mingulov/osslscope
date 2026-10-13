//! P7 item 2 live legs (privileged lane only): functional proof
//! for the 512-member chunk — load-513 + per-prog xlated margins
//! (L1), exact slot/dispatch contents on an E=7 fixture (L2, warm +
//! cold), boundary fixtures (L3 empty/one/tail, L4
//! 127-clean/128-edge/129 dispatch, L6 512-clean/513-live),
//! no_store (L5), and the cookie-mismatch negative (L7).
//!
//! Own-process target: this binary exports `osslscope_member_query`
//! (query_operation shape); tables live in memfd-backed mappings
//! (pageout-able for honest cold legs, mincore-verified). Members
//! attach to the query fn's file offset in our own image (own-pid
//! `*_multi`, the B-chunk probe's getpid pattern turned inward).
//!
//! v1 honesty bounds (stated, pinned): no T-gate — slots past the
//! terminator read meaningless memory and MAY emit; legs assert
//! prefix-exactness only (L3-tail pins the gap's presence for item 3
//! to flip to absence). Every firing leg asserts positive fire
//! evidence (CALLS / events) so a broken attach REDs, never
//! vacuous-green. One query is counted once (member 0 counts).
//!
//! Run (lane, setcaps on the test binary like the D legs):
//! `OSSL_B_LIVE=1 OSSL_MEMBERS_OBJECT=<members.o> <testbin>
//! --test-threads=1 --ignored`. Single-threaded execution is
//! load-bearing (the uprobe filter covers the whole thread group;
//! a sibling thread's stray query call would inflate counts).
//! Three legs (`target_resolves`, `fixture_builds`,
//! `temp_probe_is_nondestructive`) run offline (pure, unprivileged)
//! and gate the harness itself.
//!
//! Stage C (P7 item 3, R18): the entry plane. Every leg attaches
//! through the production path AND registers BIRTH (the entry
//! skips unregistered tids — cause 1). The drain collects CALLs
//! alongside ALG/ROW; C legs assert ENTRY-OBSERVABLE state only
//! (CALLs, cells, CALLS, LOSS, silence) — retirement/RET-dependent
//! acceptance lives in D. C-LEG CONVENTION (no retirement exists
//! in C): any same-tid admit over an unretired record carries
//! NESTED-HINT — hint ⟺ prior record, not proven nesting.
//! Multi-admit C legs use a fresh tid per admit sequence (spawned
//! worker), interleave a skip to clear, or assert the hint as
//! correct. Priming always uses sacrificial tids.

use osslscope::loader::Loaded;
use osslscope::scan::registry::BirthState;
use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

const OP: u32 = 1;
const QUERIES: usize = 3;
/// `MADV_PAGEOUT` (21, Linux 5.4+ — uapi asm-generic/mman-common.h):
/// reclaim own pages (evicting populated memfd pages needs swap —
/// swapless lanes take the labeled SKIP instead; no privilege
/// needed). Local const, not libc-version-coupled.
const MADV_PAGEOUT: libc::c_int = 21;

fn gated() -> Option<PathBuf> {
    if std::env::var("OSSL_B_LIVE").unwrap_or_default() != "1" {
        return None;
    }
    std::env::var("OSSL_MEMBERS_OBJECT")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Current thread id (BPF `pid_tgid` low half; the tid-keyed
/// maps' key width — R18 §2).
fn self_tid() -> u32 {
    unsafe { libc::gettid() as u32 }
}

/// Production attach with an explicit CTRL (no BIRTH programmed —
/// legs register explicitly via the harness-driven registry, so
/// unregistered/frozen/full setups are expressible).
fn attach_with_ctrl(
    obj: &std::path::Path,
    exe: &std::ffi::CString,
    off: u64,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> osslscope::loader::MembersAttached {
    osslscope::loader::attach_members(obj, exe, off, std::process::id(), ctrl)
        .expect("production attach")
}

/// Register tids through the production registry path (poll +
/// program). Returns the poll's program rows (legs assert the
/// registry's own behavior separately).
fn register(loaded: &Loaded, state: &mut BirthState, tids: &[u32]) -> Vec<(u32, u16)> {
    let rows = state.poll(tids);
    osslscope::scan::registry::program_births(&loaded.maps, &rows).expect("program BIRTH");
    rows
}

/// Dogfood the production attach (fd budget → prepare → load →
/// CTRL program → entry + member links) + self-tid BIRTH
/// registration. Every leg attaches through here (or
/// `attach_with_ctrl`), so the production path is live-proven
/// along with the legs. CTRL: EXPECTED = 512 attached members,
/// epoch 1, governor = min(4MiB policy, ring/2) — 1MiB on the 2MiB
/// ring (small-ring fixture rule, R18 §2; item 7 re-derives).
fn attach_chunk(
    obj: &std::path::Path,
    exe: &std::ffi::CString,
    off: u64,
) -> osslscope::loader::MembersAttached {
    let ctrl =
        osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL");
    let attached = attach_with_ctrl(obj, exe, off, &ctrl);
    let mut state = BirthState::new();
    register(&attached.loaded, &mut state, &[self_tid()]);
    attached
}

/// Populate the member object's `ALG_CLASS` with fixture entries
/// (mirrors `build_alg_entries`' push: hash+len match, fail-closed
/// on collision or over-cap names).
fn populate_alg_class(loaded: &Loaded, entries: &[(String, u16)]) {
    use osslscope_ebpf_common as wire;
    let fd = loaded.maps["ALG_CLASS"].as_raw_fd();
    let mut seen = HashSet::new();
    for (name, class) in entries {
        assert!(
            name.len() <= wire::MAX_ALG_NAME,
            "fixture name over kernel cap: {name:?}"
        );
        let h = wire::fnv1a64(name.as_bytes());
        assert!(seen.insert(h), "fixture hash collision on {name:?}");
        let mut nb = [0u8; wire::MAX_ALG_NAME];
        nb[..name.len()].copy_from_slice(name.as_bytes());
        let v = wire::AlgClassValue {
            class: *class,
            weak: 0,
            len: name.len() as u8,
            canon: 0,
            name: nb,
        };
        unsafe {
            ossl_bpf_sys::map_update_elem(fd, &h.to_le_bytes(), &wire::alg_value_bytes(&v), 0)
        }
        .expect("insert ALG_CLASS");
    }
}

/// Drain the member EVENTS ring to parsed (CALL, ALG, ROW)
/// events. Drops nothing silently: unknown kinds fail loud (stage
/// C emits CALL/ALG/ROW — no RET/GUARD until D). CALLs arrive in
/// ring order; C legs join by (tid,seq), never by position.
fn drain(
    loaded: &Loaded,
) -> (
    Vec<osslscope_ebpf_common::ScanCallEvent>,
    Vec<osslscope_ebpf_common::AlgEvent>,
    Vec<osslscope_ebpf_common::RowEvent>,
) {
    use aya::maps::{Map, MapData, RingBuf};
    use osslscope_ebpf_common as wire;
    let fd = loaded.maps["EVENTS"].try_clone().expect("clone EVENTS");
    let data = MapData::from_fd(fd).expect("EVENTS mapdata");
    let map = Map::from_map_data(data).expect("EVENTS map");
    let mut ring = RingBuf::try_from(map).expect("EVENTS ringbuf");
    let mut calls = Vec::new();
    let mut algs = Vec::new();
    let mut rows = Vec::new();
    while let Some(item) = ring.next() {
        let b = item.to_vec();
        assert!(b.len() >= 4, "short ring item: {} bytes", b.len());
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        match kind {
            wire::KIND_SCAN_CALL => {
                calls.push(wire::parse_scan_call_event(&b).expect("parse CALL"))
            }
            wire::KIND_ALG => algs.push(wire::parse_alg_event(&b, 4096).expect("parse ALG")),
            wire::KIND_ROW => rows.push(wire::parse_row_event(&b).expect("parse ROW")),
            k => panic!("unexpected ring kind {k} (C emits CALL/ALG/ROW only)"),
        }
    }
    (calls, algs, rows)
}

/// Split CALL flags to (nested-hint, cause) (wire vocabulary).
fn call_parts(c: &osslscope_ebpf_common::ScanCallEvent) -> (bool, u8) {
    osslscope_ebpf_common::split_call_flags(c.flags)
}

/// Bridge-leg CALL assert: exactly `n` admitted CALLs on this tid
/// (C emits one CALL per entry hit; all bridge legs admit).
/// Seq/hint patterns are the admit-shape leg's job — bridge legs
/// pin count + admission + op/tid only.
fn assert_calls_admitted(calls: &[osslscope_ebpf_common::ScanCallEvent], n: usize, tag: &str) {
    use osslscope_ebpf_common as wire;
    assert_eq!(calls.len(), n, "{tag}: one CALL per query");
    for c in calls {
        assert_eq!(c.kind, wire::KIND_SCAN_CALL);
        assert_eq!(c.op, OP, "{tag}: CALL op");
        assert_eq!(c.tid, self_tid(), "{tag}: CALL tid");
        let (_, cause) = call_parts(c);
        assert_eq!(cause, wire::SKIP_ADMITTED, "{tag}: CALL admitted");
    }
}

/// Folded per-CPU u32-keyed map read (mirrors the product's
/// `read_percpu_checked` fold discipline; absent key reads 0).
fn read_percpu(loaded: &Loaded, name: &str, key: u32, or: bool) -> u64 {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps[name].try_clone().expect("clone map");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        if k == key {
            return slots
                .iter()
                .fold(0u64, |a, &b| if or { a | b } else { a.wrapping_add(b) });
        }
    }
    0
}

/// Assert every LOSS entry is zero (clean legs must lose nothing).
fn assert_loss_zero(loaded: &Loaded) {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps["LOSS"].try_clone().expect("clone LOSS");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        let sum: u64 = slots.iter().fold(0, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0, "LOSS[{k}] must be zero on the clean path");
    }
}

// ===== stage-C cell readback + map programming =====

/// Raw u64-cell read (SEQ/RCOUNT): None on ENOENT (absent cell —
/// expected for fresh/skipped tids), hard error otherwise.
fn read_u64_cell(loaded: &Loaded, map: &str, tid: u32) -> Option<u64> {
    use std::os::fd::AsRawFd as _;
    let fd = loaded.maps[map].as_raw_fd();
    let mut val = [0u8; 8];
    match unsafe { ossl_bpf_sys::map_lookup_elem(fd, &tid.to_le_bytes(), &mut val) } {
        Ok(()) => Some(u64::from_le_bytes(val)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
        Err(e) => panic!("lookup {map}[{tid}]: {e}"),
    }
}

/// Raw u16-cell read (BIRTH): None on ENOENT.
fn read_u16_cell(loaded: &Loaded, map: &str, tid: u32) -> Option<u16> {
    use std::os::fd::AsRawFd as _;
    let fd = loaded.maps[map].as_raw_fd();
    let mut val = [0u8; 2];
    match unsafe { ossl_bpf_sys::map_lookup_elem(fd, &tid.to_le_bytes(), &mut val) } {
        Ok(()) => Some(u16::from_le_bytes(val)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
        Err(e) => panic!("lookup {map}[{tid}]: {e}"),
    }
}

/// SCAN cell read (40B ScanRec, byte-exact): None on ENOENT.
fn read_scan_cell(loaded: &Loaded, tid: u32) -> Option<osslscope_ebpf_common::ScanRec> {
    use std::os::fd::AsRawFd as _;
    let fd = loaded.maps["SCAN"].as_raw_fd();
    let mut val = [0u8; 40];
    match unsafe { ossl_bpf_sys::map_lookup_elem(fd, &tid.to_le_bytes(), &mut val) } {
        Ok(()) => {
            let op = u64::from_le_bytes(val[0..8].try_into().unwrap());
            let ns_ptr = u64::from_le_bytes(val[8..16].try_into().unwrap());
            let seq = u64::from_le_bytes(val[16..24].try_into().unwrap());
            let expected = u32::from_le_bytes(val[24..28].try_into().unwrap());
            let epoch = u64::from_le_bytes(val[32..40].try_into().unwrap());
            Some(osslscope_ebpf_common::ScanRec {
                op,
                ns_ptr,
                seq,
                expected,
                _pad: 0,
                epoch,
            })
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
        Err(e) => panic!("lookup SCAN[{tid}]: {e}"),
    }
}

/// PENDING presence read (C-only — D drops the map): the 16B value
/// decoded to (op, ns_ptr); None on ENOENT. The key namespaces by
/// the entry cookie over this process's pid_tgid (BPF `pend_key`
/// mirrored exactly).
fn pend_key_for(pid: u32, tid: u32) -> u64 {
    ((pid as u64) << 32 | tid as u64) ^ ((osslscope_ebpf_common::MEMBER_ENTRY_COOKIE + 1) << 56)
}

fn read_pending_cell(loaded: &Loaded, pid: u32, tid: u32) -> Option<(u64, u64)> {
    use std::os::fd::AsRawFd as _;
    let fd = loaded.maps["PENDING_QUERY"].as_raw_fd();
    let mut val = [0u8; 16];
    match unsafe {
        ossl_bpf_sys::map_lookup_elem(fd, &pend_key_for(pid, tid).to_le_bytes(), &mut val)
    } {
        Ok(()) => Some((
            u64::from_le_bytes(val[0..8].try_into().unwrap()),
            u64::from_le_bytes(val[8..16].try_into().unwrap()),
        )),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
        Err(e) => panic!("lookup PENDING[{tid}]: {e}"),
    }
}

/// ATTEMPT total (PerCpuArray[1] summed across CPUs).
fn read_attempt(loaded: &Loaded) -> u64 {
    use aya::maps::{Map, MapData, PerCpuArray};
    let fd = loaded.maps["ATTEMPT"].try_clone().expect("clone ATTEMPT");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuArray::<_, u64>::try_from(map).expect("percpu-array shape");
    m.get(&0, 0)
        .expect("ATTEMPT[0]")
        .iter()
        .fold(0u64, |a, &b| a.wrapping_add(b))
}

/// Raw cell write (programmed-cell legs): SEQ/RCOUNT u64, BIRTH u16,
/// SCAN 40B, PENDING 16B. BPF_ANY (flags 0).
fn write_cell(loaded: &Loaded, map: &str, key: &[u8], val: &[u8]) {
    use std::os::fd::AsRawFd as _;
    unsafe { ossl_bpf_sys::map_update_elem(loaded.maps[map].as_raw_fd(), key, val, 0) }
        .unwrap_or_else(|e| panic!("write {map}: {e}"));
}

fn scan_bytes(r: &osslscope_ebpf_common::ScanRec) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..8].copy_from_slice(&r.op.to_le_bytes());
    b[8..16].copy_from_slice(&r.ns_ptr.to_le_bytes());
    b[16..24].copy_from_slice(&r.seq.to_le_bytes());
    b[24..28].copy_from_slice(&r.expected.to_le_bytes());
    b[32..40].copy_from_slice(&r.epoch.to_le_bytes());
    b
}

// ===== own-process query target =====

/// Fake `OSSL_ALGORITHM` (4×u64 @32B): pointer cells as addresses.
#[repr(C)]
pub struct FakeAlg {
    pub names: u64,
    pub props: u64,
    pub imp: u64,
    pub desc: u64,
}

/// Fake `OSSL_DISPATCH` ({u32, pad, u64} @16B).
#[repr(C)]
pub struct FakeDispatch {
    pub fid: u32,
    pub pad: u32,
    pub fptr: u64,
}

const _: () = assert!(size_of::<FakeAlg>() == 32);
const _: () = assert!(size_of::<FakeDispatch>() == 16);

/// Leg-configured fixture array base (0 = null query).
static FIXTURE_ARRAY: AtomicU64 = AtomicU64::new(0);
/// Leg-configured provider lifetime verdict (0 cacheable, else no_store).
static NS_VERDICT: AtomicI32 = AtomicI32::new(0);

/// query_operation-shaped target: stashes nothing itself (the BPF
/// entry does), returns the leg's fixture array, stamps the leg's
/// lifetime verdict. `#[inline(never)]` + `no_mangle`: the uprobe
/// needs a real symbol, and every leg asserts positive fire
/// evidence, so any inlining/offset miss REDs instead of passing
/// vacuously.
///
/// # Safety
///
/// `no_store` must point to a live writable `c_int` for the call.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn osslscope_member_query(
    _provctx: *mut std::ffi::c_void,
    _op: std::ffi::c_int,
    no_store: *mut std::ffi::c_int,
) -> *const FakeAlg {
    unsafe {
        *no_store = NS_VERDICT.load(Ordering::SeqCst);
        FIXTURE_ARRAY.load(Ordering::SeqCst) as *const FakeAlg
    }
}

// NOTE: an uncalled `no_mangle` fn is dead-code-GC'd out of the
// test binary (observed — neither `no_mangle` nor a `#[used]`
// address-taken static anchors it); the direct calls below (the
// smoke test + every leg's `fire()`) are the load-bearing anchor.
// `target_resolves` is self-pinning: it REDs if the symbol is
// gone for any reason.

/// Fire the query fn `n` times (single-threaded caller only).
fn fire(op: i32, n: usize) {
    for _ in 0..n {
        let mut ns: i32 = 0;
        // SAFETY: `ns` is a live stack slot for the call.
        let _rv = unsafe {
            osslscope_member_query(std::ptr::null_mut(), op, &mut ns as *mut std::ffi::c_int)
        };
        std::hint::black_box(_rv);
    }
}

/// Depth-1 self-calling target (C nested legs): TRUE same-thread
/// recursion — the uprobe fires per call depth, uretprobes per
/// return. Extra 4th arg is BPF-invisible (entry reads arg1/arg2
/// only). Same anchor discipline as the main target (every nested
/// leg calls it; `target_resolves` pins the symbol offline).
///
/// # Safety
///
/// `no_store` must point to a live writable `c_int` for the call.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn osslscope_member_query_nested(
    _provctx: *mut std::ffi::c_void,
    _op: std::ffi::c_int,
    no_store: *mut std::ffi::c_int,
    depth: std::ffi::c_int,
) -> *const FakeAlg {
    if depth > 0 {
        let mut inner_ns: std::ffi::c_int = 0;
        // SAFETY: `inner_ns` is a live stack slot for the call.
        let _inner = unsafe {
            osslscope_member_query_nested(
                std::ptr::null_mut(),
                _op,
                &mut inner_ns as *mut std::ffi::c_int,
                depth - 1,
            )
        };
        std::hint::black_box(_inner);
    }
    unsafe {
        *no_store = NS_VERDICT.load(Ordering::SeqCst);
        FIXTURE_ARRAY.load(Ordering::SeqCst) as *const FakeAlg
    }
}

/// Fire the nested target once at `depth` (depth 1 = outer + inner).
fn fire_nested(op: i32, depth: i32) {
    let mut ns: i32 = 0;
    // SAFETY: `ns` is a live stack slot for the call.
    let _rv = unsafe {
        osslscope_member_query_nested(
            std::ptr::null_mut(),
            op,
            &mut ns as *mut std::ffi::c_int,
            depth,
        )
    };
    std::hint::black_box(_rv);
}

/// Blocking-target control: pipe fds + entry flag + once latch.
/// The target blocks between entry and return ONLY when the latch
/// is armed (first call), so churn legs can detach/bump behind it.
static BLOCK_PIPE_RD: AtomicI32 = AtomicI32::new(-1);
static BLOCK_ENTERED: AtomicI32 = AtomicI32::new(0);
static BLOCK_ONCE: AtomicI32 = AtomicI32::new(0);

/// Pipe-blocked target (C churn legs): when `BLOCK_ONCE` is armed,
/// signals entry then blocks on `BLOCK_PIPE_RD` until the harness
/// releases it (detach/epoch-bump happens behind the blocked
/// return). Unarmed calls pass straight through.
///
/// # Safety
///
/// `no_store` must point to a live writable `c_int` for the call.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn osslscope_member_query_blocking(
    _provctx: *mut std::ffi::c_void,
    _op: std::ffi::c_int,
    no_store: *mut std::ffi::c_int,
) -> *const FakeAlg {
    if BLOCK_ONCE.swap(0, Ordering::SeqCst) != 0 {
        BLOCK_ENTERED.store(1, Ordering::SeqCst);
        let mut buf = [0u8; 1];
        let r = unsafe {
            libc::read(
                BLOCK_PIPE_RD.load(Ordering::SeqCst),
                buf.as_mut_ptr() as *mut libc::c_void,
                1,
            )
        };
        assert_eq!(r, 1, "blocking target released with 1 byte");
    }
    unsafe {
        *no_store = NS_VERDICT.load(Ordering::SeqCst);
        FIXTURE_ARRAY.load(Ordering::SeqCst) as *const FakeAlg
    }
}

/// Fire the blocking target once (blocks iff the latch is armed).
fn fire_blocking(op: i32) {
    let mut ns: i32 = 0;
    // SAFETY: `ns` is a live stack slot for the call.
    let _rv = unsafe {
        osslscope_member_query_blocking(std::ptr::null_mut(), op, &mut ns as *mut std::ffi::c_int)
    };
    std::hint::black_box(_rv);
}

/// File offset of a named query symbol (uprobe attach point).
fn symbol_off(name: &str) -> u64 {
    let exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(&exe).expect("read exe");
    let elf = goblin::elf::Elf::parse(&bytes).expect("parse exe");
    let sym = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .unwrap_or_else(|| panic!("query symbol {name} present"));
    assert!(sym.st_size > 0, "query symbol {name} has nonzero size");
    assert_eq!(
        sym.st_type(),
        goblin::elf::sym::STT_FUNC,
        "query symbol {name} is a function"
    );
    for ph in elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
    {
        if ph.p_vaddr <= sym.st_value && sym.st_value < ph.p_vaddr + ph.p_memsz {
            return sym.st_value - ph.p_vaddr + ph.p_offset;
        }
    }
    panic!("query symbol {name} outside LOAD segments");
}

/// Fire `n` queries on a FRESH sacrificial worker tid (joined
/// before return — deterministic, no stray-thread window past the
/// join): the worker self-registers birth 0, fires, and reports
/// its tid. Returns the worker tid (legs filter CALLs by it).
fn fire_on_worker(loaded: &Loaded, op: i32, n: usize) -> u32 {
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let tid = self_tid();
            write_cell(loaded, "BIRTH", &tid.to_le_bytes(), &0u16.to_le_bytes());
            fire(op, n);
            tid
        });
        h.join().expect("worker join")
    })
}

/// File offset of the query symbol in our own image (uprobe
/// attach point), via symtab + containing PT_LOAD.
fn query_off() -> u64 {
    symbol_off("osslscope_member_query")
}

/// Assert exactly one LOSS id is nonzero at `val` (skip-leg
/// loss pins: the expected cause-loss fired, nothing else).
fn assert_loss_only(loaded: &Loaded, id: u32, val: u64, tag: &str) {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps["LOSS"].try_clone().expect("clone LOSS");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    let mut seen = false;
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        let sum: u64 = slots.iter().fold(0, |a, &b| a.wrapping_add(b));
        if k == id {
            assert_eq!(sum, val, "{tag}: LOSS[{id}]");
            seen = true;
        } else {
            assert_eq!(sum, 0, "{tag}: LOSS[{k}] must be zero");
        }
    }
    assert!(seen || val == 0, "{tag}: LOSS[{id}] row present");
}

fn own_exe_cstr() -> std::ffi::CString {
    let exe = std::env::current_exe().expect("current exe");
    std::ffi::CString::new(exe.into_os_string().into_string().expect("utf8 exe")).expect("cstr")
}

// ===== memfd fixture tables =====

/// One live fixture slot: name + class + dispatch legs. A trailing
/// terminator entry is appended automatically unless `no_term`.
pub struct SlotSpec {
    pub name: String,
    pub class: u16,
    /// (funcid, fptr) dispatch legs; terminator appended per leg.
    pub dispatch: Vec<(u32, u64)>,
    /// No dispatch terminator within the walked bound (overflow shape).
    pub no_term: bool,
    /// Names set but imp NULL (stable NOIMP observation).
    pub impl_null: bool,
}

impl SlotSpec {
    pub fn live(name: &str, class: u16, dispatch: Vec<(u32, u64)>) -> SlotSpec {
        SlotSpec {
            name: name.to_string(),
            class,
            dispatch,
            no_term: false,
            impl_null: false,
        }
    }
}

/// A memfd-backed fixture table: array + names + dispatch in one
/// mapping (one pageout/mincore unit). Layout: `[array (live +
/// terminator)...] [names blob] [dispatch tables...]`, all
/// offsets computed up front, then written once.
pub struct Fixture {
    ptr: *mut u8,
    len: usize,
    #[allow(dead_code)]
    fd: OwnedFd,
    pub array: u64,
    pub live: usize,
    pub classes: Vec<(String, u16)>,
}

// The mapping outlives the legs' single thread; legs never share it.
unsafe impl Send for Fixture {}

impl Fixture {
    /// Build a table with `slots` live entries + terminator. When
    /// `tail` is nonempty, its entries are planted PAST the
    /// terminator (L3-tail: nonzero garbage the v1 walker reaches).
    pub fn build(slots: &[SlotSpec], tail: &[SlotSpec]) -> Fixture {
        Self::build_padded(slots, tail, slots.len() + 1 + tail.len())
    }

    /// Build with the array region sized to `array_slots` cells
    /// (live prefix + terminator + zero tail). Zero-tail members
    /// read names==0 and stay silent, so op-level TRUNC reflects
    /// ONLY the live prefix's walk — required for v1 cleanliness
    /// asserts (unpadded past-T memory yields READ/NOIMP/NAME soup
    /// from every member past the terminator; observed TRUNC=52 on
    /// a "clean" E=7 walk). The past-T reach itself is pinned by
    /// L3-tail, not hidden here.
    pub fn build_padded(slots: &[SlotSpec], tail: &[SlotSpec], array_slots: usize) -> Fixture {
        assert!(
            array_slots >= slots.len() + 1 + tail.len(),
            "array must fit live + terminator + tail"
        );
        let all: Vec<&SlotSpec> = slots.iter().chain(tail.iter()).collect();
        let n_array = array_slots;
        let names_len: usize = all.iter().map(|s| s.name.len() + 1).sum();
        let disp_len: usize = all
            .iter()
            .map(|s| {
                if s.impl_null {
                    0
                } else {
                    (s.dispatch.len() + if s.no_term { 0 } else { 1 }) * size_of::<FakeDispatch>()
                }
            })
            .sum();
        let array_len = n_array * size_of::<FakeAlg>();
        // The dispatch region must be FakeDispatch-aligned:
        // `write_slot` uses `ptr::write` (alignment-required) and
        // names are variable-length, so an unpadded cursor is UB
        // (observed %8==3 on E7). All tables then stay aligned
        // (each advances the cursor by a multiple of 16).
        let disp_base = (array_len + names_len).next_multiple_of(align_of::<FakeDispatch>());
        let total = disp_base + disp_len;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = total.div_ceil(page) * page;
        let fd = unsafe {
            let cname = std::ffi::CString::new("members_fixture").unwrap();
            let fd = libc::memfd_create(cname.as_ptr(), 0);
            assert!(fd >= 0, "memfd_create failed");
            assert_eq!(libc::ftruncate(fd, len as libc::off_t), 0, "ftruncate");
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(ptr, libc::MAP_FAILED, "mmap fixture");
            std::ptr::write_bytes(ptr as *mut u8, 0, len);
            (OwnedFd::from_raw_fd(fd), ptr as *mut u8)
        };
        let base = fd.1 as u64;
        let mut name_off = array_len;
        let mut disp_off = disp_base;
        // The terminator cell (right after the live prefix) stays
        // zero (memfd starts zeroed); tail entries (if any) are
        // planted after it.
        let mut class_out = Vec::new();
        for (i, s) in slots.iter().enumerate() {
            class_out.push((s.name.clone(), s.class));
            unsafe {
                Self::write_slot(base, &mut name_off, &mut disp_off, i, s);
            }
        }
        for (t, s) in tail.iter().enumerate() {
            unsafe {
                Self::write_slot(base, &mut name_off, &mut disp_off, slots.len() + 1 + t, s);
            }
        }
        Fixture {
            ptr: fd.1,
            len,
            fd: fd.0,
            array: base,
            live: slots.len(),
            classes: class_out,
        }
    }

    /// Write one array cell + its name + dispatch at the cursor
    /// offsets (advancing them).
    unsafe fn write_slot(
        base: u64,
        name_off: &mut usize,
        disp_off: &mut usize,
        idx: usize,
        s: &SlotSpec,
    ) {
        // SAFETY: caller holds a zeroed mapping sized for the full
        // layout; all computed offsets land inside it.
        unsafe {
            let cell = (base as *mut FakeAlg).add(idx);
            let nptr = base + *name_off as u64;
            std::ptr::copy_nonoverlapping(s.name.as_ptr(), nptr as *mut u8, s.name.len());
            *name_off += s.name.len() + 1; // NUL already zero
            let imp = if s.impl_null {
                0
            } else {
                let dptr = base + *disp_off as u64;
                assert_eq!(
                    dptr as usize % align_of::<FakeDispatch>(),
                    0,
                    "dispatch table alignment (ptr::write requires it)"
                );
                for (k, (fid, fptr)) in s.dispatch.iter().enumerate() {
                    let e = (dptr as *mut FakeDispatch).add(k);
                    std::ptr::write(
                        e,
                        FakeDispatch {
                            fid: *fid,
                            pad: 0,
                            fptr: *fptr,
                        },
                    );
                }
                if !s.no_term {
                    let e = (dptr as *mut FakeDispatch).add(s.dispatch.len());
                    std::ptr::write(
                        e,
                        FakeDispatch {
                            fid: 0,
                            pad: 0,
                            fptr: 0,
                        },
                    );
                    *disp_off += (s.dispatch.len() + 1) * size_of::<FakeDispatch>();
                } else {
                    *disp_off += s.dispatch.len() * size_of::<FakeDispatch>();
                }
                dptr
            };
            std::ptr::write(
                cell,
                FakeAlg {
                    names: nptr,
                    props: 0,
                    imp,
                    desc: 0,
                },
            );
        }
    }

    /// Report the mapping's temperature ("cold" iff no page is
    /// resident). Mincore-only: no side effects, safe for warm legs
    /// that must keep their fixture resident.
    pub fn temp(&self) -> &'static str {
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let mut vec = vec![0u8; self.len / page];
            assert_eq!(
                libc::mincore(self.ptr as *mut libc::c_void, self.len, vec.as_mut_ptr()),
                0,
                "mincore failed"
            );
            if vec.iter().all(|b| b & 1 == 0) {
                "cold"
            } else {
                "warm"
            }
        }
    }

    /// Evict the mapping, then report its temperature. DESTRUCTIVE:
    /// the fixture is paged out as a side effect — cold legs only.
    /// (Called once as a warm-leg diagnostic, it silently voided the
    /// leg; warm legs use `pretouch` + `temp` instead.)
    pub fn pageout_and_temp(&self) -> &'static str {
        unsafe {
            let r = libc::madvise(self.ptr as *mut libc::c_void, self.len, MADV_PAGEOUT);
            assert_eq!(r, 0, "madvise PAGEOUT failed");
        }
        self.temp()
    }

    /// Fault every page back in (warm legs) and verify residence.
    pub fn pretouch(&self) {
        unsafe {
            for off in (0..self.len).step_by(4096) {
                std::ptr::read_volatile((self.ptr as *const u8).add(off));
            }
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let mut vec = vec![0u8; self.len / page];
            assert_eq!(
                libc::mincore(self.ptr as *mut libc::c_void, self.len, vec.as_mut_ptr()),
                0,
                "mincore failed"
            );
            assert!(
                vec.iter().all(|b| b & 1 == 1),
                "pretouch must leave all pages resident"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

/// Offline: the query target resolves to a real function offset.
/// Also smoke-tests the target itself (verdict stamp + array
/// return); the direct call anchors the symbol in the image.
#[test]
fn target_resolves() {
    NS_VERDICT.store(7, Ordering::SeqCst);
    FIXTURE_ARRAY.store(0x1234, Ordering::SeqCst);
    let mut ns: i32 = 0;
    // SAFETY: `ns` is a live stack slot for the call.
    let rv = unsafe { osslscope_member_query(std::ptr::null_mut(), 1, &mut ns) };
    assert_eq!(ns, 7, "verdict stamped");
    assert_eq!(rv as u64, 0x1234, "array returned");
    NS_VERDICT.store(0, Ordering::SeqCst);
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    let off = query_off();
    assert!(off > 0, "query file offset nonzero, got {off}");
    eprintln!("query target: osslscope_member_query @ file+{off:#x}");
    // C nested/churn targets resolve too (self-pinning anchors).
    for name in [
        "osslscope_member_query_nested",
        "osslscope_member_query_blocking",
    ] {
        let o = symbol_off(name);
        assert!(o > 0, "{name} file offset nonzero, got {o}");
        eprintln!("query target: {name} @ file+{o:#x}");
    }
}

/// Offline: the fixture builder lays out exact bytes (array cells,
/// NUL-terminated names, dispatch + terminator, zero terminator
/// cell) — the oracle's foundation, no BPF needed.
#[test]
fn fixture_builds() {
    let slots = vec![
        SlotSpec::live("M0A", 100, vec![(11, 0x4100), (12, 0x4101)]),
        SlotSpec::live("M0B", 101, vec![(21, 0x4200)]),
    ];
    let fx = Fixture::build(&slots, &[]);
    assert_eq!(fx.live, 2);
    assert_eq!(fx.classes.len(), 2);
    unsafe {
        let cell0 = &*(fx.array as *const FakeAlg);
        let cell1 = &*(fx.array as *const FakeAlg).add(1);
        let term = &*(fx.array as *const FakeAlg).add(2);
        assert_ne!(cell0.names, 0);
        assert_ne!(cell0.imp, 0);
        assert_ne!(cell1.names, 0);
        assert_ne!(cell1.imp, 0);
        assert_eq!((term.names, term.imp), (0, 0), "terminator cell zero");
        let n0 = std::ffi::CStr::from_ptr(cell0.names as *const i8);
        assert_eq!(n0.to_bytes(), b"M0A");
        let d0 = &*(cell0.imp as *const FakeDispatch);
        let d1 = &*(cell0.imp as *const FakeDispatch).add(1);
        let dt = &*(cell0.imp as *const FakeDispatch).add(2);
        assert_eq!((d0.fid, d0.fptr), (11, 0x4100));
        assert_eq!((d1.fid, d1.fptr), (12, 0x4101));
        assert_eq!((dt.fid, dt.fptr), (0, 0), "dispatch terminator zero");
    }
}

/// Offline: `temp()` is a pure probe — it must not evict. (L6a once
/// called the destructive `pageout_and_temp` as a diagnostic and
/// silently ran its full-chunk scan on an evicted fixture: 0 ALGs.)
/// `pageout_and_temp` keeps the eviction for cold legs; on lanes
/// without swap the evict is best-effort (no assert on its temp).
#[test]
fn temp_probe_is_nondestructive() {
    let slots = vec![SlotSpec::live("MT0", 100, vec![(91, 0x4900)])];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    assert_eq!(fx.temp(), "warm");
    assert_eq!(fx.temp(), "warm", "temp() must not evict");
    // The destructive twin still evicts-then-reports (cold legs
    // depend on the eviction happening inside this call).
    let _ = fx.pageout_and_temp();
    fx.pretouch();
    assert_eq!(fx.temp(), "warm", "fixture recoverable after evict");
}

// ===== live legs (lane only) =====

/// L1: the chunk loads through the production attach (all 513
/// progs verify — no new verifier risk shape) + per-prog xlated
/// margins recorded (T03 acceptance: margin per program) + CTRL
/// roundtrip (the attach programmed it). No fire.
#[test]
#[ignore]
fn l1_load_513_margins() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    assert_eq!(loaded.progs.len(), 513, "all member progs loaded");
    assert_eq!(loaded.maps.len(), 14, "all member maps created");
    assert_eq!(attached.members.len(), 512, "all member links attached");
    let ctrl = osslscope::loader::read_ctrl(&loaded.maps).expect("read CTRL");
    assert_eq!(
        (ctrl.expected, ctrl.skip_all, ctrl.epoch, ctrl.governor),
        (512, 0, 1, 1 << 20),
        "production attach programmed CTRL"
    );
    let mut lens: Vec<(String, usize)> = loaded
        .progs
        .iter()
        .map(|(name, fd)| {
            let x = ossl_bpf_sys::prog_xlated_bytes(fd.as_raw_fd())
                .unwrap_or_else(|e| panic!("xlated {name}: {e}"));
            (name.clone(), x.len())
        })
        .collect();
    lens.sort_by_key(|(_, l)| *l);
    let get = |n: &str| lens.iter().find(|(m, _)| m == n).unwrap().1;
    let entry = get("member_entry");
    let m000 = get("member_000");
    let m511 = get("member_511");
    let mids: Vec<usize> = lens
        .iter()
        .filter(|(n, _)| n != "member_entry" && n != "member_000" && n != "member_511")
        .map(|(_, l)| *l)
        .collect();
    let (mid_min, mid_max) = (mids.iter().min().unwrap(), mids.iter().max().unwrap());
    let mean = mids.iter().sum::<usize>() / mids.len();
    eprintln!(
        "xlated bytes: entry={entry} member_000={m000} member_511={m511} \
         mid_min={mid_min} mid_max={mid_max} mid_mean={mean} n=513"
    );
    assert!(
        lens.last().unwrap().1 <= 65536,
        "xlated per-prog sanity envelope (64KiB)"
    );
    assert!(
        m000 > *mid_max && m511 > *mid_max,
        "folds visible at xlated level too"
    );
}

/// L2 fixture: 7 live slots (§2.2 fixture E) × 7-entry dispatch,
/// classes 100+j, distinct (fid, fptr) per (slot, leg).
fn e7_slots() -> Vec<SlotSpec> {
    (0..7u32)
        .map(|j| {
            let disp = (0..7u32)
                .map(|k| (1000 + j * 16 + k, 0x4000u64 + (j * 16 + k) as u64))
                .collect();
            SlotSpec::live(&format!("M2A{j}"), 100 + j as u16, disp)
        })
        .collect()
}

/// L2: exact E=7 scan (warm) + swap-cold fail-closed + null-query
/// silence. Warm: every ALG/ROW byte-asserted on the live prefix;
/// the array is zero-padded to the full chunk so TRUNC==0 and
/// beyond-T silence are real asserts (v1 has no T-gate — unpadded
/// past-T memory yields flag soup). Cold: evicted pages are
/// unreadable via nofault (kernel contract), so the leg asserts
/// the fail-closed shape (WALK_READ alone, silent ring, counted);
/// it SKIPs labeled on lanes that cannot evict.
#[test]
#[ignore]
fn l2_exact_e7() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    run_e7(&obj, &exe, off, false);
    run_e7(&obj, &exe, off, true);
    run_null(&obj, &exe, off);
}

fn run_e7(obj: &std::path::Path, exe: &std::ffi::CString, off: u64, cold: bool) {
    use osslscope_ebpf_common as wire;
    use std::time::Instant;
    // Zero-padded to the full chunk: past-T members stay silent,
    // so TRUNC==0 reflects the live prefix's clean walk.
    let fx = Fixture::build_padded(&e7_slots(), &[], 512);
    if cold {
        return run_e7_pageout(obj, exe, off, fx);
    }
    fx.pretouch();
    let temp = "warm";
    let attached = attach_chunk(obj, exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let t0 = Instant::now();
    fire(OP as i32, QUERIES);
    let wall = t0.elapsed();
    eprintln!(
        "e7-{temp}: {QUERIES} queries in {wall:?} ({:.1}µs/scan, recorded)",
        wall.as_micros() as f64 / QUERIES as f64
    );
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, QUERIES, "e7");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        QUERIES as u64,
        "e7-{temp}: one query counted once"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "e7-{temp}: no TRUNC on the clean walk"
    );
    assert_loss_zero(loaded);
    assert_eq!(algs.len(), 7 * QUERIES, "e7-{temp}: 7 slots × N ALG");
    for j in 0..7u64 {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), QUERIES, "e7-{temp}: slot {j} ALG count");
        for a in got {
            assert_eq!(a.op, OP);
            assert_eq!(a.class, 100 + j as u16);
            assert_eq!(a.status, wire::ALG_OK);
            assert_eq!(a.weak, 0);
            assert_eq!(a.arr, fx.array);
            assert_eq!(a.generation, 0, "GEN uninstalled → 0-stamped");
        }
    }
    assert_eq!(
        rows.len(),
        7 * 7 * QUERIES,
        "e7-{temp}: 7 slots × 7 legs × N ROWs"
    );
    for j in 0..7u64 {
        let got: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
        assert_eq!(got.len(), 7 * QUERIES, "e7-{temp}: slot {j} ROW count");
        for k in 0..7u64 {
            let (fid, fptr) = (1000 + j as u32 * 16 + k as u32, 0x4000u64 + j * 16 + k);
            let n = got
                .iter()
                .filter(|r| {
                    r.funcid == fid
                        && r.addr == fptr
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                })
                .count();
            assert_eq!(n, QUERIES, "e7-{temp}: slot {j} leg {k} exact");
        }
    }
    // Zero tail ⇒ beyond-T silence is a REAL assert here (a
    // member emitting for a zero slot is a bug); the nonzero-tail
    // reach is pinned separately by L3-tail.
    assert!(
        algs.iter().all(|a| a.idx < 7) && rows.iter().all(|r| r.idx < 7),
        "e7-{temp}: zero tail stays silent"
    );
}

/// Cold-page leg (T03 amendment §3: "cold-page read failures"): the
/// evicted fixture is UNREADABLE via nofault helpers (kernel
/// contract — no IO from BPF), so every member aborts its slot
/// read: TRUNC_WALK_READ exactly, zero emissions, queries still
/// counted, zero loss. SKIPs labeled on lanes that cannot evict
/// (no swap); the munmap-hole leg (L3) always runs and proves the
/// same member-side abort path.
fn run_e7_pageout(obj: &std::path::Path, exe: &std::ffi::CString, off: u64, fx: Fixture) {
    if fx.pageout_and_temp() != "cold" {
        eprintln!("SKIP(e7-cold): lane cannot evict fixture pages (no swap?)");
        return;
    }
    // From here until the drain: touch nothing fixture-backed (any
    // touch re-faults and voids the cold).
    let attached = attach_chunk(obj, exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, QUERIES);
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, QUERIES, "e7-cold");
    assert_abort_clean(loaded, &algs, &rows, QUERIES as u64, "e7-cold");
}

/// Shared read-abort oracle (pageout-cold + munmap-hole).
/// Pageout-cold evicts the whole fixture, so every slot read
/// fails; the munmap-hole unmaps only the live prefix's page while
/// the mapped zero tail reads fine and stays silent (names==0).
/// Either way TRUNC holds WALK_READ alone, the member ring stays
/// empty, the entry still counts (admit-bump precedes the walk),
/// and nothing is lost.
fn assert_abort_clean(
    loaded: &Loaded,
    algs: &[osslscope_ebpf_common::AlgEvent],
    rows: &[osslscope_ebpf_common::RowEvent],
    n: u64,
    tag: &str,
) {
    use osslscope_ebpf_common as wire;
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        wire::TRUNC_WALK_READ,
        "{tag}: abort flags WALK_READ alone"
    );
    assert!(
        algs.is_empty() && rows.is_empty(),
        "{tag}: aborted members emit nothing"
    );
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        n,
        "{tag}: aborted queries still counted"
    );
    assert_loss_zero(loaded);
}

/// Null queries (rv == 0) stay member-silent but are COUNTED in
/// C (spec-mandated flip, R18 §6.2/§7C: the entry cannot see rv,
/// so CALLS admit-bumps NULL too; member-0 QUERY_RET-EMPTY lands
/// in D and asserts there). A positive control fires through the
/// SAME links first: a dead attach would otherwise satisfy every
/// null assert vacuously (T03 demands positive fire evidence per
/// firing leg).
fn run_null(obj: &std::path::Path, exe: &std::ffi::CString, off: u64) {
    let fx = Fixture::build(&e7_slots(), &[]);
    fx.pretouch();
    let attached = attach_chunk(obj, exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Positive control: one live query proves these links fire.
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, 1, "null-control");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        1,
        "null-leg control: live query counted"
    );
    assert!(
        !algs.is_empty() && !rows.is_empty(),
        "null-leg control: live query emits"
    );
    // Null phase: member silence, but the count advances (C flip:
    // the entry cannot see rv — both nulls admitted + counted).
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    fire(OP as i32, 2);
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, 2, "null-phase");
    assert!(
        algs.is_empty() && rows.is_empty(),
        "null queries emit no member records"
    );
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        3,
        "null queries counted in C (control 1 + 2 nulls)"
    );
    assert_loss_zero(loaded);
}

/// L3: empty / one / adjacent-tail / munmap-hole fixtures.
/// Prefix-exact; the tail leg PINS v1's past-T reach (tail
/// presence) — item 3's T-gate flips it to absence. The hole leg
/// proves the read-abort path deterministically on every lane
/// (same member-side shape as swap-cold, no swap needed).
#[test]
#[ignore]
fn l3_boundaries() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // Empty: slot 0 silent (names==0 → return), EMPTY flagged.
    {
        let fx = Fixture::build(&[], &[]);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-empty");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_ne!(
            read_percpu(loaded, "TRUNC", OP, true) & wire::TRUNC_WALK_EMPTY,
            0,
            "empty slot 0 flagged"
        );
        assert!(algs.iter().all(|a| a.idx != 0), "slot 0 silent");
        assert!(rows.iter().all(|r| r.idx != 0), "slot 0 rowless");
        eprintln!(
            "l3-empty: {} ALG + {} ROW beyond slot 0 (recorded, v1 gap)",
            algs.len(),
            rows.len()
        );
        assert_loss_zero(loaded);
    }
    // One: slot 0 exact, EMPTY bit clear.
    {
        let slots = vec![SlotSpec::live("M3A", 100, vec![(31, 0x4300), (32, 0x4301)])];
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-one");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true) & wire::TRUNC_WALK_EMPTY,
            0,
            "live slot 0 leaves EMPTY clear"
        );
        let a0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(a0.len(), 2, "slot-0 ALG × 2");
        for a in &a0 {
            assert_eq!(
                (a.op, a.class, a.status, a.arr, a.generation),
                (OP, 100, wire::ALG_OK, fx.array, 0)
            );
        }
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 4, "slot-0 ROWs 2 legs × 2");
        for (k, (fid, fptr)) in [(31u32, 0x4300u64), (32, 0x4301)].iter().enumerate() {
            let n = r0
                .iter()
                .filter(|r| {
                    r.funcid == *fid
                        && r.addr == *fptr
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                })
                .count();
            assert_eq!(n, 2, "slot-0 leg {k} exact");
        }
        assert_loss_zero(loaded);
    }
    // Adjacent tail: 3 live + term@3 + 3 planted @4..6. Prefix
    // exact AND tail present (v1 walks past T — pinned gap).
    {
        let slots: Vec<SlotSpec> = (0..3u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("M3P{j}"),
                    100 + j as u16,
                    vec![(300 + j, 0x4400 + j as u64)],
                )
            })
            .collect();
        let tail: Vec<SlotSpec> = (0..3u32)
            .map(|t| {
                SlotSpec::live(
                    &format!("M3T{t}"),
                    200 + t as u16,
                    vec![(900 + t, 0x9900 + t as u64)],
                )
            })
            .collect();
        let tail_classes: Vec<(String, u16)> =
            tail.iter().map(|s| (s.name.clone(), s.class)).collect();
        let fx = Fixture::build(&slots, &tail);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let mut entries = fx.classes.clone();
        entries.extend(tail_classes);
        populate_alg_class(loaded, &entries);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-tail");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        for j in 0..3u64 {
            let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
            assert_eq!(got.len(), 2, "prefix slot {j} exact");
            assert!(
                got.iter().all(|a| {
                    a.op == OP
                        && a.class == 100 + j as u16
                        && a.status == wire::ALG_OK
                        && a.arr == fx.array
                        && a.generation == 0
                }),
                "prefix slot {j} ALG payload"
            );
            let rws: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
            assert_eq!(rws.len(), 2, "prefix slot {j} rows exact");
            assert!(
                rws.iter().all(|r| {
                    r.funcid == 300 + j as u32
                        && r.addr == 0x4400 + j
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                }),
                "prefix slot {j} ROW payload"
            );
        }
        for t in 0..3u64 {
            let idx = 4 + t;
            let at: Vec<_> = algs.iter().filter(|a| a.idx == idx).collect();
            assert_eq!(
                at.len(),
                2,
                "v1 gap pin: tail slot {idx} PRESENT (item 3 flips to absence)"
            );
            assert!(
                at.iter().all(|a| {
                    a.op == OP
                        && a.class == 200 + t as u16
                        && a.status == wire::ALG_OK
                        && a.arr == fx.array
                        && a.generation == 0
                }),
                "tail slot {idx} ALG payload"
            );
            let rt: Vec<_> = rows.iter().filter(|r| r.idx == idx).collect();
            assert_eq!(
                rt.len(),
                2,
                "v1 gap pin: tail slot {idx} ROWs PRESENT (item 3 flips to absence)"
            );
            assert!(
                rt.iter().all(|r| {
                    r.funcid == 900 + t as u32
                        && r.addr == 0x9900 + t
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                }),
                "tail slot {idx} ROW payload"
            );
        }
        assert_loss_zero(loaded);
    }
    // Munmap hole: array page 0 (slots 0..127, incl. the live
    // prefix) unmapped ⇒ every slot read in the hole aborts:
    // TRUNC_WALK_READ exactly, zero emissions, queries counted.
    // Same member-side path as swap-cold, but deterministic on
    // every lane (no swap needed). ORDERING: no mmap/malloc may run
    // between the munmap and the end of fire (an allocator mmap
    // could reuse the hole); attach/load/allocations all precede it.
    {
        let slots = vec![
            SlotSpec::live("M3H0", 100, vec![(41, 0x4600)]),
            SlotSpec::live("M3H1", 101, vec![(42, 0x4601)]),
        ];
        let fx = Fixture::build_padded(&slots, &[], 512);
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        // Hoisted: no allocation may run between the munmap and the
        // end of fire (see the ordering note above).
        let mut probe = vec![0u8; 1];
        assert_eq!(
            unsafe { libc::munmap(fx.array as *mut libc::c_void, page) },
            0,
            "munmap hole page"
        );
        // Prove the hole (mincore on unmapped memory fails ENOMEM).
        let mc = unsafe { libc::mincore(fx.array as *mut libc::c_void, page, probe.as_mut_ptr()) };
        assert_eq!(mc, -1, "hole must read as unmapped");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM),
            "hole errno is ENOMEM"
        );
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-hole");
        assert_abort_clean(loaded, &algs, &rows, 2, "l3-hole");
    }
}

/// L4: dispatch bounds — 127 legs + terminator (128 entries,
/// clean, bit clear) vs 128 legs + terminator (term@128 out of the
/// walker's reach: TRUNC_DISPATCH despite the present term) vs 129
/// live legs unterminated (TRUNC_DISPATCH, first 128 ROWs kept, leg
/// 128 never walked). The PRD bound is 128 ENTRIES including the
/// terminator (the walker reads at most 128 entries, indices
/// 0..128); 128 live legs already overflow since their terminator
/// sits at the unread index 128. Separate fixtures isolate each
/// shape at op granularity (v1 TRUNC is per-op).
#[test]
#[ignore]
fn l4_dispatch_bounds() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // 127 + term (128 entries): clean.
    {
        let disp: Vec<(u32, u64)> = (0..127u32).map(|k| (5000 + k, 0x9000 + k as u64)).collect();
        // Zero-padded: DISPATCH-clear reflects member 0's clean walk only.
        let fx = Fixture::build_padded(&[SlotSpec::live("M4A", 100, disp)], &[], 512);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4a");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            0,
            "127+term: TRUNC exactly clear (warm, zero-padded)"
        );
        let a0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(a0.len(), 2);
        assert!(
            a0.iter().all(|a| {
                a.op == OP
                    && a.class == 100
                    && a.status == wire::ALG_OK
                    && a.arr == fx.array
                    && a.generation == 0
            }),
            "slot-0 ALG payload"
        );
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 254);
        for k in 0..127u64 {
            let n = r0
                .iter()
                .filter(|r| {
                    r.funcid == 5000 + k as u32
                        && r.addr == 0x9000 + k
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                })
                .count();
            assert_eq!(n, 2, "leg {k} exact");
        }
        assert_loss_zero(loaded);
    }
    // 128 + term@128: overflow — the terminator exists but the
    // walker exhausts its 128 reads on live legs first.
    {
        let disp: Vec<(u32, u64)> = (0..128u32).map(|k| (5000 + k, 0x9000 + k as u64)).collect();
        let fx = Fixture::build_padded(&[SlotSpec::live("M4E", 100, disp)], &[], 512);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4b");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_DISPATCH,
            "128+term: DISPATCH alone (term@128 unreachable)"
        );
        let a0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(a0.len(), 2);
        assert!(
            a0.iter().all(|a| {
                a.op == OP
                    && a.class == 100
                    && a.status == wire::ALG_OK
                    && a.arr == fx.array
                    && a.generation == 0
            }),
            "slot-0 ALG payload"
        );
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 256);
        for k in 0..128u64 {
            let n = r0
                .iter()
                .filter(|r| {
                    r.funcid == 5000 + k as u32
                        && r.addr == 0x9000 + k
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                })
                .count();
            assert_eq!(n, 2, "leg {k} exact");
        }
        assert_loss_zero(loaded);
    }
    // 129 live, no term: overflow.
    {
        let disp: Vec<(u32, u64)> = (0..129u32).map(|k| (5000 + k, 0x9000 + k as u64)).collect();
        let mut slot = SlotSpec::live("M4B", 100, disp);
        slot.no_term = true;
        // Zero-padded for a deterministic ring (garbage ALGs would
        // otherwise join the drain; the overflow bit is OR-folded).
        let fx = Fixture::build_padded(&[slot], &[], 512);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4c");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_DISPATCH,
            "129-live: DISPATCH alone"
        );
        let a0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(a0.len(), 2);
        assert!(
            a0.iter().all(|a| {
                a.op == OP
                    && a.class == 100
                    && a.status == wire::ALG_OK
                    && a.arr == fx.array
                    && a.generation == 0
            }),
            "slot-0 ALG payload"
        );
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 256, "first 128 legs × 2 kept");
        for k in 0..128u64 {
            let n = r0
                .iter()
                .filter(|r| {
                    r.funcid == 5000 + k as u32
                        && r.addr == 0x9000 + k
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                })
                .count();
            assert_eq!(n, 2, "leg {k} exact");
        }
        assert!(
            r0.iter().all(|r| r.funcid < 5000 + 128),
            "leg 128 never walked"
        );
        assert_loss_zero(loaded);
    }
}

/// L5: no_store walks (flagged, contents exact — v1 walks
/// uncacheable tables every scan and never proves) and the flag
/// sticks across a flip back to cacheable.
#[test]
#[ignore]
fn l5_no_store() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let slots = vec![
        SlotSpec::live("M5A", 100, vec![(51, 0x4500)]),
        SlotSpec::live("M5B", 101, vec![(52, 0x4501), (53, 0x4502)]),
    ];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(1, Ordering::SeqCst);
    fire(OP as i32, 2);
    assert_ne!(
        read_percpu(loaded, "TRUNC", OP, true) & wire::TRUNC_NO_STORE,
        0,
        "no_store flagged"
    );
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, 3, "l5");
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 3);
    // Masked, not exact: this fixture is unpadded, so members past
    // the terminator read names-region memory and may OR past-T soup
    // into TRUNC (the known v1 gap, pinned by L3-tail).
    assert_ne!(
        read_percpu(loaded, "TRUNC", OP, true) & wire::TRUNC_NO_STORE,
        0,
        "no_store flag sticks after flip-back"
    );
    for j in [0u64, 1] {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 3, "slot {j} ALG × 3");
        assert!(
            got.iter().all(|a| {
                a.op == OP
                    && a.class == 100 + j as u16
                    && a.status == wire::ALG_OK
                    && a.arr == fx.array
                    && a.generation == 0
            }),
            "slot {j} ALG payload"
        );
    }
    let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
    assert_eq!(r0.len(), 3);
    assert!(
        r0.iter().all(|r| {
            r.funcid == 51
                && r.addr == 0x4500
                && r.aux == fx.array
                && r.op == OP
                && r.generation == 0
        }),
        "slot-0 ROW payload"
    );
    let r1: Vec<_> = rows.iter().filter(|r| r.idx == 1).collect();
    assert_eq!(r1.len(), 6);
    for (fid, fptr) in [(52u32, 0x4501u64), (53, 0x4502)] {
        let n = r1
            .iter()
            .filter(|r| {
                r.funcid == fid
                    && r.addr == fptr
                    && r.aux == fx.array
                    && r.op == OP
                    && r.generation == 0
            })
            .count();
        assert_eq!(n, 3, "slot-1 leg {fid} exact");
    }
    assert_loss_zero(loaded);
}

/// L6: the full-chunk proof — 512 live slots walk exactly (1024
/// ALG + 1024 ROWs over 2 queries, zero TRUNC_ALGS), and a
/// 513-live array sets TRUNC_ALGS while slot 512 stays unwalked
/// (no member 512 exists — the guard only peeks its liveness).
#[test]
#[ignore]
fn l6_full_chunk() {
    use osslscope_ebpf_common as wire;
    use std::time::Instant;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // 512 live + term@512: clean full scan.
    {
        let slots: Vec<SlotSpec> = (0..512u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("M6A{j:03}"),
                    100 + j as u16,
                    vec![(7000 + j, 0xA000 + j as u64)],
                )
            })
            .collect();
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        eprintln!("l6a fixture temp: {}", fx.temp());
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let t0 = Instant::now();
        fire(OP as i32, 2);
        eprintln!("l6a: 2 full scans in {:?} (recorded)", t0.elapsed());
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l6a");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            0,
            "512-clean: TRUNC exactly clear (every slot live, guard sees term)"
        );
        assert_eq!(algs.len(), 1024, "512 slots × 2 ALG");
        assert_eq!(rows.len(), 1024, "512 slots × 1 leg × 2 ROWs");
        for j in 0..512u64 {
            let a: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
            assert_eq!(a.len(), 2, "slot {j} ALG × 2");
            assert!(
                a.iter().all(|a| {
                    a.op == OP
                        && a.class == 100 + j as u16
                        && a.status == wire::ALG_OK
                        && a.arr == fx.array
                        && a.generation == 0
                }),
                "slot {j} ALG payload"
            );
            let r: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
            assert_eq!(r.len(), 2, "slot {j} ROW × 2");
            assert!(
                r.iter().all(|r| {
                    r.funcid == 7000 + j as u32
                        && r.addr == 0xA000 + j
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                }),
                "slot {j} ROW payload"
            );
        }
        assert_loss_zero(loaded);
    }
    // 513 live + term@513: TRUNC_ALGS, slot 512 unwalked.
    {
        let slots: Vec<SlotSpec> = (0..513u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("M6B{j:03}"),
                    100 + (j % 512) as u16,
                    vec![(7000 + j, 0xA000 + j as u64)],
                )
            })
            .collect();
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let (calls, algs, rows) = drain(loaded);
        assert_calls_admitted(&calls, 2, "l6b");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_ALGS,
            "513-live: TRUNC_ALGS alone (warm, every walked slot live)"
        );
        assert_eq!(algs.len(), 1024, "slots 0..511 × 2 ALG (512 unwalked)");
        assert_eq!(rows.len(), 1024, "slots 0..511 × 1 leg × 2 ROWs");
        assert!(
            algs.iter().all(|a| a.idx <= 511) && rows.iter().all(|r| r.idx <= 511),
            "no member 512: slot 512 never walked"
        );
        for j in 0..512u64 {
            let a: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
            assert_eq!(a.len(), 2, "slot {j} ALG × 2");
            assert!(
                a.iter().all(|a| {
                    a.op == OP
                        && a.class == 100 + j as u16
                        && a.status == wire::ALG_OK
                        && a.arr == fx.array
                        && a.generation == 0
                }),
                "slot {j} ALG payload"
            );
            let r: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
            assert_eq!(r.len(), 2, "slot {j} ROW × 2");
            assert!(
                r.iter().all(|r| {
                    r.funcid == 7000 + j as u32
                        && r.addr == 0xA000 + j
                        && r.aux == fx.array
                        && r.op == OP
                        && r.generation == 0
                }),
                "slot {j} ROW payload"
            );
        }
        assert_loss_zero(loaded);
    }
}

/// L7: cookie-mismatch negative — member_3 attached with cookie 7
/// skips (LOSS_MEMBER_COOKIE, no slot-3 records) while the rest of
/// the chunk fires normally.
#[test]
#[ignore]
fn l7_cookie_mismatch() {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let slots = vec![
        SlotSpec::live("M7A", 100, vec![(71, 0x4700)]),
        SlotSpec::live("M7B", 101, vec![(72, 0x4701)]),
        SlotSpec::live("M7C", 102, vec![(73, 0x4702)]),
        SlotSpec::live("M7D", 103, vec![(74, 0x4703)]),
    ];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    let mut attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Surgical cookie fault on top of the production attach: drop
    // member_3's correct link (drop = detach) and re-attach the
    // same prog with cookie 7. Same code path as production for
    // the other 512 links.
    let m3 = ossl_bpf_sys::link_create_uretprobe_multi(
        loaded.progs["member_003"].as_raw_fd(),
        &exe,
        &[off],
        &[7],
        std::process::id(),
    )
    .expect("re-attach member_3 with cookie 7");
    drop(std::mem::replace(&mut attached.members[3], m3));
    fire(OP as i32, 2);
    let (calls, algs, rows) = drain(loaded);
    assert_calls_admitted(&calls, 2, "l7");
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
    for j in [0u64, 1, 2] {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 2, "slot {j} fires");
        assert!(
            got.iter().all(|a| {
                a.op == OP
                    && a.class == 100 + j as u16
                    && a.status == wire::ALG_OK
                    && a.arr == fx.array
                    && a.generation == 0
            }),
            "slot {j} ALG payload"
        );
        let rws: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
        assert_eq!(rws.len(), 2, "slot {j} ROWs fire");
        assert!(
            rws.iter().all(|r| {
                r.funcid == 71 + j as u32
                    && r.addr == 0x4700 + j
                    && r.aux == fx.array
                    && r.op == OP
                    && r.generation == 0
            }),
            "slot {j} ROW payload"
        );
    }
    assert!(
        algs.iter().all(|a| a.idx != 3) && rows.iter().all(|r| r.idx != 3),
        "mismatched member_3 skips its slot"
    );
    let fd = loaded.maps["LOSS"].try_clone().expect("clone LOSS");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    let mut cookie_hits = 0u64;
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        let sum: u64 = slots.iter().fold(0, |a, &b| a.wrapping_add(b));
        if k == wire::LOSS_MEMBER_COOKIE {
            cookie_hits = sum;
        } else {
            assert_eq!(
                sum, 0,
                "only LOSS_MEMBER_COOKIE may fire, got LOSS[{k}]={sum}"
            );
        }
    }
    assert_eq!(cookie_hits, 2, "one mismatch per query");
}

// ===== stage-C legs (R18 §7C; lane only) =====

/// C admit-shape: fresh tid admits (CALL + seq 0, no hint, SCAN
/// cell exact, RCOUNT ACTIVE|0, PENDING present — C-only, CALLS 1);
/// second admit on the same tid carries NESTED-HINT (asserted as
/// correct-for-C — no retirement exists; D retires between and
/// replaces these asserts with the retire-quiet pair, §10.2).
#[test]
#[ignore]
fn c_admit_shape() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst); // NULL: entry-side only
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1, "one CALL per admit");
    let c = &calls[0];
    assert_eq!((c.kind, c.op, c.tid), (wire::KIND_SCAN_CALL, OP, tid));
    assert_eq!(
        call_parts(c),
        (false, wire::SKIP_ADMITTED),
        "seq-0 admit: silent"
    );
    assert_eq!(c.seq, wire::make_seq(0, 0), "fresh tid mints (0,0)");
    assert!(algs.is_empty() && rows.is_empty(), "NULL: member silence");
    let rec = read_scan_cell(loaded, tid).expect("SCAN published");
    assert_eq!(
        (rec.op, rec.seq, rec.expected, rec.epoch),
        (OP as u64, wire::make_seq(0, 0), 512, 1),
        "SCAN cell exact (EXPECTED+epoch frozen from CTRL)"
    );
    assert_ne!(rec.ns_ptr, 0, "SCAN stashes the caller out-pointer");
    let rc = read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT reset");
    assert_eq!(
        wire::split_rcount(rc),
        (0, wire::RCOUNT_STATE_ACTIVE),
        "RCOUNT ACTIVE|0"
    );
    let pend = read_pending_cell(loaded, pid, tid).expect("PENDING present (C-only)");
    assert_eq!(pend.0, OP as u64, "PENDING op");
    assert_ne!(pend.1, 0, "PENDING ns_ptr");
    assert_eq!(
        wire::split_seq(read_u64_cell(loaded, "SEQ", tid).expect("SEQ minted")),
        (0, 0)
    );
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1, "CALLS 1");
    assert_eq!(read_attempt(loaded), 1, "ATTEMPT 1");
    assert_loss_zero(loaded);
    // Second admit, same tid: seq 1 WITH nested-hint
    // (correct-for-C — the record is unretired, ACTIVE, count 0).
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (true, wire::SKIP_ADMITTED),
        "second same-tid admit hints (C convention)"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 1));
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
    assert_eq!(read_attempt(loaded), 2);
    assert_loss_zero(loaded);
}

/// Skip-case driver (R18 §7C 4-tuple): fresh attach, same-attach
/// admit-control (positive fire evidence — T03), drain, baseline,
/// `setup` arms the skip condition, one fire, exact 4-tuple
/// (cause, ATTEMPTΔ==1 single count, CALLSΔ, state-delta) +
/// member silence + loss pin. `check_cells` asserts the
/// case-specific RCOUNT/SEQ end state (uniform parts assert here:
/// PENDING absent + SCAN absent — C-only PENDING readback).
#[allow(
    clippy::too_many_arguments,
    reason = "one driver for 8 skip shapes; bundling would hide the 4-tuple"
)]
fn skip_case(
    obj: &std::path::Path,
    exe: &std::ffi::CString,
    off: u64,
    tag: &str,
    cause: u8,
    loss: u32,
    setup: impl FnOnce(&Loaded),
    check_cells: impl FnOnce(&Loaded, u32),
) {
    use osslscope_ebpf_common as wire;
    let attached = attach_chunk(obj, exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Admit-control: same attach, must admit (else the skip below
    // could be a dead attach, not the armed condition).
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1, "{tag}: control CALL");
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "{tag}: control admits"
    );
    assert!(
        read_pending_cell(loaded, pid, tid).is_some(),
        "{tag}: control PENDING"
    );
    assert!(read_scan_cell(loaded, tid).is_some(), "{tag}: control SCAN");
    let (attempt0, calls0, loss0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
        read_percpu(loaded, "LOSS", loss, false),
    );
    setup(loaded);
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1, "{tag}: skip CALL");
    let c = &calls[0];
    assert_eq!(c.tid, tid, "{tag}: skip CALL tid");
    assert_eq!(call_parts(c), (false, cause), "{tag}: skip cause");
    assert_eq!(c.seq, 0, "{tag}: skips carry seq 0");
    assert_eq!(
        read_attempt(loaded) - attempt0,
        1,
        "{tag}: ATTEMPTΔ==1 (single count)"
    );
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        0,
        "{tag}: CALLSΔ==0"
    );
    assert_eq!(
        read_percpu(loaded, "LOSS", loss, false) - loss0,
        1,
        "{tag}: LOSS[{loss}]Δ==1"
    );
    assert!(
        algs.is_empty() && rows.is_empty(),
        "{tag}: skip member silence"
    );
    assert!(
        read_pending_cell(loaded, pid, tid).is_none(),
        "{tag}: PENDING absent (C-only)"
    );
    assert!(read_scan_cell(loaded, tid).is_none(), "{tag}: SCAN absent");
    check_cells(loaded, tid);
}

/// C skip battery: every gate skips with its cause + loss-proof
/// counter + exact 4-tuple (R18 §7C). Each case opens with a
/// same-attach admit-control.
#[test]
#[ignore]
fn c_skip_causes() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let gov = 1u64 << 20;
    // SKIP_ALL (cause 5): program the bit behind the control.
    skip_case(
        &obj,
        &exe,
        off,
        "skip-all",
        wire::SKIP_ALL,
        wire::LOSS_SKIP_ALL,
        |loaded| {
            let ctrl = wire::CtrlValue {
                expected: 512,
                skip_all: 1,
                _pad: [0; 3],
                epoch: 1,
                governor: gov,
            };
            osslscope::loader::program_ctrl(&loaded.maps, &ctrl).expect("SKIP_ALL on");
        },
        |loaded, tid| {
            assert_eq!(
                wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                (0, wire::RCOUNT_STATE_IDLE),
                "skip-all: RCOUNT IDLE|0"
            );
            assert_eq!(
                wire::split_seq(read_u64_cell(loaded, "SEQ", tid).expect("SEQ kept")),
                (0, 0),
                "skip-all: SEQ unminted"
            );
        },
    );
    // BIRTH freeze (cause 3): BIRTH=MAX behind the control.
    skip_case(
        &obj,
        &exe,
        off,
        "birth-freeze",
        wire::SKIP_BIRTH_WRAP,
        wire::LOSS_BIRTH_WRAP,
        |loaded| {
            let tid = self_tid();
            write_cell(
                loaded,
                "BIRTH",
                &tid.to_le_bytes(),
                &wire::BIRTH_FROZEN.to_le_bytes(),
            );
        },
        |loaded, tid| {
            assert_eq!(
                wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                (0, wire::RCOUNT_STATE_IDLE),
                "freeze: RCOUNT IDLE|0"
            );
            assert_eq!(
                wire::split_seq(read_u64_cell(loaded, "SEQ", tid).expect("SEQ kept")),
                (0, 0),
                "freeze: SEQ unminted (gate precedes SEQ)"
            );
        },
    );
    // SEQ-full (cause 2): 4k-fill EXCLUDING the test tid (else the
    // present-key update succeeds and no cause-2 fires).
    skip_case(
        &obj,
        &exe,
        off,
        "seq-full",
        wire::SKIP_SEQ_FULL,
        wire::LOSS_SEQ_FULL,
        |loaded| {
            for i in 0..4096u32 {
                let k = 0x4000_0000u32.wrapping_add(i);
                write_cell(
                    loaded,
                    "SEQ",
                    &k.to_le_bytes(),
                    &wire::make_seq(0, 0).to_le_bytes(),
                );
            }
        },
        |loaded, tid| {
            assert_eq!(
                wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                (0, wire::RCOUNT_STATE_IDLE),
                "seq-full: RCOUNT IDLE|0"
            );
            assert_eq!(
                wire::split_seq(read_u64_cell(loaded, "SEQ", tid).expect("SEQ kept")),
                (0, 0),
                "seq-full: no mint on insert-fail"
            );
        },
    );
    // Legacy cookie (cause 6): surgical entry re-attach with cookie
    // 7 behind the control (loader-bug shape, fail-fast before any
    // map read).
    {
        let mut attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let pid = std::process::id();
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let (calls, _, _) = drain(loaded);
        assert_eq!(
            call_parts(&calls[0]),
            (false, wire::SKIP_ADMITTED),
            "cookie: control"
        );
        let bad = ossl_bpf_sys::link_create_uprobe_multi(
            loaded.progs["member_entry"].as_raw_fd(),
            &exe,
            &[off],
            &[7],
            std::process::id(),
        )
        .expect("re-attach entry with cookie 7");
        drop(std::mem::replace(&mut attached.entry, bad));
        let (attempt0, calls0) = (
            read_attempt(loaded),
            read_percpu(loaded, "CALLS", OP, false),
        );
        fire(OP as i32, 1);
        let (calls, algs, rows) = drain(loaded);
        assert_eq!(calls.len(), 1);
        assert_eq!(call_parts(&calls[0]), (false, wire::SKIP_ENTRY_COOKIE));
        assert_eq!(calls[0].seq, 0);
        assert_eq!(read_attempt(loaded) - attempt0, 1, "cookie: ATTEMPTΔ==1");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false) - calls0, 0);
        assert_loss_only(loaded, wire::LOSS_ENTRY_COOKIE, 1, "cookie");
        assert!(algs.is_empty() && rows.is_empty(), "cookie: member silence");
        assert!(read_pending_cell(loaded, pid, tid).is_none());
        assert!(read_scan_cell(loaded, tid).is_none());
        assert_eq!(
            wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
            (0, wire::RCOUNT_STATE_IDLE)
        );
    }
    // CTRL-invalid ×3 (cause 7): EXPECTED 0, EXPECTED 513, epoch 0.
    for (tag, ctrl) in [
        ("ctrl-exp0", wire::ctrl_value(0, 1, gov)),
        ("ctrl-exp513", wire::ctrl_value(513, 1, gov)),
        ("ctrl-epoch0", wire::ctrl_value(512, 0, gov)),
    ] {
        skip_case(
            &obj,
            &exe,
            off,
            tag,
            wire::SKIP_CTRL_UNPROGRAMMED,
            wire::LOSS_CTRL_UNPROGRAMMED,
            |loaded| {
                osslscope::loader::program_ctrl(&loaded.maps, &ctrl).expect("program bad CTRL");
            },
            |loaded, tid| {
                assert_eq!(
                    wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                    (0, wire::RCOUNT_STATE_IDLE),
                    "{tag}: RCOUNT IDLE|0"
                );
            },
        );
    }
}

/// C birth-pending (cause 1): the skip fires on a FRESH
/// UNREGISTERED worker tid (no BIRTH row) after a same-attach
/// main-tid admit-control. The skip creates nothing (RCOUNT/SEQ
/// stay missing for the worker tid — the SKIP path never creates
/// cells); main-tid cells are untouched.
#[test]
#[ignore]
fn c_skip_birth_pending() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    let (attempt0, calls0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
    );
    // Unregistered worker: fires WITHOUT a BIRTH row.
    let wtid = std::thread::scope(|s| {
        s.spawn(|| {
            let w = self_tid();
            fire(OP as i32, 1);
            w
        })
        .join()
        .expect("worker join")
    });
    assert_ne!(wtid, tid, "worker tid is fresh");
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1, "skip CALL");
    assert_eq!(calls[0].tid, wtid);
    assert_eq!(call_parts(&calls[0]), (false, wire::SKIP_BIRTH_PENDING));
    assert_eq!(calls[0].seq, 0);
    assert_eq!(read_attempt(loaded) - attempt0, 1, "ATTEMPTΔ==1");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        0,
        "CALLSΔ==0"
    );
    assert_loss_only(loaded, wire::LOSS_BIRTH_PENDING, 1, "birth-pending");
    assert!(algs.is_empty() && rows.is_empty(), "skip member silence");
    // Skip creates nothing for the worker tid...
    assert!(read_pending_cell(loaded, pid, wtid).is_none());
    assert!(read_scan_cell(loaded, wtid).is_none());
    assert!(
        read_u64_cell(loaded, "RCOUNT", wtid).is_none(),
        "RCOUNT never created"
    );
    assert!(
        read_u64_cell(loaded, "SEQ", wtid).is_none(),
        "SEQ never created"
    );
    // ...and touches nothing of the control's cells.
    assert!(
        read_pending_cell(loaded, pid, tid).is_some(),
        "control PENDING kept"
    );
    assert!(read_scan_cell(loaded, tid).is_some(), "control SCAN kept");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("control RCOUNT")),
        (0, wire::RCOUNT_STATE_ACTIVE),
        "control RCOUNT still ACTIVE"
    );
}

/// C nested-hint via TRUE same-thread recursion (depth-1
/// self-calling target — hint bit + supersede, no map
/// programming). Persists in D (§10.2). Entry-side asserts only
/// (the C interim PENDING overwrite duplicates outer evidence —
/// asserted nonzero for vitality, never attributed).
#[test]
#[ignore]
fn c_nested_hint() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = symbol_off("osslscope_member_query_nested");
    let ctrl =
        osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL");
    let attached = attach_with_ctrl(&obj, &exe, off, &ctrl);
    let loaded = &attached.loaded;
    let mut state = BirthState::new();
    let tid = self_tid();
    register(loaded, &mut state, &[tid]);
    let slots = vec![
        SlotSpec::live("MNH0", 100, vec![(61, 0x6100)]),
        SlotSpec::live("MNH1", 101, vec![(62, 0x6101)]),
    ];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire_nested(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 2, "outer + inner CALLs");
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "outer: no hint"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&calls[1]),
        (true, wire::SKIP_ADMITTED),
        "inner: NESTED-HINT"
    );
    assert_eq!(calls[1].seq, wire::make_seq(0, 1));
    assert!(calls.iter().all(|c| c.tid == tid && c.op == OP));
    // Supersede: the inner record stands (SCAN seq 1, PENDING inner).
    let rec = read_scan_cell(loaded, tid).expect("SCAN stands");
    assert_eq!(rec.seq, wire::make_seq(0, 1), "inner record supersedes");
    assert_eq!(rec.expected, 512);
    assert_eq!(rec.epoch, 1);
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT")),
        (0, wire::RCOUNT_STATE_ACTIVE)
    );
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2, "both counted");
    assert_eq!(read_attempt(loaded), 2);
    assert_loss_zero(loaded);
    // Vitality only: both returns walked (PENDING present at both —
    // the interim overwrite duplicates inner evidence; C never
    // attributes member evidence).
    assert!(!algs.is_empty() && !rows.is_empty(), "both returns walked");
}

/// C nested-skip (§7C exact): prime 64B via two undrained NULL
/// queries on a sacrificial tid, baseline counters after priming,
/// execute outer/inner on a fresh tid at T=88 — outer admits at
/// 64 (CALL → 96), inner pressure-skips. The nested skip deletes
/// the outer record (tainted absence for item 4 — the ring CALLs
/// retain the superseded invocation). Replaced by nested-skip-D
/// (§10.2: IDLE|0 → IDLE|1024 + RET/guard absence).
#[test]
#[ignore]
fn c_nested_skip() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = symbol_off("osslscope_member_query_nested");
    let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, 88));
    let loaded = &attached.loaded;
    let mut state = BirthState::new();
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst); // NULL throughout
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Prime 64B on a sacrificial tid (two admitted NULL CALLs).
    let sacrificial = fire_on_worker(loaded, OP as i32, 2);
    assert_ne!(sacrificial, tid);
    register(loaded, &mut state, &[tid]);
    let (attempt0, calls0, loss0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
        read_percpu(loaded, "LOSS", wire::LOSS_RING_PRESSURE, false),
    );
    fire_nested(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    // Filter to the leg tid (priming CALLs still occupy the ring).
    let mine: Vec<_> = calls.iter().filter(|c| c.tid == tid).collect();
    assert_eq!(mine.len(), 2, "outer-CALL + inner-CALL");
    assert_eq!(
        call_parts(mine[0]),
        (false, wire::SKIP_ADMITTED),
        "outer admits at 64"
    );
    assert_eq!(mine[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(mine[1]),
        (false, wire::SKIP_RING_PRESSURE),
        "inner pressure-skips at 96"
    );
    assert_eq!(mine[1].seq, 0);
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        1,
        "CALLS Δ1"
    );
    assert_eq!(read_attempt(loaded) - attempt0, 2, "ATTEMPT Δ2");
    assert_eq!(
        read_percpu(loaded, "LOSS", wire::LOSS_RING_PRESSURE, false) - loss0,
        1,
        "LOSS23 Δ1"
    );
    assert!(algs.is_empty() && rows.is_empty(), "zero member emissions");
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (0, wire::RCOUNT_STATE_IDLE),
        "RCOUNT IDLE|0 (v1 members don't bump)"
    );
    assert!(
        read_pending_cell(loaded, pid, tid).is_none(),
        "PENDING absent (C-only)"
    );
}

/// C stale-complete trio via programmed cells (persists in D —
/// §10.2): IDLE+record → silent recovery (no LOSS, no hint);
/// ACTIVE+expected → LOSS 31 + repair; SCAN-without-RCOUNT →
/// LOSS 31 + repair.
#[test]
#[ignore]
fn c_stale_trio() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let stale = wire::ScanRec {
        op: 7,
        ns_ptr: 0x5555,
        seq: wire::make_seq(0, 0),
        expected: 512,
        _pad: 0,
        epoch: 1,
    };
    // (a) IDLE+record: silent recovery (already counted at retire —
    // recounting would double-count).
    write_cell(loaded, "SCAN", &tid.to_le_bytes(), &scan_bytes(&stale));
    write_cell(
        loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(0, wire::RCOUNT_STATE_IDLE).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(a): no hint"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    assert_loss_zero(loaded);
    assert_eq!(
        read_scan_cell(loaded, tid).expect("SCAN republished").op,
        OP as u64,
        "(a): fresh record published"
    );
    // (b) ACTIVE+expected: loud repair (LOSS 31).
    write_cell(loaded, "SCAN", &tid.to_le_bytes(), &scan_bytes(&stale));
    write_cell(
        loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(512, wire::RCOUNT_STATE_ACTIVE).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(b): no hint"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 1));
    assert_loss_only(loaded, wire::LOSS_STALE_REPAIRED, 1, "(b)");
    // (c) SCAN-without-RCOUNT: loud repair (needs an RCOUNT-less
    // tid — a registered-but-unfired worker).
    let (wtid_tx, wtid_rx) = std::sync::mpsc::channel::<u32>();
    let go = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            let w = self_tid();
            wtid_tx.send(w).expect("report tid");
            go.wait();
            fire(OP as i32, 1);
        });
        let w = wtid_rx.recv().expect("worker tid");
        assert_ne!(w, tid);
        write_cell(loaded, "BIRTH", &w.to_le_bytes(), &0u16.to_le_bytes());
        assert!(
            read_u64_cell(loaded, "RCOUNT", w).is_none(),
            "(c): RCOUNT-less setup"
        );
        write_cell(loaded, "SCAN", &w.to_le_bytes(), &scan_bytes(&stale));
        go.wait();
    });
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(c): no hint"
    );
    assert_eq!(
        calls[0].seq,
        wire::make_seq(0, 0),
        "(c): worker SEQ starts at 0"
    );
    assert_loss_only(loaded, wire::LOSS_STALE_REPAIRED, 2, "(c): second LOSS31");
}

/// C programmed-epoch churn (persists in D — §10.2): a record
/// whose epoch mismatches live CTRL churns (LOSS 25, never a hint).
#[test]
#[ignore]
fn c_churn_programmed() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let churned = wire::ScanRec {
        op: 7,
        ns_ptr: 0x5555,
        seq: wire::make_seq(0, 0),
        expected: 512,
        _pad: 0,
        epoch: 99, // Mismatches live epoch 1.
    };
    write_cell(loaded, "SCAN", &tid.to_le_bytes(), &scan_bytes(&churned));
    write_cell(
        loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(0, wire::RCOUNT_STATE_ACTIVE).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "churn: never a hint"
    );
    assert_loss_only(loaded, wire::LOSS_SCAN_CHURNED, 1, "churn");
    let rec = read_scan_cell(loaded, tid).expect("fresh record published");
    assert_eq!((rec.epoch, rec.expected), (1, 512), "fresh epoch frozen");
}

/// Pipe-blocked churn driver (C/D contrast pair — §10.2): a worker
/// blocks inside its first query (entry admitted, return pending);
/// the harness bumps epoch behind it (and, for detach-C, detaches
/// member 7 first). C has no retirement, so the record survives →
/// the worker's second take churns (LOSS 25). Entry-observable
/// half only.
fn run_blocked_churn(obj: &std::path::Path, detach_member_7: bool, tag: &str) {
    use osslscope_ebpf_common as wire;
    let exe = own_exe_cstr();
    let off = symbol_off("osslscope_member_query_blocking");
    let mut attached = attach_chunk(obj, &exe, off);
    let loaded = &attached.loaded;
    let pid = std::process::id();
    let slots = vec![SlotSpec::live("MCH0", 100, vec![(63, 0x6300)])];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Pipe + latch for the one blocked call.
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    BLOCK_PIPE_RD.store(fds[0], Ordering::SeqCst);
    BLOCK_ENTERED.store(0, Ordering::SeqCst);
    BLOCK_ONCE.store(1, Ordering::SeqCst);
    let (wtid_tx, wtid_rx) = std::sync::mpsc::channel::<u32>();
    let go = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            let w = self_tid();
            wtid_tx.send(w).expect("report tid");
            go.wait();
            fire_blocking(OP as i32); // Call 1: blocks (latch armed).
            fire_blocking(OP as i32); // Call 2: passes (latch spent).
        });
        let w = wtid_rx.recv().expect("worker tid");
        write_cell(loaded, "BIRTH", &w.to_le_bytes(), &0u16.to_le_bytes());
        go.wait();
        // Bounded wait for the worker to block inside call 1 (fail,
        // never hang).
        let mut entered = false;
        for _ in 0..10_000 {
            if BLOCK_ENTERED.load(Ordering::SeqCst) == 1 {
                entered = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(entered, "{tag}: worker blocked inside call 1");
        if detach_member_7 {
            // Detach member 7 behind the blocked return (placeholder
            // keeps the Vec dense; dropping the old link detaches).
            let devnull: OwnedFd = std::fs::File::open("/dev/null").expect("devnull").into();
            drop(std::mem::replace(&mut attached.members[7], devnull));
        }
        osslscope::loader::program_ctrl(&loaded.maps, &wire::ctrl_value(512, 2, 1 << 20))
            .expect("bump epoch to 2");
        let one = [1u8; 1];
        assert_eq!(
            unsafe { libc::write(fds[1], one.as_ptr() as *const libc::c_void, 1) },
            1,
            "{tag}: release worker"
        );
    });
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 2, "{tag}: two worker CALLs");
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "{tag}: call 1 admits"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&calls[1]),
        (false, wire::SKIP_ADMITTED),
        "{tag}: call 2 admits, no hint"
    );
    assert_eq!(calls[1].seq, wire::make_seq(0, 1));
    // The record survived call 1's return (C: no retirement — and
    // with member 7 detached, nothing could complete it) → call 2's
    // take churns on the epoch bump.
    assert_loss_only(loaded, wire::LOSS_SCAN_CHURNED, 1, tag);
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        2,
        "{tag}: both counted"
    );
    // Call 1's return walked (member vitality — the walk happened
    // behind the epoch bump but before call 2's take).
    assert!(
        !algs.is_empty() && !rows.is_empty(),
        "{tag}: call-1 return walked"
    );
    if detach_member_7 {
        assert!(
            algs.iter().all(|a| a.idx != 7) && rows.iter().all(|r| r.idx != 7),
            "{tag}: detached member_7 silent"
        );
    }
    // Post-churn record: fresh epoch frozen.
    let rec = read_scan_cell(loaded, calls[1].tid).expect("fresh record");
    assert_eq!(rec.epoch, 2, "{tag}: fresh epoch frozen");
    assert!(
        read_pending_cell(loaded, pid, calls[1].tid).is_some(),
        "{tag}: PENDING (C-only)"
    );
}

/// C detach-churn: member 7 detached behind a pipe-blocked
/// invocation + epoch bump → record survives → next take churns.
/// (C/D contrast pair — replaced by detach-D + bump-blocked-clean-retire.)
#[test]
#[ignore]
fn c_churn_detach() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    run_blocked_churn(&obj, true, "detach-C");
}

/// C bump-behind-blocked: epoch bump behind a blocked invocation
/// (no detach, no retirement exists) → next take churns.
/// (C/D contrast pair.)
#[test]
#[ignore]
fn c_churn_bump_blocked() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    run_blocked_churn(&obj, false, "bump-C");
}

/// C LRU eviction (persists in D — §10.2): SCAN record + RCOUNT
/// ACTIVE programmed for self, 2048 foreign inserts (pinned-CPU —
/// self-eviction is structural by capacity, not order),
/// read-back-absent loud check, then the take reports LOSS 20
/// (NULL + ACTIVE ⟺ evicted).
#[test]
#[ignore]
fn c_eviction() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Admit-control: a live record + ACTIVE counter for self.
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    assert!(
        read_scan_cell(loaded, tid).is_some(),
        "control SCAN present"
    );
    // 2048 foreign SCAN inserts evict self's record (1024-cap LRU).
    for i in 0..2048u32 {
        let k = 0x4000_0000u32.wrapping_add(i);
        let rec = wire::ScanRec {
            op: 7,
            ns_ptr: 0,
            seq: wire::make_seq(0, 0),
            expected: 512,
            _pad: 0,
            epoch: 1,
        };
        write_cell(loaded, "SCAN", &k.to_le_bytes(), &scan_bytes(&rec));
    }
    assert!(
        read_scan_cell(loaded, tid).is_none(),
        "self SCAN evicted (loud check — fails if the kernel disagrees)"
    );
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (0, wire::RCOUNT_STATE_ACTIVE),
        "RCOUNT (plain HASH) survives"
    );
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "post-evict admits, no hint"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 1));
    assert_loss_only(loaded, wire::LOSS_SCAN_EVICTED, 1, "eviction");
}

/// C saturation boundary (RE-PIN in D — §10.2: + RET on the MAX
/// admit, none on the cause-9 skip): SEQ programmed MAX-1 → admit
/// MAX, again → cause 9/LOSS 33 (fail-closed, never reissue).
/// NULL queries.
#[test]
#[ignore]
fn c_saturation() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    write_cell(
        loaded,
        "SEQ",
        &tid.to_le_bytes(),
        &wire::make_seq(0, wire::SEQ_CTR_MAX - 1).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "MAX admits"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, wire::SEQ_CTR_MAX));
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1);
    assert_loss_zero(loaded);
    let (attempt0, calls0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
    );
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_SEQ_SATURATED),
        "reissue skips"
    );
    assert_eq!(calls[0].seq, 0);
    assert_eq!(read_attempt(loaded) - attempt0, 1, "ATTEMPTΔ==1");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        0,
        "CALLSΔ==0"
    );
    assert_loss_only(loaded, wire::LOSS_SEQ_SATURATED, 1, "saturation");
    assert!(algs.is_empty() && rows.is_empty(), "skip member silence");
    assert!(
        read_pending_cell(loaded, pid, tid).is_none(),
        "PENDING absent (C-only)"
    );
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (0, wire::RCOUNT_STATE_IDLE)
    );
}

/// C sequential-quiet pair (RE-PIN in D — §10.2: between-count
/// IDLE|0 in C, IDLE|512 in D): admit → skip → admit — no hint
/// (the middle skip stands in for D's retirement), SCAN absent +
/// IDLE between.
#[test]
#[ignore]
fn c_sequential_pair() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let gov = 1u64 << 20;
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "first admits"
    );
    // Middle skip (SKIP_ALL toggle): clears SCAN + IDLEs.
    let off_ctrl = wire::CtrlValue {
        expected: 512,
        skip_all: 1,
        _pad: [0; 3],
        epoch: 1,
        governor: gov,
    };
    osslscope::loader::program_ctrl(&loaded.maps, &off_ctrl).expect("SKIP_ALL on");
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ALL),
        "middle skips"
    );
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent between");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (0, wire::RCOUNT_STATE_IDLE),
        "between-count IDLE|0 in C"
    );
    // Re-admit: quiet (no hint — nothing unretired stands).
    osslscope::loader::program_ctrl(&loaded.maps, &wire::ctrl_value(512, 1, gov))
        .expect("SKIP_ALL off");
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "re-admit quiet (no hint)"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 1));
    assert_loss_only(loaded, wire::LOSS_SKIP_ALL, 1, "sequential");
}

/// C store-fail (persists in D — §10.2): RCOUNT 4096-fake-filled
/// EXCLUDING the test tid → cause 8/LOSS 32 (synthetic invariant
/// violation — logically unreachable by the §2 subset invariant,
/// documented).
#[test]
#[ignore]
fn c_store_fail() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let pid = std::process::id();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    // Fake-fill RCOUNT to 4096 WITHOUT the test tid (its row
    // exists from the control — fill around it: 4095 fakes +
    // control row = full for the test tid's step-11 create... but
    // the control row EXISTS, so step 11 would UPDATE it (no
    // fail). Delete-free maps can't drop it — instead, IDLE it
    // via a skip, then fill the REST: step 11 still updates the
    // existing row. TRUE store-fail needs a tid WITHOUT a row:
    // use a fresh worker tid for the failing fire.
    for i in 0..4095u32 {
        let k = 0x4000_0000u32.wrapping_add(i);
        // Skip the test tid if it collides (it won't — tid < 2^22
        // on any lane; the assert pins the assumption).
        assert_ne!(k, tid, "fake range excludes the test tid");
        write_cell(
            loaded,
            "RCOUNT",
            &k.to_le_bytes(),
            &wire::make_rcount(0, wire::RCOUNT_STATE_IDLE).to_le_bytes(),
        );
    }
    // Fresh worker tid: BIRTH registered, NO RCOUNT row. Its
    // step-11 create fails (map full) → cause 8. SEQ has room
    // (only control + worker keys).
    let (wtid_tx, wtid_rx) = std::sync::mpsc::channel::<u32>();
    let go = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            let w = self_tid();
            wtid_tx.send(w).expect("report tid");
            go.wait();
            fire(OP as i32, 1);
        });
        let w = wtid_rx.recv().expect("worker tid");
        assert_ne!(w, tid);
        write_cell(loaded, "BIRTH", &w.to_le_bytes(), &0u16.to_le_bytes());
        assert!(
            read_u64_cell(loaded, "RCOUNT", w).is_none(),
            "worker RCOUNT-less setup"
        );
        go.wait();
    });
    // Absolute counters (control fired once: CALLS 1, ATTEMPT 1
    // before the worker's single skip).
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1, "worker skip CALL");
    assert_eq!(call_parts(&calls[0]), (false, wire::SKIP_ADMIT_STORE_FAIL));
    assert_eq!(calls[0].seq, 0);
    assert_eq!(read_attempt(loaded), 2, "ATTEMPT control + skip");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        1,
        "CALLS control only"
    );
    assert_loss_only(loaded, wire::LOSS_ADMIT_STORE_FAIL, 1, "store-fail");
    assert!(algs.is_empty() && rows.is_empty(), "skip member silence");
    let w = calls[0].tid;
    assert!(
        read_pending_cell(loaded, pid, w).is_none(),
        "PENDING absent"
    );
    assert!(read_scan_cell(loaded, w).is_none(), "SCAN absent");
    assert!(
        read_u64_cell(loaded, "RCOUNT", w).is_none(),
        "RCOUNT still missing"
    );
    // SEQ minted (the failure is post-SEQ): the id is spent.
    assert_eq!(
        wire::split_seq(read_u64_cell(loaded, "SEQ", w).expect("SEQ minted")),
        (0, 0),
        "spent seq (never observed)"
    );
}

/// C pending-capacity (C-ONLY — §10.2, map gone in D): 1024
/// distinct tids admit-and-retain with no skips between, then a
/// 1025th distinct tid → cause 8/LOSS32 with SEQ at 1025 of 4096
/// (normal E2BIG fill, no fault injection); a same-tid re-admit on
/// a RETAINED key still succeeds (BPF_ANY update — proving
/// full-for-new-keys).
#[test]
#[ignore]
fn c_pending_capacity() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    FIXTURE_ARRAY.store(0, Ordering::SeqCst); // NULL: entry-side only
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Worker A stays PARKED (alive, tid pinned) for the re-admit.
    let (a_tx, a_rx) = std::sync::mpsc::channel::<u32>();
    let phase1 = std::sync::Barrier::new(2);
    let phase2 = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            let a = self_tid();
            write_cell(loaded, "BIRTH", &a.to_le_bytes(), &0u16.to_le_bytes());
            fire(OP as i32, 1); // Admit #1 (retained).
            a_tx.send(a).expect("report A");
            phase1.wait();
            phase2.wait();
            fire(OP as i32, 1); // Re-admit (BPF_ANY update on retained key).
        });
        let a = a_rx.recv().expect("worker A tid");
        phase1.wait(); // A's PENDING retained before the fill.
        // Workers 2..=1024: 1023 sequential admit-and-retain.
        for _ in 2..=1024u32 {
            std::thread::scope(|s2| {
                s2.spawn(|| {
                    let w = self_tid();
                    assert_ne!(w, a, "fill tids distinct from A");
                    write_cell(loaded, "BIRTH", &w.to_le_bytes(), &0u16.to_le_bytes());
                    fire(OP as i32, 1);
                })
                .join()
                .expect("fill worker join");
            });
        }
        // 1025th distinct tid → PENDING-write E2BIG → cause 8.
        let b = std::thread::scope(|s2| {
            s2.spawn(|| {
                let w = self_tid();
                write_cell(loaded, "BIRTH", &w.to_le_bytes(), &0u16.to_le_bytes());
                fire(OP as i32, 1);
                w
            })
            .join()
            .expect("B join")
        });
        assert_ne!(b, a, "1025th tid distinct");
        phase2.wait(); // Release A's re-admit.
    });
    let (calls, algs, rows) = drain(loaded);
    // 1024 admits + B skip + A re-admit = 1026 CALLs.
    assert_eq!(calls.len(), 1026, "1024 + skip + re-admit");
    assert!(algs.is_empty() && rows.is_empty(), "NULL: member silence");
    let (admits, skips): (Vec<&_>, Vec<&_>) = calls
        .iter()
        .partition(|c| call_parts(c).1 == wire::SKIP_ADMITTED);
    assert_eq!(admits.len(), 1025, "1024 + re-admit admitted");
    assert_eq!(skips.len(), 1, "exactly the 1025th skips");
    assert_eq!(call_parts(skips[0]), (false, wire::SKIP_ADMIT_STORE_FAIL));
    assert_eq!(skips[0].seq, 0);
    assert_loss_only(loaded, wire::LOSS_ADMIT_STORE_FAIL, 1, "pending-capacity");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        1025,
        "CALLS = admits"
    );
    assert_eq!(read_attempt(loaded), 1026, "ATTEMPT = all hits");
}

/// C governor quantum (REPLACED by quantum-D — §10.2): NULL
/// queries no-drain at T ∈ {719, 720, 721} — 32B quantum:
/// 23/23/23 admitted (fire k sees occ (k−1)×32: fire 23 sees 704 ≤
/// T and admits → occ 736; fire 24 sees 736 > T and skips — for
/// all three T). The skip index pins the byte-exact math: wrong
/// quanta RED the transition. CALLS-read between fires, single
/// drain at end.
#[test]
#[ignore]
fn c_governor_quantum() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    for t in [719u64, 720, 721] {
        let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, t));
        let loaded = &attached.loaded;
        let mut state = BirthState::new();
        let tid = self_tid();
        register(loaded, &mut state, &[tid]);
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        // Fire one at a time, reading CALLS between fires: the
        // admit→skip transition index pins the quantum math live.
        let mut admitted = 0u32;
        for k in 1..=30u32 {
            fire(OP as i32, 1);
            let calls_now = read_percpu(loaded, "CALLS", OP, false);
            if calls_now == admitted as u64 + 1 {
                admitted += 1;
            }
            assert_eq!(
                read_attempt(loaded),
                k as u64,
                "T={t}: ATTEMPT tracks fires (k={k})"
            );
        }
        assert_eq!(admitted, 23, "T={t}: 23 admitted (32B quantum)");
        let (calls, algs, rows) = drain(loaded);
        assert_eq!(calls.len(), 30, "T={t}: 30 CALLs, single end drain");
        assert!(algs.is_empty() && rows.is_empty(), "T={t}: NULL silence");
        let (adm, skp): (Vec<&_>, Vec<&_>) = calls
            .iter()
            .partition(|c| call_parts(c).1 == wire::SKIP_ADMITTED);
        assert_eq!(adm.len(), 23, "T={t}: drain agrees (23 admits)");
        assert_eq!(skp.len(), 7, "T={t}: 7 skips");
        assert!(
            skp.iter()
                .all(|c| call_parts(c) == (false, wire::SKIP_RING_PRESSURE) && c.seq == 0),
            "T={t}: all skips cause 4, seq 0"
        );
        // C convention: first admit silent, later admits hint (no
        // retirement between sequential admits).
        assert!(!call_parts(adm[0]).0, "T={t}: first admit silent");
        assert!(
            adm[1..].iter().all(|c| call_parts(c).0),
            "T={t}: later admits hint (C convention)"
        );
        assert_loss_only(loaded, wire::LOSS_RING_PRESSURE, 7, &format!("quantum-{t}"));
    }
}

/// C pressure rewritten (RE-PIN in D — §10.2: second skip at occ
/// 80): GOVERNOR=0 extreme — first admits at occ 0, second skips
/// at 32. Clarifies GOVERNOR 0 is VALID (validation rejects only
/// EXPECTED 0/>512 and epoch 0).
#[test]
#[ignore]
fn c_pressure_gov0() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, 0));
    let loaded = &attached.loaded;
    let mut state = BirthState::new();
    let tid = self_tid();
    register(loaded, &mut state, &[tid]);
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 2);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "occ 0 admits"
    );
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&calls[1]),
        (false, wire::SKIP_RING_PRESSURE),
        "occ 32 skips"
    );
    assert_eq!(calls[1].seq, 0);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1, "CALLS Δ1");
    assert_eq!(read_attempt(loaded), 2, "ATTEMPT Δ2");
    assert_loss_only(loaded, wire::LOSS_RING_PRESSURE, 1, "gov0");
    assert!(algs.is_empty() && rows.is_empty(), "skip member silence");
    assert!(read_scan_cell(loaded, tid).is_none(), "skip cleared SCAN");
}

// ===== item-3 subtask-E registry live legs (R18 §5/§7E; lane only) =====

/// E spawn-storm: N workers fire BEFORE registration (SKIP cause
/// 1 — registration-gap honesty), the harness polls + programs,
/// then all fire again (admit). Per-worker BIRTH readback + CALL
/// sequences; counts/causes only, never joins.
#[test]
#[ignore]
fn e_registry_spawn_storm() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_with_ctrl(
        &obj,
        &exe,
        off,
        &osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL"),
    );
    let loaded = &attached.loaded;
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    const N: usize = 8;
    let tids = std::sync::Mutex::new(Vec::<u32>::new());
    let b1 = std::sync::Barrier::new(N + 1);
    let b2 = std::sync::Barrier::new(N + 1);
    std::thread::scope(|s| {
        for _ in 0..N {
            s.spawn(|| {
                let w = self_tid();
                tids.lock().expect("tids lock").push(w);
                fire(OP as i32, 1); // Phase 1: unregistered → skip.
                b1.wait();
                b2.wait();
                fire(OP as i32, 1); // Phase 2: registered → admit.
            });
        }
        b1.wait();
        let observed: Vec<u32> = tids.lock().expect("tids lock").clone();
        assert_eq!(observed.len(), N, "N worker tids reported");
        let mut state = BirthState::new();
        let rows = register(loaded, &mut state, &observed);
        assert_eq!(rows.len(), N, "all N program birth 0");
        assert!(rows.iter().all(|(_, b)| *b == 0));
        b2.wait();
    });
    let observed: Vec<u32> = tids.lock().expect("tids lock").clone();
    for w in &observed {
        assert_eq!(
            read_u16_cell(loaded, "BIRTH", *w),
            Some(0),
            "BIRTH[{w}] readback"
        );
    }
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 2 * N, "skip + admit per worker");
    assert!(algs.is_empty() && rows.is_empty(), "NULL silence");
    for w in &observed {
        let mine: Vec<_> = calls.iter().filter(|c| c.tid == *w).collect();
        assert_eq!(mine.len(), 2, "worker {w}: two CALLs");
        assert_eq!(
            call_parts(mine[0]),
            (false, wire::SKIP_BIRTH_PENDING),
            "worker {w}: fire-before-poll SKIPs"
        );
        assert_eq!(mine[0].seq, 0);
        assert_eq!(
            call_parts(mine[1]),
            (false, wire::SKIP_ADMITTED),
            "worker {w}: poll-then-admit"
        );
        assert_eq!(mine[1].seq, wire::make_seq(0, 0));
    }
    assert_loss_only(loaded, wire::LOSS_BIRTH_PENDING, N as u64, "storm");
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), N as u64);
    assert_eq!(read_attempt(loaded), 2 * N as u64);
}

/// E observed reuse: a poll cycle that observes absence then
/// reappearance supersedes (1) → the next take resets SEQ (CALL
/// seq restarts at 0). The registry's observed-set signal is the
/// contract (true kernel tid-reuse timing is out of scope).
#[test]
#[ignore]
fn e_registry_observed_reuse() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let mut state = BirthState::new();
    assert_eq!(register(loaded, &mut state, &[tid]), vec![(tid, 0)]);
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    // Observe absence (poll without the tid), then reappearance.
    assert!(
        register(loaded, &mut state, &[0x7FFF_FFFF])
            .iter()
            .all(|(t, _)| *t != tid)
    );
    assert_eq!(
        register(loaded, &mut state, &[tid]),
        vec![(tid, 1)],
        "supersede to 1"
    );
    assert_eq!(read_u16_cell(loaded, "BIRTH", tid), Some(1));
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "superseded tid admits"
    );
    assert_eq!(
        calls[0].seq,
        wire::make_seq(1, 0),
        "SEQ reset on birth mismatch"
    );
    assert_loss_zero(loaded);
}

/// E unobserved reuse: no poll between fires → the counter
/// continues (seq 1, hint — the C convention), no skip (§5.1 quiet
/// reuse).
#[test]
#[ignore]
fn e_registry_unobserved_reuse() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 2); // No poll between: quiet reuse.
    let (calls, _, _) = drain(loaded);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(calls[1].seq, wire::make_seq(0, 1), "ctr continues");
    assert_eq!(
        call_parts(&calls[1]),
        (true, wire::SKIP_ADMITTED),
        "hint (C convention)"
    );
    assert_loss_zero(loaded);
}

/// E external-child: the TARGET-pid source (R18 sol F11) — a
/// spawned child's tids are observed and registered; self tids
/// never appear (self-pid legs alone would conceal a
/// wrong-process source).
#[test]
#[ignore]
fn e_registry_external_child() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    use osslscope::scan::registry::TidSource as _;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep child");
    let cpid = child.id();
    let src = osslscope::scan::registry::ProcTaskSource::new(cpid);
    let observed = src.tids().expect("child task list");
    assert!(!observed.is_empty(), "child has at least one task");
    assert!(
        !observed.contains(&self_tid()),
        "child set never contains self (wrong-process source would)"
    );
    let mut state = BirthState::new();
    let rows = register(loaded, &mut state, &observed);
    assert_eq!(rows.len(), observed.len());
    for (t, b) in &rows {
        assert_eq!(*b, 0);
        assert_eq!(
            read_u16_cell(loaded, "BIRTH", *t),
            Some(0),
            "BIRTH[{t}] programmed"
        );
    }
    child.kill().expect("kill sleep child");
    let _ = child.wait();
}

/// E live freeze: BIRTH=MAX via the registry PROGRAM path → cause
/// 3/LOSS 19 (the entry freezes the tid — no future admits).
#[test]
#[ignore]
fn e_registry_live_freeze() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_with_ctrl(
        &obj,
        &exe,
        off,
        &osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL"),
    );
    let loaded = &attached.loaded;
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let mut state = BirthState::new();
    assert_eq!(register(loaded, &mut state, &[tid]), vec![(tid, 0)]);
    fire(OP as i32, 1);
    let (calls, _, _) = drain(loaded);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    // Freeze through the registry program path (not a raw write).
    osslscope::scan::registry::program_births(&loaded.maps, &[(tid, wire::BIRTH_FROZEN)])
        .expect("program MAX");
    fire(OP as i32, 1);
    let (calls, algs, rows) = drain(loaded);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        call_parts(&calls[0]),
        (false, wire::SKIP_BIRTH_WRAP),
        "frozen skips"
    );
    assert_loss_only(loaded, wire::LOSS_BIRTH_WRAP, 1, "freeze");
    assert!(algs.is_empty() && rows.is_empty());
}

/// E registry-full: BIRTH 4k-filled → `program_births` errors LOUD
/// (hard error — never silently unregistered).
#[test]
#[ignore]
fn e_registry_full() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_with_ctrl(
        &obj,
        &exe,
        off,
        &osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL"),
    );
    let loaded = &attached.loaded;
    for i in 0..4096u32 {
        let k = 0x4000_0000u32.wrapping_add(i);
        write_cell(loaded, "BIRTH", &k.to_le_bytes(), &0u16.to_le_bytes());
    }
    let err = osslscope::scan::registry::program_births(&loaded.maps, &[(self_tid(), 0)])
        .expect_err("4k-full BIRTH programs LOUD");
    eprintln!("registry-full hard error (expected): {err:#}");
}
