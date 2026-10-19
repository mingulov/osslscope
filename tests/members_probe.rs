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
//! Stage D (P7 item 3, R18): member conversion, T-gate, guard,
//! retire. Every leg attaches through the production path AND
//! registers BIRTH (the entry skips unregistered tids — cause 1).
//! The drain collects CALL/RET/GUARD/ALG/ROW; legs join RET/GUARD
//! to CALLs by (tid,seq), never by position. D retires every
//! admitted return (SCAN absent + RCOUNT IDLE|0), so sequential
//! same-tid admits are QUIET (retirement splits sequential from
//! nested — only TRUE nesting hints). C legs persist per the §10.2
//! split table (PERSIST/RE-PIN/REPLACE); D-only legs cover
//! retire-quiet, order-independence, T-gate, guard, nested-skip-D,
//! detach-stall, bump-absorption, quantum-D, and burst/drop.
//! Priming always uses sacrificial tids. (D PERSIST note: C legs
//! keep their take-classification asserts identical; retirement
//! end-state + RET/guard-awareness are D's new facts.)

use osslscope::loader::Loaded;
use osslscope::scan::backend::{BackendAction, ScanBackend, drain_trunc_flags};
use osslscope::scan::oracle::{Outcome, PartialReason, TrueT};
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
/// epoch 1, governor = min(4MiB policy, ring/2) — live at the 4MiB
/// policy on the item-7 16MiB ring.
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

/// Drained scan-plane ring: CALL/RET/GUARD/ALG/ROW in ring
/// order. Legs join RET/GUARD to CALLs by (tid,seq) + kind, never
/// by position (order-independence is a leg, not an assumption).
/// Item 4: ALG/ROW are the scan-keyed kinds (10/11 — (tid,seq)
/// joinable); the harvest kinds (4/5) never appear here.
struct ScanDrain {
    calls: Vec<osslscope_ebpf_common::ScanCallEvent>,
    rets: Vec<osslscope_ebpf_common::ScanRetEvent>,
    guards: Vec<osslscope_ebpf_common::GuardEvent>,
    algs: Vec<osslscope_ebpf_common::ScanAlgEvent>,
    rows: Vec<osslscope_ebpf_common::ScanRowEvent>,
}

/// Drain the member EVENTS ring to parsed events. Drops nothing
/// silently: unknown kinds fail loud (items 3–5 emit
/// CALL/RET/GUARD/SCAN-ALG/SCAN-ROW).
fn drain(loaded: &Loaded) -> ScanDrain {
    use aya::maps::{Map, MapData, RingBuf};
    use osslscope_ebpf_common as wire;
    let fd = loaded.maps["EVENTS"].try_clone().expect("clone EVENTS");
    let data = MapData::from_fd(fd).expect("EVENTS mapdata");
    let map = Map::from_map_data(data).expect("EVENTS map");
    let mut ring = RingBuf::try_from(map).expect("EVENTS ringbuf");
    let mut d = ScanDrain {
        calls: Vec::new(),
        rets: Vec::new(),
        guards: Vec::new(),
        algs: Vec::new(),
        rows: Vec::new(),
    };
    while let Some(item) = ring.next() {
        let b = item.to_vec();
        assert!(b.len() >= 4, "short ring item: {} bytes", b.len());
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        match kind {
            wire::KIND_SCAN_CALL => d
                .calls
                .push(wire::parse_scan_call_event(&b).expect("parse CALL")),
            wire::KIND_SCAN_RET => d
                .rets
                .push(wire::parse_scan_ret_event(&b).expect("parse RET")),
            wire::KIND_GUARD => d
                .guards
                .push(wire::parse_guard_event(&b).expect("parse GUARD")),
            wire::KIND_SCAN_ALG => d
                .algs
                .push(wire::parse_scan_alg_event(&b).expect("parse SCAN-ALG")),
            wire::KIND_SCAN_ROW => d
                .rows
                .push(wire::parse_scan_row_event(&b).expect("parse SCAN-ROW")),
            k => panic!("unexpected ring kind {k} (items 3-5 emit CALL/RET/GUARD/10/11 only)"),
        }
    }
    d
}

/// Split CALL flags to (nested-hint, cause) (wire vocabulary).
fn call_parts(c: &osslscope_ebpf_common::ScanCallEvent) -> (bool, u8) {
    osslscope_ebpf_common::split_call_flags(c.flags)
}

/// Join one RET to its CALL by (tid,seq): exactly one RET per
/// admitted invocation (D emits RET for every admitted return,
/// EMPTY or not).
fn ret_for(
    rets: &[osslscope_ebpf_common::ScanRetEvent],
    tid: u32,
    seq: u64,
) -> &osslscope_ebpf_common::ScanRetEvent {
    let hits: Vec<_> = rets
        .iter()
        .filter(|r| r.tid == tid && r.seq == seq)
        .collect();
    assert_eq!(hits.len(), 1, "exactly one RET for ({tid},{seq:#x})");
    hits[0]
}

/// Join guards to their CALL by (tid,seq): at most one guard per
/// admitted invocation (member 511 fires at most once per return).
fn guards_for(
    guards: &[osslscope_ebpf_common::GuardEvent],
    tid: u32,
    seq: u64,
) -> Vec<&osslscope_ebpf_common::GuardEvent> {
    let hits: Vec<_> = guards
        .iter()
        .filter(|g| g.tid == tid && g.seq == seq)
        .collect();
    assert!(hits.len() <= 1, "at most one guard for ({tid},{seq:#x})");
    hits
}

/// Assert the retired end state (SCAN absent + RCOUNT IDLE|0) —
/// the D per-return proof (every admitted return retires).
fn assert_retired(loaded: &Loaded, tid: u32, tag: &str) {
    use osslscope_ebpf_common as wire;
    assert!(
        read_scan_cell(loaded, tid).is_none(),
        "{tag}: SCAN absent (retired)"
    );
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (0, wire::RCOUNT_STATE_IDLE),
        "{tag}: RCOUNT IDLE|0"
    );
}

/// D bridge-leg RET assert (live returns): one RET per CALL
/// joined by (tid,seq), all non-EMPTY, guards empty, tid retired.
fn assert_rets_live(
    loaded: &Loaded,
    calls: &[osslscope_ebpf_common::ScanCallEvent],
    rets: &[osslscope_ebpf_common::ScanRetEvent],
    guards: &[osslscope_ebpf_common::GuardEvent],
    tag: &str,
) {
    use osslscope_ebpf_common as wire;
    assert_eq!(rets.len(), calls.len(), "{tag}: one RET per query");
    for c in calls {
        let r = ret_for(rets, c.tid, c.seq);
        assert_eq!(
            (r.kind, r.op, r.flags),
            (wire::KIND_SCAN_RET, OP, 0),
            "{tag}: live RET shape"
        );
    }
    assert!(guards.is_empty(), "{tag}: no guard");
    assert_retired(loaded, self_tid(), tag);
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

/// Per-CPU slot vector for one u32 key (R19 minor-1: the
/// concurrent-leg cross-CPU proof reads slots, not the fold).
fn read_percpu_slots(loaded: &Loaded, name: &str, key: u32) -> Vec<u64> {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps[name].try_clone().expect("clone map");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        if k == key {
            return slots.to_vec();
        }
    }
    Vec::new()
}

/// Folded LOSS[id] read (absent id reads 0).
fn loss_val(loaded: &Loaded, id: u32) -> u64 {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps["LOSS"].try_clone().expect("clone LOSS");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        if k == id {
            return slots.iter().fold(0, |a, &b| a.wrapping_add(b));
        }
    }
    0
}

/// Assert exact LOSS counts for the listed ids and zero for every
/// other id (drop-path reconciliation: named losses exact, no
/// stray loss hides in an unlisted plane).
fn assert_loss_exact(loaded: &Loaded, want: &[(u32, u64)], tag: &str) {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps["LOSS"].try_clone().expect("clone LOSS");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    let mut seen = std::collections::HashSet::new();
    for r in m.iter() {
        let (k, slots) = r.expect("percpu iter");
        let sum: u64 = slots.iter().fold(0, |a, &b| a.wrapping_add(b));
        seen.insert(k);
        match want.iter().find(|(id, _)| *id == k) {
            Some((_, v)) => assert_eq!(sum, *v, "{tag}: LOSS[{k}]"),
            None => assert_eq!(sum, 0, "{tag}: LOSS[{k}] must be zero"),
        }
    }
    for (id, v) in want {
        if !seen.contains(id) {
            assert_eq!(*v, 0, "{tag}: LOSS[{id}] row present");
        }
    }
}

/// Map one unreadable page (PROT_NONE — mapped but faulting) for
/// unreadable-pointee variants. Returns the base address; the
/// caller munmaps (RAII via [`ProtNonePage`]).
fn map_prot_none() -> u64 {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(ptr, libc::MAP_FAILED, "mmap PROT_NONE");
        ptr as u64
    }
}

/// RAII for [`map_prot_none`] (legs must not leak mappings).
struct ProtNonePage(u64);
impl Drop for ProtNonePage {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.0 as *mut libc::c_void, 4096);
        }
    }
}

/// Clear the op's TRUNC cell between sequenced fires (test-phase
/// isolation: the backend never clears — sticky bits accumulate
/// — so the leg resets the map to read each fire's flags
/// exactly). An absent key succeeds (nothing flagged); anything
/// else fails loud. Verified empty after (a failed clear REDs
/// here, never as a misattributed delta downstream).
fn clear_trunc(loaded: &Loaded, tag: &str) {
    use aya::maps::{Map, MapData, PerCpuHashMap};
    let fd = loaded.maps["TRUNC"].try_clone().expect("clone TRUNC");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let mut m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    match m.remove(&OP) {
        Ok(()) => {}
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("{tag}: clear TRUNC: {e}"),
    }
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "{tag}: TRUNC cleared"
    );
}

/// Pace sequenced single-tid fires (the tier-1 bucket bursts 4
/// and refills 40/s — back-to-back fires past the burst skip
/// cause 10, which would masquerade as the behavior under test).
fn pace_fire_gap() {
    std::thread::sleep(std::time::Duration::from_millis(30));
}

/// Two-page mapping whose second page is PROT_NONE, with `ncell`
/// array cells copied to straddle the boundary: cells fully
/// inside page 1 stay readable; a tuple read crossing into page 2
/// faults (BPF probe_read fails the whole read atomically).
/// Returns the array base (page 1 end − `ncell`×32 − 4, so the
/// next cell's 8-byte tuple read spans the boundary); RAII
/// munmaps both pages.
struct StraddleMap {
    ptr: u64,
    page: usize,
}
impl StraddleMap {
    fn build(src_array: u64, ncell: usize) -> (Self, u64) {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let ptr = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(p, libc::MAP_FAILED, "mmap straddle");
            p as u64
        };
        let rc = unsafe {
            libc::mprotect(
                (ptr + page as u64) as *mut libc::c_void,
                page,
                libc::PROT_NONE,
            )
        };
        assert_eq!(rc, 0, "mprotect straddle page 2");
        let base = ptr + page as u64 - (ncell * 32) as u64 - 4;
        unsafe {
            std::ptr::copy_nonoverlapping(src_array as *const u8, base as *mut u8, ncell * 32);
        }
        (Self { ptr, page }, base)
    }
}
impl Drop for StraddleMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, 2 * self.page);
        }
    }
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

/// T_CACHE test writer (harness helper, NOT production — the TRUE-T
/// writer is item 4): inject (T, generation) for an array base.
fn write_tcache(loaded: &Loaded, arr: u64, t: u64, generation: u64) {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&t.to_le_bytes());
    v[8..16].copy_from_slice(&generation.to_le_bytes());
    write_cell(loaded, "T_CACHE", &arr.to_le_bytes(), &v);
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
/// Leg-controlled verdict-store skip (NULL/unreadable-ns_ptr
/// variants): when nonzero, the query target returns the fixture
/// array WITHOUT storing through `no_store` (a store through a
/// NULL/unmapped out-param would crash the leg; the BPF entry
/// still records the raw arg2 — the member reads are what's under
/// test, not the fixture store).
static NS_SKIP_STORE: AtomicI32 = AtomicI32::new(0);

/// query_operation-shaped target: stashes nothing itself (the BPF
/// entry does), returns the leg's fixture array, stamps the leg's
/// lifetime verdict. `#[inline(never)]` + `no_mangle`: the uprobe
/// needs a real symbol, and every leg asserts positive fire
/// evidence, so any inlining/offset miss REDs instead of passing
/// vacuously.
///
/// # Safety
///
/// `no_store` must point to a live writable `c_int` for the call,
/// unless `NS_SKIP_STORE` is set (NULL/unreadable variants — the
/// target never touches it, the BPF entry records the raw arg2).
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn osslscope_member_query(
    _provctx: *mut std::ffi::c_void,
    _op: std::ffi::c_int,
    no_store: *mut std::ffi::c_int,
) -> *const FakeAlg {
    unsafe {
        if NS_SKIP_STORE.load(Ordering::SeqCst) == 0 {
            *no_store = NS_VERDICT.load(Ordering::SeqCst);
        }
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

/// Fire once with an explicit `no_store` out-param (NULL/unreadable
/// variants — the caller sets `NS_SKIP_STORE` first so the target
/// never touches it; the BPF entry records the raw arg2).
fn fire_ns_raw(op: i32, no_store: *mut std::ffi::c_int) {
    // SAFETY: caller upholds the target's contract (live slot or
    // NS_SKIP_STORE set).
    let _rv = unsafe { osslscope_member_query(std::ptr::null_mut(), op, no_store) };
    std::hint::black_box(_rv);
}

/// Fire `n` times paced `gap_ms` apart (bucket-safe flooding: the
/// tier-1 bucket refills 40/s, so 30ms gaps keep every fire
/// admitted — drops come from ring exhaustion, never the bucket).
fn fire_paced(op: i32, n: usize, gap_ms: u64) {
    for i in 0..n {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(gap_ms));
        }
        fire(op, 1);
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

/// Nested-target worker fire (nested legs attach the nested symbol
/// only — an ordinary `fire` hits no probe and primes nothing).
fn fire_nested_on_worker(loaded: &Loaded, op: i32, depth: i32, n: usize) -> u32 {
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let tid = self_tid();
            write_cell(loaded, "BIRTH", &tid.to_le_bytes(), &0u16.to_le_bytes());
            for _ in 0..n {
                fire_nested(op, depth);
            }
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
#[derive(Clone)]
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
    pub fn noimp(name: &str, class: u16) -> SlotSpec {
        SlotSpec {
            name: name.to_string(),
            class,
            dispatch: Vec::new(),
            no_term: false,
            impl_null: true,
        }
    }

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
    /// Total mapped span incl. guard pages (Drop only — `len`
    /// stays the fixture RW span for temp/pageout/pretouch).
    span: usize,
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
        Self::build_padded_guarded(slots, tail, array_slots, 0)
    }

    /// Abort-variant fixture (R21 finding 8): the members walk reads
    /// 513 slot cells (0..=512 × 32B = 16416B) from the array base,
    /// so a bare 1-page munmap leaves slots 128+ at the mercy of the
    /// lane's neighbor mappings (lane-b's readable neighbor emitted
    /// 256 ALGs). Five PROT_NONE guard pages make the post-munmap
    /// neighborhood lane-independent: every slot read aborts.
    pub fn build_abort_isolated(slots: &[SlotSpec]) -> Fixture {
        Self::build_padded_guarded(slots, &[], slots.len() + 1, 5)
    }

    /// Fixture mapping length: the part the leg may munmap (the
    /// guard tail stays PROT_NONE for the fixture's life).
    pub fn mapped_len(&self) -> usize {
        self.len
    }

    fn build_padded_guarded(
        slots: &[SlotSpec],
        tail: &[SlotSpec],
        array_slots: usize,
        guard_pages: usize,
    ) -> Fixture {
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
        let span = len + guard_pages * page;
        let fd = unsafe {
            let cname = std::ffi::CString::new("members_fixture").unwrap();
            let fd = libc::memfd_create(cname.as_ptr(), 0);
            assert!(fd >= 0, "memfd_create failed");
            assert_eq!(libc::ftruncate(fd, len as libc::off_t), 0, "ftruncate");
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                span,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(ptr, libc::MAP_FAILED, "mmap fixture");
            std::ptr::write_bytes(ptr as *mut u8, 0, len);
            if guard_pages > 0 {
                assert_eq!(
                    libc::mprotect(
                        (ptr as *mut u8).add(len) as *mut libc::c_void,
                        guard_pages * page,
                        libc::PROT_NONE,
                    ),
                    0,
                    "mprotect guard tail"
                );
            }
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
            span,
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
            libc::munmap(self.ptr as *mut libc::c_void, self.span);
        }
    }
}

/// R21 finding 8: the abort-variant fixture isolates its own
/// neighborhood — PROT_NONE guard pages after the fixture mapping
/// covering the walker's max reach (slots 0..=512 × 32B), so a
/// 1-page munmap deterministically aborts every slot read on every
/// lane (no readable-neighbor emits). Host-runnable: pure
/// userspace layout, verified against /proc/self/maps.
#[test]
fn abort_fixture_carries_prot_none_guards() {
    let slots = vec![SlotSpec::live("MRQA", 100, vec![(83, 0x8102)])];
    let fx = Fixture::build_abort_isolated(&slots);
    let page = 4096usize;
    assert_eq!(fx.array as usize % page, 0, "array page-aligned");
    let base = fx.array as usize;
    // The walker's farthest target read: slot-512 cell end.
    let reach_end = base + 513 * 32;
    let guard_start = base + fx.mapped_len();
    assert!(
        reach_end <= guard_start + 5 * page,
        "guard span must cover slot 512 (reach_end={reach_end:#x})"
    );
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut guard_seen = false;
    for line in maps.lines() {
        let mut f = line.split_whitespace();
        let (Some(range), Some(perms)) = (f.next(), f.next()) else {
            continue;
        };
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(s), Ok(e)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
            continue;
        };
        if s < guard_start + 5 * page && e > guard_start {
            guard_seen = true;
            assert!(
                perms.starts_with("---"),
                "guard span must be PROT_NONE, found {perms} on {range}"
            );
        }
    }
    assert!(guard_seen, "guard span missing from maps");
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
    assert_eq!(
        loaded.maps.len(),
        15,
        "all member maps created (D 13 + item-5 BUCKET + round-3 TRUNC_SEQ)"
    );
    assert!(
        loaded.maps.contains_key("TRUNC_SEQ"),
        "per-op generation map present"
    );
    assert_eq!(attached.members.len(), 512, "all member links attached");
    let ctrl = osslscope::loader::read_ctrl(&loaded.maps).expect("read CTRL");
    assert_eq!(
        (ctrl.expected, ctrl.skip_all, ctrl.epoch, ctrl.governor),
        (512, 0, 1, 4 << 20),
        "production attach programmed CTRL (item-7 16MiB ring: governor live at 4MiB policy)"
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
    // Fold structure (matches S8's raw pin): member_000 smallest
    // (no T+1 verifier — it always walks — while the middle
    // members carry the T+1 probe incl. its silent-Err arm),
    // member_511 largest (guard eligibility + GUARD event).
    assert!(m000 < *mid_min, "member_000 smallest at xlated level too");
    assert!(m511 > *mid_max, "member_511 largest at xlated level too");
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
/// beyond-T EMPTY are real asserts (v1 has no T-gate — unpadded
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
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, QUERIES, "e7");
    // D: one RET per query joined by (tid,seq), no guard (slot 511
    // zero — cold boundary has no live 511), sequential admits
    // quiet (retired between — D splits sequential from nested).
    assert_eq!(d.rets.len(), QUERIES, "e7-{temp}: one RET per query");
    assert!(d.guards.is_empty(), "e7-{temp}: no guard (slot 511 zero)");
    for (k, c) in d.calls.iter().enumerate() {
        assert!(
            !call_parts(c).0,
            "e7-{temp}: query {k} quiet (retired between)"
        );
        let r = ret_for(&d.rets, c.tid, c.seq);
        assert_eq!((r.kind, r.op, r.flags), (wire::KIND_SCAN_RET, OP, 0));
        assert_eq!(r.arr, fx.array, "e7-{temp}: RET array");
    }
    assert_retired(loaded, self_tid(), "e7");
    let (algs, rows) = (d.algs, d.rows);
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
    // Explicit EMPTY emits: every scan walks all 512 (7 OK + 505
    // EMPTY per query).
    assert_eq!(algs.len(), 512 * QUERIES, "e7-{temp}: 512 × N ALG");
    assert_eq!(
        algs.iter().filter(|a| a.status == wire::ALG_OK).count(),
        7 * QUERIES,
        "e7-{temp}: 7 slots × N OK"
    );
    assert_eq!(
        algs.iter().filter(|a| a.status == wire::ALG_EMPTY).count(),
        505 * QUERIES,
        "e7-{temp}: 505 × N EMPTY"
    );
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
    // Zero tail ⇒ beyond-T EMPTY is a REAL assert here (with
    // explicit emits, a zero slot MUST emit EMPTY — silence would
    // be a hole); the nonzero-tail reach is pinned separately by
    // L3-tail.
    assert!(
        algs.iter()
            .all(|a| a.idx < 7 || a.status == wire::ALG_EMPTY)
            && rows.iter().all(|r| r.idx < 7),
        "e7-{temp}: zero tail emits EMPTY only"
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
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, QUERIES, "e7-cold");
    assert_abort_clean(loaded, &d, QUERIES as u64, "e7-cold");
}

/// Shared read-abort oracle (pageout-cold + munmap-hole).
/// Pageout-cold evicts the whole fixture, so every slot read
/// fails; the munmap-hole unmaps only the live prefix's page while
/// the mapped zero tail reads fine and stays silent (names==0).
/// Either way TRUNC holds WALK_READ alone, the member ring stays
/// empty, the entry still counts (admit-bump precedes the walk),
/// the invocation still retires with its RET (aborts never block
/// retirement), no guard fires (slot 511 unreadable/zero), and
/// nothing is lost.
fn assert_abort_clean(loaded: &Loaded, d: &ScanDrain, n: u64, tag: &str) {
    use osslscope_ebpf_common as wire;
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        wire::TRUNC_WALK_READ,
        "{tag}: abort flags WALK_READ alone"
    );
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "{tag}: aborted members emit nothing"
    );
    assert_eq!(d.rets.len(), n as usize, "{tag}: RETs still present");
    assert!(d.guards.is_empty(), "{tag}: no guard on abort");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        n,
        "{tag}: aborted queries still counted"
    );
    assert_retired(loaded, self_tid(), tag);
    assert_loss_zero(loaded);
}

/// Null queries (rv == 0) stay ALG/ROW-silent but are COUNTED
/// (spec-mandated flip, R18 §6.2/§7C: the entry cannot see rv, so
/// CALLS admit-bumps NULL too) and present RET-EMPTY + retire
/// (D re-pin, §10.2). A positive control fires through the SAME
/// links first: a dead attach would otherwise satisfy every null
/// assert vacuously (T03 demands positive fire evidence per
/// firing leg).
fn run_null(obj: &std::path::Path, exe: &std::ffi::CString, off: u64) {
    use osslscope_ebpf_common as wire;
    let fx = Fixture::build(&e7_slots(), &[]);
    fx.pretouch();
    let attached = attach_chunk(obj, exe, off);
    let loaded = &attached.loaded;
    populate_alg_class(loaded, &fx.classes);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Positive control: one live query proves these links fire.
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, 1, "null-control");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        1,
        "null-leg control: live query counted"
    );
    assert!(
        !d.algs.is_empty() && !d.rows.is_empty(),
        "null-leg control: live query emits"
    );
    assert_eq!(d.rets.len(), 1, "null-leg control: RET");
    assert_retired(loaded, self_tid(), "null-control");
    // Null phase: ALG/ROW silence, but the count advances (the
    // entry cannot see rv — both nulls admitted + counted) and
    // each null presents RET-EMPTY + retires.
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    fire(OP as i32, 2);
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, 2, "null-phase");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "null queries emit no member records"
    );
    assert_eq!(d.rets.len(), 2, "null queries present RET");
    for c in &d.calls {
        let r = ret_for(&d.rets, c.tid, c.seq);
        assert_eq!(r.flags, wire::RET_FLAG_EMPTY, "null marks EMPTY");
        assert_eq!((r.op, r.arr), (OP, 0), "null RET shape");
    }
    assert!(d.guards.is_empty(), "null emits no guard");
    assert_retired(loaded, self_tid(), "null-phase");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        3,
        "null queries counted (control 1 + 2 nulls)"
    );
    assert_loss_zero(loaded);
}

/// L3: empty / one / adjacent-tail / munmap-hole fixtures.
/// Prefix-exact; the tail block PINS cold presence (v1 reach on
/// cold — the T-gate walks without a warm entry) while the
/// L3-tail-warm D leg flips it to absence (T=3 injected). The hole
/// leg proves the read-abort path deterministically on every lane
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
    // Empty: slot 0 emits explicit ALG_EMPTY (×2), EMPTY flagged
    // (member 0 only — other EMPTY slots emit without the flag).
    {
        let fx = Fixture::build_padded(&[], &[], 513);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-empty");
        assert_rets_live(loaded, &calls, &rets, &guards, "l3-empty");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_WALK_EMPTY,
            "empty slot 0 flagged alone"
        );
        assert_eq!(algs.len(), 1024, "512 EMPTY × 2");
        assert!(
            algs.iter().all(|a| a.status == wire::ALG_EMPTY),
            "every slot EMPTY"
        );
        let s0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(s0.len(), 2, "slot-0 EMPTY × 2");
        assert!(rows.is_empty(), "EMPTY dispatches nothing");
        assert_loss_zero(loaded);
    }
    // One: slot 0 exact, EMPTY bit clear.
    {
        let slots = vec![SlotSpec::live("M3A", 100, vec![(31, 0x4300), (32, 0x4301)])];
        // Padded: slot-0 asserts stay exact, past-T deterministic.
        let fx = Fixture::build_padded(&slots, &[], 513);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-one");
        assert_rets_live(loaded, &calls, &rets, &guards, "l3-one");
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
    // Cold presence pin (D: no warm entry → the T-gate walks —
    // prefix exact AND tail present; the warm leg flips to
    // absence).
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
        // Padded: prefix/tail presence asserts stay exact, past-tail
        // deterministic (no heap soup past the planted tail).
        let fx = Fixture::build_padded(&slots, &tail, 513);
        fx.pretouch();
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let mut entries = fx.classes.clone();
        entries.extend(tail_classes);
        populate_alg_class(loaded, &entries);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 2);
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l3-tail");
        assert_rets_live(loaded, &calls, &rets, &guards, "l3-tail");
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
    // Munmap hole: the whole array region (all 512 slots) unmapped
    // ⇒ every slot read aborts: TRUNC_WALK_READ exactly, zero
    // emissions, queries counted. A single-page hole no longer
    // silences the drain (mapped zero slots emit explicit EMPTY),
    // so the hole covers the full array. Same member-side path as
    // swap-cold, but deterministic on every lane (no swap needed).
    // ORDERING: no mmap/malloc may run between the munmap and the
    // end of fire (an allocator mmap could reuse the hole);
    // attach/load/allocations all precede it.
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
        assert_eq!(512 * 32 % page, 0, "array region is page-multiple");
        assert_eq!(
            unsafe { libc::munmap(fx.array as *mut libc::c_void, 512 * 32) },
            0,
            "munmap hole pages"
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
        let d = drain(loaded);
        assert_calls_admitted(&d.calls, 2, "l3-hole");
        assert_abort_clean(loaded, &d, 2, "l3-hole");
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
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4a");
        assert_rets_live(loaded, &calls, &rets, &guards, "l4a");
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
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4b");
        assert_rets_live(loaded, &calls, &rets, &guards, "l4b");
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
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l4c");
        assert_rets_live(loaded, &calls, &rets, &guards, "l4c");
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
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows,
    } = drain(loaded);
    assert_calls_admitted(&calls, 3, "l5");
    assert_rets_live(loaded, &calls, &rets, &guards, "l5");
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
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l6a");
        // D: RETs joined + cold guard (slot 511 live, slot 512
        // term → GUARD EMPTY, no TRUNC) + retire.
        assert_eq!(rets.len(), 2, "l6a: one RET per query");
        for c in &calls {
            let r = ret_for(&rets, c.tid, c.seq);
            assert_eq!((r.kind, r.op, r.flags), (wire::KIND_SCAN_RET, OP, 0));
        }
        assert_eq!(
            guards.len(),
            2,
            "l6a: guard fires per scan (cold, 511 live)"
        );
        for c in &calls {
            let g = guards_for(&guards, c.tid, c.seq);
            assert_eq!(g.len(), 1, "l6a: one guard per scan");
            assert_eq!(
                (g[0].kind, g[0].op, g[0].verdict, g[0].arr),
                (wire::KIND_GUARD, OP, wire::GUARD_EMPTY, fx.array),
                "l6a: GUARD EMPTY joined by (tid,seq)"
            );
        }
        assert_retired(loaded, self_tid(), "l6a");
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
        let ScanDrain {
            calls,
            rets,
            guards,
            algs,
            rows,
        } = drain(loaded);
        assert_calls_admitted(&calls, 2, "l6b");
        // D: RETs joined + cold guard (slot 511 live, slot 512
        // live → GUARD VALID + TRUNC_ALGS, guard-exclusive) +
        // retire.
        assert_eq!(rets.len(), 2, "l6b: one RET per query");
        for c in &calls {
            let r = ret_for(&rets, c.tid, c.seq);
            assert_eq!((r.kind, r.op, r.flags), (wire::KIND_SCAN_RET, OP, 0));
        }
        assert_eq!(
            guards.len(),
            2,
            "l6b: guard fires per scan (cold, 511 live)"
        );
        for c in &calls {
            let g = guards_for(&guards, c.tid, c.seq);
            assert_eq!(g.len(), 1, "l6b: one guard per scan");
            assert_eq!(
                (g[0].kind, g[0].op, g[0].verdict, g[0].arr),
                (wire::KIND_GUARD, OP, wire::GUARD_VALID, fx.array),
                "l6b: GUARD VALID joined by (tid,seq)"
            );
        }
        assert_retired(loaded, self_tid(), "l6b");
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
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows,
    } = drain(loaded);
    assert_calls_admitted(&calls, 2, "l7");
    // D: the mismatched member still bumps + runs the gated
    // epilogue (the scan completes, its slot holes — §6.4) — RETs
    // joined, retired, no guard (slot 511 zero).
    assert_rets_live(loaded, &calls, &rets, &guards, "l7");
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

/// Skip-case driver (R18 §7C 4-tuple, RE-PINNED for D — §10.2):
/// fresh attach, same-attach admit-control (positive fire evidence
/// — T03), drain, baseline, `setup` arms the skip condition, one
/// fire, exact 4-tuple (cause, ATTEMPTΔ==1 single count, CALLSΔ,
/// state-delta) + member silence + loss pin. D re-pins: the
/// PENDING readback is dropped (map gone) and the skip phase
/// asserts no-RET/no-guard member silence; the control asserts its
/// RET + retirement. `check_cells` asserts the case-specific
/// RCOUNT/SEQ end state (uniform SCAN-absent asserts here).
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
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Admit-control: same attach, must admit (else the skip below
    // could be a dead attach, not the armed condition).
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1, "{tag}: control CALL");
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "{tag}: control admits"
    );
    assert_eq!(d.rets.len(), 1, "{tag}: control RET");
    assert_retired(loaded, tid, tag);
    let (attempt0, calls0, loss0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
        read_percpu(loaded, "LOSS", loss, false),
    );
    setup(loaded);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1, "{tag}: skip CALL");
    let c = &d.calls[0];
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
        d.algs.is_empty() && d.rows.is_empty(),
        "{tag}: skip member silence"
    );
    assert!(d.rets.is_empty(), "{tag}: skip emits no RET");
    assert!(d.guards.is_empty(), "{tag}: skip emits no guard");
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
            // D: the control retired (IDLE|0), the skip re-IDLEs,
            // then the skipped return's 512 members bump-if-present
            // (SCAN-miss — silence, but the RCOUNT cell exists).
            assert_eq!(
                wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                (512, wire::RCOUNT_STATE_IDLE),
                "skip-all: RCOUNT IDLE|512 in D"
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
            // D: skipped return's members bump-if-present (IDLE|512).
            assert_eq!(
                wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                (512, wire::RCOUNT_STATE_IDLE),
                "freeze: RCOUNT IDLE|512 in D"
            );
            assert_eq!(
                wire::split_seq(read_u64_cell(loaded, "SEQ", tid).expect("SEQ kept")),
                (0, 0),
                "freeze: SEQ unminted (gate precedes SEQ)"
            );
        },
    );
    // SEQ-full (cause 2): the SEQ gate's BPF_NOEXIST insert fails
    // only for a KEYLESS tid (a present key updates in place even
    // when full — so the same-tid control + fill can never fire
    // cause-2 for the test tid). Standalone block: same-attach
    // main-tid admit-control, then a REGISTERED worker tid (BIRTH
    // row, no SEQ key) fires against the full map (control key +
    // 4095 fill = 4096 = capacity).
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1, "seq-full: control CALL");
        assert_eq!(
            call_parts(&d.calls[0]),
            (false, wire::SKIP_ADMITTED),
            "seq-full: control admits"
        );
        assert_eq!(d.rets.len(), 1, "seq-full: control RET");
        assert_retired(loaded, tid, "seq-full: control");
        // Register the worker tid BEFORE filling (BIRTH row without
        // a SEQ key — the keyless precondition for cause-2). The
        // worker publishes its real tid (no peek-then-respawn —
        // Linux hands a fresh tid per spawn) and waits for
        // registration + fill before firing.
        let barrier = std::sync::Barrier::new(2);
        let wtid_cell = std::sync::atomic::AtomicU32::new(0);
        let base_cell = std::sync::atomic::AtomicU64::new(0);
        let base_calls = std::sync::atomic::AtomicU64::new(0);
        let base_loss = std::sync::atomic::AtomicU64::new(0);
        std::thread::scope(|s| {
            s.spawn(|| {
                wtid_cell.store(self_tid(), Ordering::SeqCst);
                barrier.wait();
                barrier.wait();
                fire(OP as i32, 1);
            });
            barrier.wait();
            let wtid = wtid_cell.load(Ordering::SeqCst);
            assert_ne!(wtid, tid, "seq-full: worker tid is fresh");
            assert!(
                tid < 0x4000_0000 && wtid < 0x4000_0000,
                "seq-full: fill keys exclude both tids"
            );
            {
                let mut state = BirthState::new();
                register(loaded, &mut state, &[wtid]);
            }
            for i in 0..4095u32 {
                let k = 0x4000_0000u32.wrapping_add(i);
                write_cell(
                    loaded,
                    "SEQ",
                    &k.to_le_bytes(),
                    &wire::make_seq(0, 0).to_le_bytes(),
                );
            }
            base_cell.store(read_attempt(loaded), Ordering::SeqCst);
            base_calls.store(read_percpu(loaded, "CALLS", OP, false), Ordering::SeqCst);
            base_loss.store(
                read_percpu(loaded, "LOSS", wire::LOSS_SEQ_FULL, false),
                Ordering::SeqCst,
            );
            barrier.wait();
        });
        let wtid = wtid_cell.load(Ordering::SeqCst);
        let (attempt0, calls0, loss0) = (
            base_cell.load(Ordering::SeqCst),
            base_calls.load(Ordering::SeqCst),
            base_loss.load(Ordering::SeqCst),
        );
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1, "seq-full: skip CALL");
        assert_eq!(d.calls[0].tid, wtid, "seq-full: skip CALL tid");
        assert_eq!(
            call_parts(&d.calls[0]),
            (false, wire::SKIP_SEQ_FULL),
            "seq-full: skip cause"
        );
        assert_eq!(d.calls[0].seq, 0, "seq-full: skips carry seq 0");
        assert_eq!(
            read_attempt(loaded) - attempt0,
            1,
            "seq-full: ATTEMPTΔ==1 (single count)"
        );
        assert_eq!(
            read_percpu(loaded, "CALLS", OP, false) - calls0,
            0,
            "seq-full: CALLSΔ==0"
        );
        assert_eq!(
            read_percpu(loaded, "LOSS", wire::LOSS_SEQ_FULL, false) - loss0,
            1,
            "seq-full: LOSSΔ==1"
        );
        assert!(
            d.algs.is_empty() && d.rows.is_empty(),
            "seq-full: skip member silence"
        );
        assert!(d.rets.is_empty(), "seq-full: skip emits no RET");
        assert!(d.guards.is_empty(), "seq-full: skip emits no guard");
        assert!(
            read_scan_cell(loaded, wtid).is_none(),
            "seq-full: SCAN absent"
        );
        // The skip creates nothing for the keyless worker tid (the
        // SKIP path never creates cells; bump-if-present misses)...
        assert!(
            read_u64_cell(loaded, "RCOUNT", wtid).is_none(),
            "seq-full: worker RCOUNT never created"
        );
        assert!(
            read_u64_cell(loaded, "SEQ", wtid).is_none(),
            "seq-full: no mint on insert-fail"
        );
        // ...and the control's retired cells are untouched.
        assert_retired(loaded, tid, "seq-full: control");
    }
    // Legacy cookie (cause 6): surgical entry re-attach with cookie
    // 7 behind the control (loader-bug shape, fail-fast before any
    // map read).
    {
        let mut attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(
            call_parts(&d.calls[0]),
            (false, wire::SKIP_ADMITTED),
            "cookie: control"
        );
        assert_eq!(d.rets.len(), 1, "cookie: control RET");
        assert_retired(loaded, tid, "cookie");
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
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(call_parts(&d.calls[0]), (false, wire::SKIP_ENTRY_COOKIE));
        assert_eq!(d.calls[0].seq, 0);
        assert_eq!(read_attempt(loaded) - attempt0, 1, "cookie: ATTEMPTΔ==1");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false) - calls0, 0);
        assert_loss_only(loaded, wire::LOSS_ENTRY_COOKIE, 1, "cookie");
        assert!(
            d.algs.is_empty() && d.rows.is_empty(),
            "cookie: member silence"
        );
        assert!(d.rets.is_empty(), "cookie: skip emits no RET");
        assert!(d.guards.is_empty(), "cookie: skip emits no guard");
        assert!(read_scan_cell(loaded, tid).is_none());
        // D: skipped return's members bump-if-present (IDLE|512).
        assert_eq!(
            wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
            (512, wire::RCOUNT_STATE_IDLE),
            "cookie: RCOUNT IDLE|512 in D"
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
                // D: skipped return's members bump-if-present (IDLE|512).
                assert_eq!(
                    wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
                    (512, wire::RCOUNT_STATE_IDLE),
                    "{tag}: RCOUNT IDLE|512 in D"
                );
            },
        );
    }
}

/// C birth-pending (cause 1), RE-PINNED for D: the skip fires on
/// a FRESH UNREGISTERED worker tid (no BIRTH row) after a
/// same-attach main-tid admit-control. The skip creates nothing
/// (RCOUNT/SEQ stay missing for the worker tid — the SKIP path
/// never creates cells) and emits no RET/guard; the control
/// retired.
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
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    assert_eq!(d.rets.len(), 1, "control RET");
    assert_retired(loaded, tid, "control");
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1, "skip CALL");
    assert_eq!(d.calls[0].tid, wtid);
    assert_eq!(call_parts(&d.calls[0]), (false, wire::SKIP_BIRTH_PENDING));
    assert_eq!(d.calls[0].seq, 0);
    assert_eq!(read_attempt(loaded) - attempt0, 1, "ATTEMPTΔ==1");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        0,
        "CALLSΔ==0"
    );
    assert_loss_only(loaded, wire::LOSS_BIRTH_PENDING, 1, "birth-pending");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "skip member silence"
    );
    assert!(d.rets.is_empty(), "skip emits no RET");
    assert!(d.guards.is_empty(), "skip emits no guard");
    // Skip creates nothing for the worker tid...
    assert!(read_scan_cell(loaded, wtid).is_none());
    assert!(
        read_u64_cell(loaded, "RCOUNT", wtid).is_none(),
        "RCOUNT never created"
    );
    assert!(
        read_u64_cell(loaded, "SEQ", wtid).is_none(),
        "SEQ never created"
    );
    // ...and the control's retired cells are untouched.
    assert_retired(loaded, tid, "control");
}

/// C nested-hint via TRUE same-thread recursion (depth-1
/// self-calling target — hint bit + supersede, no map
/// programming). Persists in D (§10.2): the CALL/hint asserts are
/// identical; D adds the retirement consequence (inner return
/// retires — RCOUNT IDLE|0 + SCAN delete — then the outer
/// return's 512 members bump-if-present to IDLE|512 while their
/// SCAN-miss stays silent, so inner evidence stands alone and is
/// attributable). Padded table: member evidence is deterministic
/// (unpadded past-T reads heap soup).
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
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire_nested(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 2, "outer + inner CALLs");
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "outer: no hint"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&d.calls[1]),
        (true, wire::SKIP_ADMITTED),
        "inner: NESTED-HINT"
    );
    assert_eq!(d.calls[1].seq, wire::make_seq(0, 1));
    assert!(d.calls.iter().all(|c| c.tid == tid && c.op == OP));
    // D: the inner return retires (its 512 members reach expected)
    // while the outer return SCAN-misses (inner evidence stands
    // alone — attributable in D, unlike C's interim duplicate).
    assert_eq!(d.rets.len(), 1, "inner RET only (outer SCAN-misses)");
    let r = ret_for(&d.rets, tid, wire::make_seq(0, 1));
    assert_eq!((r.kind, r.op, r.flags), (wire::KIND_SCAN_RET, OP, 0));
    assert_eq!(r.arr, fx.array, "RET array");
    assert!(d.guards.is_empty(), "no guard (slot 511 zero)");
    assert!(read_scan_cell(loaded, tid).is_none(), "inner retired");
    // Inner walk bumps 0→512, then the last member's epilogue
    // retires (IDLE|0 + SCAN delete); the outer return's 512
    // members bump-if-present (IDLE|0→IDLE|512) while their
    // SCAN-miss emits nothing.
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT")),
        (512, wire::RCOUNT_STATE_IDLE),
        "retire-then-bump end state (IDLE|512)"
    );
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2, "both counted");
    assert_eq!(read_attempt(loaded), 2);
    assert_loss_zero(loaded);
    // Inner evidence stands alone: exactly one cold walk of the
    // padded table (2 OK + 510 EMPTY, outer silent — SCAN-miss).
    assert_eq!(d.algs.len(), 512, "inner walked once");
    assert_eq!(
        d.algs.iter().filter(|a| a.status == wire::ALG_OK).count(),
        2,
        "the 2 live slots"
    );
    assert_eq!(
        d.algs
            .iter()
            .filter(|a| a.status == wire::ALG_EMPTY)
            .count(),
        510,
        "the zero tail"
    );
    assert_eq!(d.rows.len(), 2);
    assert!(d.algs.iter().all(|a| a.arr == fx.array));
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(a): no hint"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_loss_zero(loaded);
    // The fresh record published at entry, then retired at return
    // (NULL: EMPTY RET + retire — D's new facts).
    assert_eq!(d.rets.len(), 1, "(a): RET");
    assert_retired(loaded, tid, "(a)");
    // (b) ACTIVE+expected: loud repair (LOSS 31).
    write_cell(loaded, "SCAN", &tid.to_le_bytes(), &scan_bytes(&stale));
    write_cell(
        loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(512, wire::RCOUNT_STATE_ACTIVE).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(b): no hint"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 1));
    assert_loss_only(loaded, wire::LOSS_STALE_REPAIRED, 1, "(b)");
    assert_eq!(d.rets.len(), 1, "(b): RET");
    assert_retired(loaded, tid, "(b)");
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "(c): no hint"
    );
    assert_eq!(
        d.calls[0].seq,
        wire::make_seq(0, 0),
        "(c): worker SEQ starts at 0"
    );
    assert_loss_only(loaded, wire::LOSS_STALE_REPAIRED, 2, "(c): second LOSS31");
    assert_eq!(d.rets.len(), 1, "(c): RET");
    assert_retired(loaded, d.calls[0].tid, "(c)");
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "churn: never a hint"
    );
    assert_loss_only(loaded, wire::LOSS_SCAN_CHURNED, 1, "churn");
    // Fresh epoch frozen at entry, retired at return (NULL: EMPTY
    // RET — D's new facts).
    assert_eq!(d.rets.len(), 1, "churn: RET");
    assert_retired(loaded, tid, "churn");
}

/// C LRU eviction (persists in D — §10.2): SCAN record + RCOUNT
/// ACTIVE programmed for self, 2048 foreign inserts (pinned-CPU —
/// self-eviction is structural by capacity, not order),
/// read-back-absent loud check, then the take reports LOSS 20
/// (NULL + ACTIVE ⟺ evicted). D re-pin: the record is programmed
/// (a control's return would retire it), so the loud readback +
/// the admitting fire are the positive evidence.
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
    // Program a live record + ACTIVE counter for self (a control
    // fire's return would retire it in D).
    let mine = wire::ScanRec {
        op: 7,
        ns_ptr: 0,
        seq: wire::make_seq(0, 0),
        expected: 512,
        _pad: 0,
        epoch: 1,
    };
    write_cell(loaded, "SCAN", &tid.to_le_bytes(), &scan_bytes(&mine));
    write_cell(
        loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(0, wire::RCOUNT_STATE_ACTIVE).to_le_bytes(),
    );
    assert!(
        read_scan_cell(loaded, tid).is_some(),
        "programmed SCAN present"
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "post-evict admits, no hint"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_loss_only(loaded, wire::LOSS_SCAN_EVICTED, 1, "eviction");
    assert_eq!(d.rets.len(), 1, "eviction: RET");
    assert_retired(loaded, tid, "eviction");
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
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    write_cell(
        loaded,
        "SEQ",
        &tid.to_le_bytes(),
        &wire::make_seq(0, wire::SEQ_CTR_MAX - 1).to_le_bytes(),
    );
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "MAX admits"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, wire::SEQ_CTR_MAX));
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1);
    assert_loss_zero(loaded);
    // D re-pin: RET (EMPTY — NULL) on the MAX admit + retire.
    assert_eq!(d.rets.len(), 1, "MAX admit RET");
    let r = ret_for(&d.rets, tid, wire::make_seq(0, wire::SEQ_CTR_MAX));
    assert_eq!(r.flags, wire::RET_FLAG_EMPTY, "NULL marks EMPTY");
    assert_retired(loaded, tid, "saturation");
    let (attempt0, calls0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
    );
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_SEQ_SATURATED),
        "reissue skips"
    );
    assert_eq!(d.calls[0].seq, 0);
    assert_eq!(read_attempt(loaded) - attempt0, 1, "ATTEMPTΔ==1");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false) - calls0,
        0,
        "CALLSΔ==0"
    );
    assert_loss_only(loaded, wire::LOSS_SEQ_SATURATED, 1, "saturation");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "skip member silence"
    );
    assert!(d.rets.is_empty(), "cause-9 emits no RET");
    assert!(d.guards.is_empty(), "cause-9 emits no guard");
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (512, wire::RCOUNT_STATE_IDLE),
        "skipped return bumps-if-present (IDLE|512)"
    );
}

/// C sequential-quiet pair (RE-PINNED in D — §10.2:
/// between-count IDLE|512, not C's IDLE|0 — the skipped return's
/// members bump-if-present while gated out of work): admit → skip
/// → admit — no hint, SCAN absent + IDLE between, RETs on the
/// admits only.
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
    let d = drain(loaded);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "first admits"
    );
    assert_eq!(d.rets.len(), 1, "first RET");
    assert_retired(loaded, tid, "first");
    // Middle skip (SKIP_ALL toggle): clears SCAN + IDLEs; the
    // skipped return's members bump-if-present (IDLE|512).
    let off_ctrl = wire::CtrlValue {
        expected: 512,
        skip_all: 1,
        _pad: [0; 3],
        epoch: 1,
        governor: gov,
    };
    osslscope::loader::program_ctrl(&loaded.maps, &off_ctrl).expect("SKIP_ALL on");
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ALL),
        "middle skips"
    );
    assert!(d.rets.is_empty(), "skip emits no RET");
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent between");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (512, wire::RCOUNT_STATE_IDLE),
        "between-count IDLE|512 in D"
    );
    // Re-admit: quiet (no hint — nothing unretired stands).
    osslscope::loader::program_ctrl(&loaded.maps, &wire::ctrl_value(512, 1, gov))
        .expect("SKIP_ALL off");
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "re-admit quiet (no hint)"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 1));
    assert_eq!(d.rets.len(), 1, "re-admit RET");
    assert_retired(loaded, tid, "re-admit");
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
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    assert_eq!(d.rets.len(), 1, "control RET");
    assert_retired(loaded, tid, "control");
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1, "worker skip CALL");
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMIT_STORE_FAIL)
    );
    assert_eq!(d.calls[0].seq, 0);
    assert_eq!(read_attempt(loaded), 2, "ATTEMPT control + skip");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        1,
        "CALLS control only"
    );
    assert_loss_only(loaded, wire::LOSS_ADMIT_STORE_FAIL, 1, "store-fail");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "skip member silence"
    );
    assert!(d.rets.is_empty(), "cause-8 emits no RET");
    assert!(d.guards.is_empty(), "cause-8 emits no guard");
    let w = d.calls[0].tid;
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 2 * N, "skip + admit per worker");
    assert!(d.algs.is_empty() && d.rows.is_empty(), "NULL silence");
    assert_eq!(d.rets.len(), N, "one RET per admit (skips emit none)");
    assert!(d.guards.is_empty(), "no guards (NULL)");
    for w in &observed {
        let mine: Vec<_> = d.calls.iter().filter(|c| c.tid == *w).collect();
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
        ret_for(&d.rets, *w, wire::make_seq(0, 0));
        assert_retired(loaded, *w, "storm");
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
    let d = drain(loaded);
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(d.rets.len(), 1, "first RET");
    assert_retired(loaded, tid, "observed");
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "superseded tid admits"
    );
    assert_eq!(
        d.calls[0].seq,
        wire::make_seq(1, 0),
        "SEQ reset on birth mismatch"
    );
    assert_eq!(d.rets.len(), 1, "second RET");
    assert_retired(loaded, tid, "observed");
    assert_loss_zero(loaded);
}

/// E unobserved reuse (D: retirement splits sequential from
/// nested — the second admit is QUIET, not hinted): no poll
/// between fires → the counter continues (seq 1), no skip (§5.1
/// quiet reuse), RETs on both.
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
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 2); // No poll between: quiet reuse.
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 2);
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(d.calls[1].seq, wire::make_seq(0, 1), "ctr continues");
    assert_eq!(
        call_parts(&d.calls[1]),
        (false, wire::SKIP_ADMITTED),
        "quiet (retired between — D splits sequential from nested)"
    );
    assert_eq!(d.rets.len(), 2, "RETs on both");
    assert_retired(loaded, tid, "unobserved");
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
    let d = drain(loaded);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "control admits"
    );
    assert_eq!(d.rets.len(), 1, "control RET");
    assert_retired(loaded, tid, "freeze");
    // Freeze through the registry program path (not a raw write).
    osslscope::scan::registry::program_births(&loaded.maps, &[(tid, wire::BIRTH_FROZEN)])
        .expect("program MAX");
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_BIRTH_WRAP),
        "frozen skips"
    );
    assert_loss_only(loaded, wire::LOSS_BIRTH_WRAP, 1, "freeze");
    assert!(d.algs.is_empty() && d.rows.is_empty());
    assert!(d.rets.is_empty(), "freeze emits no RET");
    assert!(d.guards.is_empty(), "freeze emits no guard");
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

// ===== stage-D legs (R18 §7D/§10.2; lane only) =====

/// D retire-quiet pair (REPLACES admit-shape — §10.2): exact
/// outputs + SCAN absent + RCOUNT IDLE|0 after return; a second
/// invocation is quiet (no hint — nothing unretired stands).
/// Variants: clean, whole-array-abort (RET still presented +
/// retire — aborts never block retirement), NOIMP@3 (flag +
/// retire).
#[test]
#[ignore]
fn d_retire_quiet() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // Clean: live E2, two quiet sequential invocations.
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let slots = vec![
            SlotSpec::live("MRQ0", 100, vec![(81, 0x8100)]),
            SlotSpec::live("MRQ1", 101, vec![(82, 0x8101)]),
        ];
        // Padded: member evidence is deterministic (unpadded
        // past-T reads names/blob bytes + unmapped faults — soup
        // to the 128-member cliff, never exact).
        let fx = Fixture::build_padded(&slots, &[], 513);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(call_parts(&d.calls[0]), (false, wire::SKIP_ADMITTED));
        assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
        let r = ret_for(&d.rets, tid, wire::make_seq(0, 0));
        assert_eq!(
            (r.kind, r.op, r.flags, r.arr),
            (wire::KIND_SCAN_RET, OP, 0, fx.array)
        );
        assert_eq!(r.generation, 0, "GEN uninstalled → 0-stamped");
        assert_eq!(d.algs.len(), 512, "exact ALG outputs");
        assert_eq!(
            d.algs.iter().filter(|a| a.status == wire::ALG_OK).count(),
            2,
            "the 2 live slots"
        );
        assert_eq!(
            d.algs
                .iter()
                .filter(|a| a.status == wire::ALG_EMPTY)
                .count(),
            510,
            "the zero tail"
        );
        assert_eq!(d.rows.len(), 2, "exact ROW outputs");
        assert!(d.guards.is_empty(), "no guard (slot 511 zero)");
        assert_retired(loaded, tid, "retire-quiet");
        assert_loss_zero(loaded);
        // Second invocation: quiet (retired between).
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(
            call_parts(&d.calls[0]),
            (false, wire::SKIP_ADMITTED),
            "second invocation quiet"
        );
        assert_eq!(d.calls[0].seq, wire::make_seq(0, 1));
        assert_eq!(d.rets.len(), 1);
        assert_retired(loaded, tid, "retire-quiet-2");
        assert_loss_zero(loaded);
    }
    // Whole-array abort: RET still presented + retire.
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let slots = vec![SlotSpec::live("MRQA", 100, vec![(83, 0x8102)])];
        // Neighbor-isolated (R21 finding 8): without guards, slots
        // 128+ read the lane's neighbor mappings post-munmap.
        let fx = Fixture::build_abort_isolated(&slots);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert!(!d.algs.is_empty(), "abort variant: live control emits");
        assert_retired(loaded, tid, "abort-control");
        // Clear-between (test-phase isolation): the control's
        // unpadded soup may flag TRUNC bits — the abort query's
        // WALK_READ-alone pin needs a clean baseline.
        clear_trunc(loaded, "abort-control");
        // Unmap the array page: every slot read aborts (slot 0
        // included) — RET must still present. The PROT_NONE guard
        // tail (never unmapped) keeps slots 128+ aborting
        // deterministically on every lane (R21 finding 8).
        let page = 4096usize;
        assert_eq!(fx.array as usize % page, 0, "array page-aligned");
        let rc = unsafe { libc::munmap(fx.array as *mut libc::c_void, fx.mapped_len()) };
        assert_eq!(rc, 0, "munmap array page");
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1, "abort query admits");
        assert_eq!(d.rets.len(), 1, "RET presented despite slot-0 abort");
        let r = ret_for(&d.rets, tid, wire::make_seq(0, 1));
        assert_eq!(r.flags, 0, "non-NULL return is not EMPTY");
        assert!(
            d.algs.is_empty() && d.rows.is_empty(),
            "aborts emit nothing"
        );
        assert!(d.guards.is_empty(), "no guard (slot 511 unreadable)");
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_WALK_READ,
            "abort flags WALK_READ alone"
        );
        assert_retired(loaded, tid, "abort-retires");
        assert_loss_zero(loaded);
    }
    // NOIMP@3: flag + retire (eligibility ≠ walkability's cousin —
    // NOIMP records and falls through to the epilogue).
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let slots = vec![
            SlotSpec::live("MRQN0", 100, vec![(84, 0x8103)]),
            SlotSpec::live("MRQN1", 101, vec![(85, 0x8104)]),
            SlotSpec::live("MRQN2", 102, vec![(86, 0x8105)]),
            SlotSpec::noimp("MRQN3", 103),
        ];
        // Padded: the NOIMP slot emits its explicit ALG_NOIMP
        // record (eligibility ≠ walkability — NOIMP records and
        // falls through to the epilogue).
        let fx = Fixture::build_padded(&slots, &[], 513);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(d.algs.len(), 512, "3 OK + NOIMP + 508 EMPTY");
        assert_eq!(
            d.algs.iter().filter(|a| a.status == wire::ALG_OK).count(),
            3,
            "the 3 live slots"
        );
        let noimp: Vec<_> = d
            .algs
            .iter()
            .filter(|a| a.status == wire::ALG_NOIMP)
            .collect();
        assert_eq!(noimp.len(), 1, "NOIMP slot emits its ALG");
        assert_eq!(noimp[0].idx, 3);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_WALK_NOIMP,
            "NOIMP flags alone"
        );
        assert_eq!(d.rets.len(), 1, "NOIMP query RETs");
        assert_retired(loaded, tid, "noimp-retires");
        assert_loss_zero(loaded);
    }
}

/// D member-0-last (order-independence): identical outputs under
/// two different member fire orders. Production attach order fires
/// members in one sequence; re-attaching member 0 moves it.
/// Proof shape: the ALG idx-sequences DIFFER (order changed —
/// observed, so the leg fails loud if fire order ever stops
/// depending on attach order) while the evidence SETS + RET shape
/// + retirement are IDENTICAL (order-independent).
#[test]
#[ignore]
fn d_member_0_last() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let mut attached = attach_chunk(&obj, &exe, off);
    let slots = vec![
        SlotSpec::live("MMZ0", 100, vec![(91, 0x9100)]),
        SlotSpec::live("MMZ1", 101, vec![(92, 0x9101)]),
    ];
    // Padded: both runs walk the identical deterministic table
    // (unpadded past-T reads heap soup to the 128-member cliff).
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    populate_alg_class(&attached.loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Run 1: production attach order.
    fire(OP as i32, 1);
    let d1 = drain(&attached.loaded);
    let seq1: Vec<u64> = d1.algs.iter().map(|a| a.idx).collect();
    assert_eq!(d1.calls.len(), 1);
    assert_eq!(d1.rets.len(), 1);
    // Re-attach member 0 (same cookie, fresh link → moved in fire
    // order), then run 2.
    let m0 = ossl_bpf_sys::link_create_uretprobe_multi(
        attached.loaded.progs["member_000"].as_raw_fd(),
        &exe,
        &[off],
        &[0],
        std::process::id(),
    )
    .expect("re-attach member_0");
    drop(std::mem::replace(&mut attached.members[0], m0));
    fire(OP as i32, 1);
    let d2 = drain(&attached.loaded);
    let seq2: Vec<u64> = d2.algs.iter().map(|a| a.idx).collect();
    assert_ne!(seq1, seq2, "fire order changed (else the leg is vacuous)");
    // Identical outputs: evidence sets, RET shape, retirement.
    let mut set1: Vec<(u64, u16)> = d1.algs.iter().map(|a| (a.idx, a.class)).collect();
    let mut set2: Vec<(u64, u16)> = d2.algs.iter().map(|a| (a.idx, a.class)).collect();
    set1.sort_unstable();
    set2.sort_unstable();
    assert_eq!(set1, set2, "evidence sets identical");
    assert_eq!(set1.len(), 512, "full cold walk both runs");
    assert_eq!(&set1[..2], &[(0, 100), (1, 101)], "the 2 live slots");
    let tail_idx: Vec<u64> = set1[2..].iter().map(|(idx, _)| *idx).collect();
    assert_eq!(
        tail_idx,
        (2..512u64).collect::<Vec<_>>(),
        "the zero tail rides along"
    );
    assert_eq!(d2.calls.len(), 1);
    assert_eq!(d2.rets.len(), 1, "RET identical");
    assert_eq!(d2.rets[0].flags, d1.rets[0].flags);
    assert_eq!(d2.rets[0].arr, d1.rets[0].arr);
    assert_retired(&attached.loaded, self_tid(), "order");
    assert_loss_zero(&attached.loaded);
    // Quiet sequential (retired between — both runs).
    assert!(!call_parts(&d1.calls[0]).0);
    assert!(!call_parts(&d2.calls[0]).0);
}

/// D L3-tail-warm absence (T=3 injected — the T-gate narrows
/// the walk; prefix intact): member 4 (T+1) cold-walks the LIVE
/// tail slot (growth evidence — the cache claims T=3 but slot 4
/// is live, so silence would hide growth); members 5+ stay
/// silent despite LIVE memory (a read would emit — absence
/// proves no firing — the T+1 verdict covers them); member 3
/// WALKS (j ≤ T). The bridge l3-tail block is the cold twin
/// (presence on cold).
#[test]
#[ignore]
fn d_l3_tail_warm() {
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
    let slots: Vec<SlotSpec> = (0..3u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDW{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    let tail: Vec<SlotSpec> = (0..3u32)
        .map(|t| {
            SlotSpec::live(
                &format!("MDWT{t}"),
                200 + t as u16,
                vec![(900 + t, 0x9900 + t as u64)],
            )
        })
        .collect();
    let mut entries: Vec<(String, u16)> = slots.iter().map(|s| (s.name.clone(), s.class)).collect();
    entries.extend(tail.iter().map(|s| (s.name.clone(), s.class)));
    let fx = Fixture::build(&slots, &tail);
    fx.pretouch();
    populate_alg_class(loaded, &entries);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Inject T=3 (gen 0 = live GEN — warm). Pointee is zero, so
    // members 5+ skip-silent; member 3 (j == T) walks; member 4
    // (T+1) cold-walks the live tail slot (growth evidence).
    write_tcache(loaded, fx.array, 3, 0);
    fire(OP as i32, 2);
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows,
    } = drain(loaded);
    assert_calls_admitted(&calls, 2, "tail-warm");
    assert_eq!(rets.len(), 2, "RETs joined");
    for c in &calls {
        ret_for(&rets, c.tid, c.seq);
    }
    assert!(guards.is_empty(), "warm T=3 ≠ 512 → no guard");
    // Prefix + member 3 exact (3 OK + terminator EMPTY).
    for j in 0..3u64 {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 2, "slot {j} walked (j < T)");
        assert!(got.iter().all(|a| a.status == wire::ALG_OK), "slot {j} OK");
        assert_eq!(
            rows.iter().filter(|r| r.idx == j).count(),
            2,
            "slot {j} rows"
        );
    }
    let t3: Vec<_> = algs.iter().filter(|a| a.idx == 3).collect();
    assert_eq!(t3.len(), 2, "slot 3 walked (j == T)");
    assert!(
        t3.iter().all(|a| a.status == wire::ALG_EMPTY),
        "slot 3 EMPTY"
    );
    // Member 4 (T+1) cold-walks the live tail slot (growth
    // evidence — silence here would hide growth past T).
    let g4: Vec<_> = algs.iter().filter(|a| a.idx == 4).collect();
    assert_eq!(g4.len(), 2, "T+1 walks live slot 4");
    assert!(g4.iter().all(|a| a.status == wire::ALG_OK), "slot 4 OK");
    assert_eq!(
        rows.iter().filter(|r| r.idx == 4).count(),
        2,
        "slot 4 rows (growth dispatch walked)"
    );
    // Members 5+ never fired (absence despite live memory — the
    // T+1 verdict covers them).
    assert!(
        algs.iter().all(|a| a.idx <= 4) && rows.iter().all(|r| r.idx <= 4),
        "members 5+ never fired (absence despite live memory)"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "warm skip + T+1 walk leave TRUNC clean"
    );
    assert_retired(loaded, tid, "tail-warm");
    assert_loss_zero(loaded);
}

/// D terminator control at j == T (+READ contrast): member AT T
/// must still READ (j > T skips — a j ≥ T gate would skip it).
/// Two cells, one attach (warm T=3, verdict 0, drain between):
/// NAME — slot 3's names pointer is poisoned (unmapped) while
/// its tuple stays readable, so member 3 attempts the name read
/// and fails it → TRUNC_WALK_NAME + ALG_UNREADABLE for idx 3
/// (proving the read); READ — a second array whose slot-3 tuple
/// read faults while 0..2 stay readable (page-straddle layout),
/// so member 3 aborts SILENT (no ALG record — the contrast with
/// the NAME cell's explicit record) with TRUNC_WALK_READ alone.
/// Member 4 (T+1) cold-walks the live slot in the NAME cell
/// (growth evidence) and aborts silent in the READ cell (same
/// READ flag, no record); members 5+ skip-silent in both cells
/// (warm + zero verdict).
#[test]
#[ignore]
fn d_terminator_control() {
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
    let slots: Vec<SlotSpec> = (0..6u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDT{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    // Poison slot 3's names pointer (tuple stays readable — imp
    // live — so member 3 attempts the name read and fails it).
    unsafe {
        ((fx.array + 3 * 32) as *mut u64).write(0x1234_5678_9abc_def0);
    }
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    write_tcache(loaded, fx.array, 3, 0);
    // NAME cell.
    fire(OP as i32, 1);
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows,
    } = drain(loaded);
    assert_calls_admitted(&calls, 1, "term-name");
    assert_eq!(rets.len(), 1, "RET joined");
    ret_for(&rets, calls[0].tid, calls[0].seq);
    assert!(guards.is_empty(), "warm T=3 ≠ 512 → no guard");
    // Member 3 READ (j == T walks): UNREADABLE record, not silence.
    let idx3: Vec<_> = algs.iter().filter(|a| a.idx == 3).collect();
    assert_eq!(idx3.len(), 1, "member 3 read (j == T walks)");
    assert_eq!(idx3[0].status, wire::ALG_UNREADABLE);
    // Member 4 (T+1) cold-walks the live slot (growth evidence);
    // members 5+ skipped (live slot 5 never read).
    let idx4: Vec<_> = algs.iter().filter(|a| a.idx == 4).collect();
    assert_eq!(idx4.len(), 1, "T+1 walks live slot 4");
    assert_eq!(idx4[0].status, wire::ALG_OK);
    assert_eq!(
        rows.iter().filter(|r| r.idx == 4).count(),
        1,
        "slot 4 row (growth dispatch walked)"
    );
    assert!(
        algs.iter().all(|a| a.idx <= 4) && rows.iter().all(|r| r.idx <= 4),
        "members 5+ never fired"
    );
    // Prefix 0..2 exact.
    for j in 0..3u64 {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 1, "slot {j} exact");
        assert_eq!(got[0].status, wire::ALG_OK);
    }
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        wire::TRUNC_WALK_NAME,
        "name-fail flags alone (skip path leaves no TRUNC)"
    );
    // READ cell: cells 0..2 copied to straddle the mapped/PROT_NONE
    // boundary (names/dispatch pointers still reach the fixture
    // above, which outlives this fire); member 3's tuple read
    // spans the boundary and faults.
    let (_straddle, base) = StraddleMap::build(fx.array, 3);
    pace_fire_gap();
    clear_trunc(loaded, "term-read");
    FIXTURE_ARRAY.store(base, Ordering::SeqCst);
    write_tcache(loaded, base, 3, 0);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, 1, "term-read");
    assert_eq!(d.rets.len(), 1, "term-read: RET joined");
    ret_for(&d.rets, d.calls[0].tid, d.calls[0].seq);
    assert!(d.guards.is_empty(), "term-read: no guard");
    // Prefix 0..2 exact (readable side of the straddle).
    for j in 0..3u64 {
        let got: Vec<_> = d.algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 1, "term-read: slot {j} exact");
        assert_eq!(got[0].status, wire::ALG_OK);
        assert_eq!(
            d.rows.iter().filter(|r| r.idx == j).count(),
            1,
            "term-read: slot {j} row"
        );
    }
    // Member 3 aborted SILENT (tuple-read fault — no ALG record,
    // contrasting the NAME cell's explicit UNREADABLE record);
    // members 4+ skipped as before.
    assert!(
        d.algs.iter().all(|a| a.idx <= 2) && d.rows.iter().all(|r| r.idx <= 2),
        "term-read: member 3 silent, members 4+ skipped"
    );
    assert_eq!(d.algs.len(), 3, "term-read: exactly the readable prefix");
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        wire::TRUNC_WALK_READ,
        "term-read: tuple abort flags READ alone"
    );
    // End-state: both queries retired + counted, no loss.
    assert_retired(loaded, tid, "term-control");
    assert_loss_zero(loaded);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
}

/// D GEN-stale-smaller (stale T=3 < live T=6 walks more — the
/// cache never narrows): a GEN-mismatched entry is logical
/// invalidation (COLD), so the full live prefix walks despite the
/// stale T.
#[test]
#[ignore]
fn d_gen_stale_smaller() {
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
    let slots: Vec<SlotSpec> = (0..6u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDG{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    // Padded: GEN-mismatch cold-walks the deterministic table
    // (unpadded past-T reads heap soup to the 128-member cliff).
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Stale entry: T=3 with generation 99 (live GEN is 0) —
    // GEN-mismatch → COLD → full reach.
    write_tcache(loaded, fx.array, 3, 99);
    fire(OP as i32, 1);
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows,
    } = drain(loaded);
    assert_calls_admitted(&calls, 1, "gen-stale");
    assert_eq!(rets.len(), 1, "RET joined");
    ret_for(&rets, calls[0].tid, calls[0].seq);
    assert!(guards.is_empty(), "slot 511 zero → no guard");
    // Cold reach despite stale T=3 (slots 4,5 walked — the cache
    // never narrows).
    for j in 0..6u64 {
        assert_eq!(
            algs.iter().filter(|a| a.idx == j).count(),
            1,
            "slot {j} walked (stale cache ignored)"
        );
    }
    assert_eq!(algs.len(), 512, "full cold walk + zero tail");
    assert_eq!(
        algs.iter().filter(|a| a.status == wire::ALG_OK).count(),
        6,
        "the 6 live slots"
    );
    assert_eq!(rows.len(), 6);
    assert_eq!(read_percpu(loaded, "TRUNC", OP, true), 0);
    assert_retired(loaded, tid, "gen-stale");
    assert_loss_zero(loaded);
}

/// D no_store-prefix matrix (R18 §4.1 + RR-04 — no shared
/// prove, per-member local reads): warm T=3 injected, the array
/// holds 7 live slots. One attach, sequenced fires with a drain
/// between (TRUNC accumulates — deltas per fire):
/// cold walks regardless of verdict (cache ignored);
/// warm+zero skips past T (members 0..=3 walk);
/// warm+nonzero cold-walks all 7 (full reach) with TRUNC_NO_STORE;
/// NULL-ns_ptr and unreadable-ns_ptr walk cold too (fail-closed —
/// only a successfully-read zero pointee skips);
/// and both verdict orders pin order-independence (a verdict-1
/// fire neither poisons the next skip nor is needed for it —
/// member-0-first is flag publisher only, LIFO fire order
/// depended on nothing).
#[test]
#[ignore]
fn d_no_store_prefix() {
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
    let slots: Vec<SlotSpec> = (0..7u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDN{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    // Zero-padded to the full chunk: cold members all walk, so
    // every slot past the live prefix must read names==0
    // (explicit EMPTY) — an unpadded array would feed
    // members 8+ names/blob bytes and unmapped faults
    // (READ/NOIMP/NAME soup + silent aborts past member 128).
    let fx = Fixture::build_padded(&slots, &[], 512);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    // Unreadable pointee: mapped but faulting (PROT_NONE).
    let _prot_none = ProtNonePage(map_prot_none());
    let unreadable = _prot_none.0 as *mut std::ffi::c_int;

    /// Drain one fire: exactly one admitted CALL + one live RET, no
    /// guard (slot 511 zero); returns the drain + this fire's
    /// TRUNC flags (the leg clears TRUNC before every fire, so the
    /// read is the fire's delta, exactly).
    fn one_fire(loaded: &Loaded, tag: &str) -> (ScanDrain, u64) {
        let d = drain(loaded);
        assert_calls_admitted(&d.calls, 1, tag);
        assert_eq!(d.rets.len(), 1, "{tag}: RET");
        let r = ret_for(&d.rets, d.calls[0].tid, d.calls[0].seq);
        assert_eq!(
            (r.kind, r.op, r.flags),
            (osslscope_ebpf_common::KIND_SCAN_RET, OP, 0)
        );
        assert!(d.guards.is_empty(), "{tag}: no guard (T ≤ 7)");
        (d, read_percpu(loaded, "TRUNC", OP, true))
    }
    /// Full cold reach: live prefix exact (1 ALG_OK + 1 ROW per
    /// slot), every slot past it an explicit EMPTY (cold members
    /// all walk — 512 ALGs; the T-gate is warm-only).
    fn assert_full_reach(d: &ScanDrain, live: u64, tag: &str) {
        assert_eq!(d.algs.len(), 512, "{tag}: cold members all walk");
        for j in 0..live {
            let got: Vec<_> = d.algs.iter().filter(|a| a.idx == j).collect();
            assert_eq!(got.len(), 1, "{tag}: slot {j} walked");
            assert_eq!(
                got[0].status,
                osslscope_ebpf_common::ALG_OK,
                "{tag}: slot {j} live"
            );
            assert_eq!(
                d.rows.iter().filter(|r| r.idx == j).count(),
                1,
                "{tag}: slot {j} row"
            );
        }
        assert!(
            d.algs
                .iter()
                .filter(|a| a.idx >= live)
                .all(|a| a.status == osslscope_ebpf_common::ALG_EMPTY),
            "{tag}: past-live slots explicit EMPTY"
        );
        assert_eq!(d.rows.len() as u64, live, "{tag}: rows = live only");
    }
    /// Warm skip past T=3: members 0..=3 walk, member 4 (T+1)
    /// cold-walks the live slot (growth evidence), 5+ skip-silent.
    fn assert_skipped(d: &ScanDrain, tag: &str) {
        assert!(
            d.algs.iter().all(|a| a.idx <= 4) && d.rows.iter().all(|r| r.idx <= 4),
            "{tag}: past-T+1 skipped"
        );
        assert_eq!(d.algs.len(), 5, "{tag}: members 0..=4 walked");
        assert_eq!(
            d.algs.iter().filter(|a| a.idx == 4).count(),
            1,
            "{tag}: T+1 walks live slot 4"
        );
        assert_eq!(d.rows.len(), 5, "{tag}: rows 0..=4");
    }

    // F1: cold + verdict 0 → full reach, TRUNC clean.
    clear_trunc(loaded, "ns-cold-0");
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-cold-0");
    assert_full_reach(&d, 7, "ns-cold-0");
    assert_eq!(dt, 0, "ns-cold-0: TRUNC clean");
    // F2: cold + verdict 1 → full reach (cache ignored anyway) +
    // NO_STORE flagged (member 0 always evaluates the verdict).
    pace_fire_gap();
    clear_trunc(loaded, "ns-cold-1");
    NS_VERDICT.store(1, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-cold-1");
    assert_full_reach(&d, 7, "ns-cold-1");
    assert_eq!(dt, wire::TRUNC_NO_STORE, "ns-cold-1: NO_STORE flagged");
    // Inject warm T=3 (gen 0 = live GEN).
    write_tcache(loaded, fx.array, 3, 0);
    // F3: warm + verdict 0 → skips past T, TRUNC clean.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-0");
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-warm-0");
    assert_skipped(&d, "ns-warm-0");
    assert_eq!(dt, 0, "ns-warm-0: TRUNC clean");
    // F4: warm + verdict 1 → all 7 walk (order 0-then-1) + NO_STORE.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-1");
    NS_VERDICT.store(1, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-warm-1");
    assert_full_reach(&d, 7, "ns-warm-1");
    assert_eq!(dt, wire::TRUNC_NO_STORE, "ns-warm-1: NO_STORE flagged");
    // F5: warm + verdict 0 again → skips (order 1-then-0: the
    // verdict-1 fire poisons nothing), TRUNC clean.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-0-again");
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-warm-0-again");
    assert_skipped(&d, "ns-warm-0-again");
    assert_eq!(dt, 0, "ns-warm-0-again: TRUNC clean");
    // F6: warm + NULL ns_ptr → all 7 walk cold (fail-closed) +
    // NO_STORE flagged.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-null");
    NS_SKIP_STORE.store(1, Ordering::SeqCst);
    fire_ns_raw(OP as i32, std::ptr::null_mut());
    NS_SKIP_STORE.store(0, Ordering::SeqCst);
    let (d, dt) = one_fire(loaded, "ns-warm-null");
    assert_full_reach(&d, 7, "ns-warm-null");
    assert_eq!(dt, wire::TRUNC_NO_STORE, "ns-warm-null: NO_STORE flagged");
    // F7: warm + unreadable ns_ptr → all 7 walk cold + NO_STORE.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-unreadable");
    NS_SKIP_STORE.store(1, Ordering::SeqCst);
    fire_ns_raw(OP as i32, unreadable);
    NS_SKIP_STORE.store(0, Ordering::SeqCst);
    let (d, dt) = one_fire(loaded, "ns-warm-unreadable");
    assert_full_reach(&d, 7, "ns-warm-unreadable");
    assert_eq!(
        dt,
        wire::TRUNC_NO_STORE,
        "ns-warm-unreadable: NO_STORE flagged"
    );
    // F8: warm + verdict 0 → skips (bad-pointer fires poison
    // nothing either), TRUNC clean.
    pace_fire_gap();
    clear_trunc(loaded, "ns-warm-0-final");
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (d, dt) = one_fire(loaded, "ns-warm-0-final");
    assert_skipped(&d, "ns-warm-0-final");
    assert_eq!(dt, 0, "ns-warm-0-final: TRUNC clean");
    // End-state: retired + silent loss planes (reservation drops:
    // none — the ring is far from full) + 8 queries counted.
    assert_retired(loaded, tid, "ns-matrix");
    assert_loss_zero(loaded);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 8);
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "ns-matrix: F8 clean"
    );
}

/// D guard-cold-ERROR: cold + slot-511-live + slot-512-UNREADABLE
/// → GUARD ERROR + LOSS_GUARD_READ_ABORT (re-covers on retry — no
/// TRUNC from the guard; walk TRUNC stays clean).
#[test]
#[ignore]
fn d_guard_cold_error() {
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
    let slots: Vec<SlotSpec> = (0..512u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDG{j:03}"),
                100 + (j % 512) as u16,
                vec![(7000 + j, 0xA000 + j as u64)],
            )
        })
        .collect();
    // Array sized to 640 cells (5 pages): slot 512 starts exactly
    // at page 4 (512 × 32B) and the names blob starts at page 5
    // (640 × 32B) — unmapping page 4 isolates the slot-512 read
    // fault (an unpadded 513-cell array shares page 4 between slot
    // 512 and name storage, faulting name reads into WALK_NAME).
    let fx = Fixture::build_padded(&slots, &[], 640);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    let page = 4096usize;
    assert_eq!(fx.array as usize % page, 0, "array page-aligned");
    assert_eq!(640 * 32 % page, 0, "names start on page 5");
    let rc = unsafe { libc::munmap((fx.array + 512 * 32) as *mut libc::c_void, page) };
    assert_eq!(rc, 0, "munmap slot-512 page");
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let ScanDrain {
        calls,
        rets,
        guards,
        algs,
        rows: _,
    } = drain(loaded);
    assert_calls_admitted(&calls, 1, "guard-error");
    assert_eq!(rets.len(), 1, "RET joined");
    ret_for(&rets, calls[0].tid, calls[0].seq);
    assert_eq!(algs.len(), 512, "all walked slots emit");
    // Guard: eligible (cold + 511 live), read fails → ERROR.
    assert_eq!(guards.len(), 1, "one GUARD");
    let g = &guards_for(&guards, calls[0].tid, calls[0].seq)[0];
    assert_eq!(
        (g.kind, g.op, g.verdict, g.arr),
        (wire::KIND_GUARD, OP, wire::GUARD_ERROR, fx.array),
        "GUARD ERROR joined by (tid,seq)"
    );
    assert_loss_only(loaded, wire::LOSS_GUARD_READ_ABORT, 1, "guard-error");
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "guard ERROR adds LOSS, not TRUNC"
    );
    assert_retired(loaded, tid, "guard-error");
}

/// D guard-warm-512 trio (eligibility ≠ walkability): warm
/// T=512 over 512-live + term → GUARD EMPTY; over 513-live →
/// GUARD VALID + TRUNC_ALGS (guard-exclusive); NOIMP@511 → guard
/// still executes (EMPTY, TRUNC NOIMP alone).
#[test]
#[ignore]
fn d_guard_warm_512() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let live512: Vec<SlotSpec> = (0..512u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDH{j:03}"),
                100 + (j % 512) as u16,
                vec![(7000 + j, 0xA000 + j as u64)],
            )
        })
        .collect();
    // EMPTY: 512 live + term@512, warm T=512.
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let fx = Fixture::build(&live512, &[]);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        write_tcache(loaded, fx.array, 512, 0);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(d.rets.len(), 1);
        assert_eq!(d.algs.len(), 512, "warm T=512 walks all");
        assert_eq!(d.guards.len(), 1, "guard fires (warm T=512)");
        let g = &guards_for(&d.guards, d.calls[0].tid, d.calls[0].seq)[0];
        assert_eq!(g.verdict, wire::GUARD_EMPTY, "GUARD EMPTY");
        assert_eq!(g.arr, fx.array);
        assert_eq!(read_percpu(loaded, "TRUNC", OP, true), 0);
        assert_retired(loaded, tid, "guard-warm-empty");
        assert_loss_zero(loaded);
    }
    // VALID: 513 live, warm T=512.
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let mut slots513 = live512.clone();
        slots513.push(SlotSpec::live("MDH513", 612, vec![(7513, 0xA513)]));
        let fx = Fixture::build(&slots513, &[]);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        write_tcache(loaded, fx.array, 512, 0);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(d.rets.len(), 1);
        assert_eq!(d.guards.len(), 1, "guard fires (warm T=512)");
        let g = &guards_for(&d.guards, d.calls[0].tid, d.calls[0].seq)[0];
        assert_eq!(g.verdict, wire::GUARD_VALID, "GUARD VALID");
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_ALGS,
            "VALID → TRUNC_ALGS alone (guard-exclusive)"
        );
        assert_retired(loaded, tid, "guard-warm-valid");
        assert_loss_zero(loaded);
    }
    // NOIMP@511: guard still executes (eligibility ≠ walkability).
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let mut slots = live512.clone();
        slots[511] = SlotSpec::noimp("MDH511N", 611);
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        write_tcache(loaded, fx.array, 512, 0);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1);
        assert_eq!(d.rets.len(), 1);
        // Explicit NOIMP emit (eligibility ≠ walkability — NOIMP
        // records and falls through to the epilogue).
        assert_eq!(d.algs.len(), 512, "511 OK + NOIMP@511");
        let noimp: Vec<_> = d
            .algs
            .iter()
            .filter(|a| a.status == wire::ALG_NOIMP)
            .collect();
        assert_eq!(noimp.len(), 1, "NOIMP slot emits its ALG");
        assert_eq!(noimp[0].idx, 511);
        assert_eq!(d.guards.len(), 1, "guard executes despite NOIMP@511");
        let g = &guards_for(&d.guards, d.calls[0].tid, d.calls[0].seq)[0];
        assert_eq!(g.verdict, wire::GUARD_EMPTY, "GUARD EMPTY (term@512)");
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_WALK_NOIMP,
            "NOIMP flags alone (guard adds nothing on EMPTY)"
        );
        assert_retired(loaded, tid, "guard-warm-noimp");
        assert_loss_zero(loaded);
    }
}

/// D IDLE+record-silence (programmed failed-delete marker): with
/// the entry link DETACHED (no take runs — ATTEMPT proves it), a
/// return over a programmed IDLE+record does no work, emits no
/// RET/guard/ALG/ROW, runs no epilogue — the record PERSISTS
/// untouched for take-time silent recovery (bump-if-present still
/// runs on the existing IDLE cell).
#[test]
#[ignore]
fn d_idle_record_silence() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let mut attached = attach_chunk(&obj, &exe, off);
    let tid = self_tid();
    let slots = vec![SlotSpec::live("MDI0", 100, vec![(95, 0x9500)])];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(&attached.loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Program the failed-delete marker: record + IDLE|0.
    let marker = wire::ScanRec {
        op: OP as u64,
        ns_ptr: 0x5555,
        seq: wire::make_seq(0, 0),
        expected: 512,
        _pad: 0,
        epoch: 1,
    };
    write_cell(
        &attached.loaded,
        "SCAN",
        &tid.to_le_bytes(),
        &scan_bytes(&marker),
    );
    write_cell(
        &attached.loaded,
        "RCOUNT",
        &tid.to_le_bytes(),
        &wire::make_rcount(0, wire::RCOUNT_STATE_IDLE).to_le_bytes(),
    );
    // Detach the ENTRY link (members stay): no take runs.
    let devnull: OwnedFd = std::fs::File::open("/dev/null").expect("devnull").into();
    drop(std::mem::replace(&mut attached.entry, devnull));
    let loaded = &attached.loaded;
    let attempt0 = read_attempt(loaded);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert!(d.calls.is_empty(), "entry detached: no CALL");
    assert_eq!(
        read_attempt(loaded) - attempt0,
        0,
        "entry detached: ATTEMPT still"
    );
    assert!(d.rets.is_empty(), "IDLE: no RET");
    assert!(d.guards.is_empty(), "IDLE: no guard");
    assert!(d.algs.is_empty() && d.rows.is_empty(), "IDLE: no work");
    // The record persists byte-identical (no epilogue ran).
    let back = read_scan_cell(loaded, tid).expect("record persists");
    assert_eq!(
        (back.op, back.ns_ptr, back.seq, back.expected, back.epoch),
        (
            marker.op,
            marker.ns_ptr,
            marker.seq,
            marker.expected,
            marker.epoch
        ),
        "record untouched"
    );
    // Bump-if-present ran on the existing IDLE cell (count+512,
    // state preserved — NOT a retire).
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (512, wire::RCOUNT_STATE_IDLE),
        "bump-if-present on IDLE (no retire)"
    );
    assert_loss_zero(loaded);
}

/// D nested-skip (REPLACES nested-skip-C — §10.2): T=168 with
/// 160B primed (two undrained NULL queries = 2× 80B CALL+RET
/// pairs on a sacrificial tid) — outer admits at 160 (pair →
/// 240), inner pressure-skips. Both returns SCAN-miss (outer
/// record deleted by the nested skip): zero member emissions, NO
/// RET/guard on either return; RCOUNT IDLE|1024 (both returns'
/// members bump-if-present, gated out of work).
#[test]
#[ignore]
fn d_nested_skip() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = symbol_off("osslscope_member_query_nested");
    let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, 168));
    let loaded = &attached.loaded;
    let mut state = BirthState::new();
    let tid = self_tid();
    FIXTURE_ARRAY.store(0, Ordering::SeqCst); // NULL throughout
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Prime 160B on a sacrificial tid (two admitted NULL pairs
    // through the NESTED target — the attach observes the nested
    // symbol only, so ordinary fires prime nothing).
    let sacrificial = fire_nested_on_worker(loaded, OP as i32, 0, 2);
    assert_ne!(sacrificial, tid);
    register(loaded, &mut state, &[tid]);
    let (attempt0, calls0, loss0) = (
        read_attempt(loaded),
        read_percpu(loaded, "CALLS", OP, false),
        read_percpu(loaded, "LOSS", wire::LOSS_RING_PRESSURE, false),
    );
    fire_nested(OP as i32, 1);
    let d = drain(loaded);
    let mine: Vec<_> = d.calls.iter().filter(|c| c.tid == tid).collect();
    assert_eq!(mine.len(), 2, "outer-CALL + inner-CALL");
    assert_eq!(
        call_parts(mine[0]),
        (false, wire::SKIP_ADMITTED),
        "outer admits at 160"
    );
    assert_eq!(mine[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(mine[1]),
        (false, wire::SKIP_RING_PRESSURE),
        "inner pressure-skips at 240"
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
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "zero member emissions"
    );
    // Both returns SCAN-miss → NO RET/guard on either (D re-pin).
    let my_rets: Vec<_> = d.rets.iter().filter(|r| r.tid == tid).collect();
    assert!(my_rets.is_empty(), "no RET on either nested return");
    assert!(
        d.guards.iter().all(|g| g.tid != tid),
        "no guard on either return"
    );
    assert!(read_scan_cell(loaded, tid).is_none(), "SCAN absent");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (1024, wire::RCOUNT_STATE_IDLE),
        "RCOUNT IDLE|1024 (both returns bump-if-present)"
    );
}

/// D detach-stall (REPLACES detach-C — §10.2): member 7 detached
/// (no in-flight games — the stall is identical whether the
/// detach lands before the fire or behind a blocked return) →
/// count stalls at 511: no retire, record STANDS (ACTIVE|511),
/// RET still emitted (member 0 fires); the NEXT take carries
/// NESTED-HINT (proving the stall — unretired record stands).
#[test]
#[ignore]
fn d_detach_stall() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let mut attached = attach_chunk(&obj, &exe, off);
    let tid = self_tid();
    let slots = vec![SlotSpec::live("MDD0", 100, vec![(96, 0x9600)])];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(&attached.loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Detach member 7 (EXPECTED stays 512 — the retire equation
    // can never complete).
    let devnull: OwnedFd = std::fs::File::open("/dev/null").expect("devnull").into();
    drop(std::mem::replace(&mut attached.members[7], devnull));
    let loaded = &attached.loaded;
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(call_parts(&d.calls[0]), (false, wire::SKIP_ADMITTED));
    assert_eq!(d.rets.len(), 1, "RET emitted (member 0 fires)");
    // Stalled: record STANDS (no retire — count 511 ≠ 512).
    let rec = read_scan_cell(loaded, tid).expect("stalled record stands");
    assert_eq!(rec.seq, wire::make_seq(0, 0));
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (511, wire::RCOUNT_STATE_ACTIVE),
        "count stalls at 511 (ACTIVE)"
    );
    assert_loss_zero(loaded);
    // Next take: NESTED-HINT over the stalled record (proving it
    // stood unretired).
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1);
    assert_eq!(
        call_parts(&d.calls[0]),
        (true, wire::SKIP_ADMITTED),
        "stalled record hints the next take"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 1));
    assert_loss_zero(loaded);
}

/// D bump-blocked-clean-retire (REPLACES bump-C — §10.2): epoch
/// bump behind a pipe-blocked invocation (no detach) → the
/// blocked return retires CLEANLY (all 512 bump, count reaches
/// expected — retire checks no epoch) → the next take is
/// fresh-silent (NO LOSS25 — the bump is absorbed by retirement;
/// the C twin churned). The CTRL readback (epoch 2) proves the
/// bump happened; the absence of churn proves absorption.
#[test]
#[ignore]
fn d_bump_blocked_clean_retire() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = symbol_off("osslscope_member_query_blocking");
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let slots = vec![SlotSpec::live("MDB0", 100, vec![(97, 0x9700)])];
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
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
        let mut entered = false;
        for _ in 0..10_000 {
            if BLOCK_ENTERED.load(Ordering::SeqCst) == 1 {
                entered = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(entered, "worker blocked inside call 1");
        // Bump epoch behind the blocked return (no detach).
        osslscope::loader::program_ctrl(&loaded.maps, &wire::ctrl_value(512, 2, 1 << 20))
            .expect("bump epoch to 2");
        let one = [1u8; 1];
        assert_eq!(
            unsafe { libc::write(fds[1], one.as_ptr() as *const libc::c_void, 1) },
            1,
            "release worker"
        );
    });
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    // The bump happened (CTRL readback) but the blocked return
    // retired cleanly, so the next take is fresh-silent.
    let ctrl = osslscope::loader::read_ctrl(&loaded.maps).expect("read CTRL");
    assert_eq!(ctrl.epoch, 2, "bump landed");
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 2, "two worker CALLs");
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "call 1 admits"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&d.calls[1]),
        (false, wire::SKIP_ADMITTED),
        "call 2 admits, quiet (fresh — no churn)"
    );
    assert_eq!(d.calls[1].seq, wire::make_seq(0, 1));
    assert_eq!(d.rets.len(), 2, "both calls RET");
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
    assert_loss_zero(loaded);
    assert_retired(loaded, d.calls[1].tid, "bump-clean");
}

/// D governor quantum (REPLACES quantum-C — §10.2): NULL queries
/// no-drain at T ∈ {159, 160, 161} — 80B CALL+RET pairs:
/// 2/3/3 admitted (fire k sees occ (k−1)×80: T=159 admits 2 —
/// fire 3 sees 160 > 159; T=160 admits 3 — fire 3 sees 160 ≤
/// 160; T=161 admits 3). The 159→160 step pins the ≤ (a <
/// comparison would admit 2 at T=160 — boundary-sensitive).
/// CALLS-read between fires, single drain at end, RETs paired.
#[test]
#[ignore]
fn d_governor_quantum() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    for (t, want) in [(159u64, 2usize), (160, 3), (161, 3)] {
        let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, t));
        let loaded = &attached.loaded;
        let mut state = BirthState::new();
        let tid = self_tid();
        register(loaded, &mut state, &[tid]);
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let mut admitted = 0u32;
        for k in 1..=6u32 {
            fire(OP as i32, 1);
            if read_percpu(loaded, "CALLS", OP, false) == admitted as u64 + 1 {
                admitted += 1;
            }
            assert_eq!(
                read_attempt(loaded),
                k as u64,
                "T={t}: ATTEMPT tracks fires"
            );
        }
        assert_eq!(
            admitted as usize, want,
            "T={t}: {want} admitted (80B quantum)"
        );
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 6, "T={t}: 6 CALLs, single end drain");
        assert!(
            d.algs.is_empty() && d.rows.is_empty(),
            "T={t}: NULL silence"
        );
        assert!(d.guards.is_empty(), "T={t}: no guards (NULL)");
        let (adm, skp): (Vec<&_>, Vec<&_>) = d
            .calls
            .iter()
            .partition(|c| call_parts(c).1 == wire::SKIP_ADMITTED);
        assert_eq!(adm.len(), want, "T={t}: drain agrees");
        assert_eq!(skp.len(), 6 - want, "T={t}: skips");
        assert!(
            skp.iter()
                .all(|c| call_parts(c) == (false, wire::SKIP_RING_PRESSURE) && c.seq == 0),
            "T={t}: all skips cause 4, seq 0"
        );
        // RETs pair every admit (occupancy arrives in CALL+RET pairs).
        assert_eq!(d.rets.len(), want, "T={t}: RET per admit");
        for c in adm {
            ret_for(&d.rets, c.tid, c.seq);
        }
        // D: retired between → all admits quiet (no hints).
        assert!(d.calls.iter().all(|c| !call_parts(c).0), "T={t}: all quiet");
        assert_loss_only(
            loaded,
            wire::LOSS_RING_PRESSURE,
            (6 - want) as u64,
            &format!("quantum-{t}"),
        );
    }
}

/// D pressure re-pin (RE-PINNED — §10.2: second skip at occ 80,
/// not C's 32): GOVERNOR=0 extreme — first admits at occ 0
/// (CALL+RET pair → 80), second skips at 80.
#[test]
#[ignore]
fn d_pressure_gov0() {
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
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 2);
    assert_eq!(
        call_parts(&d.calls[0]),
        (false, wire::SKIP_ADMITTED),
        "occ 0 admits"
    );
    assert_eq!(d.calls[0].seq, wire::make_seq(0, 0));
    assert_eq!(
        call_parts(&d.calls[1]),
        (false, wire::SKIP_RING_PRESSURE),
        "occ 80 skips"
    );
    assert_eq!(d.calls[1].seq, 0);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1, "CALLS Δ1");
    assert_eq!(read_attempt(loaded), 2, "ATTEMPT Δ2");
    assert_loss_only(loaded, wire::LOSS_RING_PRESSURE, 1, "gov0");
    assert_eq!(d.rets.len(), 1, "RET on the admit only");
    ret_for(&d.rets, tid, wire::make_seq(0, 0));
    assert!(d.guards.is_empty(), "no guards (NULL)");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "skip member silence"
    );
    assert!(read_scan_cell(loaded, tid).is_none(), "skip cleared SCAN");
    assert_eq!(
        wire::split_rcount(read_u64_cell(loaded, "RCOUNT", tid).expect("RCOUNT kept")),
        (512, wire::RCOUNT_STATE_IDLE),
        "skipped return bumps-if-present (IDLE|512)"
    );
}

/// D burst-exactness + pressure-skip (§7D): (a) burst — 3× 512-live
/// scans no-drain, per-(tid,seq) pairing exact (1 CALL + 1 RET +
/// 512 ALG + 512 ROW + 1 GUARD each), each retired; (b)
/// pressure-skip — 200 NULL no-drain at T=8000: exactly 101 admit
/// (fire 101 sees occ 8000 ≤ 8000), 99 skip cause 4; RETs ==
/// admits. The 200 fires spread over 50 worker tids × 4 (item 5: a
/// single tid's bucket burst is 4 — 200 on one tid would
/// bucket-skip, not occupancy-skip; occupancy is global so the
/// math is unchanged). (This cell proves governor backpressure,
/// not reservation failure — the drop-path control is
/// `d_drop_path_reservation`.)
#[test]
#[ignore]
fn d_burst_exactness() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // (a) Burst: 3 full scans, no drain between.
    {
        let attached = attach_chunk(&obj, &exe, off);
        let loaded = &attached.loaded;
        let tid = self_tid();
        let slots: Vec<SlotSpec> = (0..512u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("MDB{j:03}"),
                    100 + (j % 512) as u16,
                    vec![(7000 + j, 0xA000 + j as u64)],
                )
            })
            .collect();
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 3);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 3, "burst: 3 CALLs");
        assert_eq!(d.rets.len(), 3, "burst: 3 RETs");
        assert_eq!(
            d.guards.len(),
            3,
            "burst: 3 guards (cold, 511 live, term@512)"
        );
        for c in &d.calls {
            assert_eq!(call_parts(c), (false, wire::SKIP_ADMITTED));
            let r = ret_for(&d.rets, c.tid, c.seq);
            assert_eq!(r.flags, 0);
            let g = guards_for(&d.guards, c.tid, c.seq);
            assert_eq!(g.len(), 1);
            assert_eq!(g[0].verdict, wire::GUARD_EMPTY);
        }
        assert_eq!(d.algs.len(), 3 * 512, "burst: 512 ALG per scan");
        assert_eq!(d.rows.len(), 3 * 512, "burst: 512 ROW per scan");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 3);
        assert_eq!(read_percpu(loaded, "TRUNC", OP, true), 0);
        assert_retired(loaded, tid, "burst");
        assert_loss_zero(loaded);
    }
    // (b) Pressure-skip: 200 NULL at T=8000 → 101 admit / 99 skip.
    {
        let attached = attach_with_ctrl(&obj, &exe, off, &wire::ctrl_value(512, 1, 8000));
        let loaded = &attached.loaded;
        FIXTURE_ARRAY.store(0, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        // 50 workers × 4 NULL fires each, sequential (each
        // worker fires exactly the bucket burst; occupancy
        // accumulates globally across workers, the bucket
        // never binds).
        for _ in 0..50 {
            fire_on_worker(loaded, OP as i32, 4);
        }
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 200, "pressure: 200 CALLs, single drain");
        let (adm, skp): (Vec<&_>, Vec<&_>) = d
            .calls
            .iter()
            .partition(|c| call_parts(c).1 == wire::SKIP_ADMITTED);
        assert_eq!(
            adm.len(),
            101,
            "pressure: 101 admit (fire 101 sees occ 8000)"
        );
        assert_eq!(skp.len(), 99, "pressure: 99 pressure-skips");
        assert!(
            skp.iter()
                .all(|c| call_parts(c).1 == wire::SKIP_RING_PRESSURE)
        );
        assert_eq!(d.rets.len(), 101, "pressure: RET per admit");
        assert!(
            d.algs.is_empty() && d.rows.is_empty(),
            "pressure: NULL silence"
        );
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 101);
        assert_eq!(read_attempt(loaded), 200);
        assert_loss_only(loaded, wire::LOSS_RING_PRESSURE, 99, "pressure");
    }
}

/// D drop-path: forced reservation failure + per-kind
/// reconciliation (R18 §7D — the accepted control, recomputed
/// for the current wire format and 16MiB ring: R18's "2979th of
/// 2MiB" predates explicit EMPTY emits and the item-7 ring
/// growth). 600 cold T=6 1-ROW scans, no drain, ring-permissive
/// governor (occupancy can never exceed the ring, so cause 4
/// cannot trip — backpressure arrives only as reservation
/// failure), bucket-safe pacing (no cause-10 skips).
/// One scan = CALL(32) + RET(48) + 512×ALG(64) + 6×ROW(72) =
/// 33,280B on the ring (8B header + 8-rounding per record — the
/// 80B NULL quantum pins the framing); the 16MiB ring holds 504
/// full scans, then scan 505 lands a partial prefix and every
/// later reservation fails. Members fire descending (511 first,
/// 0 last — LIFO), so scan 505's prefix is CALL + 63 ALGs (idx
/// 511..=449): member 0's RET finds 32B left and drops, as does
/// member 0's ALG; the 6 live-slot ROWs attempt and drop too.
/// Attempts: CALL/RET 600, ALG 512×600, ROW 6×600, GUARD 0.
/// Reconcile: emitted + LOSS_RING_* == attempted per kind; zero
/// cause-4 (ATTEMPT−CALLS==0 — every fire admitted); TRUNC clean
/// (reservation drops are LOSS, never TRUNC); every query still
/// retires (emission failure never aborts the member epilogue).
#[test]
#[ignore]
fn d_drop_path_reservation() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    const N: usize = 600;
    const LIVE: u64 = 6;
    // Ring capacity in whole scans + the partial tail (recomputed
    // above — pinned here so a wire-format change REDs loudly
    // instead of silently re-baselining). Scan 505 emits CALL +
    // 63 ALGs but no RET (member 0 fires last).
    const FULL_SCANS: usize = 504;
    const TAIL_ALGS: usize = 63;
    let exe = own_exe_cstr();
    let off = query_off();
    // Ring-permissive governor: occupancy never exceeds the ring,
    // so the governor cannot trip (cause 4 impossible by
    // construction — drops prove reservation failure, only it).
    let ctrl = wire::ctrl_value(512, 1, osslscope::loader::MEMBER_RING_BYTES);
    let attached = attach_with_ctrl(&obj, &exe, off, &ctrl);
    let loaded = &attached.loaded;
    let tid = self_tid();
    let mut births = BirthState::new();
    register(loaded, &mut births, &[tid]);
    let slots: Vec<SlotSpec> = (0..LIVE as u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDP{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    // Zero-padded to the full chunk (cold members all walk —
    // every scan emits exactly 512 ALGs: 6 live + 506 EMPTY).
    let fx = Fixture::build_padded(&slots, &[], 512);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire_paced(OP as i32, N, 30);
    let d = drain(loaded);
    // CALLs: scans 1..=505 emitted (seqs 0..=504, ring FIFO
    // order), all admitted — scans 506.. never reserved.
    assert_eq!(d.calls.len(), FULL_SCANS + 1, "drop: 505 CALLs");
    let seqs: Vec<u64> = d.calls.iter().map(|c| c.seq).collect();
    assert_eq!(
        seqs,
        (0..(FULL_SCANS + 1) as u64).collect::<Vec<_>>(),
        "drop: CALL seqs 0..=504 in order"
    );
    assert_calls_admitted(&d.calls, FULL_SCANS + 1, "drop");
    // RETs join the complete scans 1:1, all live; scan 505's RET
    // dropped (member 0 fires last — the ring filled first).
    assert_eq!(d.rets.len(), FULL_SCANS, "drop: 504 RETs");
    for c in d.calls.iter().take(FULL_SCANS) {
        let r = ret_for(&d.rets, c.tid, c.seq);
        assert_eq!(
            (r.kind, r.op, r.flags, r.arr),
            (wire::KIND_SCAN_RET, OP, 0, fx.array),
            "drop: live RET shape"
        );
    }
    assert!(d.guards.is_empty(), "drop: no guard (slot 511 zero)");
    // ALGs/ROWs group per seq: full scans complete, scan 505 a
    // 62-ALG 0-ROW prefix, later seqs absent.
    let mut alg_per_seq = std::collections::HashMap::new();
    for a in &d.algs {
        assert_eq!(a.tid, tid, "drop: ALG tid");
        *alg_per_seq.entry(a.seq).or_insert(0usize) += 1;
    }
    let mut row_per_seq = std::collections::HashMap::new();
    for r in &d.rows {
        *row_per_seq.entry(r.seq).or_insert(0usize) += 1;
    }
    assert_eq!(
        d.algs.len(),
        FULL_SCANS * 512 + TAIL_ALGS,
        "drop: 504×512 + 63 ALGs"
    );
    assert_eq!(d.rows.len(), FULL_SCANS * LIVE as usize, "drop: 504×6 ROWs");
    for seq in 0..FULL_SCANS as u64 {
        assert_eq!(
            alg_per_seq.get(&seq),
            Some(&512),
            "drop: seq {seq} complete (512 ALGs)"
        );
        assert_eq!(
            row_per_seq.get(&seq),
            Some(&(LIVE as usize)),
            "drop: seq {seq} complete (6 ROWs)"
        );
    }
    assert_eq!(
        alg_per_seq.get(&(FULL_SCANS as u64)),
        Some(&TAIL_ALGS),
        "drop: scan 505 a 63-ALG prefix"
    );
    // The prefix is the DESCENDING fire order made visible (511
    // first): idx 511..=449 landed, member 0's ALG did not.
    let mut tail_idx: Vec<u64> = d
        .algs
        .iter()
        .filter(|a| a.seq == FULL_SCANS as u64)
        .map(|a| a.idx)
        .collect();
    tail_idx.sort_unstable();
    assert_eq!(
        tail_idx,
        (449..512u64).collect::<Vec<_>>(),
        "drop: scan 505 prefix is idx 511..=449"
    );
    assert!(
        !row_per_seq.contains_key(&(FULL_SCANS as u64)),
        "drop: scan 505 has 0 ROWs (ring filled mid-scan)"
    );
    assert_eq!(alg_per_seq.len(), FULL_SCANS + 1, "drop: no seq past 504");
    // Full-scan shape on samples (live prefix exact, past-live
    // explicit EMPTY — the flood emits honest evidence, not soup).
    for seq in [0u64, 250, 503] {
        let live_ok = d
            .algs
            .iter()
            .filter(|a| a.seq == seq && a.status == wire::ALG_OK)
            .count();
        assert_eq!(live_ok, LIVE as usize, "drop: seq {seq} 6 live ALGs");
        assert!(
            d.algs
                .iter()
                .filter(|a| a.seq == seq && a.idx >= LIVE)
                .all(|a| a.status == wire::ALG_EMPTY),
            "drop: seq {seq} past-live EMPTY"
        );
    }
    // Reconcile: emitted + dropped == attempted per kind.
    let l_call = loss_val(loaded, wire::LOSS_RING_CALL);
    let l_ret = loss_val(loaded, wire::LOSS_RING_RET);
    let l_alg = loss_val(loaded, wire::LOSS_RING_ALG);
    let l_row = loss_val(loaded, wire::LOSS_RING_ROW);
    assert_eq!(
        d.calls.len() as u64 + l_call,
        N as u64,
        "drop: CALL reconcile"
    );
    assert_eq!(d.rets.len() as u64 + l_ret, N as u64, "drop: RET reconcile");
    assert_eq!(
        d.algs.len() as u64 + l_alg,
        512 * N as u64,
        "drop: ALG reconcile"
    );
    assert_eq!(
        d.rows.len() as u64 + l_row,
        LIVE * N as u64,
        "drop: ROW reconcile"
    );
    assert_loss_exact(
        loaded,
        &[
            (wire::LOSS_RING_CALL, (N - FULL_SCANS - 1) as u64),
            // Scan 505's RET dropped with the 95 never-attempted.
            (wire::LOSS_RING_RET, (N - FULL_SCANS) as u64),
            (
                wire::LOSS_RING_ALG,
                (512 * N - (FULL_SCANS * 512 + TAIL_ALGS)) as u64,
            ),
            (
                wire::LOSS_RING_ROW,
                (LIVE as usize * N - FULL_SCANS * LIVE as usize) as u64,
            ),
        ],
        "drop",
    );
    // Zero cause-4 (governor never tripped) — and zero skips of
    // any cause: every fire admitted.
    assert_eq!(read_attempt(loaded), N as u64, "drop: 600 attempts");
    assert_eq!(
        read_percpu(loaded, "CALLS", OP, false),
        N as u64,
        "drop: 600 admits"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "drop: TRUNC clean (drops are LOSS, never TRUNC)"
    );
    assert_retired(loaded, tid, "drop");
}

/// Tier-1 bucket live (item 5, §5.5): burst 4 admits back-to-back,
/// 5th rapid fire skips cause 10 (no SEQ mint), 120ms later the
/// refill (40/s) re-admits. NULL queries (occupancy never binds —
/// the bucket is the only skip source). Margins: fires are
/// back-to-back (µs ≪ 25ms period); the sleep is 4.8× the
/// 1token period.
#[test]
#[ignore]
fn d_bucket_burst_refill() {
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
    fire(OP as i32, 4); // burst: all admit
    fire(OP as i32, 1); // 5th: bucket empty → skip cause 10
    std::thread::sleep(std::time::Duration::from_millis(120));
    fire(OP as i32, 1); // refilled → admit
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 6, "bucket: 6 CALLs, single drain");
    let (adm, skp): (Vec<&_>, Vec<&_>) = d
        .calls
        .iter()
        .partition(|c| call_parts(c).1 == wire::SKIP_ADMITTED);
    assert_eq!(adm.len(), 5, "bucket: 4 burst + 1 refill admit");
    assert_eq!(skp.len(), 1, "bucket: 1 empty-skip");
    assert_eq!(
        call_parts(skp[0]),
        (false, wire::SKIP_BUCKET_EMPTY),
        "bucket: skip cause 10, quiet"
    );
    assert_eq!(skp[0].seq, 0, "bucket: skip mints no SEQ");
    let seqs: Vec<u64> = adm.iter().map(|c| c.seq).collect();
    assert_eq!(
        seqs,
        (0..5).map(|i| wire::make_seq(0, i)).collect::<Vec<_>>(),
        "bucket: admits mint ctr 0..4 (the skip minted nothing)"
    );
    assert_eq!(d.rets.len(), 5, "bucket: RET per admit");
    assert!(
        d.algs.is_empty() && d.rows.is_empty(),
        "bucket: NULL silence"
    );
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 5);
    assert_eq!(read_attempt(loaded), 6);
    assert_loss_only(loaded, wire::LOSS_BUCKET_EMPTY, 1, "bucket");
    assert_retired(loaded, tid, "bucket");
}

/// Corrupt exactly one member's first helper call (keep-good
/// live forcing): parse the object's symtab for `member_J`, scan
/// its code for the first BPF `call` with a helper (non-pseudo)
/// target, and rewrite its imm to an unknown helper id.
/// ELF/shape/relocs stay intact (prepare passes — only one code
/// immediate changes, at a relocation-free offset), while the
/// verifier rejects exactly this prog at load (keep-good records
/// it, the rest proceed). Returns the corrupted bytes.
fn corrupt_member_first_call(obj: &std::path::Path, slot: u32) -> Vec<u8> {
    let mut bytes = std::fs::read(obj).expect("read members.o");
    let elf = goblin::elf::Elf::parse(&bytes).expect("parse members.o");
    let sec_idx = elf
        .section_headers
        .iter()
        .position(|s| &elf.shdr_strtab[s.sh_name] == "uretprobe")
        .expect("uretprobe section");
    let sec = &elf.section_headers[sec_idx];
    let sec_off = sec.sh_offset as usize;
    let name = format!("member_{slot:03}");
    let sym = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name.as_str()))
        .unwrap_or_else(|| panic!("symbol {name} present"));
    assert_eq!(sym.st_shndx as usize, sec_idx, "{name} lives in uretprobe");
    let code_off = sec_off + sym.st_value as usize;
    let code_len = sym.st_size as usize;
    assert!(code_len % 8 == 0 && code_len > 0, "{name} has code");
    // Relocation targets within uretprobe (section-relative):
    // the corruption must not sit on one (prepare would repair
    // it back — or worse, the reloc would apply onto garbage).
    let mut relocs = std::collections::HashSet::new();
    for s in &elf.section_headers {
        if &elf.shdr_strtab[s.sh_name] == ".reluretprobe" {
            let o = s.sh_offset as usize;
            let e = o + s.sh_size as usize;
            for ent in bytes[o..e].chunks_exact(16) {
                let r_off = u64::from_le_bytes(ent[0..8].try_into().unwrap());
                relocs.insert(r_off);
            }
        }
    }
    // First helper call (opcode 0x85, src_reg 0 — pseudo-calls
    // carry relocs and src_reg 1; lddw spans two slots).
    let mut at = None;
    let mut o = 0usize;
    while o + 8 <= code_len {
        let op = bytes[code_off + o];
        if op == 0x18 {
            o += 16;
            continue;
        }
        if op == 0x85 && (bytes[code_off + o + 1] >> 4) == 0 {
            at = Some(o);
            break;
        }
        o += 8;
    }
    let insn = at.unwrap_or_else(|| panic!("{name} has a helper call"));
    let sec_rel = sym.st_value + insn as u64;
    assert!(
        !relocs.contains(&sec_rel),
        "{name}: first call is relocation-free"
    );
    bytes[code_off + insn + 4..code_off + insn + 8].copy_from_slice(&0x7fffffffi32.to_le_bytes());
    eprintln!(
        "selective-reject: corrupted {name} call at file+{:#x}",
        code_off + insn
    );
    bytes
}

/// Selective load live (item 6): attach members {0,1,2,3} with
/// EXPECTED=4 — only the entry + 4 members prepare/load (never
/// the full 513), the scan retires (count reaches attached
/// EXPECTED), evidence covers the attached window (live slots +
/// explicit EMPTY terminator), and unattached slots stay silent
/// (out of scope — the oracle reports them as unobserved, never
/// as holes). Keep-good is FORCED, not just asserted empty: the
/// rejection cell corrupts member_003's first helper call (the
/// verifier rejects exactly it at load), the rest attach,
/// EXPECTED reprograms to 3, the scan retires, and slot 3 stays
/// out of the evidence.
#[test]
#[ignore]
fn d_selective_scope() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let ctrl =
        osslscope::loader::default_ctrl(4, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL/4");
    let sub = osslscope::loader::attach_members_subset(
        &obj,
        &exe,
        off,
        std::process::id(),
        &ctrl,
        &[0, 1, 2, 3],
    )
    .expect("selective attach");
    assert_eq!(sub.attached.members.len(), 4, "selective: 4 links");
    assert_eq!(sub.slots, vec![0, 1, 2, 3], "selective: actual slots");
    assert!(sub.failed.is_empty(), "selective: no failures");
    let loaded = &sub.attached.loaded;
    let mut state = BirthState::new();
    register(loaded, &mut state, &[self_tid()]);
    let tid = self_tid();
    let slots = vec![
        SlotSpec::live("MS0", 101, vec![(21, 0x4200)]),
        SlotSpec::live("MS1", 102, vec![(22, 0x4300)]),
    ];
    // Padded: slot 3 reads past-T zero (an unpadded array feeds
    // slot 3 names-blob bytes → UNREADABLE, not EMPTY).
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_eq!(d.calls.len(), 1, "selective: 1 CALL");
    assert_eq!(call_parts(&d.calls[0]), (false, wire::SKIP_ADMITTED));
    assert_eq!(d.rets.len(), 1, "selective: RET (member 0 attached)");
    let mut idxs: Vec<u64> = d.algs.iter().map(|a| a.idx).collect();
    idxs.sort_unstable();
    // Attached window fully evidenced: 2 live + explicit EMPTY
    // terminator at 2 AND the walked EMPTY at 3 (every attached
    // slot emits its read-status; slot 3 reads past-T zero).
    assert_eq!(idxs, vec![0, 1, 2, 3], "selective: full window");
    let st: Vec<u8> = {
        let mut v: Vec<(u64, u8)> = d.algs.iter().map(|a| (a.idx, a.status)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, s)| s).collect()
    };
    assert_eq!(
        st,
        vec![wire::ALG_OK, wire::ALG_OK, wire::ALG_EMPTY, wire::ALG_EMPTY],
        "selective: live + explicit terminator + past-T zero"
    );
    assert!(d.guards.is_empty(), "selective: no guard (511 unattached)");
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1);
    assert_retired(loaded, tid, "selective");
    assert_loss_zero(loaded);
    // Rejection cell: member_003 corrupted (unknown helper) — the
    // verifier rejects exactly it at load (keep-good records
    // stage=load), members {0,1,2} attach, EXPECTED reprograms to
    // 3, the scan retires, and slot 3 stays out of the evidence
    // (unattached — the oracle scope excludes it, never a hole).
    {
        let bad = corrupt_member_first_call(&obj, 3);
        let ctrl4 = osslscope::loader::default_ctrl(4, osslscope::loader::MEMBER_RING_BYTES)
            .expect("CTRL/4");
        let sub = osslscope::loader::attach_members_subset_from_bytes(
            &bad,
            &exe,
            off,
            std::process::id(),
            &ctrl4,
            &[0, 1, 2, 3],
        )
        .expect("keep-good attach proceeds");
        assert_eq!(sub.slots, vec![0, 1, 2], "selective: attached set");
        assert_eq!(sub.failed.len(), 1, "selective: exactly one rejection");
        assert_eq!(sub.failed[0].slot, 3, "selective: slot 3 rejected");
        assert_eq!(sub.failed[0].stage, "load", "selective: load-stage");
        assert!(
            !sub.failed[0].error.is_empty(),
            "selective: rejection recorded"
        );
        let loaded = &sub.attached.loaded;
        let mut state = BirthState::new();
        register(loaded, &mut state, &[self_tid()]);
        let tid = self_tid();
        let slots = vec![
            SlotSpec::live("MSR0", 101, vec![(21, 0x4200)]),
            SlotSpec::live("MSR1", 102, vec![(22, 0x4300)]),
        ];
        let fx = Fixture::build_padded(&slots, &[], 513);
        fx.pretouch();
        populate_alg_class(loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d = drain(loaded);
        assert_eq!(d.calls.len(), 1, "selective-reject: 1 CALL");
        assert_eq!(
            call_parts(&d.calls[0]),
            (false, wire::SKIP_ADMITTED),
            "selective-reject: admits"
        );
        assert_eq!(d.rets.len(), 1, "selective-reject: RET (member 0 attached)");
        let mut idxs: Vec<u64> = d.algs.iter().map(|a| a.idx).collect();
        idxs.sort_unstable();
        assert_eq!(
            idxs,
            vec![0, 1, 2],
            "selective-reject: attached window only"
        );
        assert!(d.guards.is_empty(), "selective-reject: no guard");
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 1);
        assert_retired(loaded, tid, "selective-reject");
        assert_loss_zero(loaded);
    }
}

/// Drain floor live (item 7, §5.6): 240 × 512-live scans in 6
/// waves of 40 (each wave 10 worker tids × 4 fires — bucket-safe;
/// ~2.7MB/wave < 4MiB governor so every fire admits), timed
/// drains sustain ≥ 120MB/s aggregate (the ring criterion; P9
/// verifies — typical ringbuf+parse is GB/s, 10×+ margin).
#[test]
#[ignore]
fn d_drain_floor() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let attached = attach_chunk(&obj, &exe, off);
    let loaded = &attached.loaded;
    let slots: Vec<SlotSpec> = (0..512u32)
        .map(|j| {
            SlotSpec::live(
                &format!("MDF{j:03}"),
                100 + (j % 512) as u16,
                vec![(7000 + j, 0xA000 + j as u64)],
            )
        })
        .collect();
    let fx = Fixture::build(&slots, &[]);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let mut total_bytes: u64 = 0;
    let mut total_drain = std::time::Duration::ZERO;
    let mut total_calls = 0usize;
    for wave in 0..6 {
        for _ in 0..10 {
            fire_on_worker(loaded, OP as i32, 4);
        }
        let t0 = std::time::Instant::now();
        let d = drain(loaded);
        let dt = t0.elapsed();
        total_drain += dt;
        total_calls += d.calls.len();
        let bytes = d.calls.len() as u64 * 32
            + d.rets.len() as u64 * 48
            + d.guards.len() as u64 * 48
            + d.algs.len() as u64 * 64
            + d.rows.len() as u64 * 72;
        total_bytes += bytes;
        eprintln!(
            "drain-floor wave {wave}: {} CALLs, {bytes} bytes in {dt:?}",
            d.calls.len()
        );
        assert_eq!(d.calls.len(), 40, "drain-floor: wave admits all 40");
        assert!(
            d.calls
                .iter()
                .all(|c| call_parts(c).1 == wire::SKIP_ADMITTED),
            "drain-floor: no skips (occupancy + bucket both clear)"
        );
    }
    assert_eq!(total_calls, 240, "drain-floor: 240 scans");
    let secs = total_drain.as_secs_f64();
    let rate = total_bytes as f64 / secs;
    eprintln!("drain-floor: {total_bytes} bytes in {total_drain:?} = {rate:.1} B/s");
    assert!(
        rate >= 120_000_000.0,
        "drain-floor: {rate:.1} B/s < 120MB/s criterion"
    );
    assert_loss_zero(loaded);
}

/// Teardown wall live (item 7 resource): attach + drop of all 513
/// links completes (hang-guard bound — P9 tightens from lane
/// evidence; the measured split is reported for the record).
#[test]
#[ignore]
fn d_detach_wall() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let t0 = std::time::Instant::now();
    let attached = attach_chunk(&obj, &exe, off);
    let attach_dt = t0.elapsed();
    assert_eq!(attached.members.len(), 512, "detach-wall: 512 links");
    let t1 = std::time::Instant::now();
    drop(attached);
    let detach_dt = t1.elapsed();
    eprintln!("detach-wall: attach {attach_dt:?}, detach {detach_dt:?}");
    assert!(
        attach_dt + detach_dt < std::time::Duration::from_secs(60),
        "detach-wall: attach+detach {attach_dt:?}+{detach_dt:?} exceeds hang-guard 60s"
    );
}

// ===== R19 production-path proof legs (integration) =====
//
// The legs above attach through `loader::attach_members` and drain
// the ring by hand. These legs drive the PRODUCTION backend
// (`ScanBackend`: attach → register → poll → completed — the same
// API `capture::run_traversal` composes) against the real object:
// one query with later slots (E=256, terminator deep in the array —
// first fire completes uncached + warms T_CACHE, second completes
// cached) and the 512/513 termination boundary (512-clean
// completes; 513-live closes Partial{Trunc, Overfull} with a VALID
// guard and TRUE-T demoted to Candidate(512)). Same lane rules as
// the D legs (OSSL_B_LIVE=1, OSSL_MEMBERS_OBJECT,
// --test-threads=1, #[ignore]).

/// Attach the production backend over a single verified byte
/// snapshot (full 512, production CTRL) and register this thread
/// (BIRTH must exist before the entry fires — the entry skips
/// unregistered tids). This is the production attach: the snapshot
/// is size-capped exactly as at resolution, the same bytes identity
/// would hash are the bytes the loader consumes (no path re-read
/// can interpose a swap), and ALG_CLASS arrives populated from the
/// single registry — legs never hand-fill it. Closure is
/// production too: `poll()` (quiesced=false, opens close on
/// successor takes) with `finish()` as the window-edge backstop —
/// never quiesced inference.
fn backend_chunk(obj: &std::path::Path, exe: &std::ffi::CString, off: u64) -> ScanBackend {
    let bytes = std::fs::read(obj).expect("read members object");
    assert!(
        bytes.len() as u64 <= osslscope::discovery::onboard::MAX_OBJECT_SCAN_BYTES,
        "production cap applies to the snapshot the backend loads"
    );
    let ctrl =
        osslscope::loader::default_ctrl(512, osslscope::loader::MEMBER_RING_BYTES).expect("CTRL");
    let mut backend =
        ScanBackend::attach_bytes(&bytes, obj, exe, off, std::process::id(), &ctrl, None, 0)
            .expect("backend attach");
    backend.register(&[self_tid()]).expect("register self");
    backend
}

/// Per-CPU width of a percpu map (slot count of any row — the
/// ATTEMPT cell always exists, so it reports the width).
fn percpu_width(loaded: &Loaded, name: &str) -> usize {
    use aya::maps::{Map, MapData, PerCpuArray};
    let fd = loaded.maps[name].try_clone().expect("clone width map");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let m = PerCpuArray::<_, u64>::try_from(map).expect("percpu-array shape");
    m.get(&0, 0).expect("cell 0").len()
}

/// Stage one TRUNC sticky bit (harness-side exactly what a member
/// flag would leave: the bit on CPU 0, zeros elsewhere).
fn stage_trunc(loaded: &Loaded, op: u32, bit: u64) {
    use aya::maps::{Map, MapData, PerCpuHashMap, PerCpuValues};
    let ncpu = percpu_width(loaded, "ATTEMPT");
    let fd = loaded.maps["TRUNC"].try_clone().expect("clone TRUNC");
    let data = MapData::from_fd(fd).expect("mapdata");
    let map = Map::from_map_data(data).expect("map");
    let mut m = PerCpuHashMap::<_, u32, u64>::try_from(map).expect("percpu shape");
    let mut slots = vec![0u64; ncpu];
    slots[0] = bit;
    let vals = PerCpuValues::try_from(slots).expect("widths");
    m.insert(op, vals, 0).expect("stage TRUNC");
}

/// Round-2 F6 (round-3 hardened): `finish()` quiesces the
/// producer FIRST — post-window queries skip honestly (SKIP_ALL)
/// instead of starting new scans after counting closed, while
/// in-flight scans still settle and close through the backstop.
/// The throttle is ENGAGED first (30 paced full-table queries —
/// duty crosses the 100ms trip line well inside any 1s trailing
/// window) and its samples EXPIRE
/// (1.2s idle, no poll — the throttle sits stale-engaged), so
/// the finish poll would idle-release the gate under ordinary
/// tier aging: the leg pins that finish holds the gate anyway
/// (tiers frozen — no age-release, no reattach, no storm-detach
/// abandoning the trailing evidence).
#[test]
#[ignore]
fn r19_finish_quiesces_producer() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let mut backend = backend_chunk(&obj, &exe, off);
    backend.register(&[self_tid()]).expect("register self");
    // 512 live slots named with REAL registry spellings: the
    // backend attach already populated ALG_CLASS from the
    // production registry, so the members classify OK with zero
    // fixture populate (a 512-name fixture populate would
    // overflow the 1024-entry map atop production).
    let reg: Vec<&str> = osslscope::kinds::ALG_NAMES
        .iter()
        .map(|a| a.name)
        .take(512)
        .collect();
    assert_eq!(reg.len(), 512, "registry covers 512 live slots");
    let slots: Vec<SlotSpec> = reg
        .iter()
        .enumerate()
        .map(|(j, name)| SlotSpec::live(name, 0, vec![(300 + j as u32, 0x4400 + j as u64)]))
        .collect();
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Engage the throttle: 30 paced full-table queries (~6.5ms
    // each — duty crosses the 100ms trip line well inside any 1s
    // trailing window, while 33/s stays far under the 1k/s storm
    // line). Engagement skips the tail of the loop (cause 5) —
    // by design; every fire still closes (Complete or Skipped).
    let mut dones = 0usize;
    for _ in 0..30 {
        pace_fire_gap();
        fire(OP as i32, 1);
        let d = backend.poll().expect("window poll drains");
        dones += d.done.len();
    }
    assert!(
        backend.snapshot().throttled,
        "throttle engaged before finish (else this leg proves nothing)"
    );
    let admitted = read_percpu(backend.loaded(), "CALLS", OP, false);
    assert!(
        admitted >= 15,
        "most queries admitted before the trip ({admitted})"
    );
    // Expire the samples WITHOUT polling (the throttle sits
    // stale-engaged — an ordinary poll would idle-release now).
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let tail = backend.finish().expect("finish settles");
    let ctrl = osslscope::loader::read_ctrl(&backend.loaded().maps).expect("read CTRL");
    assert_eq!(
        ctrl.skip_all, 1,
        "finish holds the gate (no tier-2 release)"
    );
    assert!(
        backend.snapshot().throttled,
        "throttle state frozen, not released"
    );
    dones += tail.done.len();
    assert_eq!(dones, 30, "every window fire closes (none abandoned)");
    // A post-window query skips honestly (never admitted, never
    // walked) instead of starting a scan after counting closed.
    pace_fire_gap();
    fire(OP as i32, 1);
    let post = backend.poll().expect("post-finish poll drains the skip");
    assert_eq!(
        read_percpu(backend.loaded(), "CALLS", OP, false),
        admitted,
        "post-window query never admitted"
    );
    assert_eq!(post.done.len(), 1, "the skip closes immediately");
    assert!(
        matches!(post.done[0].outcome, Outcome::Skipped { .. }),
        "post-window query skips: {:?}",
        post.done[0].outcome
    );
    assert!(
        post.done[0].algs.is_empty(),
        "a skipped query walks nothing"
    );
}

/// Round-3 F3: the lossless TRUNC drain (sticky snapshot +
/// per-op flag-event generation, never cleared). First sighting
/// attributes; a quiet re-drain is empty (consumed, never
/// repeats) with the map bits intact (sticky, never cleared);
/// a REPEAT fault (same bit re-flagged — the generation
/// advanced) re-reports the op's set bits (recurring faults
/// stay visible — hiding them would fail open on flag-only
/// evidence like dispatch overflow); a flag injected just AFTER
/// a snapshot (the deterministic hook — no timing dependence)
/// appears in the NEXT drain (delayed one drain, never lost,
/// never tainted, in any producer order — there is no clear to
/// race at all).
#[test]
#[ignore]
fn d_trunc_lossless_deltas() {
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
    let slots = vec![
        SlotSpec::live("TSG0", 100, vec![(300, 0x4400)]),
        SlotSpec::live("TSG1", 101, vec![(301, 0x4401)]),
        SlotSpec::noimp("TSG2", 102),
        SlotSpec::noimp("TSG3", 103),
    ];
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    populate_alg_class(loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let d = drain(loaded);
    assert_calls_admitted(&d.calls, 1, "trunc-acc");
    assert_eq!(d.rets.len(), 1, "trunc-lossless: RET joined");
    ret_for(&d.rets, d.calls[0].tid, d.calls[0].seq);
    assert!(
        d.guards.is_empty(),
        "trunc-lossless: slot 511 EMPTY → no guard"
    );
    // Cold: every member walks — 2 OK + 2 NOIMP + 508 EMPTY.
    assert_eq!(d.algs.len(), 512, "trunc-lossless: every slot read once");
    assert_eq!(
        d.algs
            .iter()
            .filter(|a| a.status == wire::ALG_NOIMP)
            .count(),
        2,
        "trunc-lossless: both NOIMP slots explicit"
    );
    assert_eq!(
        d.rows.len(),
        2,
        "trunc-lossless: live slots dispatch rows only"
    );
    // First sighting attributes; quiet re-drain is empty
    // (consumed); the map bit stays (sticky, never cleared).
    let mut consumed = std::collections::BTreeMap::new();
    let mut last_seq = std::collections::BTreeMap::new();
    let delta =
        drain_trunc_flags(&mut consumed, &mut last_seq, &loaded.maps, None).expect("drain 1");
    assert_eq!(
        delta.get(&OP),
        Some(&wire::TRUNC_WALK_NOIMP),
        "trunc-lossless: first sighting attributes"
    );
    let delta =
        drain_trunc_flags(&mut consumed, &mut last_seq, &loaded.maps, None).expect("drain 2");
    assert!(
        delta.is_empty(),
        "trunc-lossless: quiet re-drain reports nothing"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        wire::TRUNC_WALK_NOIMP,
        "trunc-lossless: map bit intact (never cleared)"
    );
    // Repeat fault (same bit re-flagged by a second identical
    // query): the generation advanced, so the op's set bits
    // re-report (recurring faults stay visible).
    pace_fire_gap();
    fire(OP as i32, 1);
    let _ = drain(loaded);
    let delta =
        drain_trunc_flags(&mut consumed, &mut last_seq, &loaded.maps, None).expect("drain 3");
    assert_eq!(
        delta.get(&OP),
        Some(&wire::TRUNC_WALK_NOIMP),
        "trunc-lossless: repeat fault re-reports"
    );
    // Injected just after the snapshot: absent from this delta,
    // present in the next (delayed one drain, never lost).
    let hook = || stage_trunc(loaded, OP + 1, wire::TRUNC_ALGS);
    let delta = drain_trunc_flags(&mut consumed, &mut last_seq, &loaded.maps, Some(&hook))
        .expect("drain 4");
    assert!(
        !delta.contains_key(&(OP + 1)),
        "trunc-lossless: post-snapshot flag not in this delta"
    );
    let delta =
        drain_trunc_flags(&mut consumed, &mut last_seq, &loaded.maps, None).expect("drain 5");
    assert_eq!(
        delta.get(&(OP + 1)),
        Some(&wire::TRUNC_ALGS),
        "trunc-lossless: post-snapshot flag lands next drain"
    );
    assert_retired(loaded, tid, "trunc-lossless");
    assert_loss_zero(loaded);
    // Concurrent cell (fresh attach — clean generation map):
    // two worker threads pinned to different CPUs fire the
    // same NOIMP table concurrently (paced: bucket + storm
    // quiet). Per-CPU single-writer slots make the summed
    // generation EXACT regardless of interleaving or placement
    // (no read-modify-write anywhere — no lost increments, no
    // stale-writer rollback, deterministically).
    {
        let attached2 = attach_chunk(&obj, &exe, off);
        let loaded2 = &attached2.loaded;
        populate_alg_class(loaded2, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        let barrier = std::sync::Barrier::new(3);
        let tids = std::sync::Mutex::new(Vec::new());
        let pins = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for cpu in [0usize, 1usize] {
                let barrier = &barrier;
                let tids = &tids;
                let pins = &pins;
                s.spawn(move || {
                    // Pin to force cross-CPU increments; each
                    // worker records its pin outcome for the
                    // slot proof below (R19 minor-1).
                    let ok = unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(cpu, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) == 0
                    };
                    if !ok {
                        eprintln!("trunc-lossless: pin to CPU {cpu} failed, continuing");
                    }
                    pins.lock().unwrap().push(ok);
                    let tid = self_tid();
                    tids.lock().unwrap().push(tid);
                    barrier.wait();
                    barrier.wait();
                    for _ in 0..10 {
                        pace_fire_gap();
                        fire(OP as i32, 1);
                    }
                });
            }
            barrier.wait();
            let tids = tids.lock().unwrap().clone();
            assert_eq!(tids.len(), 2, "trunc-lossless: two workers publish");
            assert_ne!(tids[0], tids[1]);
            let mut state = BirthState::new();
            register(loaded2, &mut state, &tids);
            barrier.wait();
        });
        let _ = drain(loaded2);
        // R19 minor-1: the cross-CPU proof needs two online CPUs
        // and two successful pins; without either, the slot
        // assertion would prove nothing.
        let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if ncpu < 2 {
            eprintln!("SKIP: single-CPU host cannot prove cross-CPU placement");
            return;
        }
        {
            let pins = pins.lock().unwrap();
            assert_eq!(pins.len(), 2, "trunc-lossless: two workers report pins");
            if !pins.iter().all(|p| *p) {
                panic!("affinity failure on multi-CPU host: cross-CPU proof impossible");
            }
        }
        assert_eq!(
            read_percpu(loaded2, "TRUNC_SEQ", OP, false),
            40,
            "trunc-lossless: concurrent generations sum exactly (2 threads x 10 fires x 2 NOIMP)"
        );
        let slots = read_percpu_slots(loaded2, "TRUNC_SEQ", OP);
        assert!(
            slots.iter().filter(|s| **s > 0).count() >= 2,
            "trunc-lossless: two contributing CPU slots prove cross-CPU placement: {slots:?}"
        );
        assert_eq!(
            read_percpu(loaded2, "TRUNC", OP, true),
            wire::TRUNC_WALK_NOIMP,
            "trunc-lossless: sticky bit holds NOIMP"
        );
        let mut consumed2 = std::collections::BTreeMap::new();
        let mut last_seq2 = std::collections::BTreeMap::new();
        let delta = drain_trunc_flags(&mut consumed2, &mut last_seq2, &loaded2.maps, None)
            .expect("concurrent drain");
        assert_eq!(
            delta.get(&OP),
            Some(&wire::TRUNC_WALK_NOIMP),
            "trunc-lossless: concurrent faults attribute"
        );
        assert_loss_zero(loaded2);
    }
}

/// Round-2 F5: the T+1 member never skips silently (warm T=3 +
/// zero verdict). Cell 1 — growth by one (table T=4): member 4
/// reads zero and emits the boundary ALG_EMPTY (the fresh
/// terminator proof the oracle stales the cache from); members 5+
/// stay silent. Cell 2 — growth by N (slots 4,5 live, terminator
/// at 6): member 4 cold-walks the live slot (growth evidence —
/// an OK record, never EMPTY), members 5+ stay silent (the
/// silent terminator at 6 is covered by member 4's walked
/// evidence — the oracle stales from walked-beyond).
#[test]
#[ignore]
fn d_warm_boundary_proof() {
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
    // Cell 1: slots 0..=3 live, terminator at 4 (cached T=3).
    let slots1: Vec<SlotSpec> = (0..4u32)
        .map(|j| {
            SlotSpec::live(
                &format!("WBP{j}"),
                100 + j as u16,
                vec![(300 + j, 0x4400 + j as u64)],
            )
        })
        .collect();
    let fx1 = Fixture::build_padded(&slots1, &[], 513);
    fx1.pretouch();
    populate_alg_class(loaded, &fx1.classes);
    FIXTURE_ARRAY.store(fx1.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    write_tcache(loaded, fx1.array, 3, 0);
    fire(OP as i32, 1);
    let d1 = drain(loaded);
    assert_calls_admitted(&d1.calls, 1, "warm-boundary-1");
    assert_eq!(d1.rets.len(), 1, "warm-boundary-1: RET joined");
    ret_for(&d1.rets, d1.calls[0].tid, d1.calls[0].seq);
    for j in 0..4u64 {
        let got: Vec<_> = d1.algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 1, "warm-boundary-1: slot {j} walked");
        assert_eq!(got[0].status, wire::ALG_OK);
    }
    let b1: Vec<_> = d1.algs.iter().filter(|a| a.idx == 4).collect();
    assert_eq!(b1.len(), 1, "warm-boundary-1: T+1 proves termination");
    assert_eq!(b1[0].status, wire::ALG_EMPTY);
    assert!(
        d1.algs.iter().all(|a| a.idx <= 4) && d1.rows.iter().all(|r| r.idx <= 3),
        "warm-boundary-1: members 5+ silent"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "warm-boundary-1: TRUNC clean"
    );
    // Cell 2: slots 0..=5 live, terminator at 6 (cached T=3).
    let slots2: Vec<SlotSpec> = (0..6u32)
        .map(|j| {
            SlotSpec::live(
                &format!("WBQ{j}"),
                200 + j as u16,
                vec![(400 + j, 0x5500 + j as u64)],
            )
        })
        .collect();
    let fx2 = Fixture::build_padded(&slots2, &[], 513);
    fx2.pretouch();
    populate_alg_class(loaded, &fx2.classes);
    pace_fire_gap();
    clear_trunc(loaded, "warm-boundary-2");
    FIXTURE_ARRAY.store(fx2.array, Ordering::SeqCst);
    write_tcache(loaded, fx2.array, 3, 0);
    fire(OP as i32, 1);
    let d2 = drain(loaded);
    assert_calls_admitted(&d2.calls, 1, "warm-boundary-2");
    assert_eq!(d2.rets.len(), 1, "warm-boundary-2: RET joined");
    ret_for(&d2.rets, d2.calls[0].tid, d2.calls[0].seq);
    let w4: Vec<_> = d2.algs.iter().filter(|a| a.idx == 4).collect();
    assert_eq!(w4.len(), 1, "warm-boundary-2: T+1 cold-walks live slot");
    assert_eq!(w4[0].status, wire::ALG_OK);
    assert_eq!(
        d2.rows.iter().filter(|r| r.idx == 4).count(),
        1,
        "warm-boundary-2: walked slot dispatches its row"
    );
    assert!(
        d2.algs.iter().all(|a| a.idx <= 4) && d2.rows.iter().all(|r| r.idx <= 4),
        "warm-boundary-2: members 5+ silent (terminator at 6 covered)"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "warm-boundary-2: TRUNC clean"
    );
    // Cell 3: 127 live slots, terminator at 127 (cached T=127),
    // slot 128 (T+1) UNMAPPED. Inaccessible-beyond-T is not
    // growth (live requires readable) — member 128 stays silent
    // with NO flag (the walked terminator at 127 stands), so a
    // valid warm table Completes instead of Partialling on a
    // phantom READ.
    let slots3: Vec<SlotSpec> = (0..127u32)
        .map(|j| {
            SlotSpec::live(
                &format!("WBR{j}"),
                300 + (j % 200) as u16,
                vec![(600 + j, 0x6600 + j as u64)],
            )
        })
        .collect();
    // Array spans exactly 2 pages (256 cells); names/dispatch
    // live on page 2+. Unmapping page 1 takes slots 128..255
    // (T+1 inaccessible) and nothing else.
    let fx3 = Fixture::build_padded(&slots3, &[], 256);
    fx3.pretouch();
    populate_alg_class(loaded, &fx3.classes);
    pace_fire_gap();
    clear_trunc(loaded, "warm-boundary-3");
    FIXTURE_ARRAY.store(fx3.array, Ordering::SeqCst);
    write_tcache(loaded, fx3.array, 127, 0);
    assert_eq!(
        unsafe { libc::munmap((fx3.array + 4096) as *mut libc::c_void, 4096) },
        0,
        "warm-boundary-3: unmap T+1 page"
    );
    fire(OP as i32, 1);
    let d3 = drain(loaded);
    assert_calls_admitted(&d3.calls, 1, "warm-boundary-3");
    assert_eq!(d3.rets.len(), 1, "warm-boundary-3: RET joined");
    ret_for(&d3.rets, d3.calls[0].tid, d3.calls[0].seq);
    for j in 0..127u64 {
        let got: Vec<_> = d3.algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 1, "warm-boundary-3: slot {j} walked");
        assert_eq!(got[0].status, wire::ALG_OK);
    }
    let t127: Vec<_> = d3.algs.iter().filter(|a| a.idx == 127).collect();
    assert_eq!(t127.len(), 1, "warm-boundary-3: terminator walked");
    assert_eq!(t127[0].status, wire::ALG_EMPTY);
    assert!(
        d3.algs.iter().all(|a| a.idx <= 127) && d3.rows.iter().all(|r| r.idx <= 126),
        "warm-boundary-3: T+1 silent on inaccessible slot"
    );
    assert_eq!(
        read_percpu(loaded, "TRUNC", OP, true),
        0,
        "warm-boundary-3: inaccessible T+1 flags nothing"
    );
    assert!(d3.guards.is_empty(), "warm-boundary-3: no guard");
    assert_retired(loaded, tid, "warm-boundary");
    assert_loss_zero(loaded);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 3);
}

/// R19: one query with later slots through the production backend
/// (E=256 — the terminator sits deep in the array, past the early
/// prefix the small fixtures exercise). Past-T is zero by
/// construction (padded) — the T-gate is D's proven fact; what's
/// under test here is the backend join at depth through production
/// closure: the lone query stays open on its poll (quiesced=false
/// — no successor), the successor's take closes it (exact TRUE-T,
/// exact counts, warms T_CACHE @256), and the window-edge
/// backstop closes the trailing warm query (cached close, no
/// rewrite). No guard joins either verdict: slot 511 is EMPTY, so
/// the cold scan is guard-ineligible (eligibility gates on slot
/// 511 names, not on slot 512) — and T ≤ 511 is established by
/// the explicit EMPTY terminator, which needs no positional proof.
#[test]
#[ignore]
fn r19_backend_later_slots() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    let mut backend = backend_chunk(&obj, &exe, off);
    let slots: Vec<SlotSpec> = (0..256u32)
        .map(|j| {
            SlotSpec::live(
                &format!("M9A{j:03}"),
                100 + j as u16,
                vec![(7000 + j, 0xA000 + j as u64)],
            )
        })
        .collect();
    let fx = Fixture::build_padded(&slots, &[], 513);
    fx.pretouch();
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    // Fire 1 (cold): the lone query stays open — production polls
    // quiesced=false, so opens close on successor takes, never on
    // retirement inference.
    fire(OP as i32, 1);
    let d1 = backend.poll().expect("backend poll 1");
    assert!(d1.findings.is_empty(), "later-slots: no findings");
    assert!(
        d1.done.is_empty(),
        "later-slots: lone query stays open (no successor)"
    );
    // Fire 2: the successor's take closes query 1 — cold Complete
    // @256, warms T_CACHE @256. Every walked slot emits exactly
    // one ALG read-status (256 live + 256 explicit EMPTY); only
    // live slots dispatch rows.
    fire(OP as i32, 1);
    let d2 = backend.poll().expect("backend poll 2");
    assert_eq!(d2.done.len(), 1, "later-slots: successor closes query 1");
    let w1 = &d2.done[0];
    assert_eq!((w1.tid, w1.op, w1.arr), (self_tid(), OP, fx.array));
    assert_eq!(
        w1.outcome,
        Outcome::Complete {
            true_t: 256,
            cached: false
        },
        "later-slots: cold Complete @256"
    );
    assert_eq!(w1.true_t, TrueT::Proven(256));
    assert_eq!((w1.alg_count, w1.row_count), (512, 256));
    assert!(
        w1.guard.is_none(),
        "later-slots: no guard (slot 511 EMPTY → cold-ineligible)"
    );
    assert!(
        d2.actions.iter().any(
            |a| matches!(a, BackendAction::CacheWarmed { arr, t } if *arr == fx.array && *t == 256)
        ),
        "later-slots: warms T_CACHE @256, got {:?}",
        d2.actions
    );
    assert!(
        d2.actions
            .iter()
            .all(|a| !matches!(a, BackendAction::Detached | BackendAction::SkipAllEngaged)),
        "later-slots: no storm/throttle"
    );
    // Fire 3: the successor's take closes query 2 — a cold
    // re-proof, not a cached ride (query 2 fired before query 1
    // closed, so the cache was empty at its fire time; its gen-0
    // stamp against epoch 1 is the benign unrecorded-at-fire
    // race, never GenStale). Full cold evidence re-proves
    // T=256: Complete, uncached, no rewrite.
    fire(OP as i32, 1);
    let d3 = backend.poll().expect("backend poll 3");
    assert_eq!(d3.done.len(), 1, "later-slots: successor closes query 2");
    let w2 = &d3.done[0];
    assert_eq!(
        w2.outcome,
        Outcome::Complete {
            true_t: 256,
            cached: false
        },
        "later-slots: cold re-proof Complete @256"
    );
    assert_eq!(w2.true_t, TrueT::Proven(256));
    assert_eq!((w2.alg_count, w2.row_count), (512, 256));
    assert!(
        w2.guard.is_none(),
        "later-slots: no guard on the re-proof either (slot 511 EMPTY)"
    );
    assert_eq!(w2.seq, w1.seq + 1, "later-slots: seq advances");
    assert!(
        d3.actions
            .iter()
            .all(|a| !matches!(a, BackendAction::CacheWarmed { .. })),
        "later-slots: no rewrite on re-proof"
    );
    // Window edge: the backstop closes query 3 — the true cached
    // ride (fired post-warming, stamped gen 1, T-gated walk: the
    // 256 live slots emit ALG/ROW evidence, member 256 walks the
    // EMPTY terminator, and member 257 (T+1) emits the boundary
    // EMPTY — the warm verdict never coasts on an unverified T,
    // and growth by one is caught at the boundary).
    let d4 = backend.finish().expect("backend finish");
    assert_eq!(d4.done.len(), 1, "later-slots: backstop closes query 3");
    let w3 = &d4.done[0];
    assert_eq!(
        w3.outcome,
        Outcome::Complete {
            true_t: 256,
            cached: true
        },
        "later-slots: cached Complete @256"
    );
    assert_eq!(w3.true_t, TrueT::Proven(256));
    // 256 OK + walked EMPTY@256 + T+1 boundary EMPTY@257 (members
    // 258+ stay silent — covered by T+1).
    assert_eq!((w3.alg_count, w3.row_count), (258, 256));
    assert!(
        w3.guard.is_none(),
        "later-slots: no guard on the warm close (T=256 ≠ 512)"
    );
    assert_eq!(w3.seq, w2.seq + 1, "later-slots: seq advances");
    assert!(
        d4.actions
            .iter()
            .all(|a| !matches!(a, BackendAction::CacheWarmed { .. })),
        "later-slots: no rewrite on cached close"
    );
    // End-state: retired + silent loss planes + all queries counted.
    let loaded = backend.loaded();
    assert_retired(loaded, self_tid(), "later-slots");
    assert_loss_zero(loaded);
    assert_eq!(read_percpu(loaded, "CALLS", OP, false), 3);
    assert_eq!(read_percpu(loaded, "TRUNC", OP, true), 0);
}

/// R19: the 512/513 termination boundary through the production
/// backend and production closure. Producer shapes mirror L6
/// (512-clean: GUARD EMPTY, TRUNC clear; 513-live: GUARD VALID,
/// TRUNC_ALGS, slot 512 unwalked); what's under test is the
/// backend close — 512 completes (cold, then cached with a fresh
/// boundary proof every scan), 513 closes Partial with the
/// Overfull reason and TRUE-T demoted to Candidate(512), never
/// Proven. Each lone query stays open on its own poll; the
/// successor's take closes the predecessor and the window-edge
/// backstop closes the trailer.
#[test]
#[ignore]
fn r19_backend_termination_512_513() {
    use osslscope_ebpf_common as wire;
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let exe = own_exe_cstr();
    let off = query_off();
    // 512-clean: cold Complete, then the cached close with its own
    // fresh EMPTY guard (a 512 belief still needs its boundary
    // proof every scan — the warm verdict never coasts).
    {
        let slots: Vec<SlotSpec> = (0..512u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("M9B{j:03}"),
                    100 + j as u16,
                    vec![(7000 + j, 0xA000 + j as u64)],
                )
            })
            .collect();
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        let mut backend = backend_chunk(&obj, &exe, off);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d1 = backend.poll().expect("backend poll 512-1");
        assert!(
            d1.done.is_empty(),
            "512-clean: lone query stays open (no successor)"
        );
        fire(OP as i32, 1);
        let d2 = backend.poll().expect("backend poll 512-2");
        assert_eq!(d2.done.len(), 1, "512-clean: successor closes query 1");
        let w1 = &d2.done[0];
        assert_eq!(
            w1.outcome,
            Outcome::Complete {
                true_t: 512,
                cached: false
            },
            "512-clean: cold Complete @512"
        );
        assert_eq!(w1.true_t, TrueT::Proven(512));
        assert_eq!((w1.alg_count, w1.row_count), (512, 512));
        let g = w1.guard.as_ref().expect("512-clean: guard joined");
        assert_eq!(
            (g.kind, g.op, g.verdict, g.arr),
            (wire::KIND_GUARD, OP, wire::GUARD_EMPTY, fx.array),
            "512-clean: EMPTY guard"
        );
        // Query 2 fired before query 1 closed (cache empty at
        // its fire time): a cold re-proof — full 512 walk, fresh
        // EMPTY guard, Complete uncached. The gen-0 stamp against
        // epoch 1 is the benign race, never GenStale.
        fire(OP as i32, 1);
        let d3 = backend.poll().expect("backend poll 512-3");
        assert_eq!(d3.done.len(), 1, "512-clean: successor closes query 2");
        let w2 = &d3.done[0];
        assert_eq!(
            w2.outcome,
            Outcome::Complete {
                true_t: 512,
                cached: false
            },
            "512-clean: cold re-proof Complete @512"
        );
        assert_eq!(w2.true_t, TrueT::Proven(512));
        assert_eq!((w2.alg_count, w2.row_count), (512, 512));
        let g2 = w2.guard.as_ref().expect("512-clean: re-proof guard joined");
        assert_eq!(
            g2.verdict,
            wire::GUARD_EMPTY,
            "512-clean: re-proof carries its own fresh EMPTY guard"
        );
        assert_eq!(w2.seq, w1.seq + 1, "512-clean: seq advances");
        // Query 3 fired post-warming: the true cached ride (warm
        // T=512 walk + its own fresh EMPTY guard — a 512 belief
        // still needs its boundary proof every scan; the warm
        // verdict never coasts).
        let d4 = backend.finish().expect("backend finish 512");
        assert_eq!(d4.done.len(), 1, "512-clean: backstop closes query 3");
        let w3 = &d4.done[0];
        assert_eq!(
            w3.outcome,
            Outcome::Complete {
                true_t: 512,
                cached: true
            },
            "512-clean: cached Complete @512"
        );
        assert_eq!(w3.true_t, TrueT::Proven(512));
        let g3 = w3.guard.as_ref().expect("512-clean: warm guard joined");
        assert_eq!(
            g3.verdict,
            wire::GUARD_EMPTY,
            "512-clean: warm close carries its own fresh EMPTY guard"
        );
        assert_eq!(w3.seq, w2.seq + 1, "512-clean: seq advances");
        let loaded = backend.loaded();
        assert_retired(loaded, self_tid(), "512-clean");
        assert_loss_zero(loaded);
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 3);
        assert_eq!(read_percpu(loaded, "TRUNC", OP, true), 0);
    }
    // 513-live: Partial{Trunc, Overfull}, VALID guard, no warm.
    // The trailer re-fires the overfull walk, so its TRUNC_ALGS
    // flag re-reports (generation advanced) — Partial again
    // with the identical reasons, never a quiet downgrade.
    {
        let slots: Vec<SlotSpec> = (0..513u32)
            .map(|j| {
                SlotSpec::live(
                    &format!("M9C{j:03}"),
                    100 + (j % 512) as u16,
                    vec![(7000 + j, 0xA000 + j as u64)],
                )
            })
            .collect();
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        let mut backend = backend_chunk(&obj, &exe, off);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        fire(OP as i32, 1);
        let d1 = backend.poll().expect("backend poll 513-1");
        assert!(d1.findings.is_empty(), "513-live: no findings");
        assert!(
            d1.done.is_empty(),
            "513-live: lone query stays open (no successor)"
        );
        fire(OP as i32, 1);
        let d2 = backend.poll().expect("backend poll 513-2");
        assert_eq!(d2.done.len(), 1, "513-live: successor closes query 1");
        let w1 = &d2.done[0];
        assert_eq!(
            w1.outcome,
            Outcome::Partial {
                reasons: vec![
                    PartialReason::Overfull,
                    PartialReason::Trunc(wire::TRUNC_ALGS),
                ]
            },
            "513-live: Partial{{Overfull, Trunc}}"
        );
        assert_eq!(w1.true_t, TrueT::Candidate(512));
        assert_eq!((w1.alg_count, w1.row_count), (512, 512));
        let g = w1.guard.as_ref().expect("513-live: guard joined");
        assert_eq!(
            (g.op, g.verdict, g.arr),
            (OP, wire::GUARD_VALID, fx.array),
            "513-live: VALID guard"
        );
        assert!(
            d2.actions
                .iter()
                .all(|a| !matches!(a, BackendAction::CacheWarmed { .. })),
            "513-live: Partial never warms"
        );
        // Trailer: still Partial with identical reasons (nothing
        // warmed; the re-fired walk re-flags TRUNC_ALGS).
        let d3 = backend.finish().expect("backend finish 513");
        assert_eq!(d3.done.len(), 1, "513-live: backstop closes query 2");
        assert_eq!(
            d3.done[0].outcome, w1.outcome,
            "513-live: Partial again, identical reasons"
        );
        assert_eq!(d3.done[0].true_t, TrueT::Candidate(512));
        let loaded = backend.loaded();
        assert_retired(loaded, self_tid(), "513-live");
        assert_loss_zero(loaded);
        assert_eq!(read_percpu(loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(loaded, "TRUNC", OP, true),
            wire::TRUNC_ALGS,
            "513-live: TRUNC sticky (never cleared — both flags landed in verdicts via lossless deltas, none lost)"
        );
    }
}

// ===== R19 installed-path proof (F12) =====

/// Pinned vehicle (Ubuntu 3.5.5-1ubuntu3.7 — same pins as the P5d
/// suite: binary + libcrypto sha256 asserted before the run).
const F12_VEHICLE_BIN: &str = "/usr/bin/openssl";
const F12_VEHICLE_SHA256: &str = "1d72cbc5bf62be3f3dbd7626c295b63c5fdc1dd8439f323ac47998d8a062b4c9";
const F12_LIBCRYPTO: &str = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const F12_LIBCRYPTO_SHA256: &str =
    "5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28";

fn f12_sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn f12_assert_vehicle_pinned() {
    assert!(
        std::env::var_os("LD_LIBRARY_PATH").is_none(),
        "refusing to measure under LD_LIBRARY_PATH (loader substitution risk)"
    );
    assert!(
        std::env::var_os("LD_PRELOAD").is_none(),
        "refusing to measure under LD_PRELOAD (interposition risk)"
    );
    let out = std::process::Command::new(F12_VEHICLE_BIN)
        .arg("version")
        .output()
        .expect("vehicle runs");
    assert!(out.status.success(), "vehicle `openssl version` failed");
    let v = String::from_utf8_lossy(&out.stdout);
    assert!(v.contains("3.5.5"), "vehicle version drift: {v:?}");
    let digest = f12_sha256_hex(&std::fs::read(F12_VEHICLE_BIN).expect("read vehicle"));
    assert_eq!(digest, F12_VEHICLE_SHA256, "vehicle binary drift");
    let lib_digest = f12_sha256_hex(&std::fs::read(F12_LIBCRYPTO).expect("read libcrypto"));
    assert_eq!(lib_digest, F12_LIBCRYPTO_SHA256, "libcrypto drift");
}

/// Explicit enrollment table for the pinned build (same offsets
/// the P5d fixture pins — build-id + query + anchor). Unique path
/// per run, removed on drop.
struct F12Enrollment {
    path: std::path::PathBuf,
}

impl F12Enrollment {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!("f12-table-{}.json", std::process::id()));
        let content = r#"{"table_version": 1,
    "entries": [{"build_id": "0ebcfeaee273dc860b29e067d255def704185b41",
      "openssl": "3.5.5-1ubuntu3.7",
      "query_offset": 2577296,
      "anchor": "OSSL_PROVIDER_available",
      "anchor_offset": 2576784}]}"#;
        std::fs::write(&path, content).expect("write enrollment table");
        Self { path }
    }
}

impl Drop for F12Enrollment {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Root-owned install prefix under /usr/local (production trust
/// needs root-owned, non-writable ancestry — /tmp can never pass).
/// Removed (best-effort sudo) on drop, including unwind paths.
struct F12Prefix {
    path: std::path::PathBuf,
}

impl Drop for F12Prefix {
    fn drop(&mut self) {
        let st = std::process::Command::new("sudo")
            .args(["-n", "rm", "-rf"])
            .arg(&self.path)
            .status();
        if !st.map(|s| s.success()).unwrap_or(false) {
            eprintln!(
                "f12: WARN prefix cleanup failed for {}",
                self.path.display()
            );
        }
    }
}

/// Installed-path live prerequisites (shared by the F12 +
/// dispatch-blind legs): live gate, built triple, host binary,
/// passwordless sudo. Returns harvest/count/members/host-bin/
/// installer paths, or None after the labeled SKIP.
fn f12_prereqs(
    tag: &str,
) -> Option<(
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    let live = gated().or_else(|| {
        eprintln!("SKIP({tag}): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        None
    })?;
    let members_obj = live;
    let objdir = members_obj
        .parent()
        .expect("members object has a parent dir")
        .to_path_buf();
    let harvest_obj = objdir.join("osslscope-harvest");
    let count_obj = objdir.join("osslscope-count");
    for p in [&harvest_obj, &count_obj, &members_obj] {
        if !p.is_file() {
            eprintln!("SKIP({tag}): triple object missing: {}", p.display());
            return None;
        }
    }
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let host_bin = manifest_dir.join("target/debug/osslscope");
    if !host_bin.is_file() {
        eprintln!(
            "SKIP({tag}): host binary missing (cargo build first): {}",
            host_bin.display()
        );
        return None;
    }
    let sudo = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo {
        eprintln!("SKIP({tag}): needs passwordless sudo for the root-owned prefix");
        return None;
    }
    let installer = manifest_dir.join("scripts/install-dev.sh");
    Some((harvest_obj, count_obj, members_obj, host_bin, installer))
}

/// Installer-laid prefix (the REAL installer, explicit object
/// overrides — no manifest dependence). Returns the prefix guard
/// + installed object dir.
fn f12_install_prefix(
    tag: &str,
    harvest_obj: &std::path::Path,
    count_obj: &std::path::Path,
    members_obj: &std::path::Path,
    host_bin: &std::path::Path,
    installer: &std::path::Path,
) -> (F12Prefix, std::path::PathBuf) {
    let prefix = F12Prefix {
        path: std::path::PathBuf::from(format!("/usr/local/osslscope-f12-{}", std::process::id())),
    };
    let st = std::process::Command::new("sudo")
        .arg("-n")
        .arg(installer)
        .arg("--prefix")
        .arg(&prefix.path)
        .arg("--binary")
        .arg(host_bin)
        .arg("--harvest")
        .arg(harvest_obj)
        .arg("--count")
        .arg(count_obj)
        .arg("--members")
        .arg(members_obj)
        .status()
        .expect("run installer");
    assert!(st.success(), "{tag}: installer lays the triple");
    let installed_dir = prefix.path.join("lib").join("osslscope");
    assert!(
        installed_dir.join("osslscope-members").is_file(),
        "{tag}: members installed"
    );
    (prefix, installed_dir)
}

/// F12 paced multi-op workload (C, compiled to temp): one
/// fresh-libctx fetch per iteration, 300ms apart — every query
/// admits (tier-1 bucket: burst 4, 40/s refill), unlike a burst
/// workload that correctly skips almost everything. Each fetch
/// queries the default provider through the traversal anchor;
/// alternating digest/cipher ops spreads verdicts across provider
/// tables. Attachments: none (links `-lcrypto`, default paths).
const F12_WORKLOAD_C: &str = r#"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    const char *mds[] = {"SHA256", "SHA512"};
    const char *ciphers[] = {"AES-128-CBC", "AES-256-CBC"};
    unsigned char buf[64];
    size_t len = 0;
    size_t olen = 0;
    for (int i = 0; i < 12; i++) {
        OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
        if (!ctx) { fprintf(stderr, "f12work: libctx\n"); return 1; }
        OSSL_PROVIDER *def = OSSL_PROVIDER_load(ctx, "default");
        if (!def) { fprintf(stderr, "f12work: provider\n"); return 1; }
        /* One fetch per iteration (alternate ops): intra-iteration
           queries stay under the tier-1 burst. */
        if (i % 2 == 0) {
            EVP_MD *md = EVP_MD_fetch(ctx, mds[(i / 2) % 2], NULL);
            if (!md) { fprintf(stderr, "f12work: md fetch\n"); return 1; }
            if (!EVP_Q_digest(ctx, mds[(i / 2) % 2], NULL, "abc", 3, buf, &len))
                { fprintf(stderr, "f12work: digest\n"); return 1; }
            EVP_MD_free(md);
        } else {
            EVP_CIPHER *c = EVP_CIPHER_fetch(ctx, ciphers[(i / 2) % 2], NULL);
            if (!c) { fprintf(stderr, "f12work: cipher fetch\n"); return 1; }
            EVP_CIPHER_free(c);
            olen++;
        }
        OSSL_PROVIDER_unload(def);
        OSSL_LIB_CTX_free(ctx);
        if (i < 11) usleep(300000);
    }
    if (len == 0 || olen == 0) { fprintf(stderr, "f12work: void\n"); return 1; }
    return 0;
}
"#;

/// R19 F12: the installed triple observes REAL provider traffic
/// through the ordinary run — installer-laid prefix (production
/// trust), automatic triple selection (no explicit object flags),
/// paced multi-op workload (provider queries during the window),
/// ordinary close + report rendering. Asserts positive traversal
/// records with explicit verdicts, real below-terminator evidence
/// (registry classes — a misprobed offset walks garbage that can
/// never hash-match a known name), the exact installed triple in
/// the capture provenance and the rendered `traversal` section.
///
/// Verdict-shape note: real provider tables live in mapped
/// neighborhoods, so v1 full scans systematically observe
/// past-terminator soup (VALID guard + dispatch overflow) and
/// close Partial with explicit Trunc reasons — fail-closed per
/// F2/F3/F5, not a defect. No inventory adaptation exists
/// (round 3, F1): traversal evidence reports natively, and the
/// document inventory carries only count-observed executions.
#[test]
#[ignore]
fn r19_installed_positive_traffic() {
    use osslscope_ebpf_common as wire;
    let Some((harvest_obj, count_obj, members_obj, host_bin, installer)) = f12_prereqs("f12")
    else {
        return;
    };
    f12_assert_vehicle_pinned();
    // Compile the paced workload (needs a C compiler + system
    // libcrypto headers — lane prerequisites, skipped labeled).
    let work_src = std::env::temp_dir().join(format!("f12work-{}.c", std::process::id()));
    let work_bin = std::env::temp_dir().join(format!("f12work-{}", std::process::id()));
    std::fs::write(&work_src, F12_WORKLOAD_C).expect("write workload");
    let cc = std::process::Command::new("cc")
        .args([
            "-O2",
            "-o",
            work_bin.to_str().unwrap(),
            work_src.to_str().unwrap(),
            "-lcrypto",
        ])
        .status();
    std::fs::remove_file(&work_src).ok();
    match cc {
        Ok(s) if s.success() && work_bin.is_file() => {}
        _ => {
            eprintln!("SKIP(f12): C workload did not compile (needs cc + libcrypto headers)");
            return;
        }
    }
    struct F12WorkBin {
        path: std::path::PathBuf,
    }
    impl Drop for F12WorkBin {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).ok();
        }
    }
    let _work_bin = F12WorkBin {
        path: work_bin.clone(),
    };
    let enrollment = F12Enrollment::create();
    let (_prefix, installed_dir) = f12_install_prefix(
        "f12",
        &harvest_obj,
        &count_obj,
        &members_obj,
        &host_bin,
        &installer,
    );
    // Ordinary run, FULLY automatic (no explicit object flags —
    // the installed triple resolves via production trust +
    // receipt, exactly like a deployed run).
    let cfg = osslscope::capture::Config {
        harvest_object: None,
        count_object: None,
        members_object: None,
        provider: Some(std::path::PathBuf::from(F12_LIBCRYPTO)),
        builtin: true,
        table: Some(enrollment.path.clone()),
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: std::time::Duration::from_secs(10),
        settle: std::time::Duration::from_secs(2),
        harvest_timeout: std::time::Duration::from_secs(30),
        grace: std::time::Duration::from_secs(5),
        image_digest: String::new(),
    };
    let cap = osslscope::capture::run_with_dirs(
        &cfg,
        osslscope::capture::Target::Spawn {
            argv: vec![work_bin.to_str().unwrap().to_string()],
            workload: osslscope::target::WorkloadDest::Null,
        },
        std::slice::from_ref(&installed_dir),
        &osslscope::discovery::onboard::TrustPolicy::production(),
    )
    .expect("f12: ordinary run traverses");
    // The workload itself succeeded (a failing workload would
    // void the traffic evidence — fail loud, never vacuous).
    let disp = cap
        .document
        .disposition
        .as_ref()
        .expect("f12: disposition recorded");
    assert_eq!(
        (disp.outcome, disp.code),
        (osslscope::evidence::DispositionOutcome::Exited, Some(0)),
        "f12: workload exits 0"
    );
    // Traversal ran (not harvest-only) with the exact installed
    // triple (paths under the prefix, hashes of the installed
    // bytes — the reported identity IS the loaded bytes).
    let t = cap.traversal.as_ref().expect("f12: traversal ran");
    let prov = t.provenance.as_ref().expect("f12: triple provenance");
    for (role, p, installed) in [
        (
            "harvest",
            &prov.harvest,
            installed_dir.join("osslscope-harvest"),
        ),
        ("count", &prov.count, installed_dir.join("osslscope-count")),
        (
            "members",
            &prov.members,
            installed_dir.join("osslscope-members"),
        ),
    ] {
        assert_eq!(p.path, installed, "f12: {role} is the installed object");
        let digest = f12_sha256_hex(&std::fs::read(&installed).expect("read installed"));
        assert_eq!(p.sha256, digest, "f12: {role} hash binds installed bytes");
    }
    // POSITIVE records from real traffic (the core F12 ask —
    // round-1's smoke had polls but zero records), with explicit
    // verdicts (nothing silent, nothing dropped).
    let mut hist = std::collections::BTreeMap::new();
    for w in &t.done {
        let k = match &w.outcome {
            osslscope::scan::oracle::Outcome::Complete { .. } => "Complete",
            osslscope::scan::oracle::Outcome::Partial { .. } => "Partial",
            osslscope::scan::oracle::Outcome::Skipped { .. } => "Skipped",
            osslscope::scan::oracle::Outcome::Tainted { .. } => "Tainted",
            osslscope::scan::oracle::Outcome::Abandoned { .. } => "Abandoned",
        };
        *hist.entry(k).or_insert(0u64) += 1;
    }
    eprintln!(
        "f12: {} records, {} findings, {} polls, verdicts={:?}, detached={}",
        t.done.len(),
        t.findings.len(),
        t.polls,
        hist,
        t.detached
    );
    assert!(!t.done.is_empty(), "f12: positive traversal records");
    let admitted = t.done.len() - hist.get("Skipped").copied().unwrap_or(0) as usize;
    assert!(
        admitted >= 8,
        "f12: paced queries admit (got {admitted} admitted of {})",
        t.done.len()
    );
    assert!(
        !t.detached,
        "f12: paced traffic never storms (no tier-3 detach)"
    );
    for w in &t.done {
        if let osslscope::scan::oracle::Outcome::Partial { reasons } = &w.outcome {
            assert!(
                !reasons.is_empty(),
                "f12: Partial reasons explicit, never silent"
            );
        }
    }
    // Log one sample Partial's reasons + TRUE-T (mechanism
    // evidence: past-terminator soup degrades explicitly).
    if let Some(sample) = t
        .done
        .iter()
        .find(|w| matches!(w.outcome, osslscope::scan::oracle::Outcome::Partial { .. }))
    {
        eprintln!(
            "f12: sample Partial: outcome={:?} true_t={:?} algs={} rows={} guard={}",
            sample.outcome,
            sample.true_t,
            sample.alg_count,
            sample.row_count,
            sample.guard.is_some()
        );
    }
    // Real below-terminator evidence (registry classes below the
    // evidenced TRUE-T — a misprobed offset walks garbage that
    // can never hash-match a known name, so this validates the
    // anchor end to end).
    assert!(
        t.done.iter().any(|w| {
            let bound = match w.true_t {
                osslscope::scan::oracle::TrueT::Proven(t)
                | osslscope::scan::oracle::TrueT::Candidate(t) => t,
                _ => return false,
            };
            w.algs
                .iter()
                .any(|a| a.idx < bound && a.status == wire::ALG_OK && a.class != wire::OTHER_CLASS)
        }),
        "f12: real algorithm names below TRUE-T"
    );
    // No inventory adaptation exists (round 3, F1): traversal
    // evidence reports natively (records above), and the document
    // inventory carries only count-observed executions — the leg
    // asserts nothing synthetic here by construction.
    // Ordinary report rendering carries the traversal section with
    // the exact triple + positive record count.
    let json = osslscope::report::render_json(&cap.document).expect("f12: render");
    let v: serde_json::Value = serde_json::from_slice(&json).expect("f12: json parses");
    let tr = v.get("traversal").expect("f12: traversal section renders");
    assert!(
        tr.get("records").and_then(|n| n.as_u64()).unwrap_or(0) > 0,
        "f12: rendered records positive"
    );
    assert_eq!(
        tr.get("members")
            .and_then(|m| m.get("path"))
            .and_then(|p| p.as_str()),
        Some(installed_dir.join("osslscope-members").to_str().unwrap()),
        "f12: rendered triple names the installed members"
    );
}

/// R19 F6/init-mode: automatic selection for an init-mode
/// (file-provider) run degrades to harvest-only — the triple
/// resolves, the session attaches the init pair, but no builtin
/// query anchor ever pins, so traversal stands down (never
/// refuses the run, never guesses an offset). Asserts the run
/// succeeds with NO traversal capture and NO traversal section
/// in the rendered report (harvest-only, exactly like round 0).
#[test]
#[ignore]
fn r19_init_mode_degrades_harvest_only() {
    let Some((harvest_obj, count_obj, members_obj, host_bin, installer)) = f12_prereqs("degrade")
    else {
        return;
    };
    // System legacy provider (init anchor via dynsym — drift-proof,
    // no pin needed). Skipped labeled when the lane lacks it.
    let legacy = std::path::PathBuf::from("/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so");
    if !legacy.is_file() {
        eprintln!("SKIP(degrade): no system legacy provider module");
        return;
    }
    let (_prefix, installed_dir) = f12_install_prefix(
        "degrade",
        &harvest_obj,
        &count_obj,
        &members_obj,
        &host_bin,
        &installer,
    );
    let cfg = osslscope::capture::Config {
        harvest_object: None,
        count_object: None,
        members_object: None,
        provider: Some(legacy),
        builtin: false,
        table: None,
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: std::time::Duration::from_secs(6),
        settle: std::time::Duration::from_secs(2),
        harvest_timeout: std::time::Duration::from_secs(30),
        grace: std::time::Duration::from_secs(5),
        image_digest: String::new(),
    };
    let cap = osslscope::capture::run_with_dirs(
        &cfg,
        osslscope::capture::Target::Spawn {
            argv: vec![F12_VEHICLE_BIN.to_string(), "version".to_string()],
            workload: osslscope::target::WorkloadDest::Null,
        },
        std::slice::from_ref(&installed_dir),
        &osslscope::discovery::onboard::TrustPolicy::production(),
    )
    .expect("degrade: init-mode run succeeds harvest-only");
    assert!(
        cap.traversal.is_none(),
        "degrade: no traversal without an anchor"
    );
    let json = osslscope::report::render_json(&cap.document).expect("degrade: render");
    let v: serde_json::Value = serde_json::from_slice(&json).expect("degrade: json parses");
    assert!(
        v.get("traversal").is_none(),
        "degrade: harvest-only report carries no traversal section"
    );
}

/// F12 boundary provider: fixed C parts (stub dispatches +
/// query + init). Tables are generated by the leg (entries
/// cycle canonical registry spellings — verified present, so
/// every slot classifies OK with zero fixture populate).
const F12BOUND_PROV_HEAD: &str = r#"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

static void *stub_new(void *provctx) { (void)provctx; return (void *)0x1; }
static void stub_free(void *ctx) { (void)ctx; }
static int stub_init(void *ctx, unsigned char *out) { (void)ctx; (void)out; return 1; }
static int stub_update(void *ctx, const unsigned char *in, size_t inl) {
    (void)ctx; (void)in; (void)inl; return 1;
}
static int stub_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz) {
    (void)ctx; (void)out; (void)outsz;
    if (outl) *outl = 0;
    return 1;
}
static int stub_digest(void *provctx, const unsigned char *in, size_t inl,
                       unsigned char *out, size_t *outl, size_t outsz) {
    (void)provctx; (void)in; (void)inl; (void)out; (void)outsz;
    if (outl) *outl = 0;
    return 1;
}
static void *stub_dup(void *ctx) { return ctx; }
static int stub_get_params(const OSSL_PARAM *p) { (void)p; return 1; }
static const OSSL_PARAM *stub_gettable(void *a, void *b) { (void)a; (void)b; return NULL; }
static int stub_c_init(void *cctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen, const OSSL_PARAM *params) {
    (void)cctx; (void)key; (void)keylen; (void)iv; (void)ivlen; (void)params;
    return 1;
}
static int stub_c_update(void *cctx, unsigned char *out, size_t *outl, size_t outsz,
                         const unsigned char *in, size_t inl) {
    (void)cctx; (void)out; (void)outsz; (void)in; (void)inl;
    if (outl) *outl = 0;
    return 1;
}

static const OSSL_DISPATCH ddisp[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))stub_new },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))stub_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))stub_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))stub_final },
    { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))stub_digest },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))stub_free },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))stub_dup },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))stub_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))stub_gettable },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH cdisp[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))stub_new },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))stub_c_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))stub_c_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))stub_c_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))stub_final },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))stub_free },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))stub_dup },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))stub_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))stub_gettable },
    OSSL_DISPATCH_END
};

"#;

/// Canonical spellings cycled through the boundary tables
/// (verified present in the registry at leg start — every
/// slot classifies OK).
const F12BOUND_DIGEST_NAMES: &[&str] = &[
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA224",
    "SHA512-224",
    "SHA512-256",
    "SHA3-256",
    "SHA3-512",
];
const F12BOUND_CIPHER_NAMES: &[&str] = &[
    "AES-128-CBC",
    "AES-256-CBC",
    "AES-128-GCM",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "ARIA-128-CBC",
    "CAMELLIA-128-CBC",
    "DES-EDE3-CBC",
];

/// F12 boundary workload: fresh libctx, load ONLY the boundary
/// provider, fetch one digest + one cipher (argv[1..=2]).
/// Two queries, no pacing needed (bucket burst covers).
const F12BOUND_WORK_C: &str = r#"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "f12bound: need md + cipher names\n"); return 3; }
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) { fprintf(stderr, "f12bound: libctx\n"); return 1; }
    OSSL_PROVIDER *p = OSSL_PROVIDER_load(ctx, "f12bound");
    if (!p) { fprintf(stderr, "f12bound: provider load\n"); return 1; }
    EVP_MD *md = EVP_MD_fetch(ctx, argv[1], NULL);
    EVP_CIPHER *c = EVP_CIPHER_fetch(ctx, argv[2], NULL);
    int ok = (md != NULL) && (c != NULL);
    if (md) EVP_MD_free(md);
    if (c) EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(p);
    OSSL_LIB_CTX_free(ctx);
    if (!ok) fprintf(stderr, "f12bound: fetch failed\n");
    return ok ? 0 : 2;
}
"#;

/// R19 F12: the 512/513 termination boundary through the
/// INSTALLED ordinary path (the brief's checkbox 5: "through
/// that production path" — backend-direct no longer suffices).
/// A controlled provider (512-live digest table + 513-live
/// cipher table, cycled canonical spellings) served from a temp
/// modules dir; the installed triple (production trust,
/// automatic selection) observes the workload's two fetches
/// through the ordinary run. Asserts the digest close
/// Completes clean-full (Proven(512), EMPTY guard) and the
/// cipher close Partials boundary-exact (Overfull + Trunc with
/// a VALID guard), plus installed provenance and the rendered
/// traversal section incl. per-record entries.
#[test]
#[ignore]
fn r19_installed_termination_boundary() {
    use osslscope_ebpf_common as wire;
    let Some((harvest_obj, count_obj, members_obj, host_bin, installer)) = f12_prereqs("f12b")
    else {
        return;
    };
    f12_assert_vehicle_pinned();
    // Canonical spellings verified present (every table slot
    // must classify OK — fail loud on registry drift, never
    // silent UNKNOWN).
    for n in F12BOUND_DIGEST_NAMES
        .iter()
        .chain(F12BOUND_CIPHER_NAMES.iter())
    {
        assert!(
            osslscope::kinds::ALG_NAMES.iter().any(|a| a.name == *n),
            "f12b: registry spelling present: {n}"
        );
    }
    // Build the provider + workload under a temp modules dir.
    let moddir = std::env::temp_dir().join(format!("f12bound-{}", std::process::id()));
    std::fs::create_dir_all(&moddir).expect("modules dir");
    struct F12BoundDir {
        path: std::path::PathBuf,
    }
    impl Drop for F12BoundDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).ok();
        }
    }
    let _moddir = F12BoundDir {
        path: moddir.clone(),
    };
    let mut prov_src = String::from(F12BOUND_PROV_HEAD);
    prov_src.push_str("static const OSSL_ALGORITHM f12_digests[] = {\n");
    for j in 0..512usize {
        prov_src.push_str(&format!(
            "    {{ \"{}\", \"provider=f12bound\", ddisp, \"f12 boundary digest\" }},\n",
            F12BOUND_DIGEST_NAMES[j % F12BOUND_DIGEST_NAMES.len()]
        ));
    }
    prov_src.push_str("    { NULL, NULL, NULL, NULL },\n};\n\n");
    prov_src.push_str("static const OSSL_ALGORITHM f12_ciphers[] = {\n");
    for j in 0..513usize {
        prov_src.push_str(&format!(
            "    {{ \"{}\", \"provider=f12bound\", cdisp, \"f12 boundary cipher\" }},\n",
            F12BOUND_CIPHER_NAMES[j % F12BOUND_CIPHER_NAMES.len()]
        ));
    }
    prov_src.push_str("    { NULL, NULL, NULL, NULL },\n};\n\n");
    prov_src.push_str(
        r#"
static const OSSL_ALGORITHM *f12_query(void *provctx, int operation_id, int *no_cache) {
    (void)provctx; (void)no_cache;
    if (operation_id == OSSL_OP_DIGEST)
        return f12_digests;
    if (operation_id == OSSL_OP_CIPHER)
        return f12_ciphers;
    return NULL;
}

static const OSSL_DISPATCH f12_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))f12_query },
    OSSL_DISPATCH_END,
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx) {
    (void)handle; (void)in; (void)provctx;
    *out = f12_dispatch;
    return 1;
}
"#,
    );
    let prov_c = moddir.join("f12bound_prov.c");
    let prov_so = moddir.join("f12bound.so");
    let work_c = moddir.join("f12bound_work.c");
    let work_bin = moddir.join("f12bound_work");
    std::fs::write(&prov_c, &prov_src).expect("write provider");
    std::fs::write(&work_c, F12BOUND_WORK_C).expect("write workload");
    for (src, out, shared) in [
        (prov_c.to_str().unwrap(), prov_so.to_str().unwrap(), true),
        (work_c.to_str().unwrap(), work_bin.to_str().unwrap(), false),
    ] {
        let mut cmd = std::process::Command::new("cc");
        if shared {
            cmd.args(["-shared", "-fPIC"]);
        } else {
            cmd.arg("-O2");
        }
        let st = cmd
            .args(["-o", out, src, "-lcrypto"])
            .status()
            .expect("run cc");
        if !st.success() || !std::path::Path::new(out).is_file() {
            eprintln!("SKIP(f12b): boundary C sources did not compile");
            return;
        }
    }
    let enrollment = F12Enrollment::create();
    let (_prefix, installed_dir) = f12_install_prefix(
        "f12b",
        &harvest_obj,
        &count_obj,
        &members_obj,
        &host_bin,
        &installer,
    );
    let cfg = osslscope::capture::Config {
        harvest_object: None,
        count_object: None,
        members_object: None,
        provider: Some(std::path::PathBuf::from(F12_LIBCRYPTO)),
        builtin: true,
        table: Some(enrollment.path.clone()),
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: std::time::Duration::from_secs(10),
        settle: std::time::Duration::from_secs(2),
        harvest_timeout: std::time::Duration::from_secs(30),
        grace: std::time::Duration::from_secs(5),
        image_digest: String::new(),
    };
    // Point the child's module loader at our provider (restored
    // after — live legs run single-threaded (--test-threads=1),
    // so no other thread observes the swap).
    // SAFETY: live legs run single-threaded; no concurrent
    // readers/writers of the process environment exist here.
    let prev_modules = std::env::var_os("OPENSSL_MODULES");
    unsafe { std::env::set_var("OPENSSL_MODULES", &moddir) };
    let cap = osslscope::capture::run_with_dirs(
        &cfg,
        osslscope::capture::Target::Spawn {
            argv: vec![
                work_bin.to_str().unwrap().to_string(),
                F12BOUND_DIGEST_NAMES[0].to_string(),
                F12BOUND_CIPHER_NAMES[0].to_string(),
            ],
            workload: osslscope::target::WorkloadDest::Null,
        },
        std::slice::from_ref(&installed_dir),
        &osslscope::discovery::onboard::TrustPolicy::production(),
    )
    .expect("f12b: ordinary run traverses");
    // SAFETY: same single-threaded justification as above.
    match prev_modules {
        Some(v) => unsafe { std::env::set_var("OPENSSL_MODULES", v) },
        None => unsafe { std::env::remove_var("OPENSSL_MODULES") },
    };
    // Workload fetched both algs (else the queries never ran).
    let disp = cap
        .document
        .disposition
        .as_ref()
        .expect("f12b: disposition recorded");
    assert_eq!(
        (disp.outcome, disp.code),
        (osslscope::evidence::DispositionOutcome::Exited, Some(0)),
        "f12b: workload exits 0"
    );
    let t = cap.traversal.as_ref().expect("f12b: traversal ran");
    let prov = t.provenance.as_ref().expect("f12b: triple provenance");
    assert_eq!(
        prov.members.path,
        installed_dir.join("osslscope-members"),
        "f12b: installed members observed"
    );
    // Exactly the two fetches closed (provider load queries
    // nothing — spike-proven).
    assert_eq!(t.done.len(), 2, "f12b: one close per fetch");
    // 512-live digest table: clean-full Complete (Proven(512),
    // EMPTY guard, 512 OK, no TRUNC).
    let d512 = t
        .done
        .iter()
        .find(|w| w.true_t == osslscope::scan::oracle::TrueT::Proven(512))
        .expect("f12b: 512 close present");
    assert!(
        matches!(
            d512.outcome,
            osslscope::scan::oracle::Outcome::Complete { .. }
        ),
        "f12b: 512-live completes clean-full: {:?}",
        d512.outcome
    );
    assert_eq!(
        d512.algs
            .iter()
            .filter(|a| a.status == wire::ALG_OK)
            .count(),
        512,
        "f12b: 512 OK slots"
    );
    assert_eq!(
        d512.guard.as_ref().map(|g| g.verdict),
        Some(wire::GUARD_EMPTY),
        "f12b: EMPTY guard proves slot-512 zero"
    );
    // 513-live cipher table: boundary-exact Partial (Overfull +
    // Trunc with a VALID guard).
    let d513 = t
        .done
        .iter()
        .find(|w| w.true_t == osslscope::scan::oracle::TrueT::Candidate(512))
        .expect("f12b: 513 close present");
    assert_eq!(
        d513.outcome,
        osslscope::scan::oracle::Outcome::Partial {
            reasons: vec![
                osslscope::scan::oracle::PartialReason::Overfull,
                osslscope::scan::oracle::PartialReason::Trunc(wire::TRUNC_ALGS),
            ],
        },
        "f12b: 513-live Partial{{Overfull, Trunc}}"
    );
    assert_eq!(
        d513.guard.as_ref().map(|g| g.verdict),
        Some(wire::GUARD_VALID),
        "f12b: VALID guard"
    );
    // Known classes (registry hits — anchor validation, same
    // argument as F12).
    assert!(
        t.done.iter().any(|w| w
            .algs
            .iter()
            .any(|a| { a.status == wire::ALG_OK && a.class != wire::OTHER_CLASS })),
        "f12b: real algorithm names observed"
    );
    // Rendered report carries the traversal section with the
    // per-record entries (F1c live proof).
    let json = osslscope::report::render_json(&cap.document).expect("f12b: render");
    let v: serde_json::Value = serde_json::from_slice(&json).expect("f12b: json parses");
    let tr = v.get("traversal").expect("f12b: traversal section renders");
    assert_eq!(
        tr.get("records").and_then(|n| n.as_u64()),
        Some(2),
        "f12b: rendered records"
    );
    let entries = tr
        .get("entries")
        .and_then(|e| e.as_array())
        .expect("entries render");
    assert_eq!(entries.len(), 2, "f12b: one entry per close");
    assert!(
        entries
            .iter()
            .any(|e| e["outcome"].get("Complete").is_some()
                && e["true_t"] == serde_json::json!({"Proven": 512})),
        "f12b: Complete/Proven(512) entry renders"
    );
}
