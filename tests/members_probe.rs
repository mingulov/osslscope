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

use osslscope::loader::{Loaded, MEMBER_MAPS, MEMBER_PROGS};
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

fn load_members(obj: &std::path::Path) -> Loaded {
    raise_fd_limit();
    let bytes = std::fs::read(obj).expect("read members.o");
    let prep =
        osslscope::loader::prepare(&bytes, &MEMBER_MAPS, &MEMBER_PROGS).expect("prepare members.o");
    osslscope::loader::load(&prep).expect("load members.o")
}

/// Raise RLIMIT_NOFILE for the chunk's fd budget: 513 prog fds + 7
/// map fds + 513 link fds (all held — drop = detach) + clones +
/// stdio ≈ 1040 > the 1024 default (observed EMFILE at member_499).
/// Unprivileged (soft raise under the hard cap), fail-closed when
/// the hard cap itself is too small. Item-3 session carryover: the
/// production attach path must raise/check this too.
fn raise_fd_limit() {
    const WANT: libc::rlim_t = 8192;
    const NEED: libc::rlim_t = 4096;
    unsafe {
        let mut r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _),
            0,
            "getrlimit"
        );
        if r.rlim_cur < WANT {
            r.rlim_cur = std::cmp::min(WANT, r.rlim_max);
            assert_eq!(
                libc::setrlimit(libc::RLIMIT_NOFILE, &r as *const _),
                0,
                "setrlimit NOFILE"
            );
            assert_eq!(
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _),
                0,
                "getrlimit"
            );
        }
        assert!(
            r.rlim_cur >= NEED,
            "NOFILE {} below the 1033-fd chunk budget",
            r.rlim_cur
        );
    }
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

/// Attach the entry (cookie 512) + all 512 members (cookie = slot)
/// to `off` in our own image. `cookie_override` (L7) attaches one
/// member with a wrong cookie. Returns the links (drop = detach).
fn attach_all(
    loaded: &Loaded,
    exe: &std::ffi::CString,
    off: u64,
    cookie_override: Option<(u64, u64)>,
) -> (OwnedFd, Vec<OwnedFd>) {
    let pid = std::process::id();
    let entry_fd = loaded.progs["member_entry"].as_raw_fd();
    let entry = ossl_bpf_sys::link_create_uprobe_multi(
        entry_fd,
        exe,
        &[off],
        &[osslscope_ebpf_common::MEMBER_ENTRY_COOKIE],
        pid,
    )
    .expect("attach member_entry");
    let mut members = Vec::with_capacity(512);
    for j in 0..512u64 {
        let name = format!("member_{j:03}");
        let fd = loaded.progs[&name].as_raw_fd();
        let cookie = match cookie_override {
            Some((idx, c)) if idx == j => c,
            _ => j,
        };
        members.push(
            ossl_bpf_sys::link_create_uretprobe_multi(fd, exe, &[off], &[cookie], pid)
                .unwrap_or_else(|e| panic!("attach {name}: {e}")),
        );
    }
    (entry, members)
}

/// Drain the member EVENTS ring to parsed (ALG, ROW) events. Drops
/// nothing silently: unknown kinds fail loud (members emit only
/// ALG/ROW in v1 — no QUERY_RET, no WALK-DONE yet).
fn drain(
    loaded: &Loaded,
) -> (
    Vec<osslscope_ebpf_common::AlgEvent>,
    Vec<osslscope_ebpf_common::RowEvent>,
) {
    use aya::maps::{Map, MapData, RingBuf};
    use osslscope_ebpf_common as wire;
    let fd = loaded.maps["EVENTS"].try_clone().expect("clone EVENTS");
    let data = MapData::from_fd(fd).expect("EVENTS mapdata");
    let map = Map::from_map_data(data).expect("EVENTS map");
    let mut ring = RingBuf::try_from(map).expect("EVENTS ringbuf");
    let mut algs = Vec::new();
    let mut rows = Vec::new();
    while let Some(item) = ring.next() {
        let b = item.to_vec();
        assert!(b.len() >= 4, "short ring item: {} bytes", b.len());
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        match kind {
            wire::KIND_ALG => algs.push(wire::parse_alg_event(&b, 4096).expect("parse ALG")),
            wire::KIND_ROW => rows.push(wire::parse_row_event(&b).expect("parse ROW")),
            k => panic!("unexpected ring kind {k} (v1 emits ALG/ROW only)"),
        }
    }
    (algs, rows)
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

/// File offset of the query symbol in our own image (uprobe
/// attach point), via symtab + containing PT_LOAD.
fn query_off() -> u64 {
    let exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(&exe).expect("read exe");
    let elf = goblin::elf::Elf::parse(&bytes).expect("parse exe");
    let sym = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("osslscope_member_query"))
        .expect("query symbol present");
    assert!(sym.st_size > 0, "query symbol has nonzero size");
    assert_eq!(
        sym.st_type(),
        goblin::elf::sym::STT_FUNC,
        "query symbol is a function"
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
    panic!("query symbol outside LOAD segments");
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

/// L1: the chunk loads (all 513 progs verify — no new verifier
/// risk shape) + per-prog xlated margins recorded (T03 acceptance:
/// margin per program). Load-only: no attach, no fire.
#[test]
#[ignore]
fn l1_load_513_margins() {
    let Some(obj) = gated() else {
        eprintln!("SKIP(members-live): OSSL_B_LIVE/OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let loaded = load_members(&obj);
    assert_eq!(loaded.progs.len(), 513, "all member progs loaded");
    assert_eq!(loaded.maps.len(), 7, "all member maps created");
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
    let loaded = load_members(obj);
    populate_alg_class(&loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let _links = attach_all(&loaded, exe, off, None);
    let t0 = Instant::now();
    fire(OP as i32, QUERIES);
    let wall = t0.elapsed();
    eprintln!(
        "e7-{temp}: {QUERIES} queries in {wall:?} ({:.1}µs/scan, recorded)",
        wall.as_micros() as f64 / QUERIES as f64
    );
    let (algs, rows) = drain(&loaded);
    assert_eq!(
        read_percpu(&loaded, "CALLS", OP, false),
        QUERIES as u64,
        "e7-{temp}: one query counted once"
    );
    assert_eq!(
        read_percpu(&loaded, "TRUNC", OP, true),
        0,
        "e7-{temp}: no TRUNC on the clean walk"
    );
    assert_loss_zero(&loaded);
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
    let loaded = load_members(obj);
    populate_alg_class(&loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let _links = attach_all(&loaded, exe, off, None);
    fire(OP as i32, QUERIES);
    let (algs, rows) = drain(&loaded);
    assert_abort_clean(&loaded, &algs, &rows, QUERIES as u64, "e7-cold");
}

/// Shared read-abort oracle (pageout-cold + munmap-hole).
/// Pageout-cold evicts the whole fixture, so every slot read
/// fails; the munmap-hole unmaps only the live prefix's page while
/// the mapped zero tail reads fine and stays silent (names==0).
/// Either way TRUNC holds WALK_READ alone, the ring stays empty,
/// member 0 still counts (its bump precedes the slot read), and
/// nothing is lost.
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

/// Null queries (rv == 0) stay silent and uncounted (v1 returns
/// before CALLS; member-0 QUERY_RET-EMPTY is item 3). A positive
/// control fires through the SAME links first: a dead attach would
/// otherwise satisfy every null assert vacuously (T03 demands
/// positive fire evidence per firing leg).
fn run_null(obj: &std::path::Path, exe: &std::ffi::CString, off: u64) {
    let fx = Fixture::build(&e7_slots(), &[]);
    fx.pretouch();
    let loaded = load_members(obj);
    populate_alg_class(&loaded, &fx.classes);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let _links = attach_all(&loaded, exe, off, None);
    // Positive control: one live query proves these links fire.
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (algs, rows) = drain(&loaded);
    assert_eq!(
        read_percpu(&loaded, "CALLS", OP, false),
        1,
        "null-leg control: live query counted"
    );
    assert!(
        !algs.is_empty() && !rows.is_empty(),
        "null-leg control: live query emits"
    );
    // Null phase: silence, and the count stays at the control's 1.
    FIXTURE_ARRAY.store(0, Ordering::SeqCst);
    fire(OP as i32, 2);
    let (algs, rows) = drain(&loaded);
    assert!(
        algs.is_empty() && rows.is_empty(),
        "null queries emit nothing"
    );
    assert_eq!(
        read_percpu(&loaded, "CALLS", OP, false),
        1,
        "null queries uncounted (control count unchanged)"
    );
    assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_ne!(
            read_percpu(&loaded, "TRUNC", OP, true) & wire::TRUNC_WALK_EMPTY,
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
        assert_loss_zero(&loaded);
    }
    // One: slot 0 exact, EMPTY bit clear.
    {
        let slots = vec![SlotSpec::live("M3A", 100, vec![(31, 0x4300), (32, 0x4301)])];
        let fx = Fixture::build(&slots, &[]);
        fx.pretouch();
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true) & wire::TRUNC_WALK_EMPTY,
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
        assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        let mut entries = fx.classes.clone();
        entries.extend(tail_classes);
        populate_alg_class(&loaded, &entries);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
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
            assert_eq!(
                algs.iter().filter(|a| a.idx == idx).count(),
                2,
                "v1 gap pin: tail slot {idx} PRESENT (item 3 flips to absence)"
            );
            let a = algs.iter().find(|a| a.idx == idx).unwrap();
            assert_eq!(a.class, 200 + t as u16, "tail slot {idx} classified");
            let rt: Vec<_> = rows.iter().filter(|r| r.idx == idx).collect();
            assert_eq!(
                rt.len(),
                2,
                "v1 gap pin: tail slot {idx} ROWs PRESENT (item 3 flips to absence)"
            );
            assert!(
                rt.iter().all(|r| r.funcid == 900 + t as u32
                    && r.addr == 0x9900 + t
                    && r.aux == fx.array),
                "tail slot {idx} ROW payload"
            );
        }
        assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
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
        let (algs, rows) = drain(&loaded);
        assert_abort_clean(&loaded, &algs, &rows, 2, "l3-hole");
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true),
            0,
            "127+term: TRUNC exactly clear (warm, zero-padded)"
        );
        let a0: Vec<_> = algs.iter().filter(|a| a.idx == 0).collect();
        assert_eq!(a0.len(), 2);
        assert!(
            a0.iter().all(|a| {
                a.op == OP && a.class == 100 && a.status == wire::ALG_OK && a.arr == fx.array
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
        assert_loss_zero(&loaded);
    }
    // 128 + term@128: overflow — the terminator exists but the
    // walker exhausts its 128 reads on live legs first.
    {
        let disp: Vec<(u32, u64)> = (0..128u32).map(|k| (5000 + k, 0x9000 + k as u64)).collect();
        let fx = Fixture::build_padded(&[SlotSpec::live("M4E", 100, disp)], &[], 512);
        fx.pretouch();
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true),
            wire::TRUNC_DISPATCH,
            "128+term: DISPATCH alone (term@128 unreachable)"
        );
        assert_eq!(algs.iter().filter(|a| a.idx == 0).count(), 2);
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 256);
        for k in 0..128u64 {
            let n = r0
                .iter()
                .filter(|r| r.funcid == 5000 + k as u32 && r.addr == 0x9000 + k)
                .count();
            assert_eq!(n, 2, "leg {k} exact");
        }
        assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true),
            wire::TRUNC_DISPATCH,
            "129-live: DISPATCH alone"
        );
        assert_eq!(algs.iter().filter(|a| a.idx == 0).count(), 2);
        let r0: Vec<_> = rows.iter().filter(|r| r.idx == 0).collect();
        assert_eq!(r0.len(), 256, "first 128 legs × 2 kept");
        for k in 0..128u64 {
            let n = r0
                .iter()
                .filter(|r| r.funcid == 5000 + k as u32 && r.addr == 0x9000 + k)
                .count();
            assert_eq!(n, 2, "leg {k} exact");
        }
        assert!(
            r0.iter().all(|r| r.funcid < 5000 + 128),
            "leg 128 never walked"
        );
        assert_loss_zero(&loaded);
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
    let loaded = load_members(&obj);
    populate_alg_class(&loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    let _links = attach_all(&loaded, &exe, off, None);
    NS_VERDICT.store(1, Ordering::SeqCst);
    fire(OP as i32, 2);
    assert_ne!(
        read_percpu(&loaded, "TRUNC", OP, true) & wire::TRUNC_NO_STORE,
        0,
        "no_store flagged"
    );
    NS_VERDICT.store(0, Ordering::SeqCst);
    fire(OP as i32, 1);
    let (algs, rows) = drain(&loaded);
    assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 3);
    // Masked, not exact: this fixture is unpadded, so members past
    // the terminator read names-region memory and may OR past-T soup
    // into TRUNC (the known v1 gap, pinned by L3-tail).
    assert_ne!(
        read_percpu(&loaded, "TRUNC", OP, true) & wire::TRUNC_NO_STORE,
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
        r0.iter()
            .all(|r| r.funcid == 51 && r.addr == 0x4500 && r.aux == fx.array),
        "slot-0 ROW payload"
    );
    let r1: Vec<_> = rows.iter().filter(|r| r.idx == 1).collect();
    assert_eq!(r1.len(), 6);
    for (fid, fptr) in [(52u32, 0x4501u64), (53, 0x4502)] {
        let n = r1
            .iter()
            .filter(|r| r.funcid == fid && r.addr == fptr && r.aux == fx.array)
            .count();
        assert_eq!(n, 3, "slot-1 leg {fid} exact");
    }
    assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        let t0 = Instant::now();
        fire(OP as i32, 2);
        eprintln!("l6a: 2 full scans in {:?} (recorded)", t0.elapsed());
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true),
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
        assert_loss_zero(&loaded);
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
        let loaded = load_members(&obj);
        populate_alg_class(&loaded, &fx.classes);
        FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
        NS_VERDICT.store(0, Ordering::SeqCst);
        let _links = attach_all(&loaded, &exe, off, None);
        fire(OP as i32, 2);
        let (algs, rows) = drain(&loaded);
        assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
        assert_eq!(
            read_percpu(&loaded, "TRUNC", OP, true),
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
                }),
                "slot {j} ALG payload"
            );
            let r: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
            assert_eq!(r.len(), 2, "slot {j} ROW × 2");
            assert!(
                r.iter().all(|r| r.funcid == 7000 + j as u32
                    && r.addr == 0xA000 + j
                    && r.aux == fx.array),
                "slot {j} ROW payload"
            );
        }
        assert_loss_zero(&loaded);
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
    let loaded = load_members(&obj);
    populate_alg_class(&loaded, &fx.classes);
    FIXTURE_ARRAY.store(fx.array, Ordering::SeqCst);
    NS_VERDICT.store(0, Ordering::SeqCst);
    let _links = attach_all(&loaded, &exe, off, Some((3, 7)));
    fire(OP as i32, 2);
    let (algs, rows) = drain(&loaded);
    assert_eq!(read_percpu(&loaded, "CALLS", OP, false), 2);
    for j in [0u64, 1, 2] {
        let got: Vec<_> = algs.iter().filter(|a| a.idx == j).collect();
        assert_eq!(got.len(), 2, "slot {j} fires");
        assert!(
            got.iter().all(|a| a.class == 100 + j as u16
                && a.status == wire::ALG_OK
                && a.arr == fx.array),
            "slot {j} ALG payload"
        );
        let rws: Vec<_> = rows.iter().filter(|r| r.idx == j).collect();
        assert_eq!(rws.len(), 2, "slot {j} ROWs fire");
        assert!(
            rws.iter()
                .all(|r| r.funcid == 71 + j as u32 && r.addr == 0x4700 + j && r.aux == fx.array),
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
