//! SPDX-License-Identifier: GPL-3.0-or-later
//! Own minimal `ossl-bpf-sys`: raw multi `link_create`, `map_create`,
//! `prog_load`, and feature probes (`token_create` is retained for the
//! gated debug-only path only). Promoted from `spike/bpf-sys` at P1
//! (exit-5 `doctor` needs raw feature probes without a compiled BPF
//! object); `map_create` takes raw dimensions instead of an aya-obj
//! definition so this crate stays dependency-lean (P2 may re-add
//! aya-obj sugar if the token path wants it).
//!
//! UAPI values verified against the compiler (`linux/bpf.h`) on
//! 2026-09-17 (MAP_CREATE=0 PROG_LOAD=5 LINK_CREATE=28
//! TOKEN_CREATE=36, PROG_KPROBE=2 RINGBUF=27 ARRAY=2,
//! ATTACH_UPROBE_MULTI=48 FUNC_probe_read_user=112;
//! FUNC_ringbuf_query=134 verified 2026-10-12 against
//! /usr/include/linux/bpf.h + aya-obj bindings).
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_BTF_LOAD: u32 = 18;
pub const BPF_MAP_FREEZE: u32 = 22;
pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_TOKEN_CREATE: u32 = 36;
/// `BPF_MAP_UPDATE_ELEM` flags (create-or-update / must-create).
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
pub const BPF_FUNC_PROBE_READ_USER: u64 = 112;
pub const BPF_FUNC_RINGBUF_QUERY: u64 = 134;
pub const BPF_F_TOKEN_FD: u32 = 1 << 16;
/// uprobe_multi link flag: return probes (verified in
/// `linux/bpf.h`: `BPF_F_UPROBE_MULTI_RETURN = (1U << 0)`).
pub const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;

#[repr(C)]
struct MapAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_id: u32,
    btf_value_id: u32,
    btf_vmlinux_id: u32,
    map_extra: u64,
    value_btf_fd: i32,
    map_token_fd: i32,
}

#[repr(C)]
struct ProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
    prog_token_fd: i32,
    fd_array_cnt: u32,
}

/// `BPF_LINK_CREATE` attr, `uprobe_multi` member layout (field offsets
/// verified against `linux/bpf.h`: the member flags live at 52, NOT in
/// the common flags at 12 — setting 12 EINVALs, which is how the
/// return-flag bug announced itself).
#[repr(C)]
struct LinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    common_flags: u32, // 12: must stay 0 for multi
    path: u64,
    offsets: u64,
    ref_ctr_offsets: u64, // 32: 0 = none
    cookies: u64,
    cnt: u32,
    flags: u32, // 52: BPF_F_UPROBE_MULTI_RETURN goes here
    pid: u32,
}

#[repr(C)]
struct TokenAttr {
    flags: u32,
    bpffs_fd: u32,
}

/// `BPF_BTF_LOAD` attr: btf@0, log_buf@8, size@16, log_size@20,
/// log_level@24 (offsets per `linux/bpf.h`).
#[repr(C)]
struct BtfAttr {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
}

/// Program BTF attachment for `prog_load_*`: a loaded BTF fd plus
/// serialized func_info (`(insn_off, type_id)` u32 pairs, 8 bytes
/// each — `func_info_rec_size` 8). `None` loads BTF-less (the
/// frozen default; every existing prog).
pub struct ProgBtf<'a> {
    pub btf_fd: RawFd,
    pub func_info: &'a [u8],
}

/// `BPF_MAP_*_ELEM` attr: map_fd@0, key@8, value@16, flags@24
/// (offsets verified against `linux/bpf.h`).
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Close an owned descriptor once using Linux's raw `SYS_close` syscall.
///
/// Ownership is consumed before the syscall. Only return value zero is success;
/// an error preserves errno and never restores ownership or retries the numeric
/// descriptor, which Linux may already have released and reused even on EINTR.
/// This explicit result, unlike `OwnedFd`'s destructor, can acknowledge failure.
pub fn close_owned(fd: OwnedFd) -> io::Result<()> {
    close_owned_with(fd, |raw| {
        // SAFETY: ownership was consumed before this single Linux close syscall.
        let result = unsafe { libc::syscall(libc::SYS_close, raw) };
        match result {
            0 => Ok(()),
            -1 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("close syscall returned a nonzero result")),
        }
    })
}

fn close_owned_with(fd: OwnedFd, call: impl FnOnce(RawFd) -> io::Result<()>) -> io::Result<()> {
    call(fd.into_raw_fd())
}

fn bpf(cmd: u32, attr: *mut std::ffi::c_void, size: usize) -> io::Result<i32> {
    // SAFETY: raw bpf() with a caller-sized attr; exactly what libbpf does.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

fn zeroed<T>() -> T {
    // SAFETY: all attr structs are plain-old-data (ints/arrays).
    unsafe { std::mem::zeroed() }
}

/// Freeze a map against later userspace updates. The final UAPI attribute
/// field is map_fd alone; the kernel zero-extends any omitted union bytes.
pub fn map_freeze(map_fd: RawFd) -> io::Result<()> {
    map_freeze_with(map_fd, |cmd, attr, size| {
        bpf(cmd, attr.as_mut_ptr().cast(), size)
    })
}

fn map_freeze_with(
    map_fd: RawFd,
    call: impl FnOnce(u32, &mut [u8; 4], usize) -> io::Result<i32>,
) -> io::Result<()> {
    let mut attr = (map_fd as u32).to_ne_bytes();
    call(BPF_MAP_FREEZE, &mut attr, 4)?;
    Ok(())
}

/// Create a map from raw dimensions, authorized by `token` when set.
/// `name` lands in the kernel map name (truncated to 15 bytes) so
/// operators and the canary map poller can inventory our maps via
/// bpftool; unnamed maps are invisible to name-based inventory.
pub fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    token: Option<RawFd>,
    name: &str,
) -> io::Result<OwnedFd> {
    let mut attr: MapAttr = zeroed();
    attr.map_type = map_type;
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    attr.map_name[..n].copy_from_slice(&bytes[..n]);
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_token_fd = token.unwrap_or(0);
    if token.is_some() {
        attr.map_flags |= BPF_F_TOKEN_FD;
    }
    let fd = bpf(
        BPF_MAP_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<MapAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create the single-slot writer admission outer map. The template is an
/// observer-owned ARRAY (u32 key, u64 value, one entry), never a target value.
pub fn writer_gate_outer(inner: &OwnedFd) -> io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    let mut attr: MapAttr = zeroed();
    attr.map_type = 12; // BPF_MAP_TYPE_ARRAY_OF_MAPS
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    attr.inner_map_fd = inner.as_raw_fd() as u32;
    attr.map_name[..5].copy_from_slice(b"ADMIT");
    let fd = bpf(
        BPF_MAP_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<MapAttr>(),
    )?;
    // SAFETY: successful creation returns a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Delete slot zero of a typed writer outer map. Success includes the kernel's
/// map-in-map RCU wait; ENOENT is an error, never a closure receipt.
///
/// # Safety
/// `outer` must be the ARRAY_OF_MAPS returned by `writer_gate_outer`.
pub unsafe fn writer_gate_delete(outer: RawFd) -> io::Result<()> {
    let key = 0u32;
    let mut attr: ElemAttr = zeroed();
    attr.map_fd = outer as u32;
    attr.key = std::ptr::addr_of!(key) as u64;
    bpf(
        3,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ElemAttr>(),
    )?;
    Ok(())
}

/// Stable bpf_prog_info prefix: actual program type and ID only.
pub fn prog_type(fd: RawFd) -> io::Result<u32> {
    let mut info = [0u32; 2];
    let mut attr = InfoAttr {
        bpf_fd: fd as u32,
        info_len: 8,
        info: info.as_mut_ptr() as u64,
    };
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<InfoAttr>(),
    )?;
    if attr.info_len < 8 || info[1] == 0 {
        return Err(io::Error::other("program type unavailable"));
    }
    Ok(info[0])
}

/// Finite kernel map identities only. No program text, pointers or map values.
pub fn prog_map_ids(fd: RawFd) -> io::Result<Vec<u32>> {
    let mut ids = [0u32; 64];
    let mut info = [0u64; 8];
    // bpf_prog_info: nr_map_ids@52, map_ids@56. No optional trailing fields.
    info[6] = 64u64 << 32;
    info[7] = ids.as_mut_ptr() as u64;
    let mut attr = InfoAttr {
        bpf_fd: fd as u32,
        info_len: 64,
        info: info.as_mut_ptr() as u64,
    };
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<InfoAttr>(),
    )?;
    let n = (info[6] >> 32) as usize;
    if n > ids.len() || n == 0 {
        return Err(io::Error::other("program map inventory unavailable"));
    }
    Ok(ids[..n].to_vec())
}

/// Full `bpf_prog_info` layout for the selected ABI: 232 bytes,
/// 8-aligned, through `attach_btf_id` plus final padding (offsets
/// verified against the local `linux/bpf.h`: type@0 id@4 tag@8
/// nr_map_ids@52 map_ids@56 name@64 btf_id@128 func_info_rec_size@132
/// func_info@136 nr_func_info@144 nr_line_info@148 line_info@152
/// jited_line_info@160 nr_jited_line_info@168 line_info_rec_size@172
/// jited_line_info_rec_size@176 attach_btf_obj_id@220
/// attach_btf_id@224). No Debug: the raw struct must never be
/// printed or serialized (it carries kernel pointers as integers).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct ProgInfo {
    prog_type: u32,
    prog_id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
    attach_btf_obj_id: u32,
    attach_btf_id: u32,
    _pad: u32,
}

const PROG_INFO_LEN: u32 = 232;
/// Existing bounded ceiling shared with `prog_map_ids`.
const PROG_INFO_MAX_MAPS: u32 = 64;

const _: () = assert!(size_of::<ProgInfo>() == PROG_INFO_LEN as usize);
const _: () = assert!(align_of::<ProgInfo>() == 8);
const _: () = assert!(std::mem::offset_of!(ProgInfo, prog_type) == 0);
const _: () = assert!(std::mem::offset_of!(ProgInfo, prog_id) == 4);
const _: () = assert!(std::mem::offset_of!(ProgInfo, tag) == 8);
const _: () = assert!(std::mem::offset_of!(ProgInfo, nr_map_ids) == 52);
const _: () = assert!(std::mem::offset_of!(ProgInfo, map_ids) == 56);
const _: () = assert!(std::mem::offset_of!(ProgInfo, name) == 64);
const _: () = assert!(std::mem::offset_of!(ProgInfo, btf_id) == 128);
const _: () = assert!(std::mem::offset_of!(ProgInfo, func_info_rec_size) == 132);
const _: () = assert!(std::mem::offset_of!(ProgInfo, func_info) == 136);
const _: () = assert!(std::mem::offset_of!(ProgInfo, nr_func_info) == 144);
const _: () = assert!(std::mem::offset_of!(ProgInfo, nr_line_info) == 148);
const _: () = assert!(std::mem::offset_of!(ProgInfo, line_info) == 152);
const _: () = assert!(std::mem::offset_of!(ProgInfo, jited_line_info) == 160);
const _: () = assert!(std::mem::offset_of!(ProgInfo, nr_jited_line_info) == 168);
const _: () = assert!(std::mem::offset_of!(ProgInfo, line_info_rec_size) == 172);
const _: () = assert!(std::mem::offset_of!(ProgInfo, jited_line_info_rec_size) == 176);
const _: () = assert!(std::mem::offset_of!(ProgInfo, attach_btf_obj_id) == 220);
const _: () = assert!(std::mem::offset_of!(ProgInfo, attach_btf_id) == 224);

/// Safe scalar program-info summary: requested/returned ABI lengths,
/// type, nonzero program ID, name/tag, finite map IDs, own BTF ID,
/// func/line metadata counts and record sizes, and the separate
/// attachment target IDs. No code, ksym, function/line records,
/// pointers, or map contents cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfoSummary {
    pub requested_len: u32,
    pub returned_len: u32,
    pub prog_type: u32,
    pub prog_id: u32,
    pub name: [u8; 16],
    pub tag: [u8; 8],
    pub map_ids: Vec<u32>,
    pub own_btf_id: u32,
    pub func_info_count: u32,
    pub line_info_count: u32,
    pub jited_line_info_count: u32,
    pub func_info_rec_size: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
}

/// Full safe program-info query: identity, finite map IDs, own-BTF
/// metadata counts and attachment target IDs. Every syscall starts
/// from a fresh zeroed struct; only `nr_map_ids`/`map_ids` are ever
/// supplied, so no code/ksym/func/line buffer can be requested. The
/// first query learns the count with no map buffer; the bounded
/// buffer (at most 64 IDs) follows, with at most one resize when the
/// count grows. Returned length must be exactly 232 (older,
/// truncated, or newer-than-selected replies are unavailable, never
/// decoded), the program ID must be nonzero, and identity
/// (type/ID/name/tag) must not drift between queries. Map IDs must
/// be nonzero and duplicate-free. A zero map count decodes to an
/// empty set; route-level ADMIT/map-set checks still apply.
pub fn program_info_summary(fd: BorrowedFd<'_>) -> io::Result<ProgramInfoSummary> {
    program_info_summary_with(fd.as_raw_fd(), |attr, info| {
        // The syscall pointer derives from the callback's live borrow
        // immediately before use: no independently held pointer spans
        // the exclusive borrow.
        attr.info = std::ptr::addr_of_mut!(*info) as u64;
        bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            std::ptr::addr_of_mut!(*attr).cast(),
            size_of::<InfoAttr>(),
        )?;
        Ok(())
    })
}

/// Shared query driver: the request arrives with `attr.info` unset
/// (zero) and every callback — real or scripted — derives the
/// syscall pointer from its supplied `&mut ProgInfo` immediately
/// before use. Deriving from the live borrow (rather than from an
/// earlier pointer held across the borrow) keeps a single provenance
/// chain for the kernel-visible write.
fn program_info_summary_with(
    fd: RawFd,
    mut call: impl FnMut(&mut InfoAttr, &mut ProgInfo) -> io::Result<()>,
) -> io::Result<ProgramInfoSummary> {
    /// One fresh zeroed request; only the map-ID out-param is supplied.
    /// `attr.info` stays zero here: the callback derives it.
    fn query(
        fd: RawFd,
        nr_map_ids: u32,
        map_ids: u64,
        call: &mut impl FnMut(&mut InfoAttr, &mut ProgInfo) -> io::Result<()>,
    ) -> io::Result<(u32, ProgInfo)> {
        let mut info: ProgInfo = zeroed();
        info.nr_map_ids = nr_map_ids;
        info.map_ids = map_ids;
        let mut attr = InfoAttr {
            bpf_fd: fd as u32,
            info_len: PROG_INFO_LEN,
            info: 0,
        };
        call(&mut attr, &mut info)?;
        Ok((attr.info_len, info))
    }
    fn check_reply(returned_len: u32, info: &ProgInfo) -> io::Result<()> {
        if returned_len != PROG_INFO_LEN {
            return Err(io::Error::other("program info length unavailable"));
        }
        if info.prog_id == 0 {
            return Err(io::Error::other("program identity unavailable"));
        }
        Ok(())
    }
    // Count query with no map buffer.
    let (len, first) = query(fd, 0, 0, &mut call)?;
    check_reply(len, &first)?;
    let count = first.nr_map_ids;
    if count > PROG_INFO_MAX_MAPS {
        return Err(io::Error::other("program map count unavailable"));
    }
    if count == 0 {
        return decode_info_summary(len, &first, &[]);
    }
    // Bounded map query; identity must not drift between the calls.
    let mut ids = vec![0u32; count as usize];
    let (len, second) = query(fd, count, ids.as_mut_ptr() as u64, &mut call)?;
    check_reply(len, &second)?;
    check_identity_stable(&first, &second)?;
    let grown = second.nr_map_ids;
    if grown > PROG_INFO_MAX_MAPS {
        return Err(io::Error::other("program map count unavailable"));
    }
    if grown <= count {
        return decode_info_summary(len, &second, &ids[..grown as usize]);
    }
    // The count grew once: single bounded resize, then no further growth.
    ids.resize(grown as usize, 0);
    let (len, third) = query(fd, grown, ids.as_mut_ptr() as u64, &mut call)?;
    check_reply(len, &third)?;
    check_identity_stable(&first, &third)?;
    let final_count = third.nr_map_ids;
    if final_count > grown {
        return Err(io::Error::other("program map count unavailable"));
    }
    decode_info_summary(len, &third, &ids[..final_count as usize])
}

fn check_identity_stable(first: &ProgInfo, next: &ProgInfo) -> io::Result<()> {
    if first.prog_type != next.prog_type
        || first.prog_id != next.prog_id
        || first.name != next.name
        || first.tag != next.tag
    {
        return Err(io::Error::other("program identity drift"));
    }
    Ok(())
}

/// Capability numbers gating program-info queries (`linux/capability.h`).
const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;
const SYS_CAPGET: libc::c_long = 125;
const CAP_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Calling-thread privilege snapshot taken around a program-info
/// query: full capget v3 words, effective UID, thread ID, and the
/// thread's user-namespace identity. Capability bits alone never
/// prove the kernel honored the query in the required namespace;
/// they pair with the bracketing legacy calibration below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCredentials {
    /// capget v3 data: `[set][effective, permitted, inheritable]`;
    /// set 0 covers capabilities 0–31, set 1 covers 32–63.
    pub caps: [[u32; 3]; 2],
    pub euid: u32,
    pub tid: i32,
    pub userns_dev: u64,
    pub userns_ino: u64,
}

/// Observe the calling thread's credentials: capget v3 of pid 0
/// (the calling thread), effective UID, TID, and the thread's
/// user-namespace device/inode. Any missing observation is an
/// error; the query it brackets is then unavailable, never assumed.
pub fn calling_thread_credentials() -> io::Result<ThreadCredentials> {
    let header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: versioned header plus two data words; pid 0 names self.
    let ret = unsafe { libc::syscall(SYS_CAPGET, &header as *const CapHeader, data.as_mut_ptr()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: trivial getters with no failure mode.
    let euid = unsafe { libc::geteuid() };
    let tid = unsafe { libc::gettid() };
    let ns = std::fs::metadata(format!("/proc/self/task/{tid}/ns/user"))?;
    use std::os::unix::fs::MetadataExt as _;
    Ok(ThreadCredentials {
        caps: data.map(|set| [set.effective, set.permitted, set.inheritable]),
        euid,
        tid,
        userns_dev: ns.dev(),
        userns_ino: ns.ino(),
    })
}

/// Effective CAP_BPF or CAP_SYS_ADMIN in the snapshot: the minimum
/// privilege for a trustworthy program-info query. Missing bits
/// refuse; present bits still require the paired calibration.
pub fn has_bpf_query_capabilities(creds: &ThreadCredentials) -> bool {
    fn effective(creds: &ThreadCredentials, cap: u32) -> bool {
        let set = (cap / 32) as usize;
        let bit = cap % 32;
        creds.caps[set][0] & (1 << bit) != 0
    }
    effective(creds, CAP_BPF) || effective(creds, CAP_SYS_ADMIN)
}

/// Paired anti-redaction calibration verdict over already-obtained
/// summaries. The same-artifact legacy control (callback-bearing
/// observation_return, queried with the same credentials, query
/// path, length, and decoder) must show nonzero own BTF **and**
/// nonzero function metadata both before and after the source
/// series, while the source root shows zero own BTF and zero
/// func/line metadata counts. Record sizes may be nonzero with zero
/// counts. The source root's legitimate attachment target IDs stay
/// separate: `expected_attach_btf_id` must match exactly (0 for
/// roots without a kernel target), and the target object ID must be
/// nonzero exactly when `expect_target_object` holds (the
/// source-registration roots). Decision logic only: native
/// non-redaction is established by the actual queries, never here.
pub fn calibration_admits_source_zero(
    control_before: &ProgramInfoSummary,
    source: &ProgramInfoSummary,
    control_after: &ProgramInfoSummary,
    expected_attach_btf_id: u32,
    expect_target_object: bool,
) -> Result<(), &'static str> {
    fn control_ok(control: &ProgramInfoSummary) -> bool {
        control.own_btf_id != 0 && control.func_info_count != 0
    }
    if !control_ok(control_before) {
        return Err("control-before missing own BTF or function count");
    }
    if !control_ok(control_after) {
        return Err("control-after missing own BTF or function count");
    }
    if source.own_btf_id != 0 {
        return Err("source owns program BTF");
    }
    if source.func_info_count != 0
        || source.line_info_count != 0
        || source.jited_line_info_count != 0
    {
        return Err("source carries function/line metadata");
    }
    if source.attach_btf_id != expected_attach_btf_id {
        return Err("source attachment FUNC mismatch");
    }
    if expect_target_object {
        if source.attach_btf_obj_id == 0 {
            return Err("source target object missing");
        }
    } else if source.attach_btf_obj_id != 0 {
        return Err("source target object unexpected");
    }
    Ok(())
}

fn decode_info_summary(
    returned_len: u32,
    info: &ProgInfo,
    ids: &[u32],
) -> io::Result<ProgramInfoSummary> {
    if ids.contains(&0) {
        return Err(io::Error::other("program map identities unavailable"));
    }
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::other("program map identities unavailable"));
    }
    Ok(ProgramInfoSummary {
        requested_len: PROG_INFO_LEN,
        returned_len,
        prog_type: info.prog_type,
        prog_id: info.prog_id,
        name: info.name,
        tag: info.tag,
        map_ids: ids.to_vec(),
        own_btf_id: info.btf_id,
        func_info_count: info.nr_func_info,
        line_info_count: info.nr_line_info,
        jited_line_info_count: info.nr_jited_line_info,
        func_info_rec_size: info.func_info_rec_size,
        line_info_rec_size: info.line_info_rec_size,
        jited_line_info_rec_size: info.jited_line_info_rec_size,
        attach_btf_obj_id: info.attach_btf_obj_id,
        attach_btf_id: info.attach_btf_id,
    })
}

/// Update one map element (`GEN`/`TARGET` programming). `flags` is
/// `BPF_ANY` (create-or-update) or `BPF_NOEXIST` (must-create).
///
/// # Safety
///
/// The kernel reads exactly the map's key/value sizes from the raw
/// pointers: `key` must be exactly `key_size` bytes, `value`
/// exactly `value_size` bytes (per-CPU maps: `round_up(value_size,
/// 8)` × possible CPUs), and `map_fd` a live fd for that map. Short
/// slices make the kernel read past the allocation.
pub unsafe fn map_update_elem(
    map_fd: RawFd,
    key: &[u8],
    value: &[u8],
    flags: u64,
) -> io::Result<()> {
    let mut attr: ElemAttr = zeroed();
    debug_assert_eq!(size_of::<ElemAttr>(), 32);
    debug_assert_eq!(std::mem::offset_of!(ElemAttr, key), 8);
    debug_assert_eq!(std::mem::offset_of!(ElemAttr, value), 16);
    debug_assert_eq!(std::mem::offset_of!(ElemAttr, flags), 24);
    attr.map_fd = map_fd as u32;
    attr.key = key.as_ptr() as u64;
    attr.value = value.as_ptr() as u64;
    attr.flags = flags;
    bpf(
        BPF_MAP_UPDATE_ELEM,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ElemAttr>(),
    )?;
    Ok(())
}

/// `BPF_OBJ_GET_INFO_BY_FD` attr: bpf_fd@0, info_len@4, info@8.
#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// Fetch a program's xlated image bytes from the kernel (two-step
/// length-then-bytes dance; needs caps on the fd). Early
/// `bpf_prog_info` fields (through `xlated_prog_insns`) are ABI
/// stable; the info buffer is oversized so version growth cannot
/// truncate them. A successful call does not prove bytes were copied
/// (the kernel withholds on restricted paths), so the returned
/// length and pointer are validated before the buffer is trusted.
pub fn prog_xlated_bytes(prog_fd: RawFd) -> io::Result<Vec<u8>> {
    // bpf_prog_info head: type@0 id@4 tag@8 jited_len@16
    // xlated_len@20 jited_ptr@24 xlated_ptr@32.
    let mut info = vec![0u8; 256];
    let mut attr = InfoAttr {
        bpf_fd: prog_fd as u32,
        info_len: info.len() as u32,
        info: info.as_mut_ptr() as u64,
    };
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<InfoAttr>(),
    )?;
    let len = u32::from_le_bytes([info[20], info[21], info[22], info[23]]) as usize;
    if len == 0 {
        // Unprivileged callers get length 0 with success: no image
        // exists to fetch, and requesting 0 bytes would copy nothing.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "xlated bytes withheld: kernel returned length 0",
        ));
    }
    // Fresh info for the bytes fetch: call 1 leaves nonzero lens
    // (e.g. jited) with NULL pointers, which would EFAULT the copy.
    let mut info = vec![0u8; 256];
    let mut bytes = vec![0u8; len];
    let our_ptr = bytes.as_mut_ptr() as u64;
    info[32..40].copy_from_slice(&our_ptr.to_le_bytes());
    info[20..24].copy_from_slice(&(len as u32).to_le_bytes());
    let mut attr = InfoAttr {
        bpf_fd: prog_fd as u32,
        info_len: info.len() as u32,
        info: info.as_mut_ptr() as u64,
    };
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<InfoAttr>(),
    )?;
    let got_len = u32::from_le_bytes([info[20], info[21], info[22], info[23]]);
    let got_ptr = u64::from_le_bytes([
        info[32], info[33], info[34], info[35], info[36], info[37], info[38], info[39],
    ]);
    check_xlated_copied(len, got_len, got_ptr, our_ptr)?;
    Ok(bytes)
}

/// Read one map value by key (needs caps on the fd). A missing key
/// errors (`ENOENT`) rather than returning a default.
///
/// # Safety
///
/// The kernel writes the map's full value size into `value` and
/// reads `key_size` bytes from `key`: `value` must be exactly
/// `value_size` bytes (per-CPU maps: `round_up(value_size, 8)` ×
/// possible CPUs), `key` exactly `key_size` bytes, and `map_fd` a
/// live fd for that map. A short `value` is a heap/stack overflow
/// through this call.
pub unsafe fn map_lookup_elem(map_fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<()> {
    let mut attr: ElemAttr = zeroed();
    attr.map_fd = map_fd as u32;
    attr.key = key.as_ptr() as u64;
    attr.value = value.as_mut_ptr() as u64;
    attr.flags = 0;
    bpf(
        BPF_MAP_LOOKUP_ELEM,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ElemAttr>(),
    )?;
    Ok(())
}

/// Read the first key (`key = None`) or the key following `key`. Natural end of
/// enumeration is ENOENT; a concurrently absent input key may restart a hash
/// map's iteration, so callers must detect duplicate/cyclic results themselves.
///
/// # Safety
///
/// `map_fd` must name a live map. `next` and every present `key` must each have
/// exactly that map's key size. The kernel writes the complete key into `next`.
pub unsafe fn map_get_next_key(
    map_fd: RawFd,
    key: Option<&[u8]>,
    next: &mut [u8],
) -> io::Result<()> {
    let mut attr: ElemAttr = zeroed();
    attr.map_fd = map_fd as u32;
    attr.key = key.map_or(0, |key| key.as_ptr() as u64);
    attr.value = next.as_mut_ptr() as u64;
    bpf(
        BPF_MAP_GET_NEXT_KEY,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ElemAttr>(),
    )?;
    Ok(())
}

/// Load raw BTF bytes, returning the BTF fd (needs caps). The
/// kernel validates the type graph (fail-closed, loud errno);
/// callers pass `log` for the diagnostic on failure.
pub fn btf_load(btf: &[u8], log: &mut [u8]) -> io::Result<OwnedFd> {
    let mut attr: BtfAttr = zeroed();
    attr.btf = btf.as_ptr() as u64;
    attr.btf_size = btf.len() as u32;
    attr.btf_log_buf = log.as_mut_ptr() as u64;
    attr.btf_log_size = log.len() as u32;
    attr.btf_log_level = 1;
    let fd = bpf(
        BPF_BTF_LOAD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<BtfAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One raw program-load attempt: the syscall result plus the
/// kernel-reported verifier log true size (read back from the load
/// attributes on both success and failure, so observed loading can
/// prove log completeness instead of trusting truncation). Ordinary
/// wrappers return only `.result`.
#[derive(Debug)]
pub struct ProgLoadAttempt {
    pub result: io::Result<OwnedFd>,
    pub log_true_size: u32,
}

/// Load a KPROBE-typed program (uprobe family) with no verifier log
/// (`log_level` 0): the success path needs no diagnostics, and a
/// large-but-valid verification can overflow any fixed log buffer
/// (`ENOSPC`) even when the program verifies. Callers retry
/// failures via [`prog_load_kprobe`] to capture the report.
pub fn prog_load_kprobe_quiet(
    insns: &[u8],
    license: &CStr,
    token: Option<RawFd>,
    name: &str,
    btf: Option<ProgBtf<'_>>,
) -> io::Result<OwnedFd> {
    prog_load_kprobe_attempt(insns, license, token, None, name, btf).result
}

/// Load a KPROBE-typed program (uprobe family). `insns` is raw 8B-stride
/// BPF bytecode; verifier output lands in `log_buf` on failure.
/// `name` lands in the kernel prog name (truncated to 15 bytes) so
/// operators and the canary map poller can identify our programs via
/// bpftool; unnamed programs are invisible to name-based inventory.
pub fn prog_load_kprobe(
    insns: &[u8],
    license: &CStr,
    token: Option<RawFd>,
    log_buf: &mut [u8],
    name: &str,
    btf: Option<ProgBtf<'_>>,
) -> io::Result<OwnedFd> {
    prog_load_kprobe_attempt(insns, license, token, Some(log_buf), name, btf).result
}

/// KPROBE load with the raw attempt metadata. `log` selects the quiet
/// (`None`, log level 0) versus logged (level 1) shape; attributes
/// are constructed once here so ordinary and observed calls cannot
/// drift. No alternate load flags.
pub fn prog_load_kprobe_attempt(
    insns: &[u8],
    license: &CStr,
    token: Option<RawFd>,
    log: Option<&mut [u8]>,
    name: &str,
    btf: Option<ProgBtf<'_>>,
) -> ProgLoadAttempt {
    prog_load_kprobe_with(insns, license, token, log, name, btf, |attr| {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::from_mut(attr).cast(),
            size_of::<ProgAttr>(),
        )
    })
}

fn prog_load_kprobe_with(
    insns: &[u8],
    license: &CStr,
    token: Option<RawFd>,
    log: Option<&mut [u8]>,
    name: &str,
    btf: Option<ProgBtf<'_>>,
    call: impl FnOnce(&mut ProgAttr) -> io::Result<i32>,
) -> ProgLoadAttempt {
    assert!(insns.len() % 8 == 0, "BPF insn stride is 8 bytes");
    let mut attr: ProgAttr = zeroed();
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    if let Some(b) = btf {
        assert!(b.func_info.len() % 8 == 0, "func_info stride is 8 bytes");
        attr.prog_btf_fd = b.btf_fd as u32;
        attr.func_info_rec_size = 8;
        attr.func_info = b.func_info.as_ptr() as u64;
        attr.func_info_cnt = (b.func_info.len() / 8) as u32;
    }
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    attr.prog_name[..n].copy_from_slice(&bytes[..n]);
    // Multi attach requires this at load (is_uprobe_multi checks
    // expected_attach_type, not the link's attach_type); 0 yields EINVAL.
    attr.expected_attach_type = BPF_TRACE_UPROBE_MULTI;
    attr.insn_cnt = (insns.len() / 8) as u32;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license.as_ptr() as u64;
    if let Some(log) = log {
        attr.log_level = 1;
        attr.log_size = log.len() as u32;
        attr.log_buf = log.as_mut_ptr() as u64;
    }
    attr.prog_token_fd = token.unwrap_or(0);
    if token.is_some() {
        attr.prog_flags |= BPF_F_TOKEN_FD;
    }
    if attr.prog_flags & (1 << 4) != 0 {
        return ProgLoadAttempt {
            result: Err(io::Error::other("sleepable producer refused")),
            log_true_size: 0,
        };
    }
    let result = call(&mut attr);
    let log_true_size = attr.log_true_size;
    // SAFETY: a successful BPF_PROG_LOAD returns a fresh owned descriptor.
    let result = result.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    ProgLoadAttempt {
        result,
        log_true_size,
    }
}

/// Reviewed synchronous roots. No arbitrary event name, BTF attachment,
/// sleepable flag, token, target PID, cookie, or tracepoint context read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleTracepoint {
    Exit,
    Exec,
}
impl LifecycleTracepoint {
    pub const fn tracepoint_name(self) -> &'static CStr {
        match self {
            Self::Exit => c"sched_process_exit",
            Self::Exec => c"sched_process_exec",
        }
    }
    pub const fn program_name(self) -> &'static str {
        match self {
            Self::Exit => "attr_exit",
            Self::Exec => "attr_exec",
        }
    }
    pub const fn section(self) -> &'static str {
        match self {
            Self::Exit => "raw_tracepoint/sched_process_exit",
            Self::Exec => "raw_tracepoint/sched_process_exec",
        }
    }
}

/// Load only the reviewed non-sleepable raw lifecycle type. Optional logging
/// changes diagnostics only; the complete remaining load attributes stay zero.
pub fn prog_load_lifecycle(
    insns: &[u8],
    root: LifecycleTracepoint,
    log: Option<&mut [u8]>,
) -> io::Result<OwnedFd> {
    prog_load_lifecycle_attempt(insns, root, log).result
}

/// Lifecycle load with the raw attempt metadata. Attributes are
/// constructed once here so ordinary and observed calls cannot drift.
pub fn prog_load_lifecycle_attempt(
    insns: &[u8],
    root: LifecycleTracepoint,
    log: Option<&mut [u8]>,
) -> ProgLoadAttempt {
    prog_load_lifecycle_with(insns, root, log, |attr| {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::from_mut(attr).cast(),
            size_of::<ProgAttr>(),
        )
    })
}
fn prog_load_lifecycle_with(
    insns: &[u8],
    root: LifecycleTracepoint,
    log: Option<&mut [u8]>,
    call: impl FnOnce(&mut ProgAttr) -> io::Result<i32>,
) -> ProgLoadAttempt {
    if insns.is_empty() || insns.len() % 8 != 0 {
        return ProgLoadAttempt {
            result: Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw instruction stride",
            )),
            log_true_size: 0,
        };
    }
    let mut attr: ProgAttr = zeroed();
    attr.prog_type = 17; // BPF_PROG_TYPE_RAW_TRACEPOINT; not writable-raw/TRACING.
    attr.insn_cnt = match u32::try_from(insns.len() / 8) {
        Ok(count) => count,
        Err(_) => {
            return ProgLoadAttempt {
                result: Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "raw instruction count",
                )),
                log_true_size: 0,
            };
        }
    };
    attr.insns = insns.as_ptr() as u64;
    attr.license = c"GPL".as_ptr() as u64;
    let name = root.program_name().as_bytes();
    attr.prog_name[..name.len()].copy_from_slice(name);
    if let Some(log) = log {
        attr.log_level = 1;
        attr.log_size = match u32::try_from(log.len()) {
            Ok(size) => size,
            Err(_) => {
                return ProgLoadAttempt {
                    result: Err(io::Error::new(io::ErrorKind::InvalidInput, "raw log size")),
                    log_true_size: 0,
                };
            }
        };
        attr.log_buf = log.as_mut_ptr() as u64;
    }
    let result = call(&mut attr);
    let log_true_size = attr.log_true_size;
    // SAFETY: successful BPF_PROG_LOAD returns a fresh descriptor.
    let result = result.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    ProgLoadAttempt {
        result,
        log_true_size,
    }
}

/// Attach a global lifecycle program and retain the returned descriptor for the
/// entire writer lifetime. Caller must retain/attest its actual shared gate.
pub fn raw_tracepoint_open(prog_fd: RawFd, root: LifecycleTracepoint) -> io::Result<OwnedFd> {
    raw_tracepoint_open_with(prog_fd, root, |cmd, attr| {
        bpf(cmd, attr.as_mut_ptr().cast(), attr.len())
    })
}
fn raw_tracepoint_open_with(
    prog_fd: RawFd,
    root: LifecycleTracepoint,
    call: impl FnOnce(u32, &mut [u8; 16]) -> io::Result<i32>,
) -> io::Result<OwnedFd> {
    if prog_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw program descriptor",
        ));
    }
    // Exact legacy UAPI prefix: name@0, prog_fd@8; all trailing bytes zero.
    // Do not send the later raw-tracepoint cookie field to older kernels.
    let mut attr = [0u8; 16];
    attr[..8].copy_from_slice(&(root.tracepoint_name().as_ptr() as u64).to_ne_bytes());
    attr[8..12].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
    let fd = call(17, &mut attr)?; // BPF_RAW_TRACEPOINT_OPEN.
    // SAFETY: successful open returns a fresh, unique global attachment FD.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Exact non-sleepable observer registration roots. The caller must derive the
/// attach BTF ID from the finite running-kernel signature validator and retain
/// the actual program/link/shared admission owner before exposing any source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceTracingRoot {
    Enter,
    Exit,
}
impl SourceTracingRoot {
    pub const fn attach_type(self) -> u32 {
        match self {
            Self::Enter => 24,
            Self::Exit => 25,
        }
    }
    pub const fn program_name(self) -> &'static str {
        match self {
            Self::Enter => "source_reg_in",
            Self::Exit => "source_reg_out",
        }
    }
    pub const fn section(self) -> &'static str {
        match self {
            Self::Enter => "fentry/uprobe_register",
            Self::Exit => "fexit/uprobe_register",
        }
    }
}

/// No program BTF, sleepable flag, token, alternate attach target or consumer
/// metadata is accepted by this finite source-registration loader.
pub fn prog_load_source_registration(
    insns: &[u8],
    root: SourceTracingRoot,
    attach_btf_id: u32,
    log: Option<&mut [u8]>,
) -> io::Result<OwnedFd> {
    prog_load_source_attempt(insns, root, attach_btf_id, log).result
}

/// Source-registration load with the raw attempt metadata. Attributes
/// are constructed once here so ordinary and observed calls cannot
/// drift. No alternate attach target, flags, or program BTF.
pub fn prog_load_source_attempt(
    insns: &[u8],
    root: SourceTracingRoot,
    attach_btf_id: u32,
    log: Option<&mut [u8]>,
) -> ProgLoadAttempt {
    prog_load_source_with(insns, root, attach_btf_id, log, |attr| {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::from_mut(attr).cast(),
            size_of::<ProgAttr>(),
        )
    })
}
fn prog_load_source_with(
    insns: &[u8],
    root: SourceTracingRoot,
    attach_btf_id: u32,
    log: Option<&mut [u8]>,
    call: impl FnOnce(&mut ProgAttr) -> io::Result<i32>,
) -> ProgLoadAttempt {
    if attach_btf_id == 0 || insns.is_empty() || insns.len() % 8 != 0 {
        return ProgLoadAttempt {
            result: Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source load shape",
            )),
            log_true_size: 0,
        };
    }
    let mut attr: ProgAttr = zeroed();
    attr.prog_type = 26; // BPF_PROG_TYPE_TRACING, not KPROBE or sleepable tracing.
    attr.expected_attach_type = root.attach_type();
    attr.attach_btf_id = attach_btf_id;
    attr.insn_cnt = match u32::try_from(insns.len() / 8) {
        Ok(count) => count,
        Err(_) => {
            return ProgLoadAttempt {
                result: Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source instruction count",
                )),
                log_true_size: 0,
            };
        }
    };
    attr.insns = insns.as_ptr() as u64;
    attr.license = c"GPL".as_ptr() as u64;
    let name = root.program_name().as_bytes();
    attr.prog_name[..name.len()].copy_from_slice(name);
    if let Some(log) = log {
        attr.log_level = 1;
        attr.log_size = match u32::try_from(log.len()) {
            Ok(size) => size,
            Err(_) => {
                return ProgLoadAttempt {
                    result: Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "source log size",
                    )),
                    log_true_size: 0,
                };
            }
        };
        attr.log_buf = log.as_mut_ptr() as u64;
    }
    let result = call(&mut attr);
    let log_true_size = attr.log_true_size;
    // SAFETY: successful BPF_PROG_LOAD returns a fresh owned descriptor.
    let result = result.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    ProgLoadAttempt {
        result,
        log_true_size,
    }
}
/// Attach only to the target frozen at load; all retargeting/cookie fields zero.
pub fn link_create_source_registration(
    prog_fd: RawFd,
    root: SourceTracingRoot,
) -> io::Result<OwnedFd> {
    source_link_with(prog_fd, root, |cmd, attr| {
        bpf(cmd, attr.as_mut_ptr().cast(), attr.len())
    })
}
fn source_link_with(
    prog_fd: RawFd,
    root: SourceTracingRoot,
    call: impl FnOnce(u32, &mut [u8; 32]) -> io::Result<i32>,
) -> io::Result<OwnedFd> {
    if prog_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source program descriptor",
        ));
    }
    // LINK_CREATE fixed prefix: prog_fd@0,target_fd@4,type@8,flags@12,
    // target_btf_id@16,padding@20,tracing.cookie@24. No alternate target.
    let mut attr = [0; 32];
    attr[..4].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
    attr[8..12].copy_from_slice(&root.attach_type().to_ne_bytes());
    let fd = call(BPF_LINK_CREATE, &mut attr)?;
    // SAFETY: successful link creation returns a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Observer-only provisional trigger body. It cannot count, read, call helpers
/// or mutate any map, independently of admission state or target activity.
/// Caller must attach only to its nonzero observer PID and retain/clean its FD.
pub fn prog_load_source_noop() -> io::Result<OwnedFd> {
    source_noop_with(|attr| {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::from_mut(attr).cast(),
            size_of::<ProgAttr>(),
        )
    })
}
fn source_noop_with(call: impl FnOnce(&mut ProgAttr) -> io::Result<i32>) -> io::Result<OwnedFd> {
    const CODE: [u8; 16] = [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let mut attr: ProgAttr = zeroed();
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.expected_attach_type = BPF_TRACE_UPROBE_MULTI;
    attr.insn_cnt = 2;
    attr.insns = CODE.as_ptr() as u64;
    attr.license = c"GPL".as_ptr() as u64;
    attr.prog_name[..11].copy_from_slice(b"source_noop");
    let fd = call(&mut attr)?;
    // SAFETY: successful BPF_PROG_LOAD returns a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One uprobe_multi link: `offsets[i]` fires with `cookies[i]`.
pub fn link_create_uprobe_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
) -> io::Result<OwnedFd> {
    link_create_multi(prog_fd, path, offsets, cookies, pid, 0)
}

/// One uretprobe_multi link (return probes): same shape, the
/// `BPF_F_UPROBE_MULTI_RETURN` flag set.
pub fn link_create_uretprobe_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
) -> io::Result<OwnedFd> {
    link_create_multi(
        prog_fd,
        path,
        offsets,
        cookies,
        pid,
        BPF_F_UPROBE_MULTI_RETURN,
    )
}

fn link_create_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
    flags: u32,
) -> io::Result<OwnedFd> {
    assert!(offsets.len() == cookies.len() && !offsets.is_empty());
    debug_assert_eq!(size_of::<LinkAttr>(), 64);
    debug_assert_eq!(std::mem::offset_of!(LinkAttr, flags), 52);
    let mut attr: LinkAttr = zeroed();
    attr.prog_fd = prog_fd as u32;
    attr.attach_type = BPF_TRACE_UPROBE_MULTI;
    attr.flags = flags;
    attr.path = path.as_ptr() as u64;
    attr.offsets = offsets.as_ptr() as u64;
    attr.cookies = cookies.as_ptr() as u64;
    attr.cnt = offsets.len() as u32;
    attr.pid = pid;
    let fd = bpf(
        BPF_LINK_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<LinkAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Validate the second get-info call actually copied xlated bytes.
/// The kernel can succeed while withholding: unprivileged callers get
/// `xlated_prog_len = 0`, and blinded progs without dump rights get
/// `xlated_prog_insns = 0` with the length still set (v6.12
/// `bpf_prog_get_info_by_fd`). Returning our zeroed buffer as a
/// "successful image" would mislead the caller.
fn check_xlated_copied(
    requested: usize,
    returned_len: u32,
    returned_ptr: u64,
    our_ptr: u64,
) -> io::Result<()> {
    if returned_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "xlated bytes withheld: kernel returned length 0",
        ));
    }
    if returned_ptr == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "xlated bytes withheld: kernel cleared the output pointer",
        ));
    }
    if returned_ptr != our_ptr {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xlated output pointer changed by the kernel",
        ));
    }
    if returned_len as usize != requested {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xlated length changed: requested {requested}, got {returned_len}"),
        ));
    }
    Ok(())
}

/// Mint a BPF token against a delegated bpffs mount dir fd. Must be
/// called by the worker itself inside its userns (broker-minted tokens
/// are impossible). Debug-only path (STOP#6-PIVOT retired tokens from v1).
pub fn token_create(bpffs_fd: RawFd) -> io::Result<OwnedFd> {
    let mut attr: TokenAttr = TokenAttr {
        flags: 0,
        bpffs_fd: bpffs_fd as u32,
    };
    let fd = bpf(
        BPF_TOKEN_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<TokenAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    use std::sync::Mutex;

    static G1_FD_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn source_load_and_link_freeze_registration_target_and_zero_btf() {
        for root in [SourceTracingRoot::Enter, SourceTracingRoot::Exit] {
            let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
            let error = prog_load_source_with(&code, root, 123, None, |attr| {
                assert_eq!(attr.prog_type, 26);
                assert_eq!(attr.expected_attach_type, root.attach_type());
                assert_eq!(attr.attach_btf_id, 123);
                assert_eq!(attr.prog_flags, 0);
                assert_eq!(attr.prog_btf_fd, 0);
                assert_eq!(attr.attach_prog_fd, 0);
                assert_eq!(attr.prog_token_fd, 0);
                assert_eq!(attr.func_info, 0);
                assert_eq!(attr.func_info_cnt, 0);
                assert_eq!(attr.line_info, 0);
                assert_eq!(attr.line_info_cnt, 0);
                assert_eq!(attr.insns, code.as_ptr() as u64);
                assert_eq!(attr.insn_cnt, 1);
                Err(io::Error::from_raw_os_error(libc::EPERM))
            })
            .result
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(
                prog_load_source_with(&code, root, 0, None, |_| panic!(
                    "missing target reached load"
                ))
                .result
                .is_err()
            );
            let error = source_link_with(313, root, |cmd, attr| {
                assert_eq!(cmd, BPF_LINK_CREATE);
                assert_eq!(u32::from_ne_bytes(attr[..4].try_into().unwrap()), 313);
                assert_eq!(
                    u32::from_ne_bytes(attr[8..12].try_into().unwrap()),
                    root.attach_type()
                );
                assert_eq!(&attr[4..8], &[0; 4]);
                assert!(attr[12..].iter().all(|byte| *byte == 0));
                Err(io::Error::from_raw_os_error(libc::EIO))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
    }
    #[test]
    fn source_writers_use_only_ordinary_rcu_load_attributes() {
        // Frozen ordinary-RCU premises for all four source writers, checked
        // against inspected stable 6.12.113: `prog_flags == 0` selects
        // non-sleepable execution (`prog->sleepable` is false per
        // kernel/bpf/syscall.c:2778), so fentry/fexit roots run under
        // ordinary `rcu_read_lock` via `__bpf_prog_enter`
        // (kernel/bpf/trampoline.c:1017-1026, selected at :1049-1060) and raw
        // roots via `__bpf_trace_run` (kernel/trace/bpf_trace.c:2313-2337).
        // Sleepable execution would use Tasks-Trace RCU instead; these
        // loaders accept no sleepable flag, program BTF or token.
        for root in [SourceTracingRoot::Enter, SourceTracingRoot::Exit] {
            let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
            let error = prog_load_source_with(&code, root, 4242, None, |attr| {
                assert_eq!(attr.prog_type, 26);
                assert_eq!(attr.expected_attach_type, root.attach_type());
                assert_eq!(attr.prog_flags, 0);
                assert_eq!(attr.attach_btf_id, 4242);
                Err(io::Error::from_raw_os_error(libc::EPERM))
            })
            .result
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            let error = source_link_with(313, root, |cmd, attr| {
                assert_eq!(cmd, BPF_LINK_CREATE);
                assert_eq!(
                    u32::from_ne_bytes(attr[8..12].try_into().unwrap()),
                    root.attach_type()
                );
                // The target frozen at load; no cookie or retargeting identity.
                assert!(attr[12..].iter().all(|byte| *byte == 0));
                Err(io::Error::from_raw_os_error(libc::EIO))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
        for root in [LifecycleTracepoint::Exit, LifecycleTracepoint::Exec] {
            let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
            let error = prog_load_lifecycle_with(&code, root, None, |attr| {
                assert_eq!(attr.prog_type, 17);
                assert_eq!(attr.expected_attach_type, 0);
                assert_eq!(attr.prog_flags, 0);
                Err(io::Error::from_raw_os_error(libc::EPERM))
            })
            .result
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
    }
    #[test]
    fn source_noop_is_literal_nonwriting_two_instruction_program() {
        let error = source_noop_with(|attr| {
            assert_eq!(attr.prog_type, BPF_PROG_TYPE_KPROBE);
            assert_eq!(attr.expected_attach_type, BPF_TRACE_UPROBE_MULTI);
            assert_eq!(attr.insn_cnt, 2);
            assert_eq!(attr.prog_flags, 0);
            assert_eq!(attr.prog_btf_fd, 0);
            assert_eq!(attr.attach_btf_id, 0);
            assert_eq!(attr.func_info, 0);
            // The native call borrows the immutable built-in bytes for its duration.
            let code = unsafe { std::slice::from_raw_parts(attr.insns as *const u8, 16) };
            assert_eq!(
                code,
                &[0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]
            );
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn lifecycle_load_has_exact_non_sleepable_raw_attributes() {
        for root in [LifecycleTracepoint::Exit, LifecycleTracepoint::Exec] {
            let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
            let error = prog_load_lifecycle_with(&code, root, None, |attr| {
                assert_eq!(attr.prog_type, 17);
                assert_eq!(attr.expected_attach_type, 0);
                assert_eq!(attr.prog_flags, 0);
                assert_eq!(attr.prog_btf_fd, 0);
                assert_eq!(attr.attach_btf_id, 0);
                assert_eq!(attr.attach_prog_fd, 0);
                assert_eq!(attr.prog_token_fd, 0);
                assert_eq!(attr.func_info, 0);
                assert_eq!(attr.func_info_cnt, 0);
                assert_eq!(attr.insn_cnt, 1);
                assert_eq!(attr.insns, code.as_ptr() as u64);
                assert_eq!(attr.log_level, 0);
                assert_eq!(attr.log_size, 0);
                assert_eq!(attr.log_buf, 0);
                Err(io::Error::from_raw_os_error(libc::EPERM))
            })
            .result
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
        for code in [&[][..], &[0; 7][..]] {
            assert!(
                prog_load_lifecycle_with(code, LifecycleTracepoint::Exit, None, |_| panic!(
                    "invalid input reached syscall"
                ))
                .result
                .is_err()
            );
        }
    }

    #[test]
    fn lifecycle_open_uses_constant_name_and_zero_trailing_fields() {
        for (root, name) in [
            (LifecycleTracepoint::Exit, c"sched_process_exit"),
            (LifecycleTracepoint::Exec, c"sched_process_exec"),
        ] {
            assert_eq!(root.tracepoint_name(), name);
            let error = raw_tracepoint_open_with(123, root, |cmd, attr| {
                assert_eq!(cmd, 17);
                assert_eq!(
                    u64::from_ne_bytes(attr[..8].try_into().unwrap()),
                    name.as_ptr() as u64
                );
                assert_eq!(u32::from_ne_bytes(attr[8..12].try_into().unwrap()), 123);
                assert_eq!(&attr[12..], &[0; 4]);
                Err(io::Error::from_raw_os_error(libc::EIO))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
    }

    #[test]
    fn map_freeze_uses_four_byte_fd_attribute_and_preserves_error() {
        let mut calls = 0;
        let error = map_freeze_with(313, |cmd, attr, size| {
            calls += 1;
            assert_eq!(cmd, 22);
            assert_eq!(size, 4);
            assert_eq!(*attr, 313u32.to_ne_bytes());
            Err(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn map_freeze_success_uses_only_selected_fd_field() {
        let mut calls = 0;
        map_freeze_with(0x1234, |cmd, attr, size| {
            calls += 1;
            assert_eq!(cmd, BPF_MAP_FREEZE);
            assert_eq!(size, size_of::<u32>());
            assert_eq!(u32::from_ne_bytes(*attr), 0x1234);
            Ok(0)
        })
        .unwrap();
        assert_eq!(calls, 1);
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 writes two fresh descriptor numbers into this array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both successful pipe2 results are fresh and uniquely owned.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn high_pipe() -> (OwnedFd, OwnedFd) {
        let (read, write) = pipe();
        // Keep the tested number away from ordinary harness allocations while
        // it is briefly closed, before dup2 installs the controlled replacement.
        // SAFETY: read is live and F_DUPFD_CLOEXEC returns a fresh descriptor.
        let raw = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 256) };
        assert!(raw >= 256, "{}", io::Error::last_os_error());
        // SAFETY: the successful duplicate is fresh and uniquely owned.
        (unsafe { OwnedFd::from_raw_fd(raw) }, write)
    }

    fn fd_is_open(raw: RawFd) -> bool {
        // SAFETY: F_GETFD only queries the number, including when it is closed.
        let result = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        if result == -1 {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            false
        } else {
            true
        }
    }

    // A raw owner is deliberate: if a regressed implementation closes the
    // replacement, cleanup must not drop an invalid OwnedFd or close it twice.
    // Arm it before handing ownership to the helper so early failures also clean up.
    struct Replacement(Option<RawFd>);

    impl Replacement {
        fn install(&mut self, source: RawFd, destination: RawFd) {
            assert_eq!(self.0, Some(destination));
            // SAFETY: source is a live borrowed pipe end; destination was just
            // closed by the injected call. No other test uses this high number.
            assert_eq!(unsafe { libc::dup2(source, destination) }, destination);
            self.0 = Some(destination);
        }
    }

    impl Drop for Replacement {
        fn drop(&mut self) {
            if let Some(raw) = self.0.take() {
                // Do not close twice if the implementation under test already
                // closed the replacement. This also makes assertion unwinding safe.
                // SAFETY: F_GETFD accepts any numeric descriptor.
                let result = unsafe { libc::fcntl(raw, libc::F_GETFD) };
                let already_closed =
                    result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
                if !already_closed {
                    // SAFETY: this fixture uniquely owns the installed duplicate.
                    unsafe { libc::close(raw) };
                }
            }
        }
    }

    fn legacy_ignored_result_close_owned_with(
        fd: OwnedFd,
        call: impl FnOnce(RawFd) -> io::Result<()>,
    ) -> io::Result<()> {
        // Negative control: the old ignored-result policy fabricates a receipt.
        let _ = call(fd.into_raw_fd());
        Ok(())
    }

    #[test]
    fn g1_close_success_consumes_once() {
        let _lock = G1_FD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (read, write) = high_pipe();
        let raw = read.as_raw_fd();
        let _cleanup = Replacement(Some(raw));
        let result = close_owned(read);
        result.expect("a real pipe close must succeed");
        assert!(!fd_is_open(raw), "the consumed descriptor must be EBADF");
        assert!(fd_is_open(write.as_raw_fd()), "the peer must survive");
    }

    #[test]
    fn g1_close_eintr_never_retries_reused_fd() {
        let _lock = G1_FD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for errno in [libc::EINTR, libc::EBADF, libc::EIO] {
            let (read, write) = high_pipe();
            let raw = read.as_raw_fd();
            let mut replacement = Replacement(Some(raw));
            let mut calls = 0;
            let result = close_owned_with(read, |number| {
                calls += 1;
                assert_eq!(number, raw);
                // SAFETY: the injected operation receives the consumed end and
                // really closes it before installing a new descriptor there.
                assert_eq!(unsafe { libc::syscall(libc::SYS_close, number) }, 0);
                replacement.install(write.as_raw_fd(), number);
                Err(io::Error::from_raw_os_error(errno))
            });
            assert_eq!(calls, 1);
            assert!(fd_is_open(raw), "an extra close killed the replacement");
            assert!(fd_is_open(write.as_raw_fd()), "the peer must survive");
            assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn g1_close_error_is_not_acknowledged() {
        let _lock = G1_FD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (read, write) = high_pipe();
        let raw = read.as_raw_fd();
        let _cleanup = Replacement(Some(raw));
        let result = close_owned_with(read, |number| {
            // SAFETY: this is the one close of the consumed pipe end.
            assert_eq!(unsafe { libc::syscall(libc::SYS_close, number) }, 0);
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        assert!(!fd_is_open(raw));
        assert!(fd_is_open(write.as_raw_fd()));
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn g1_close_legacy_ignored_result_negative_control() {
        let _lock = G1_FD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (read, write) = high_pipe();
        let raw = read.as_raw_fd();
        let _cleanup = Replacement(Some(raw));
        let result = legacy_ignored_result_close_owned_with(read, |number| {
            // SAFETY: this is the one close of the consumed pipe end.
            assert_eq!(unsafe { libc::syscall(libc::SYS_close, number) }, 0);
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        assert!(
            result.is_ok(),
            "the negative control ignores a real failure"
        );
        assert!(!fd_is_open(raw));
        assert!(fd_is_open(write.as_raw_fd()));
    }

    const OURS: u64 = 0x7fff_0000;

    #[test]
    fn xlated_copy_accepts_exact() {
        check_xlated_copied(360, 360, OURS, OURS).expect("exact copy must pass");
    }

    #[test]
    fn xlated_copy_rejects_cleared_pointer() {
        // Blinded prog without dump rights: length set, pointer
        // cleared, no bytes copied.
        let e = check_xlated_copied(360, 360, 0, OURS).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("withheld"), "{e}");
    }

    #[test]
    fn xlated_copy_rejects_zero_length() {
        // Unprivileged caller: length zeroed, no bytes copied.
        let e = check_xlated_copied(360, 0, OURS, OURS).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("withheld"), "{e}");
    }

    #[test]
    fn xlated_copy_rejects_changed_pointer() {
        let e = check_xlated_copied(360, 360, 0x1234, OURS).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn xlated_copy_rejects_length_change() {
        // Same fd pins the image: a changed length means a short
        // copy (`min()` truncation) or kernel drift.
        let e = check_xlated_copied(360, 100, OURS, OURS).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    /// Scripted kernel reply for one info query: the reported length,
    /// an optional syscall errno, the identity/count/metadata fields,
    /// and the map IDs "written" into the caller-supplied buffer.
    struct InfoReply {
        returned_len: u32,
        errno: Option<i32>,
        prog_type: u32,
        prog_id: u32,
        name: [u8; 16],
        tag: [u8; 8],
        count: u32,
        written: Vec<u32>,
        btf_id: u32,
        nr_func: u32,
        nr_line: u32,
        nr_jline: u32,
        func_rec: u32,
        line_rec: u32,
        jline_rec: u32,
        attach_obj: u32,
        attach_id: u32,
        /// Poison every other reply field nonzero, proving the next
        /// request is still a fresh zeroed struct (no count reuse).
        poison_rest: bool,
    }

    impl InfoReply {
        fn ok(prog_id: u32, count: u32, written: &[u32]) -> Self {
            let mut name = [0u8; 16];
            name[..4].copy_from_slice(b"root");
            Self {
                returned_len: PROG_INFO_LEN,
                errno: None,
                prog_type: 2,
                prog_id,
                name,
                tag: [9u8; 8],
                count,
                written: written.to_vec(),
                btf_id: 0,
                nr_func: 0,
                nr_line: 0,
                nr_jline: 0,
                func_rec: 0,
                line_rec: 0,
                jline_rec: 0,
                attach_obj: 0,
                attach_id: 0,
                poison_rest: true,
            }
        }
    }

    /// Recorded request: (requested len, supplied nr_map_ids, map ptr null?).
    struct InfoDriver {
        script: std::collections::VecDeque<InfoReply>,
        requests: Vec<(u32, u32, bool)>,
    }

    impl InfoDriver {
        fn run(&mut self, attr: &mut InfoAttr, info: &mut ProgInfo, fd: RawFd) -> io::Result<()> {
            assert_eq!(attr.bpf_fd, fd as u32);
            assert_eq!(attr.info_len, PROG_INFO_LEN);
            // The script mirrors the real callback exactly: the pointer
            // arrives unset and derives from the live borrow here.
            assert_eq!(attr.info, 0, "pointer must derive inside the callback");
            attr.info = std::ptr::addr_of_mut!(*info) as u64;
            // Fresh zeroed request: only the map-ID out-param supplied.
            let clean = info.prog_type == 0
                && info.prog_id == 0
                && info.tag == [0u8; 8]
                && info.jited_prog_len == 0
                && info.xlated_prog_len == 0
                && info.jited_prog_insns == 0
                && info.xlated_prog_insns == 0
                && info.load_time == 0
                && info.created_by_uid == 0
                && info.name == [0u8; 16]
                && info.ifindex == 0
                && info.gpl_compatible == 0
                && info.netns_dev == 0
                && info.netns_ino == 0
                && info.nr_jited_ksyms == 0
                && info.nr_jited_func_lens == 0
                && info.jited_ksyms == 0
                && info.jited_func_lens == 0
                && info.btf_id == 0
                && info.func_info_rec_size == 0
                && info.func_info == 0
                && info.nr_func_info == 0
                && info.nr_line_info == 0
                && info.line_info == 0
                && info.jited_line_info == 0
                && info.nr_jited_line_info == 0
                && info.line_info_rec_size == 0
                && info.jited_line_info_rec_size == 0
                && info.nr_prog_tags == 0
                && info.prog_tags == 0
                && info.run_time_ns == 0
                && info.run_cnt == 0
                && info.recursion_misses == 0
                && info.verified_insns == 0
                && info.attach_btf_obj_id == 0
                && info.attach_btf_id == 0;
            assert!(clean, "request carried non-map fields");
            self.requests
                .push((attr.info_len, info.nr_map_ids, info.map_ids == 0));
            let reply = self.script.pop_front().expect("script exhausted");
            if let Some(errno) = reply.errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            attr.info_len = reply.returned_len;
            info.prog_type = reply.prog_type;
            info.prog_id = reply.prog_id;
            info.name = reply.name;
            info.tag = reply.tag;
            info.nr_map_ids = reply.count;
            info.btf_id = reply.btf_id;
            info.nr_func_info = reply.nr_func;
            info.nr_line_info = reply.nr_line;
            info.nr_jited_line_info = reply.nr_jline;
            info.func_info_rec_size = reply.func_rec;
            info.line_info_rec_size = reply.line_rec;
            info.jited_line_info_rec_size = reply.jline_rec;
            info.attach_btf_obj_id = reply.attach_obj;
            info.attach_btf_id = reply.attach_id;
            if reply.poison_rest {
                info.jited_prog_len = 0xdead;
                info.xlated_prog_len = 0xbeef;
                info.jited_prog_insns = 0x1111;
                info.xlated_prog_insns = 0x2222;
                info.load_time = 0x3333;
                info.created_by_uid = 0x4444;
                info.ifindex = 0x5555;
                info.nr_jited_ksyms = 0x6666;
                info.jited_ksyms = 0x7777;
                info.func_info = 0x8888;
                info.line_info = 0x9999;
                info.run_cnt = 0xaaaa;
                info.verified_insns = 0xbbbb;
            }
            if !reply.written.is_empty() {
                assert_ne!(info.map_ids, 0, "no caller buffer for reply IDs");
                // SAFETY: the harness writes only the reply IDs into the
                // caller-supplied buffer the request advertised.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        reply.written.as_ptr(),
                        info.map_ids as *mut u32,
                        reply.written.len(),
                    );
                }
            }
            Ok(())
        }
    }

    fn drive_info(
        fd: RawFd,
        script: Vec<InfoReply>,
    ) -> (io::Result<ProgramInfoSummary>, Vec<(u32, u32, bool)>) {
        let mut driver = InfoDriver {
            script: script.into(),
            requests: Vec::new(),
        };
        let result = program_info_summary_with(fd, |attr, info| driver.run(attr, info, fd));
        (result, driver.requests)
    }

    #[test]
    fn info_layout_matches_selected_uapi() {
        assert_eq!(size_of::<ProgInfo>(), 232);
        assert_eq!(align_of::<ProgInfo>(), 8);
        assert_eq!(PROG_INFO_LEN, 232);
        assert_eq!(PROG_INFO_MAX_MAPS, 64);
    }

    #[test]
    fn info_happy_path_returns_safe_scalars_only() {
        let (result, requests) = drive_info(
            99,
            vec![
                InfoReply::ok(7, 2, &[]),
                InfoReply {
                    btf_id: 0,
                    nr_func: 0,
                    func_rec: 8,
                    attach_obj: 11,
                    attach_id: 12,
                    ..InfoReply::ok(7, 2, &[40, 41])
                },
            ],
        );
        let summary = result.unwrap();
        assert_eq!(requests, vec![(232, 0, true), (232, 2, false)]);
        assert_eq!(summary.requested_len, 232);
        assert_eq!(summary.returned_len, 232);
        assert_eq!(summary.prog_type, 2);
        assert_eq!(summary.prog_id, 7);
        assert_eq!(summary.map_ids, vec![40, 41]);
        assert_eq!(summary.own_btf_id, 0);
        assert_eq!(summary.func_info_rec_size, 8);
        assert_eq!(summary.attach_btf_obj_id, 11);
        assert_eq!(summary.attach_btf_id, 12);
        assert_eq!(&summary.name[..4], b"root".as_slice());
        // Poisoned reply fields never leak into the safe summary.
        let debug = format!("{summary:?}");
        assert!(!debug.contains("dead"), "{debug}");
        assert!(!debug.contains("1111"), "{debug}");
    }

    #[test]
    fn info_zero_maps_decodes_to_empty_set() {
        let (result, requests) = drive_info(99, vec![InfoReply::ok(7, 0, &[])]);
        let summary = result.unwrap();
        assert_eq!(requests, vec![(232, 0, true)]);
        assert!(summary.map_ids.is_empty());
    }

    #[test]
    fn info_count_over_ceiling_refuses_without_map_query() {
        for count in [65, 100, u32::MAX] {
            let (result, requests) = drive_info(99, vec![InfoReply::ok(7, count, &[])]);
            assert!(result.is_err(), "count {count} must refuse");
            assert_eq!(requests.len(), 1);
        }
        // Exactly 64 allocates the bounded buffer.
        let (result, requests) = drive_info(
            99,
            vec![
                InfoReply::ok(7, 64, &[]),
                InfoReply::ok(7, 64, &(1..=64).collect::<Vec<_>>()),
            ],
        );
        assert_eq!(result.unwrap().map_ids.len(), 64);
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn info_single_growth_gets_one_resize_then_freezes() {
        let (result, requests) = drive_info(
            99,
            vec![
                InfoReply::ok(7, 2, &[]),
                InfoReply::ok(7, 3, &[40, 41]),
                InfoReply::ok(7, 3, &[40, 41, 42]),
            ],
        );
        assert_eq!(result.unwrap().map_ids, vec![40, 41, 42]);
        assert_eq!(
            requests,
            vec![(232, 0, true), (232, 2, false), (232, 3, false)]
        );
        // Repeated growth after the resize refuses.
        let (result, _) = drive_info(
            99,
            vec![
                InfoReply::ok(7, 2, &[]),
                InfoReply::ok(7, 3, &[40, 41]),
                InfoReply::ok(7, 4, &[40, 41, 42]),
            ],
        );
        assert!(result.is_err());
        // Growth past the ceiling on the second query refuses outright.
        let (result, requests) = drive_info(
            99,
            vec![InfoReply::ok(7, 2, &[]), InfoReply::ok(7, 65, &[40, 41])],
        );
        assert!(result.is_err());
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn info_zero_or_duplicate_ids_refuse() {
        let (zero, _) = drive_info(
            99,
            vec![InfoReply::ok(7, 2, &[]), InfoReply::ok(7, 2, &[0, 41])],
        );
        assert!(zero.is_err());
        let (dup, _) = drive_info(
            99,
            vec![InfoReply::ok(7, 2, &[]), InfoReply::ok(7, 2, &[41, 41])],
        );
        assert!(dup.is_err());
        // Shrinking counts decode the reported prefix only.
        let (shrunk, _) = drive_info(
            99,
            vec![InfoReply::ok(7, 2, &[]), InfoReply::ok(7, 1, &[40, 41])],
        );
        assert_eq!(shrunk.unwrap().map_ids, vec![40]);
    }

    #[test]
    fn info_identity_drift_refuses() {
        for mutate in [
            |reply: &mut InfoReply| reply.prog_type = 26,
            |reply: &mut InfoReply| reply.prog_id = 8,
            |reply: &mut InfoReply| reply.name[0] = b'X',
            |reply: &mut InfoReply| reply.tag[0] = 0,
        ] {
            let mut second = InfoReply::ok(7, 2, &[40, 41]);
            mutate(&mut second);
            let (result, _) = drive_info(99, vec![InfoReply::ok(7, 2, &[]), second]);
            assert!(result.is_err(), "drifted identity must refuse");
        }
    }

    #[test]
    fn info_short_or_long_replies_refuse() {
        for len in [0, 8, 64, 231, 233, 4096] {
            let (result, requests) = drive_info(
                99,
                vec![InfoReply {
                    returned_len: len,
                    ..InfoReply::ok(7, 0, &[])
                }],
            );
            assert!(result.is_err(), "length {len} must refuse");
            assert_eq!(requests.len(), 1);
        }
        // A short second reply refuses even after a good count query.
        let (result, _) = drive_info(
            99,
            vec![
                InfoReply::ok(7, 2, &[]),
                InfoReply {
                    returned_len: 64,
                    ..InfoReply::ok(7, 2, &[40, 41])
                },
            ],
        );
        assert!(result.is_err());
    }

    #[test]
    fn kprobe_quiet_and_logged_share_one_attribute_shape() {
        let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
        let mut log = [0u8; 64];
        let check_common = |attr: &ProgAttr| {
            assert_eq!(attr.prog_type, BPF_PROG_TYPE_KPROBE);
            assert_eq!(attr.expected_attach_type, BPF_TRACE_UPROBE_MULTI);
            assert_eq!(attr.insn_cnt, 1);
            assert_eq!(attr.insns, code.as_ptr() as u64);
            assert_eq!(attr.license, c"GPL".as_ptr() as u64);
            // Name truncated to 15 bytes on both shapes.
            assert_eq!(&attr.prog_name[..15], b"observer_name_i");
            assert_eq!(attr.prog_btf_fd, 0);
            assert_eq!(attr.func_info_cnt, 0);
            assert_eq!(attr.prog_token_fd, 0);
            assert_eq!(attr.prog_flags, 0);
        };
        let quiet = prog_load_kprobe_with(
            &code,
            c"GPL",
            None,
            None,
            "observer_name_is_long",
            None,
            |attr| {
                check_common(attr);
                assert_eq!(attr.log_level, 0);
                assert_eq!(attr.log_size, 0);
                assert_eq!(attr.log_buf, 0);
                attr.log_true_size = 41;
                Err(io::Error::from_raw_os_error(libc::EACCES))
            },
        );
        assert_eq!(quiet.log_true_size, 41);
        assert_eq!(quiet.result.unwrap_err().raw_os_error(), Some(libc::EACCES));
        let log_ptr = log.as_mut_ptr() as u64;
        let logged = prog_load_kprobe_with(
            &code,
            c"GPL",
            None,
            Some(log.as_mut_slice()),
            "observer_name_is_long",
            None,
            |attr| {
                check_common(attr);
                assert_eq!(attr.log_level, 1);
                assert_eq!(attr.log_size, 64);
                assert_eq!(attr.log_buf, log_ptr);
                attr.log_true_size = 42;
                Err(io::Error::from_raw_os_error(libc::EACCES))
            },
        );
        assert_eq!(logged.log_true_size, 42);
        assert_eq!(
            logged.result.unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn kprobe_attempt_carries_btf_token_and_true_size() {
        let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
        let mut log = [0u8; 32];
        let func_info = [1u8; 16];
        let btf = ProgBtf {
            btf_fd: 77,
            func_info: &func_info,
        };
        let (read, _write) = pipe();
        let raw = read.as_raw_fd();
        // The attempt takes ownership of the fresh descriptor number the
        // syscall reports; hand it a duplicate so the pipe stays usable.
        let dup = read.try_clone().unwrap();
        let attempt = prog_load_kprobe_with(
            &code,
            c"GPL",
            Some(55),
            Some(log.as_mut_slice()),
            "n",
            Some(btf),
            |attr| {
                assert_eq!(attr.prog_btf_fd, 77);
                assert_eq!(attr.func_info_rec_size, 8);
                assert_eq!(attr.func_info_cnt, 2);
                assert_eq!(attr.prog_token_fd, 55);
                assert_eq!(attr.prog_flags, BPF_F_TOKEN_FD);
                attr.log_true_size = 7;
                Ok(dup.into_raw_fd())
            },
        );
        assert_eq!(attempt.log_true_size, 7);
        let owned = attempt.result.unwrap();
        assert_ne!(owned.as_raw_fd(), raw);
        assert!(fd_is_open(owned.as_raw_fd()));
        drop(owned);
        drop(read);
    }

    #[test]
    fn lifecycle_and_source_attempts_report_true_size_both_ways() {
        let code = [0x95, 0, 0, 0, 0, 0, 0, 0];
        let mut log = [0u8; 16];
        // Failure still reports the kernel's true size.
        let failed = prog_load_lifecycle_with(
            &code,
            LifecycleTracepoint::Exit,
            Some(log.as_mut_slice()),
            |attr| {
                assert_eq!(attr.log_level, 1);
                assert_eq!(attr.log_size, 16);
                attr.log_true_size = 900;
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            },
        );
        assert_eq!(failed.log_true_size, 900);
        assert_eq!(
            failed.result.unwrap_err().raw_os_error(),
            Some(libc::ENOSPC)
        );
        // Success with no log keeps a zero true size.
        let (read, _write) = pipe();
        let dup = read.try_clone().unwrap();
        let ok = prog_load_source_with(&code, SourceTracingRoot::Enter, 4242, None, |attr| {
            assert_eq!(attr.log_level, 0);
            assert_eq!(attr.log_size, 0);
            assert_eq!(attr.attach_btf_id, 4242);
            Ok(dup.into_raw_fd())
        });
        assert_eq!(ok.log_true_size, 0);
        let owned = ok.result.unwrap();
        assert!(fd_is_open(owned.as_raw_fd()));
        drop(owned);
        drop(read);
    }

    #[test]
    fn info_zero_program_id_and_syscall_failure_refuse() {
        let (zero, _) = drive_info(
            99,
            vec![InfoReply {
                prog_id: 0,
                ..InfoReply::ok(0, 0, &[])
            }],
        );
        assert!(zero.is_err());
        let (failed, requests) = drive_info(
            99,
            vec![InfoReply {
                errno: Some(libc::EPERM),
                ..InfoReply::ok(7, 0, &[])
            }],
        );
        assert_eq!(failed.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn thread_credentials_match_direct_observation() {
        let creds = calling_thread_credentials().unwrap();
        // SAFETY: trivial getters with no failure mode.
        assert_eq!(creds.euid, unsafe { libc::geteuid() });
        assert_eq!(creds.tid, unsafe { libc::gettid() });
        use std::os::unix::fs::MetadataExt as _;
        let ns = std::fs::metadata(format!("/proc/self/task/{}/ns/user", creds.tid)).unwrap();
        assert_eq!(creds.userns_dev, ns.dev());
        assert_eq!(creds.userns_ino, ns.ino());
        // Independent capget oracle: the same versioned call, spelled
        // out here instead of through the helper.
        let header = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        // SAFETY: versioned header plus two data words; pid 0 names self.
        let ret =
            unsafe { libc::syscall(SYS_CAPGET, &header as *const CapHeader, data.as_mut_ptr()) };
        assert_eq!(ret, 0);
        assert_eq!(
            creds.caps,
            data.map(|set| [set.effective, set.permitted, set.inheritable])
        );
        // A stable process observes itself identically twice.
        assert_eq!(creds, calling_thread_credentials().unwrap());
    }

    #[test]
    fn query_capability_predicate_reads_effective_bits_only() {
        fn snapshot(effective0: u32, effective1: u32) -> ThreadCredentials {
            ThreadCredentials {
                caps: [[effective0, 0, 0], [effective1, 0, 0]],
                euid: 0,
                tid: 0,
                userns_dev: 0,
                userns_ino: 0,
            }
        }
        // CAP_SYS_ADMIN = 21 (set 0), CAP_BPF = 39 (set 1, bit 7).
        assert!(has_bpf_query_capabilities(&snapshot(1 << 21, 0)));
        assert!(has_bpf_query_capabilities(&snapshot(0, 1 << 7)));
        assert!(has_bpf_query_capabilities(&snapshot(1 << 21, 1 << 7)));
        assert!(!has_bpf_query_capabilities(&snapshot(0, 0)));
        // Neighboring bits and the wrong set never satisfy the predicate.
        assert!(!has_bpf_query_capabilities(&snapshot(0, 1 << 21)));
        assert!(!has_bpf_query_capabilities(&snapshot(1 << 7, 0)));
        assert!(!has_bpf_query_capabilities(&snapshot(0, 1 << 8)));
        // Permitted/inheritable words are not effective privilege.
        let mut unprivileged = snapshot(0, 0);
        unprivileged.caps[0][1] = 1 << 21;
        unprivileged.caps[1][2] = 1 << 7;
        assert!(!has_bpf_query_capabilities(&unprivileged));
    }

    fn calibration_summary() -> ProgramInfoSummary {
        ProgramInfoSummary {
            requested_len: PROG_INFO_LEN,
            returned_len: PROG_INFO_LEN,
            prog_type: 2,
            prog_id: 7,
            name: [0u8; 16],
            tag: [0u8; 8],
            map_ids: vec![40],
            own_btf_id: 0,
            func_info_count: 0,
            line_info_count: 0,
            jited_line_info_count: 0,
            func_info_rec_size: 0,
            line_info_rec_size: 0,
            jited_line_info_rec_size: 0,
            attach_btf_obj_id: 0,
            attach_btf_id: 0,
        }
    }

    #[test]
    fn calibration_admits_zero_source_between_live_controls() {
        let mut control = calibration_summary();
        control.own_btf_id = 5;
        control.func_info_count = 2;
        // Registration root: zero own metadata, exact FUNC target,
        // nonzero target object, nonzero record sizes allowed.
        let mut source = calibration_summary();
        source.func_info_rec_size = 8;
        source.line_info_rec_size = 16;
        source.jited_line_info_rec_size = 8;
        source.attach_btf_obj_id = 3;
        source.attach_btf_id = 4242;
        assert_eq!(
            calibration_admits_source_zero(&control, &source, &control, 4242, true),
            Ok(())
        );
        // Typed/count/lifecycle roots carry no kernel target at all.
        let mut plain = calibration_summary();
        plain.func_info_rec_size = 8;
        assert_eq!(
            calibration_admits_source_zero(&control, &plain, &control, 0, false),
            Ok(())
        );
    }

    #[test]
    fn calibration_refuses_each_missing_or_extra_predicate() {
        let mut control = calibration_summary();
        control.own_btf_id = 5;
        control.func_info_count = 2;
        let mut source = calibration_summary();
        source.attach_btf_obj_id = 3;
        source.attach_btf_id = 4242;
        let run = |before: &ProgramInfoSummary,
                   source: &ProgramInfoSummary,
                   after: &ProgramInfoSummary| {
            calibration_admits_source_zero(before, source, after, 4242, true)
        };
        // Either control predicate missing, on either side, refuses.
        for mutate in [
            |c: &mut ProgramInfoSummary| c.own_btf_id = 0,
            |c: &mut ProgramInfoSummary| c.func_info_count = 0,
        ] {
            let mut before = control.clone();
            mutate(&mut before);
            assert!(run(&before, &source, &control).is_err());
            let mut after = control.clone();
            mutate(&mut after);
            assert!(run(&control, &source, &after).is_err());
        }
        // Any source-owned metadata refuses.
        for mutate in [
            |s: &mut ProgramInfoSummary| s.own_btf_id = 1,
            |s: &mut ProgramInfoSummary| s.func_info_count = 1,
            |s: &mut ProgramInfoSummary| s.line_info_count = 1,
            |s: &mut ProgramInfoSummary| s.jited_line_info_count = 1,
        ] {
            let mut bad = source.clone();
            mutate(&mut bad);
            assert!(run(&control, &bad, &control).is_err());
        }
        // Attachment target handling stays exact in both directions.
        let mut wrong_func = source.clone();
        wrong_func.attach_btf_id = 4243;
        assert!(run(&control, &wrong_func, &control).is_err());
        let mut missing_obj = source.clone();
        missing_obj.attach_btf_obj_id = 0;
        assert!(run(&control, &missing_obj, &control).is_err());
        let mut plain = calibration_summary();
        plain.attach_btf_obj_id = 9;
        assert!(calibration_admits_source_zero(&control, &plain, &control, 0, false).is_err());
    }
}
