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
//! ATTACH_UPROBE_MULTI=48 FUNC_probe_read_user=112).
use std::ffi::CStr;
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_BTF_LOAD: u32 = 18;
pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_TOKEN_CREATE: u32 = 36;
/// `BPF_MAP_UPDATE_ELEM` flags (create-or-update / must-create).
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
pub const BPF_FUNC_PROBE_READ_USER: u64 = 112;
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

/// Update one map element (`GEN`/`TARGET` programming). `flags` is
/// `BPF_ANY` (create-or-update) or `BPF_NOEXIST` (must-create).
pub fn map_update_elem(map_fd: RawFd, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
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
/// truncate them.
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
    // Fresh info for the bytes fetch: call 1 leaves nonzero lens
    // (e.g. jited) with NULL pointers, which would EFAULT the copy.
    let mut info = vec![0u8; 256];
    let mut bytes = vec![0u8; len];
    info[32..40].copy_from_slice(&(bytes.as_mut_ptr() as u64).to_le_bytes());
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
    Ok(bytes)
}

/// Read one map value by key (needs caps on the fd). `value` must
/// fit the map's value size; a missing key errors (`ENOENT`) rather
/// than returning a default.
pub fn map_lookup_elem(map_fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<()> {
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
    attr.log_level = 0;
    attr.log_size = 0;
    attr.log_buf = 0;
    attr.prog_token_fd = token.unwrap_or(0);
    if token.is_some() {
        attr.prog_flags |= BPF_F_TOKEN_FD;
    }
    let fd = bpf(
        BPF_PROG_LOAD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ProgAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
    attr.log_level = 1;
    attr.log_size = log_buf.len() as u32;
    attr.log_buf = log_buf.as_mut_ptr() as u64;
    attr.prog_token_fd = token.unwrap_or(0);
    if token.is_some() {
        attr.prog_flags |= BPF_F_TOKEN_FD;
    }
    let fd = bpf(
        BPF_PROG_LOAD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ProgAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
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
