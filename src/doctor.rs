//! `doctor` preflight (P1 exit 5): fail-closed environment + target matrix.
//!
//! Doctrine (PLAN exit 5 + PRD §6, post-STOP#6 file-caps pivot):
//! - Functional probes, never config-grep: the kernel check loads a
//!   real kprobe prog / creates real maps / links a real uprobe_multi
//!   onto self; errno (+verifier-log sniffing) classifies wrong-kernel
//!   vs missing-caps vs LSM/lockdown/seccomp denial. `uname` is INFO.
//! - Fail closed with actionable messages: every `fail` names the
//!   blocker + remediation; exit 4. Checks doctor cannot run for
//!   want of privilege are `degraded` (labeled, exit still 0 unless
//!   something hard-failed). `info` never fails (BTF/IMA/versions).
//! - Golden-safe JSON: stable facts only (no pids/addrs/inos/
//!   timestamps/usernames). `--format human` (default) is the
//!   operator view; `--format json` is the gate view.
//! - Token path is debug-only (STOP#6): doctor probes token EXISTENCE
//!   as a 6.9-floor feature row but never mints/uses tokens; the
//!   file-caps path (multi+ringbuf+cookie+probe_read) is the gate.
//! - No `--pid` pinning here (TOCTOU accepted for a diagnostic);
//!   exit 6 owns pidfd/starttime pinning for evidence paths.
//! - Panics are avoid-by-construction (no unwrap on fallible paths);
//!   internal errors exit 1 via anyhow.
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Pass,
    Fail,
    Degraded,
    Info,
}

impl Status {
    fn as_str(&self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Degraded => "degraded",
            Status::Info => "info",
        }
    }
}

struct Check {
    id: &'static str,
    status: Status,
    message: String,
    remediation: Option<String>,
}

impl Check {
    fn pass(id: &'static str, message: String) -> Self {
        Check {
            id,
            status: Status::Pass,
            message,
            remediation: None,
        }
    }
    fn fail(id: &'static str, message: String, remediation: String) -> Self {
        Check {
            id,
            status: Status::Fail,
            message,
            remediation: Some(remediation),
        }
    }
    fn degraded(id: &'static str, message: String, remediation: String) -> Self {
        Check {
            id,
            status: Status::Degraded,
            message,
            remediation: Some(remediation),
        }
    }
    fn info(id: &'static str, message: String) -> Self {
        Check {
            id,
            status: Status::Info,
            message,
            remediation: None,
        }
    }
    fn json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "id": self.id,
            "status": self.status.as_str(),
            "message": self.message,
        });
        if let Some(r) = &self.remediation {
            v["remediation"] = r.clone().into();
        }
        v
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// ---- capability bits (linux/capability.h) ----
const CAP_SYS_PTRACE: u32 = 19;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

fn parse_capeff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

fn has_cap(eff: u64, bit: u32) -> bool {
    eff & (1u64 << bit) != 0
}

fn status_field(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k == key).then(|| v.trim().to_string())
    })
}

pub(crate) fn uname_release() -> String {
    // SAFETY: uname writes a fresh struct; read-only after.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return "unknown".into();
        }
        let b = u
            .release
            .iter()
            .map(|&c| c as u8)
            .take_while(|&c| c != 0)
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&b).into_owned()
    }
}

/// Active lockdown mode: the `[bracketed]` entry, or "none" when the
/// file is missing/unreadable (pre-lockdown kernels).
fn lockdown_mode() -> String {
    parse_lockdown(&read_trimmed("/sys/kernel/security/lockdown").unwrap_or_default())
}

fn parse_lockdown(s: &str) -> String {
    for tok in s.split_whitespace() {
        if let Some(m) = tok.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            return m.to_string();
        }
    }
    "none".to_string()
}

/// LSM list (`/sys/kernel/security/lsm`, comma-separated).
fn lsm_list() -> Vec<String> {
    parse_lsm(&read_trimmed("/sys/kernel/security/lsm").unwrap_or_default())
}

fn parse_lsm(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Enforcement-shaped LSMs (beyond the stub/inert modules): denials
/// get attributed here when caps are present but BPF ops EPERM.
fn enforcing_lsm(mods: &[String]) -> Vec<String> {
    mods.iter()
        .filter(|m| {
            !["capability", "lockdown", "yama", "landlock", "ima", "evm"].contains(&m.as_str())
        })
        .cloned()
        .collect()
}

fn ima_state() -> String {
    if std::path::Path::new("/sys/kernel/security/ima/policy").exists() {
        "active".to_string()
    } else {
        "absent-or-disabled".to_string()
    }
}

const SETCAP_RECIPE: &str = "grant file caps: sudo setcap cap_bpf,cap_perfmon+ep $(command -v osslscope) [+cap_sys_ptrace for foreign-uid targets], then re-run";

// ---- functional BPF probes (kernel feature set + caps) ----

// r0 = 0; exit (verifier-trivially-valid no-op program).
fn insns_noop() -> Vec<u8> {
    vec![
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]
}

// r1 = r10-8 (dst); r2 = 8; r3 = r10-16 (src); call
// probe_read_user; r0 = 0; exit. Verifier-valid on any kernel with
// helper 112 (MOV ignores its offset field, so frame-pointer
// arithmetic is MOV64_REG + ADD64_IMM; all pointers are aligned
// stack slots, which the unsafe_ptr check accepts).
fn insns_probe_read_user() -> Vec<u8> {
    vec![
        0xbf, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = r10
        0x07, 0x01, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, // r1 += -8
        0xb7, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r2 = 8
        0xbf, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = r10
        0x07, 0x03, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, // r3 += -16
        0x85, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, // call 112
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ]
}

struct ProbeOut {
    ok: bool,
    errno: i32,
    log: String,
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

fn run_prog_load(insns: &[u8]) -> ProbeOut {
    let mut log = vec![0u8; 4096];
    let license = c"GPL";
    match ossl_bpf_sys::prog_load_kprobe(insns, license, None, &mut log, "doctorprobe") {
        Ok(_) => ProbeOut {
            ok: true,
            errno: 0,
            log: String::new(),
        },
        Err(e) => ProbeOut {
            ok: false,
            errno: errno_of(&e),
            log: String::from_utf8_lossy(&log)
                .trim_end_matches('\0')
                .to_string(),
        },
    }
}

fn run_map_create(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> ProbeOut {
    match ossl_bpf_sys::map_create(
        map_type,
        key_size,
        value_size,
        max_entries,
        None,
        "doctorprobe",
    ) {
        Ok(_) => ProbeOut {
            ok: true,
            errno: 0,
            log: String::new(),
        },
        Err(e) => ProbeOut {
            ok: false,
            errno: errno_of(&e),
            log: String::new(),
        },
    }
}

/// File offset of the ELF entry point (for the self multi-attach
/// probe — always a valid offset, never re-fired mid-probe).
fn entry_file_offset(exe_bytes: &[u8]) -> Option<u64> {
    let elf = goblin::Object::parse(exe_bytes).ok()?;
    let goblin::Object::Elf(elf) = elf else {
        return None;
    };
    let vaddr = elf.header.e_entry;
    elf.program_headers.iter().find_map(|ph| {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && ph.p_vaddr <= vaddr
            && vaddr < ph.p_vaddr + ph.p_memsz
        {
            Some(vaddr - ph.p_vaddr + ph.p_offset)
        } else {
            None
        }
    })
}

fn run_multi_self() -> ProbeOut {
    let exe = match std::fs::read("/proc/self/exe") {
        Ok(b) => b,
        Err(e) => {
            return ProbeOut {
                ok: false,
                errno: errno_of(&e),
                log: "self-exe unreadable".into(),
            };
        }
    };
    let off = match entry_file_offset(&exe) {
        Some(o) => o,
        None => {
            return ProbeOut {
                ok: false,
                errno: libc::EINVAL,
                log: "no entry offset".into(),
            };
        }
    };
    let path = match std::ffi::CString::new("/proc/self/exe") {
        Ok(p) => p,
        Err(_) => {
            return ProbeOut {
                ok: false,
                errno: libc::EINVAL,
                log: "bad exe path".into(),
            };
        }
    };
    let mut log = vec![0u8; 4096];
    let license = c"GPL";
    let fd =
        match ossl_bpf_sys::prog_load_kprobe(&insns_noop(), license, None, &mut log, "doctorprobe")
        {
            Ok(f) => f,
            Err(e) => {
                return ProbeOut {
                    ok: false,
                    errno: errno_of(&e),
                    log: format!(
                        "load: {}",
                        String::from_utf8_lossy(&log).trim_end_matches('\0')
                    ),
                };
            }
        };
    use std::os::fd::AsRawFd as _;
    // Attach to SELF at the entry offset with a no-op prog: safe even
    // if it fired (it can't — entry runs once at exec); drop = detach.
    match ossl_bpf_sys::link_create_uprobe_multi(
        fd.as_raw_fd(),
        &path,
        &[off],
        &[1],
        std::process::id(),
    ) {
        Ok(_) => ProbeOut {
            ok: true,
            errno: 0,
            log: String::new(),
        },
        Err(e) => ProbeOut {
            ok: false,
            errno: errno_of(&e),
            log: String::new(),
        },
    }
}

fn run_token_probe() -> ProbeOut {
    // Existence probe only (6.9-floor feature row — never used for
    // privilege post-STOP#6): ENOSYS happens at dispatch (before any
    // caps/fd validation), so it alone proves absence; any other
    // outcome (EINVAL/ENOTDIR/EPERM — wrong fd type or no caps)
    // proves the subcommand dispatched, i.e. present.
    let f = std::fs::File::open("/dev/null");
    let fd = match &f {
        Ok(f) => {
            use std::os::fd::AsRawFd as _;
            f.as_raw_fd()
        }
        Err(e) => {
            return ProbeOut {
                ok: false,
                errno: errno_of(e),
                log: "/dev/null?!".into(),
            };
        }
    };
    match ossl_bpf_sys::token_create(fd) {
        Ok(_) => ProbeOut {
            ok: true,
            errno: 0,
            log: String::new(),
        },
        Err(e) => {
            if errno_of(&e) == libc::ENOSYS {
                ProbeOut {
                    ok: false,
                    errno: libc::ENOSYS,
                    log: String::new(),
                }
            } else {
                ProbeOut {
                    ok: true,
                    errno: 0,
                    log: String::new(),
                }
            }
        }
    }
}

// ---- denial classifier (pure — the unit-test star) ----

/// Environment facts feeding denial attribution.
struct DenyCtx {
    cap_bpf: bool,
    cap_perfmon: bool,
    lockdown_conf: bool,
    enforcing_lsm: Vec<String>,
    seccomp_filter: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ProbeVerdict {
    /// Feature present and usable.
    Pass,
    /// Kernel lacks the feature (wrong kernel — fail closed).
    TooOld(String),
    /// Unverifiable for want of caps (degraded — re-run with caps).
    DegradedCaps,
    /// Caps present but the op was denied (fail closed, attributed).
    Denied(String, String),
}

fn is_perm_errno(n: i32) -> bool {
    n == libc::EPERM || n == libc::EACCES
}

/// Classify one failed feature probe. `need_perfmon` marks probes
/// whose permission is CAP_PERFMON rather than CAP_BPF (perf path).
fn classify_probe(
    feature: &'static str,
    out: &ProbeOut,
    ctx: &DenyCtx,
    need_perfmon: bool,
) -> ProbeVerdict {
    if out.ok {
        return ProbeVerdict::Pass;
    }
    let n = out.errno;
    if n == libc::ENOSYS {
        return ProbeVerdict::TooOld("bpf() missing (pre-4.4 kernel?)".to_string());
    }
    if n == libc::EINVAL || n == libc::EOPNOTSUPP {
        return ProbeVerdict::TooOld(format!("{feature} unsupported (EINVAL-class)"));
    }
    // Verifier rejects unknown helpers; the log is decisive even when
    // errno is EACCES-shaped.
    if out.log.contains("unknown func") {
        return ProbeVerdict::TooOld(format!("{feature} helper missing (verifier log)"));
    }
    if is_perm_errno(n) {
        let have = if need_perfmon {
            ctx.cap_perfmon
        } else {
            ctx.cap_bpf
        };
        if !have {
            return ProbeVerdict::DegradedCaps;
        }
        if ctx.lockdown_conf {
            return ProbeVerdict::Denied(
                format!("{feature} blocked by lockdown=confidentiality"),
                "boot with lockdown=integrity (or none) if policy allows — confidentiality mode blocks BPF even with caps".into(),
            );
        }
        if !ctx.enforcing_lsm.is_empty() {
            return ProbeVerdict::Denied(
                format!("{feature} denied with caps held (likely LSM: {})", ctx.enforcing_lsm.join(",")),
                "check audit denials (ausearch -m AVC,USER_AVC -ts recent); AppArmor: aa-status + profile in complain? SELinux: audit2why; attach needs bpf+perfmon allowed".into(),
            );
        }
        if ctx.seccomp_filter {
            return ProbeVerdict::Denied(
                format!("{feature} denied with caps held (seccomp filter active)"),
                "a seccomp filter is blocking bpf(); restricted-SCC/Autopilot-class environments are stretch (unproven) — run outside the filter".into(),
            );
        }
        return ProbeVerdict::Denied(
            format!("{feature} denied (errno {n}) with caps held, no lockdown/LSM/seccomp"),
            "unexplained denial — see dmesg + audit log; file it with the doctor JSON".into(),
        );
    }
    ProbeVerdict::Denied(
        format!("{feature} failed (errno {n})"),
        "unexpected errno — see dmesg; file it with the doctor JSON".into(),
    )
}

// ---- perf_event probe (CAP_PERFMON leg of the caps check) ----

// Minimal perf_event_attr: type/config/size + zeroed tail (the kernel
// versions by `size`; 128 + zero tail is accepted everywhere).
#[repr(C)]
struct PerfAttr {
    typ: u32,
    size: u32,
    config: u64,
    rest: [u8; 112],
}

fn run_perf_self() -> ProbeOut {
    // SOFTWARE/CONTEXT_SWITCHES on self: no PMU needed, so the result
    // purely reflects permission (paranoid>=2 wants CAP_PERFMON).
    let attr = PerfAttr {
        typ: 1,
        size: 128,
        config: 3,
        rest: [0; 112],
    };
    // SAFETY: plain-old-data attr; pid 0 = self, cpu -1 = any.
    let ret = unsafe {
        libc::syscall(
            298, // __NR_perf_event_open (x86-64)
            &attr as *const PerfAttr,
            0,  // pid: self
            -1, // cpu: any
            -1, // group: none
            0,  // flags
        )
    };
    if ret < 0 {
        ProbeOut {
            ok: false,
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            log: String::new(),
        }
    } else {
        // SAFETY: fresh owned fd; close immediately (probe only).
        unsafe { libc::close(ret as i32) };
        ProbeOut {
            ok: true,
            errno: 0,
            log: String::new(),
        }
    }
}

// ---- foreign-uid maps probe (PTRACE path + claimed-PERFMON carve-out) ----

const SYS_CAPGET: libc::c_long = 125;
const SYS_CAPSET: libc::c_long = 126;
const CAP_VERSION_3: u32 = 0x20080522;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Clear every capability except `keep` (for the PERFMON-only child).
fn cap_drop_all_except(data: &mut [CapData; 2], keep: u32) {
    for (i, d) in data.iter_mut().enumerate() {
        let base = (i as u32) * 32;
        for w in [&mut d.effective, &mut d.permitted, &mut d.inheritable] {
            *w = if keep >= base && keep < base + 32 {
                1u32 << (keep - base)
            } else {
                0
            };
        }
    }
}

fn capset_self(data: &[CapData; 2]) -> std::io::Result<()> {
    let hdr = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    // SAFETY: versioned header + 2 data words; pid 0 = self.
    let ret = unsafe { libc::syscall(SYS_CAPSET, &hdr as *const CapHeader, data.as_ptr()) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn capget_self() -> std::io::Result<[CapData; 2]> {
    let hdr = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: versioned header + 2 data words; pid 0 = self.
    let ret = unsafe { libc::syscall(SYS_CAPGET, &hdr as *const CapHeader, data.as_mut_ptr()) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(data)
    }
}

/// Can the CURRENT credentials open the target's maps? (PTRACE-mode
/// check: same-uid-dumpable, CAP_SYS_PTRACE, or the 6.14+ PERFMON
/// carve-out if real.)
fn can_open_maps(pid: u32) -> bool {
    std::fs::File::open(format!("/proc/{pid}/maps")).is_ok()
}

/// Fork a child that drops to PERFMON-only and reports whether the
/// target's maps stay readable: the 6.14+ carve-out verdict.
/// Single-threaded CLI — fork is safe (no threads, no held locks).
fn probe_perfmon_only(pid: u32) -> Option<bool> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe writes two fresh fds.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: single-threaded; child only capsets/opens/writes/_exits.
    let cpid = unsafe { libc::fork() };
    if cpid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1])
        };
        return None;
    }
    if cpid == 0 {
        unsafe { libc::close(fds[0]) };
        let verdict = (|| {
            let mut data = capget_self().ok()?;
            cap_drop_all_except(&mut data, CAP_PERFMON);
            capset_self(&data).ok()?;
            Some(can_open_maps(pid))
        })();
        let byte = match verdict {
            Some(true) => b'1',
            Some(false) => b'0',
            None => b'?',
        };
        unsafe {
            libc::write(fds[1], &byte as *const u8 as *const libc::c_void, 1);
            libc::close(fds[1]);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut byte = [0u8; 1];
    let n = unsafe { libc::read(fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe {
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(cpid, &mut st, 0);
    }
    if n != 1 {
        return None;
    }
    match byte[0] {
        b'1' => Some(true),
        b'0' => Some(false),
        _ => None,
    }
}

// ---- target checks (pure cores, unit-tested) ----

fn proc_exe_name(pid: u32) -> Option<String> {
    // exe readlink goes silently empty for foreign-uid readers; fall
    // back to comm (world-readable), then give up.
    if let Some(n) = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name()?.to_str().map(str::to_string))
        .filter(|n| !n.is_empty())
    {
        return Some(n);
    }
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|n| !n.is_empty())
}

fn proc_uid(pid: u32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|m| m.uid())
}

fn pidns_of(pid: u32) -> Option<String> {
    // Foreign-uid ns readlinks succeed EMPTY (not EACCES) — treat
    // empty as unreadable, never as a (mismatching) namespace.
    std::fs::read_link(format!("/proc/{pid}/ns/pid"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
}

fn self_uid() -> u32 {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() }
}

enum LibcryptoHit {
    None,
    Deleted,
    One { path: String },
    Multi { paths: Vec<String> },
}

fn find_libcrypto(maps: &[crate::discovery::maps::Mapping]) -> LibcryptoHit {
    use std::collections::BTreeMap;
    let mut by_file: BTreeMap<(String, u64), String> = BTreeMap::new();
    let mut deleted_only = false;
    for m in maps {
        if !m.path.contains("libcrypto.so") {
            continue;
        }
        if m.path.contains("(deleted)") {
            deleted_only = true;
            continue;
        }
        by_file
            .entry((m.dev.clone(), m.ino))
            .or_insert_with(|| m.path.clone());
    }
    let mut paths: Vec<String> = by_file.into_values().collect();
    match paths.len() {
        0 if deleted_only => LibcryptoHit::Deleted,
        0 => LibcryptoHit::None,
        1 => LibcryptoHit::One {
            path: paths.pop().unwrap(),
        },
        _ => {
            paths.sort();
            LibcryptoHit::Multi { paths }
        }
    }
}

fn arch_name(machine: u16) -> String {
    // EM_ numbers per /usr/include/elf.h.
    match machine {
        3 => "i386".into(),
        20 => "PowerPC".into(),
        21 => "PowerPC64".into(),
        22 => "s390x".into(),
        40 => "ARM".into(),
        62 => "x86-64".into(),
        183 => "AArch64".into(),
        243 => "RISC-V".into(),
        n => format!("EM_{n}"),
    }
}

fn evidence_str(ev: &crate::discovery::flavor::Evidence) -> String {
    format!(
        "anchors: provider_load={} version_major={} engine={} boring_prefix={} awslc_prefix={}",
        ev.has_provider_load as u8,
        ev.has_version_major as u8,
        ev.has_engine_by_id as u8,
        ev.has_boring_prefix as u8,
        ev.has_awslc_prefix as u8,
    )
}

// ---- environment checks ----

struct Env {
    eff: u64,
    lockdown: String,
    lsm: Vec<String>,
    enforcing: Vec<String>,
    seccomp: u32,
    nnp: u32,
    release: String,
}

fn gather_env() -> Env {
    let status_txt = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let eff = parse_capeff(&status_txt).unwrap_or(0);
    Env {
        eff,
        lockdown: lockdown_mode(),
        lsm: lsm_list(),
        enforcing: enforcing_lsm(&lsm_list()),
        seccomp: status_field(&status_txt, "Seccomp")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        nnp: status_field(&status_txt, "NoNewPrivs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        release: uname_release(),
    }
}

impl Env {
    fn deny_ctx(&self) -> DenyCtx {
        DenyCtx {
            cap_bpf: has_cap(self.eff, CAP_BPF),
            cap_perfmon: has_cap(self.eff, CAP_PERFMON),
            lockdown_conf: self.lockdown == "confidentiality",
            enforcing_lsm: self.enforcing.clone(),
            seccomp_filter: self.seccomp == 2,
        }
    }
}

fn check_kernel(env: &Env) -> Check {
    // Feature set for the file-caps path: kprobe load, ringbuf maps,
    // uprobe_multi+cookies self-attach, probe_read_user helper.
    let probes = [
        ("kprobe-load", run_prog_load(&insns_noop()), false),
        (
            "ringbuf",
            run_map_create(ossl_bpf_sys::BPF_MAP_TYPE_RINGBUF, 0, 0, 4096),
            false,
        ),
        ("uprobe-multi", run_multi_self(), false),
        (
            "probe_read_user",
            run_prog_load(&insns_probe_read_user()),
            false,
        ),
    ];
    let ctx = env.deny_ctx();
    let mut too_old = Vec::new();
    let mut denied = Vec::new();
    let mut degraded = false;
    for (name, out, perf) in &probes {
        match classify_probe(name, out, &ctx, *perf) {
            ProbeVerdict::Pass => {}
            ProbeVerdict::TooOld(m) => too_old.push(m),
            ProbeVerdict::DegradedCaps => degraded = true,
            ProbeVerdict::Denied(m, _) => denied.push(m),
        }
    }
    if let Some(m) = too_old.into_iter().next() {
        return Check::fail(
            "kernel",
            format!("wrong kernel: {m} (feature probe, not uname; release {} informational)", env.release),
            "need a kernel with kprobe-load + ringbuf + uprobe-multi + probe_read_user (6.9+ verified; 6.12-LTS oldest tested)".into(),
        );
    }
    if let Some(m) = denied.into_iter().next() {
        return Check::fail(
            "kernel",
            m,
            "see the caps/lsm/lockdown checks for attribution".into(),
        );
    }
    if degraded {
        return Check::degraded(
            "kernel",
            format!(
                "kernel features unverifiable without CAP_BPF (release {} informational)",
                env.release
            ),
            SETCAP_RECIPE.into(),
        );
    }
    Check::pass(
        "kernel",
        format!(
            "features ok (kprobe-load, ringbuf, uprobe-multi+cookies, probe_read_user) on {} (informational)",
            env.release
        ),
    )
}

fn check_token_support(env: &Env) -> Check {
    // 6.9-floor feature row — informational only post-STOP#6 (the
    // file-caps path never uses tokens).
    let out = run_token_probe();
    match classify_probe("token-create", &out, &env.deny_ctx(), false) {
        ProbeVerdict::Pass => Check::info(
            "token-support",
            "BPF_TOKEN_CREATE present (6.9+ floor signal; tokens debug-only, never used for privilege)".into(),
        ),
        ProbeVerdict::TooOld(_) => Check::info(
            "token-support",
            "BPF_TOKEN_CREATE absent (pre-6.9? — informational only; file-caps path needs multi+ringbuf+cookie, not tokens)".into(),
        ),
        _ => Check::info(
            "token-support",
            "token existence unverifiable without CAP_BPF (informational only)".into(),
        ),
    }
}

fn check_caps(env: &Env) -> Check {
    // CapEff-first (doctrine: v1 requires the pair, paranoid-independent;
    // exit 6 ratifies against the file-caps harvest proof): the perf
    // probe corroborates and feeds LSM attribution on the perf path.
    let bpf = has_cap(env.eff, CAP_BPF);
    let perfmon = has_cap(env.eff, CAP_PERFMON);
    let admin = has_cap(env.eff, CAP_SYS_ADMIN);
    if admin || (bpf && perfmon) {
        let via = if admin {
            "CAP_SYS_ADMIN"
        } else {
            "CAP_BPF+CAP_PERFMON"
        };
        // Corroborate the perf path (LSM can block perf with caps held).
        let perf = run_perf_self();
        if !perf.ok && is_perm_errno(perf.errno) {
            let ctx = env.deny_ctx();
            if let ProbeVerdict::Denied(m, r) = classify_probe("perf", &perf, &ctx, true) {
                return Check::fail("caps", format!("{via} held but perf denied: {m}"), r);
            }
        }
        return Check::pass("caps", format!("{via} effective"));
    }
    let mut missing = Vec::new();
    if !bpf {
        missing.push("CAP_BPF");
    }
    if !perfmon {
        missing.push("CAP_PERFMON");
    }
    Check::fail(
        "caps",
        format!(
            "missing caps: {} (have neither file caps nor root)",
            missing.join("+")
        ),
        SETCAP_RECIPE.into(),
    )
}

fn check_btf() -> Check {
    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        Check::info(
            "btf",
            "BTF present (optional — probe path has zero BTF dependence)".into(),
        )
    } else {
        Check::info(
            "btf",
            "BTF absent — OK (probe path has zero BTF dependence); if you want it: ls /sys/kernel/btf/vmlinux; install: apt install linux-headers-$(uname -r) (Debian/Ubuntu) / dnf install kernel-devel (RHEL)".into(),
        )
    }
}

fn check_lockdown(env: &Env) -> Check {
    if env.lockdown == "confidentiality" {
        Check::fail(
            "lockdown",
            "lockdown=confidentiality blocks BPF even with caps".into(),
            "boot with lockdown=integrity (or none) if policy allows".into(),
        )
    } else {
        Check::pass(
            "lockdown",
            format!("lockdown={} (BPF allowed)", env.lockdown),
        )
    }
}

fn check_ima() -> Check {
    Check::info(
        "ima",
        format!(
            "IMA {} (informational — no known BPF interaction)",
            ima_state()
        ),
    )
}

fn check_lsm(env: &Env) -> Check {
    // Distinguished probe: BPF ops attempted above would have failed
    // with caps held iff LSM (or lockdown/seccomp) denies. Re-run one
    // cheap op to attribute the perf path too.
    let bpf_ok = run_map_create(ossl_bpf_sys::BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok;
    let perf_ok = run_perf_self().ok;
    let mods = if env.lsm.is_empty() {
        "none".to_string()
    } else {
        env.lsm.join(",")
    };
    if bpf_ok && perf_ok {
        return Check::pass(
            "lsm",
            format!("no LSM denial (BPF+perf ops succeed; active: {mods})"),
        );
    }
    if !has_cap(env.eff, CAP_BPF) {
        return Check::degraded(
            "lsm",
            format!("LSM denial unverifiable without caps (active: {mods})"),
            SETCAP_RECIPE.into(),
        );
    }
    // Caps held but an op failed: attribute via the classifier inputs.
    if env.lockdown == "confidentiality" {
        return Check::fail(
            "lsm",
            "BPF/perf denied with caps held — lockdown=confidentiality, not LSM".into(),
            "see the lockdown check".into(),
        );
    }
    if !env.enforcing.is_empty() {
        return Check::fail(
            "lsm",
            format!("likely LSM denial with caps held (enforcing: {})", env.enforcing.join(",")),
            "check audit denials (ausearch -m AVC,USER_AVC -ts recent); AppArmor: aa-status + profile in complain? SELinux: audit2why; attach needs bpf+perfmon allowed".into(),
        );
    }
    if env.seccomp == 2 {
        return Check::fail(
            "lsm",
            "BPF/perf denied with caps held, no enforcing LSM — suspect the seccomp filter".into(),
            "see the seccomp check".into(),
        );
    }
    Check::fail(
        "lsm",
        "BPF/perf denied with caps held, no lockdown/LSM/seccomp attribution".into(),
        "unexplained denial — see dmesg + audit log; file it with the doctor JSON".into(),
    )
}

fn check_seccomp(env: &Env) -> Check {
    match env.seccomp {
        0 => Check::info("seccomp", format!("no seccomp filter (NNP={})", env.nnp)),
        1 => Check::info(
            "seccomp",
            format!("seccomp strict mode (legacy; NNP={})", env.nnp),
        ),
        _ => Check::info(
            "seccomp",
            format!(
                "seccomp filter active (mode 2, NNP={}) — hint: if BPF ops fail with caps held, suspect the filter (restricted-SCC/Autopilot-class environments are stretch, unproven)",
                env.nnp
            ),
        ),
    }
}

// ---- target assembly ----

struct Target {
    exe: String,
    uid: Option<u32>,
    self_uid: u32,
    libcrypto: Option<String>,
}

fn target_json(t: &Option<Target>) -> serde_json::Value {
    match t {
        None => serde_json::Value::Null,
        Some(t) => serde_json::json!({
            "exe": t.exe,
            "uid": t.uid,
            "self_uid": t.self_uid,
            "libcrypto": t.libcrypto,
        }),
    }
}

fn check_pidns(pid: u32) -> Check {
    // Golden rule: no namespace ids, no pids in messages (both vary
    // per boot/run) — the remediation names the command shape only.
    let own = pidns_of(std::process::id());
    let tgt = pidns_of(pid);
    match (own, tgt) {
        (Some(o), Some(t)) if o == t => Check::pass("pidns", "same pid namespace".into()),
        (Some(_), Some(_)) => Check::fail(
            "pidns",
            "target is in a different pid namespace — attach sees wrong PIDs".into(),
            "nsenter -t <pid> -p -- osslscope <cmd> ...".into(),
        ),
        _ => Check::degraded(
            "pidns",
            "target pid namespace unreadable (need CAP_SYS_PTRACE or same uid to compare)".into(),
            "run as the target uid, or grant cap_sys_ptrace file cap and re-run".into(),
        ),
    }
}

fn check_foreign_uid(pid: u32, tuid: u32, env: &Env) -> Check {
    let s_uid = self_uid();
    if tuid == s_uid {
        return Check::info(
            "foreign-uid",
            format!("same-uid target (uid {tuid}) — no foreign-uid probe needed"),
        );
    }
    let readable = can_open_maps(pid);
    let ptrace = has_cap(env.eff, CAP_SYS_PTRACE);
    let perfmon = has_cap(env.eff, CAP_PERFMON);
    if readable && ptrace {
        match probe_perfmon_only(pid) {
            Some(true) => Check::pass(
                "foreign-uid",
                format!(
                    "target uid {tuid}: maps readable via PTRACE; PERFMON-only child also readable → 6.14+ carve-out CONFIRMED on this kernel"
                ),
            ),
            Some(false) => Check::pass(
                "foreign-uid",
                format!(
                    "target uid {tuid}: maps readable via PTRACE; PERFMON-only child denied → carve-out absent (PTRACE required)"
                ),
            ),
            None => Check::degraded(
                "foreign-uid",
                format!(
                    "target uid {tuid}: PTRACE path works; carve-out probe failed (fork/capset?)"
                ),
                "re-run; persistent failure is a doctor bug — file it".into(),
            ),
        }
    } else if readable && perfmon {
        Check::pass(
            "foreign-uid",
            format!(
                "target uid {tuid}: maps readable PERFMON-only (no PTRACE held) → 6.14+ carve-out CONFIRMED on this kernel"
            ),
        )
    } else if readable {
        Check::info(
            "foreign-uid",
            format!(
                "target uid {tuid}: maps readable without caps (kernel allows it; carve-out question moot)"
            ),
        )
    } else if perfmon {
        Check::info(
            "foreign-uid",
            format!(
                "target uid {tuid}: PERFMON-only denied → carve-out absent on this kernel (need CAP_SYS_PTRACE or same uid)"
            ),
        )
    } else if ptrace {
        Check::info(
            "foreign-uid",
            format!("target uid {tuid}: PTRACE held but maps denied — likely LSM (see lsm check)"),
        )
    } else {
        Check::degraded(
            "foreign-uid",
            format!(
                "target uid {tuid}: need caps to probe the carve-out (unverifiable unprivileged)"
            ),
            SETCAP_RECIPE.into(),
        )
    }
}

fn check_libcrypto_bytes(path: &str, table: &crate::discovery::builtin::Table) -> Vec<Check> {
    let mut out = Vec::new();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            out.push(Check::fail(
                "libcrypto-found",
                format!("libcrypto file unreadable ({path}): {e}"),
                "check the path/permissions (deleted underfoot?)".into(),
            ));
            return out;
        }
    };
    out.push(Check::pass("libcrypto-found", format!("libcrypto: {path}")));
    if bytes.len() < 20 {
        out.push(Check::fail(
            "arch",
            format!("libcrypto file too small ({}B, truncated?)", bytes.len()),
            "not a usable ELF object".into(),
        ));
        return out;
    }
    // EI_CLASS + e_machine by raw offset (no parser dependence).
    match bytes[4] {
        2 => {}
        1 => {
            out.push(Check::fail(
                "arch",
                "32-bit target libcrypto (ELFCLASS32) — v1 x86-64 only".into(),
                "run against a 64-bit OpenSSL build".into(),
            ));
            return out;
        }
        n => {
            out.push(Check::fail(
                "arch",
                format!("unknown EI_CLASS {n} — v1 x86-64 only"),
                "run against a 64-bit OpenSSL build".into(),
            ));
            return out;
        }
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 62 {
        out.push(Check::fail(
            "arch",
            format!("arch {} — v1 x86-64 only", arch_name(machine)),
            "run against a 64-bit x86-64 OpenSSL build".into(),
        ));
        return out;
    }
    out.push(Check::pass("arch", "x86-64 (ELFCLASS64, EM_X86_64)".into()));
    match crate::discovery::flavor::classify_elf(&bytes) {
        Ok((flavor, ev)) => {
            use crate::discovery::flavor::Flavor;
            match flavor {
                Flavor::OpenSSL { major, minor } => {
                    let line = crate::discovery::flavor::openssl_line(&ev).unwrap_or("?");
                    let ver = match minor {
                        Some(m) => format!("{major}.{m}"),
                        None => format!("{major}.?"),
                    };
                    out.push(Check::pass("flavor", format!("OpenSSL {ver} ({line})")));
                }
                Flavor::BoringSSL | Flavor::AwsLc => {
                    out.push(Check::fail(
                        "flavor",
                        format!("lookalike libcrypto ({flavor:?}): provider model absent — harvest REFUSED ({})", evidence_str(&ev)),
                        "v1 supports genuine OpenSSL only (P5 qualifies forks)".into(),
                    ));
                    return out;
                }
                Flavor::UnknownLookalike => {
                    out.push(Check::fail(
                        "flavor",
                        format!("unrecognized crypto library (no OpenSSL anchors, no fork prefix) — REFUSED fail-closed ({})", evidence_str(&ev)),
                        "v1 supports genuine OpenSSL only".into(),
                    ));
                    return out;
                }
                Flavor::NotCrypto => {
                    out.push(Check::fail(
                        "flavor",
                        "mapped libcrypto.so is not a crypto library (path confusion?)".into(),
                        "check which file the target maps".into(),
                    ));
                    return out;
                }
            }
        }
        Err(e) => {
            out.push(Check::fail(
                "flavor",
                format!("libcrypto bytes are not ELF ({e:#})"),
                "check which file the target maps".into(),
            ));
            return out;
        }
    }
    match crate::discovery::elf::read_build_id(&bytes) {
        None => out.push(Check::fail(
            "build-id",
            "no GNU build-id in target libcrypto (custom build or stripped notes?)".into(),
            "enroll the build: add build-id + query_offset to etc/build-id-table.json (see exit-6 privilege doc)".into(),
        )),
        Some(bid) => match table.by_build_id(&bid) {
            Some(e) => out.push(Check::pass(
                "build-id",
                format!("known build {bid} (OpenSSL {}, query_offset {})", e.openssl, e.query_offset),
            )),
            None => out.push(Check::fail(
                "build-id",
                format!("unknown build-id {bid} (not in frozen table of {} entries) — custom libcrypto build?", table.entry_count()),
                "anchor+delta fallback may work (inspect tries it); enroll via etc/build-id-table.json".into(),
            )),
        },
    }
    out
}

// ---- entry point ----

const USAGE: &str =
    "usage: osslscope doctor [--pid PID | --libcrypto PATH] [--table FILE] [--format human|json]";

pub fn run(args: &[String]) -> ExitCode {
    let mut pid: Option<u32> = None;
    let mut libcrypto: Option<String> = None;
    let mut table_path: Option<String> = None;
    let mut format = "human".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            println!("{USAGE}");
            println!("  no target: environment preflight (kernel, caps, LSM, lockdown)");
            println!("  --pid PID | --libcrypto PATH: also vet the target");
            println!("  --format human|json (default human)");
            return ExitCode::SUCCESS;
        }
        let val = |it: &mut std::slice::Iter<String>| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("missing value for {a}"))
        };
        let r: Result<(), String> = (|| {
            match a.as_str() {
                "--pid" => pid = Some(val(&mut it)?.parse().map_err(|_| "bad --pid")?),
                "--libcrypto" => libcrypto = Some(val(&mut it)?),
                "--table" => table_path = Some(val(&mut it)?),
                "--format" => {
                    let f = val(&mut it)?;
                    if f != "human" && f != "json" {
                        return Err("bad --format (want human|json)".into());
                    }
                    format = f;
                }
                _ => return Err(format!("unknown arg {a}")),
            }
            Ok(())
        })();
        if let Err(e) = r {
            eprintln!("osslscope doctor: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    if pid.is_some() && libcrypto.is_some() {
        eprintln!("osslscope doctor: use one target selector (--pid or --libcrypto)\n{USAGE}");
        return ExitCode::from(2);
    }
    // Build-id table: shipped frozen, --table overrides. Needed only
    // for target byte checks; a bad override is a usage error.
    let table_src = match &table_path {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("osslscope doctor: bad --table {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => include_str!("../etc/build-id-table.json").to_string(),
    };
    let table = match crate::discovery::builtin::load_table_str(&table_src) {
        Ok(t) => t,
        Err(e) => {
            if table_path.is_some() {
                eprintln!("osslscope doctor: bad --table file: {e:#}");
                return ExitCode::from(2);
            }
            eprintln!("osslscope doctor: internal error (shipped table corrupt): {e:#}");
            return ExitCode::from(1);
        }
    };
    if pid.is_some_and(|p| !std::path::Path::new(&format!("/proc/{p}")).exists()) {
        eprintln!("osslscope doctor: no such process {} (died?)", pid.unwrap());
        return ExitCode::from(2);
    }

    let env = gather_env();
    let mut checks = vec![
        check_kernel(&env),
        check_token_support(&env),
        check_caps(&env),
        check_btf(),
        check_lockdown(&env),
        check_ima(),
        check_lsm(&env),
        check_seccomp(&env),
    ];

    let mut target: Option<Target> = None;
    if let Some(p) = pid {
        let exe = proc_exe_name(p).unwrap_or_else(|| "?".into());
        let tuid = proc_uid(p).unwrap_or(u32::MAX);
        checks.push(check_pidns(p));
        checks.push(check_foreign_uid(p, tuid, &env));
        match crate::discovery::maps::read_maps(p) {
            Ok(maps) => {
                checks.push(Check::pass("target-access", "target maps readable".into()));
                match find_libcrypto(&maps) {
                    LibcryptoHit::One { path } => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: Some(path.clone()),
                        });
                        checks.extend(check_libcrypto_bytes(&path, &table));
                    }
                    LibcryptoHit::None => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: None,
                        });
                        checks.push(Check::fail(
                            "libcrypto-found",
                            "no libcrypto.so mapped in target (static link? non-crypto process?)"
                                .into(),
                            "inspect needs a dynamically-linked libcrypto target".into(),
                        ));
                    }
                    LibcryptoHit::Deleted => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: None,
                        });
                        checks.push(Check::fail(
                            "libcrypto-found",
                            "libcrypto mapping is (deleted) (upgraded underfoot?)".into(),
                            "restart the target".into(),
                        ));
                    }
                    LibcryptoHit::Multi { paths } => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: None,
                        });
                        checks.push(Check::fail(
                            "libcrypto-found",
                            format!(
                                "multiple libcrypto builds mapped (dual-load, ambiguous): {}",
                                paths.join(", ")
                            ),
                            "run with a single libcrypto (dual-load refused fail-closed)".into(),
                        ));
                    }
                }
            }
            Err(e) => {
                target = Some(Target {
                    exe,
                    uid: Some(tuid),
                    self_uid: self_uid(),
                    libcrypto: None,
                });
                // anyhow wraps the io error; downcast for the stable kind().
                let kind = e
                    .downcast_ref::<std::io::Error>()
                    .map(|io| io.kind().to_string())
                    .unwrap_or_else(|| e.to_string());
                checks.push(Check::fail(
                    "target-access",
                    format!("cannot read target maps ({kind}) — need CAP_SYS_PTRACE or same uid (target {tuid}, self {})", self_uid()),
                    "run as the target uid, or grant cap_sys_ptrace file cap and re-run".into(),
                ));
            }
        }
    } else if let Some(path) = libcrypto {
        let base = std::path::Path::new(&path)
            .file_name()
            .and_then(|b| b.to_str())
            .unwrap_or("?")
            .to_string();
        target = Some(Target {
            exe: base,
            uid: None,
            self_uid: self_uid(),
            libcrypto: Some(path.clone()),
        });
        checks.push(Check::info(
            "pidns",
            "no process target (--libcrypto is bytes-only)".into(),
        ));
        checks.push(Check::info(
            "foreign-uid",
            "no process target (--libcrypto is bytes-only)".into(),
        ));
        checks.push(Check::pass(
            "target-access",
            "libcrypto file given directly (--libcrypto)".into(),
        ));
        checks.extend(check_libcrypto_bytes(&path, &table));
    }

    let failed = checks.iter().any(|c| c.status == Status::Fail);
    if format == "json" {
        let doc = serde_json::json!({
            "target": target_json(&target),
            "checks": checks.iter().map(Check::json).collect::<Vec<_>>(),
            "verdict": if failed { "fail-closed" } else { "ok" },
            "exit": if failed { 4 } else { 0 },
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    } else {
        if let Some(t) = &target {
            println!(
                "target: {} (libcrypto: {})",
                t.exe,
                t.libcrypto.as_deref().unwrap_or("-")
            );
        }
        for c in &checks {
            let tag = match c.status {
                Status::Pass => "pass",
                Status::Fail => "FAIL",
                Status::Degraded => "degraded",
                Status::Info => "info",
            };
            println!("[{tag}] {}: {}", c.id, c.message);
            if let Some(r) = &c.remediation {
                println!("  remediate: {r}");
            }
        }
        println!("verdict: {}", if failed { "FAIL-CLOSED" } else { "ok" });
    }
    if failed {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(caps: u64, lockdown_conf: bool, lsm: &[&str], seccomp: bool) -> DenyCtx {
        DenyCtx {
            cap_bpf: has_cap(caps, CAP_BPF),
            cap_perfmon: has_cap(caps, CAP_PERFMON),
            lockdown_conf,
            enforcing_lsm: lsm.iter().map(|s| s.to_string()).collect(),
            seccomp_filter: seccomp,
        }
    }

    fn out(errno: i32, log: &str) -> ProbeOut {
        ProbeOut {
            ok: errno == 0,
            errno,
            log: log.into(),
        }
    }

    #[test]
    fn capeff_parse_and_bits() {
        let hex = format!("{:016x}", (1u64 << CAP_SYS_PTRACE) | (1u64 << CAP_BPF));
        let eff = parse_capeff(&format!("Name:\tdoctor\nCapEff:\t{hex}\n")).unwrap();
        assert!(has_cap(eff, CAP_SYS_PTRACE));
        assert!(has_cap(eff, CAP_BPF));
        assert!(!has_cap(eff, CAP_PERFMON));
        assert!(!has_cap(eff, CAP_SYS_ADMIN));
        assert_eq!(parse_capeff("no caps here"), None);
    }

    #[test]
    fn lockdown_parse() {
        assert_eq!(parse_lockdown("[none] integrity confidentiality"), "none");
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality"),
            "integrity"
        );
        assert_eq!(
            parse_lockdown("none integrity [confidentiality]"),
            "confidentiality"
        );
        assert_eq!(parse_lockdown(""), "none");
    }

    #[test]
    fn lsm_split_and_enforcing() {
        let l = parse_lsm("lockdown,capability,landlock,yama,apparmor,ima,evm");
        assert_eq!(enforcing_lsm(&l), vec!["apparmor".to_string()]);
        let l = parse_lsm("capability,selinux");
        assert_eq!(enforcing_lsm(&l), vec!["selinux".to_string()]);
        assert!(enforcing_lsm(&parse_lsm("capability")).is_empty());
        assert!(parse_lsm("").is_empty());
    }

    #[test]
    fn classifier_pass_and_too_old() {
        let c = ctx(0, false, &[], false);
        assert_eq!(
            classify_probe("f", &out(0, ""), &c, false),
            ProbeVerdict::Pass
        );
        assert!(matches!(
            classify_probe("f", &out(libc::ENOSYS, ""), &c, false),
            ProbeVerdict::TooOld(_)
        ));
        assert!(matches!(
            classify_probe("ringbuf", &out(libc::EINVAL, ""), &c, false),
            ProbeVerdict::TooOld(_)
        ));
        // Verifier log beats errno shape for unknown helpers.
        assert!(matches!(
            classify_probe(
                "f",
                &out(libc::EACCES, "unknown func bpf_probe_read_user#112"),
                &c,
                false
            ),
            ProbeVerdict::TooOld(_)
        ));
    }

    #[test]
    fn classifier_perm_ladder() {
        // No caps -> degraded (re-run with caps), never fail.
        let c = ctx(0, false, &[], false);
        assert_eq!(
            classify_probe("f", &out(libc::EPERM, ""), &c, false),
            ProbeVerdict::DegradedCaps
        );
        // Perf leg keys on PERFMON, not BPF.
        let c = ctx(1u64 << CAP_BPF, false, &[], false);
        assert_eq!(
            classify_probe("perf", &out(libc::EACCES, ""), &c, true),
            ProbeVerdict::DegradedCaps
        );
        // Caps held: lockdown > lsm > seccomp > unknown.
        let full = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let c = ctx(full, true, &["apparmor"], true);
        assert!(matches!(
            classify_probe("f", &out(libc::EPERM, ""), &c, false),
            ProbeVerdict::Denied(m, _) if m.contains("lockdown")
        ));
        let c = ctx(full, false, &["apparmor"], true);
        assert!(matches!(
            classify_probe("f", &out(libc::EPERM, ""), &c, false),
            ProbeVerdict::Denied(m, _) if m.contains("apparmor")
        ));
        let c = ctx(full, false, &[], true);
        assert!(matches!(
            classify_probe("f", &out(libc::EPERM, ""), &c, false),
            ProbeVerdict::Denied(m, _) if m.contains("seccomp")
        ));
        let c = ctx(full, false, &[], false);
        assert!(matches!(
            classify_probe("f", &out(libc::EPERM, ""), &c, false),
            ProbeVerdict::Denied(m, r) if m.contains("no lockdown/LSM/seccomp") && r.contains("unexplained")
        ));
        // Weird errno -> denied-unknown, never pass.
        assert!(matches!(
            classify_probe("f", &out(libc::ENOMEM, ""), &c, false),
            ProbeVerdict::Denied(_, _)
        ));
    }

    fn mapping(dev: &str, ino: u64, path: &str) -> crate::discovery::maps::Mapping {
        crate::discovery::maps::Mapping {
            start: 0,
            end: 0x1000,
            x: true,
            offset: 0,
            dev: dev.into(),
            ino,
            path: path.into(),
        }
    }

    #[test]
    fn libcrypto_find_cases() {
        let maps = vec![
            mapping("08:01", 1, "/lib/libc.so.6"),
            mapping("08:01", 2, "/opt/lib/libcrypto.so.4"),
            mapping("08:01", 2, "/opt/lib/libcrypto.so.4"),
        ];
        assert!(matches!(find_libcrypto(&maps), LibcryptoHit::One { .. }));
        let maps = vec![mapping("08:01", 1, "/lib/libc.so.6")];
        assert!(matches!(find_libcrypto(&maps), LibcryptoHit::None));
        let maps = vec![
            mapping("08:01", 2, "/a/libcrypto.so.4"),
            mapping("08:01", 3, "/b/libcrypto.so.3"),
        ];
        match find_libcrypto(&maps) {
            LibcryptoHit::Multi { paths } => assert_eq!(paths.len(), 2),
            _ => panic!("want multi"),
        }
        let maps = vec![mapping("08:01", 2, "/a/libcrypto.so.4 (deleted)")];
        assert!(matches!(find_libcrypto(&maps), LibcryptoHit::Deleted));
    }

    #[test]
    fn arch_names() {
        assert_eq!(arch_name(62), "x86-64");
        assert_eq!(arch_name(183), "AArch64");
        assert_eq!(arch_name(40), "ARM");
        assert_eq!(arch_name(3), "i386");
        assert_eq!(arch_name(21), "PowerPC64");
        assert_eq!(arch_name(22), "s390x");
        assert_eq!(arch_name(243), "RISC-V");
        assert_eq!(arch_name(999), "EM_999");
    }

    #[test]
    fn cap_drop_keeps_only_perfmon() {
        let mut d = [CapData {
            effective: 0xffff_ffff,
            permitted: 0xffff_ffff,
            inheritable: 0xffff_ffff,
        }; 2];
        cap_drop_all_except(&mut d, CAP_PERFMON);
        // PERFMON = 38 -> word 1, bit 6.
        assert_eq!((d[0].effective, d[1].effective), (0, 1u32 << 6));
        assert_eq!((d[0].permitted, d[1].permitted), (0, 1u32 << 6));
        assert_eq!((d[0].inheritable, d[1].inheritable), (0, 1u32 << 6));
        cap_drop_all_except(&mut d, CAP_SYS_PTRACE);
        // PTRACE = 19 -> word 0, bit 19.
        assert_eq!((d[0].effective, d[1].effective), (1u32 << 19, 0));
    }

    #[test]
    fn entry_offset_of_self() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let off = entry_file_offset(&exe).unwrap();
        assert!(off < exe.len() as u64);
        assert_eq!(entry_file_offset(b"not an elf"), None);
    }

    #[test]
    fn insn_shapes() {
        assert_eq!(insns_noop().len() % 8, 0);
        let p = insns_probe_read_user();
        assert_eq!(p.len() % 8, 0);
        assert_eq!(p.len(), 64);
        // 6th insn is call imm32 == 112 (BPF_FUNC_probe_read_user).
        assert_eq!(p[5 * 8], 0x85);
        assert_eq!(&p[5 * 8 + 4..5 * 8 + 8], &[0x70, 0x00, 0x00, 0x00]);
        // Last insn is exit.
        assert_eq!(p[7 * 8], 0x95);
    }

    #[test]
    fn shipped_table_loads() {
        let t =
            crate::discovery::builtin::load_table_str(include_str!("../etc/build-id-table.json"))
                .unwrap();
        assert!(t.entry_count() >= 5);
        assert!(
            t.by_build_id("b12cd44337cb70619dd290b2396ab5dfcaea230f")
                .is_some()
        );
        assert!(t.by_build_id("0".repeat(40).as_str()).is_none());
    }

    #[test]
    fn check_json_shape() {
        let c = Check::fail("x", "m".into(), "r".into());
        let j = c.json();
        assert_eq!(j["id"], "x");
        assert_eq!(j["status"], "fail");
        assert_eq!(j["message"], "m");
        assert_eq!(j["remediation"], "r");
        let c = Check::pass("y", "m".into());
        assert!(c.json().get("remediation").is_none());
    }
}
