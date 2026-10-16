//! SPDX-License-Identifier: GPL-3.0-or-later
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
//!
//! T12 onboarding agreement: target/object verdicts come from the
//! same [`crate::discovery::onboard`] qualification the backend
//! runs, so doctor cannot drift from `report`/`check`. Qualification
//! is three-way — Supported (attach now), Unsupported (never
//! supportable: arch/flavor), Unknown (stripped unenrolled build:
//! needs `--table` enrollment) — and privilege/capability,
//! target-support, and cold/coverage caveats are independent rows:
//! a caps failure never masks a target verdict and vice versa.
use crate::discovery::legacy;
use crate::discovery::maps;
use crate::discovery::onboard::{self, LibcryptoMaps, QualifyOpts, TargetQualification};
use crate::discovery::provider::{ProviderTable, ResolutionInputs, resolve_provider_class};
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::{Path, PathBuf};
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

// r1 = map_fd (ld_map_fd, slots 0-1); r2 = 0
// (BPF_RB_AVAIL_DATA); call ringbuf_query; r0 = 0; exit.
// Verifier-trivially-valid on any kernel with helper 134; the
// fd is patched in directly (known at build time — no loader
// relocation needed for a probe).
fn insns_ringbuf_query(map_fd: RawFd) -> Vec<u8> {
    let mut v = vec![0x18, 0x11, 0x00, 0x00];
    v.extend_from_slice(&(map_fd as u32).to_le_bytes()); // r1 = map_fd ll
    v.extend_from_slice(&[0u8; 8]); // (imm64 high)
    v.extend_from_slice(&[0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // r2 = 0
    v.extend_from_slice(&[0x85, 0x00, 0x00, 0x00]); // call
    v.extend_from_slice(&(ossl_bpf_sys::BPF_FUNC_RINGBUF_QUERY as u32).to_le_bytes()); // 134
    v.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // r0 = 0
    v.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // exit
    v
}

/// `bpf_ringbuf_query` floor-probe failure: which stage failed
/// (map creation vs program load), the errno, and the verifier
/// log (empty unless the load stage produced one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingbufQueryError {
    pub stage: &'static str,
    pub errno: i32,
    pub log: String,
}

impl std::fmt::Display for RingbufQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ringbuf_query unavailable ({} failed, errno {}): {}",
            self.stage,
            self.errno,
            if self.log.is_empty() {
                "no verifier log"
            } else {
                self.log.trim()
            }
        )
    }
}

impl std::error::Error for RingbufQueryError {}

/// `bpf_ringbuf_query` availability probe (P7 item 1a, §5.4
/// floor): creates a scratch ringbuf map, loads a trivial prog
/// calling the helper against it, and reports the outcome. Needs
/// CAP_BPF-or-CAP_SYS_ADMIN (map creation) plus, for the kprobe
/// program load, CAP_PERFMON as well (or CAP_SYS_ADMIN instead of
/// both); fail-closed on any error. Intended for B-traversal
/// startup gating (P7 item 3+); doctor surfaces it as an
/// informational row until then.
pub fn probe_ringbuf_query() -> Result<(), RingbufQueryError> {
    let map = ossl_bpf_sys::map_create(
        ossl_bpf_sys::BPF_MAP_TYPE_RINGBUF,
        0,
        0,
        4096,
        None,
        "rbqprobe",
    )
    .map_err(|e| RingbufQueryError {
        stage: "map_create",
        errno: errno_of(&e),
        log: String::new(),
    })?;
    let insns = insns_ringbuf_query(map.as_raw_fd());
    let mut log = vec![0u8; 4096];
    let license = c"GPL";
    ossl_bpf_sys::prog_load_kprobe(&insns, license, None, &mut log, "rbqprobe", None)
        .map(|_| ())
        .map_err(|e| RingbufQueryError {
            stage: "prog_load",
            errno: errno_of(&e),
            log: String::from_utf8_lossy(&log)
                .trim_end_matches('\0')
                .to_string(),
        })
}

/// Render a failed floor probe honestly (pure — unit-tested).
/// Syscall-missing defers to the shared ladder (no caps
/// involved). Permission failures evaluate COMPLETE stage
/// permissions — map creation needs CAP_BPF-or-CAP_SYS_ADMIN,
/// kprobe program load needs
/// (CAP_BPF-and-CAP_PERFMON)-or-CAP_SYS_ADMIN — and report the
/// actual missing capability; satisfied-yet-denied cases share
/// the lockdown→LSM→seccomp attribution. Everything else is
/// evidence-gated per stage: only a verifier "unknown func" log
/// establishes helper absence — allocation and setup failures
/// (EINVAL included) stay unverifiable, never "absent".
fn ringbuf_query_detail(e: &RingbufQueryError, deny: &DenyCtx) -> String {
    let n = e.errno;
    if n == libc::ENOSYS {
        let out = ProbeOut {
            ok: false,
            errno: n,
            log: e.log.clone(),
        };
        return match classify_probe("ringbuf-query", &out, deny, false) {
            ProbeVerdict::TooOld(m) => {
                format!("bpf_ringbuf_query unavailable ({m}; B traversal unavailable, sampler unaffected)")
            }
            _ => {
                "bpf_ringbuf_query probe inconclusive (classifier disagreement; report with doctor JSON)"
                    .into()
            }
        };
    }
    if is_perm_errno(n) {
        // Verifier evidence beats errno shape (a reject can arrive
        // EACCES-shaped with "unknown func" in the log).
        if e.stage == "prog_load" && e.log.contains("unknown func") {
            return "bpf_ringbuf_query absent (verifier: unknown helper; B traversal unavailable, sampler unaffected)"
                .into();
        }
        let need_perfmon = e.stage == "prog_load";
        let mut missing = Vec::new();
        if !deny.cap_bpf && !deny.cap_sys_admin {
            missing.push("CAP_BPF");
        }
        if need_perfmon && !deny.cap_perfmon && !deny.cap_sys_admin {
            missing.push("CAP_PERFMON");
        }
        if !missing.is_empty() {
            return format!(
                "bpf_ringbuf_query unverifiable without {} (informational only)",
                missing.join("+")
            );
        }
        let (m, _) = denied_detail("ringbuf-query", n, deny);
        return format!("bpf_ringbuf_query denied ({m}; informational only)");
    }
    if e.stage == "prog_load" && n == libc::EINVAL && e.log.contains("unknown func") {
        return "bpf_ringbuf_query absent (verifier: unknown helper; B traversal unavailable, sampler unaffected)"
            .into();
    }
    let what = if e.stage == "map_create" {
        "ringbuf map creation"
    } else {
        "probe program load"
    };
    let mut msg = format!("bpf_ringbuf_query unverifiable ({what} failed, errno {n}");
    let excerpt: String = e
        .log
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(120)
        .collect();
    if !excerpt.is_empty() {
        msg.push_str(": ");
        msg.push_str(&excerpt);
    }
    msg.push_str("; B traversal gated, sampler unaffected)");
    msg
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

fn run_prog_load(insns: &[u8]) -> ProbeOut {
    let mut log = vec![0u8; 4096];
    let license = c"GPL";
    match ossl_bpf_sys::prog_load_kprobe(insns, license, None, &mut log, "doctorprobe", None) {
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
    let fd = match ossl_bpf_sys::prog_load_kprobe(
        &insns_noop(),
        license,
        None,
        &mut log,
        "doctorprobe",
        None,
    ) {
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
    cap_sys_admin: bool,
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
        let (m, r) = denied_detail(feature, n, ctx);
        return ProbeVerdict::Denied(m, r);
    }
    ProbeVerdict::Denied(
        format!("{feature} failed (errno {n})"),
        "unexpected errno — see dmesg; file it with the doctor JSON".into(),
    )
}

/// Denial attribution once stage caps are satisfied (shared by
/// classify_probe and the ringbuf-query floor detail): lockdown →
/// LSM → seccomp → unexplained. Pure.
fn denied_detail(feature: &'static str, n: i32, ctx: &DenyCtx) -> (String, String) {
    if ctx.lockdown_conf {
        return (
            format!("{feature} blocked by lockdown=confidentiality"),
            "boot with lockdown=integrity (or none) if policy allows — confidentiality mode blocks BPF even with caps".into(),
        );
    }
    if !ctx.enforcing_lsm.is_empty() {
        return (
            format!(
                "{feature} denied with caps held (likely LSM: {})",
                ctx.enforcing_lsm.join(",")
            ),
            "check audit denials (ausearch -m AVC,USER_AVC -ts recent); AppArmor: aa-status + profile in complain? SELinux: audit2why; attach needs bpf+perfmon allowed".into(),
        );
    }
    if ctx.seccomp_filter {
        return (
            format!("{feature} denied with caps held (seccomp filter active)"),
            "a seccomp filter is blocking bpf(); restricted-SCC/Autopilot-class environments are stretch (unproven) — run outside the filter".into(),
        );
    }
    (
        format!("{feature} denied (errno {n}) with caps held, no lockdown/LSM/seccomp"),
        "unexplained denial — see dmesg + audit log; file it with the doctor JSON".into(),
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
            cap_sys_admin: has_cap(self.eff, CAP_SYS_ADMIN),
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

fn check_ringbuf_query(env: &Env) -> Check {
    // B-traversal floor signal (P7 item 1a, §5.4) — informational
    // until the B entry gates startup on it (P7 item 3+ wires
    // fail-closed): the sampler path needs no ringbuf_query.
    match probe_ringbuf_query() {
        Ok(()) => Check::info(
            "ringbuf-query",
            "bpf_ringbuf_query present (B-traversal floor ok; entry admission can query occupancy)"
                .into(),
        ),
        Err(e) => Check::info("ringbuf-query", ringbuf_query_detail(&e, &env.deny_ctx())),
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
        // Perf corroboration is INFORMATIONAL only (reunification
        // 2026-09-18): the raw-multi attach path uses zero
        // perf_events (proven: full attach works with perf denied),
        // and the kernel row functionally proves the BPF ops. A
        // perf denial with caps held is an LSM curiosity about an
        // unused interface — never a verdict.
        let perf = run_perf_self();
        if !perf.ok && is_perm_errno(perf.errno) {
            return Check::pass(
                "caps",
                format!(
                    "{via} effective (perf_event_open denied — unused by the attach path; informational)"
                ),
            );
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
    // with caps held iff LSM (or lockdown/seccomp) denies. Perf is
    // probed for context only — the attach path never uses it
    // (reunification 2026-09-18), so a perf denial alone is not a
    // denial of anything we do.
    let bpf_ok = run_map_create(ossl_bpf_sys::BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok;
    let perf_ok = run_perf_self().ok;
    let mods = if env.lsm.is_empty() {
        "none".to_string()
    } else {
        env.lsm.join(",")
    };
    if bpf_ok {
        let perf_note = if perf_ok {
            ""
        } else {
            " (perf_event_open denied — unused; informational)"
        };
        return Check::pass(
            "lsm",
            format!("no LSM denial (BPF ops succeed; active: {mods}){perf_note}"),
        );
    }
    if !has_cap(env.eff, CAP_BPF) {
        return Check::degraded(
            "lsm",
            format!("LSM denial unverifiable without caps (active: {mods})"),
            SETCAP_RECIPE.into(),
        );
    }
    // Caps held but the BPF op failed: attribute via the classifier inputs.
    if env.lockdown == "confidentiality" {
        return Check::fail(
            "lsm",
            "BPF denied with caps held — lockdown=confidentiality, not LSM".into(),
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
            "BPF denied with caps held, no enforcing LSM — suspect the seccomp filter".into(),
            "see the seccomp check".into(),
        );
    }
    Check::fail(
        "lsm",
        "BPF denied with caps held, no lockdown/LSM/seccomp attribution".into(),
        "unexplained denial — see dmesg + audit log; file it with the doctor JSON".into(),
    )
}

/// Current dumpable state of this process via prctl (the
/// historical /proc/self/status Dumpable field is absent on
/// 6.12+/7.0, so status parsing cannot report it).
fn self_dumpable() -> Option<libc::c_int> {
    let r = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if r < 0 { None } else { Some(r) }
}

/// F-CAPS-1: replicate the `run --` setup maps read exactly — fork a
/// stopped child that opts itself dumpable pre-exec (the product
/// path in target.rs), then read its maps from here. Under filecaps
/// this read is what decides whether `run --` setup passes: without
/// the product's self-dumpable call it fails EACCES (the child
/// inherits the observer's non-dumpable state); with it, it must
/// pass. Single-threaded CLI — fork is safe (no threads, no held
/// locks). The probe child is always killed and reaped (never a
/// zombie, never left stopped).
fn check_spawn_access() -> Check {
    let dump_txt = self_dumpable().map_or("unknown".to_string(), |d| d.to_string());
    // SAFETY: single-threaded; child only prctls/stops/_exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Check::fail(
            "spawn-access",
            "cannot fork the spawn-setup probe".into(),
            "check process limits (ulimit -u), then re-run".into(),
        );
    }
    if pid == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
    }
    let mut status = 0;
    // Reap confirming (not assumed): the first wait may already reap
    // a child that died instead of stopping; otherwise the kill +
    // second wait must observe the death. ECHILD anywhere means no
    // unwaited-for child exists (already reaped — safe, not an
    // error). A SIGKILLed 3-instruction child always dies, so the
    // second wait cannot hang; any non-EINTR surprise still breaks
    // out and fails the check below (never a silent leak).
    let mut reaped = false;
    let stopped = loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if r == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            reaped = true;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            reaped = true;
        }
        break r == pid && libc::WIFSTOPPED(status);
    };
    let maps = if stopped {
        std::fs::read_to_string(format!("/proc/{pid}/maps"))
    } else {
        Err(std::io::Error::other("probe child never stopped"))
    };
    let k = unsafe { libc::kill(pid, libc::SIGKILL) };
    let kill_errno = std::io::Error::last_os_error().raw_os_error();
    if k != 0 && !reaped && kill_errno != Some(libc::ESRCH) {
        // Kill failed on a live, unreaped child (EPERM/EINVAL are
        // impossible for our own pid+SIGKILL — this is defensive):
        // the wait below still reaps, but say so loudly.
        crate::report::err_line(&format!(
            "osslscope doctor: probe kill failed: {kill_errno:?}"
        ));
    }
    let mut status2 = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status2, 0) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if r == pid || std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            reaped = true;
        }
        break;
    }
    if !reaped {
        return Check::fail(
            "spawn-access",
            "spawn-setup probe leaked its child (reap unconfirmed)".into(),
            "re-run; a leftover stopped child blocks the next probe — report this".into(),
        );
    }
    match maps {
        Ok(body) if !body.is_empty() => Check::pass(
            "spawn-access",
            format!(
                "spawn setup maps read ok: pre-exec child maps readable ({} bytes; self dumpable={dump_txt})",
                body.len()
            ),
        ),
        Ok(_) => Check::fail(
            "spawn-access",
            "spawn setup maps read would fail: pre-exec child maps empty".into(),
            "run with sudo once to confirm, then report (observer self-dumpable mechanism failed)"
                .into(),
        ),
        Err(e) => Check::fail(
            "spawn-access",
            format!("spawn setup maps read would fail: pre-exec child maps unreadable ({e})"),
            "run with sudo once to confirm, then report (observer self-dumpable mechanism failed)"
                .into(),
        ),
    }
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

// ---- installed objects + coverage caveats (T12/R09) ----

/// Installed-object rows (both roles): explicit paths validate
/// individually; a fully automatic pair resolves from the first
/// trusted dir holding a complete pair — the same primitives the
/// backend composes, so doctor agrees with `report`/`check`. A
/// failed pair fails both rows (neither role is usable without
/// its mate).
fn objects_checks(harvest: Option<&str>, count: Option<&str>, members: Option<&str>) -> Vec<Check> {
    objects_checks_in(
        harvest,
        count,
        members,
        &onboard::default_object_dirs(),
        &onboard::TrustPolicy::production(),
    )
}

/// Installed-object rows over explicit dirs/trust (production
/// passes the installed defaults; tests pass fixtures).
fn objects_checks_in(
    harvest: Option<&str>,
    count: Option<&str>,
    members: Option<&str>,
    dirs: &[PathBuf],
    trust: &onboard::TrustPolicy,
) -> Vec<Check> {
    use onboard::ObjectRole::{Count, Harvest, Members};
    let row = |role: onboard::ObjectRole,
               r: Result<PathBuf, onboard::OnboardError>,
               how: &str|
     -> Check {
        let (id, noun) = match role {
            Harvest => ("objects-harvest", "harvest"),
            Count => ("objects-count", "count"),
            Members => ("objects-members", "members"),
        };
        match r {
            Ok(path) => Check::pass(
                id,
                format!("{noun} object: {} ({how}, compatible)", path.display()),
            ),
            Err(e) => Check::fail(id, e.message, e.remediation),
        }
    };
    let mut search = onboard::ObjectSearch::default();
    // Implicit roles verify against the prefix receipt exactly
    // like the run's mixed arm (receiptless pair roles stay
    // compatible for old installs — Decision 4; a receiptless
    // members role refuses — its matched-build identity is not
    // established).
    let implicit = |role: onboard::ObjectRole,
                    search: &mut onboard::ObjectSearch|
     -> Result<PathBuf, onboard::OnboardError> {
        let p = onboard::resolve_implicit_role(role, dirs, trust, search)?;
        onboard::verify_role_receipt(role, &p)?;
        Ok(p)
    };
    match (harvest, count, members) {
        // Fully automatic: the ONE shared run-set decision (F9) —
        // doctor renders exactly what capture runs (Triple rows,
        // PairOnly rows + members INFO, or fail-all-three).
        // Missing/mixed/stale sets behave identically in both by
        // construction; an empty install fails all three (no pair
        // exists to call compatible).
        (None, None, None) => match onboard::resolve_run_set(None, None, None, dirs, trust) {
            Ok((onboard::RunSet::Triple(set), _)) => vec![
                Check::pass(
                    "objects-harvest",
                    format!(
                        "harvest object: {} (installed, compatible)",
                        set.harvest.display()
                    ),
                ),
                Check::pass(
                    "objects-count",
                    format!(
                        "count object: {} (installed, compatible)",
                        set.count.display()
                    ),
                ),
                Check::pass(
                    "objects-members",
                    format!(
                        "members object: {} (installed, compatible)",
                        set.members.display()
                    ),
                ),
            ],
            Ok((onboard::RunSet::PairOnly(pair), _)) => vec![
                Check::pass(
                    "objects-harvest",
                    format!(
                        "harvest object: {} (installed, compatible)",
                        pair.harvest.display()
                    ),
                ),
                Check::pass(
                    "objects-count",
                    format!(
                        "count object: {} (installed, compatible)",
                        pair.count.display()
                    ),
                ),
                Check::info(
                    "objects-members",
                    "members object: not installed (traversal unavailable — old harvest/count pair compatible)".to_string(),
                ),
            ],
            Ok((onboard::RunSet::NoObjects(pair_e), _)) => vec![
                Check::fail(
                    "objects-harvest",
                    pair_e.message.clone(),
                    pair_e.remediation.clone(),
                ),
                Check::fail("objects-count", pair_e.message, pair_e.remediation),
                Check::info(
                    "objects-members",
                    "members object: not installed (traversal unavailable — old harvest/count pair compatible)".to_string(),
                ),
            ],
            Err(e) => vec![
                Check::fail("objects-harvest", e.message.clone(), e.remediation.clone()),
                Check::fail("objects-count", e.message.clone(), e.remediation.clone()),
                Check::fail("objects-members", e.message, e.remediation),
            ],
        },
        // Explicit members: the operator demanded traversal — the
        // same matched-set resolution a run performs (mixed
        // explicit/implicit arms identical). One error fails all
        // three (matched-set semantics, like the pair rows).
        (_, _, Some(_)) => {
            match onboard::resolve_set(
                harvest.map(Path::new),
                count.map(Path::new),
                members.map(Path::new),
                dirs,
                trust,
            ) {
                Ok((set, _)) => vec![
                    row(Harvest, Ok(set.harvest), "explicit"),
                    row(Count, Ok(set.count), "explicit"),
                    row(Members, Ok(set.members), "explicit"),
                ],
                Err(e) => vec![
                    Check::fail("objects-harvest", e.message.clone(), e.remediation.clone()),
                    Check::fail("objects-count", e.message.clone(), e.remediation.clone()),
                    Check::fail("objects-members", e.message, e.remediation),
                ],
            }
        }
        // Explicit pair roles, implicit members: pair rows as
        // usual; members INFOs when absent, resolves
        // receipt-required when a trusted dir holds it.
        (Some(h), Some(c), None) => vec![
            row(
                Harvest,
                onboard::resolve_explicit(Harvest, Path::new(h)),
                "explicit",
            ),
            row(
                Count,
                onboard::resolve_explicit(Count, Path::new(c)),
                "explicit",
            ),
            members_row(members, dirs, trust, &mut search, &implicit),
        ],
        (Some(h), None, None) => vec![
            row(
                Harvest,
                onboard::resolve_explicit(Harvest, Path::new(h)),
                "explicit",
            ),
            row(Count, implicit(Count, &mut search), "installed"),
            members_row(members, dirs, trust, &mut search, &implicit),
        ],
        (None, Some(c), None) => vec![
            row(Harvest, implicit(Harvest, &mut search), "installed"),
            row(
                Count,
                onboard::resolve_explicit(Count, Path::new(c)),
                "explicit",
            ),
            members_row(members, dirs, trust, &mut search, &implicit),
        ],
    }
}

/// Members (traversal) row for mixed explicit/implicit selections:
/// absent INFOs on old installs (the pair still works —
/// Decision 7); a trusted dir holding the role resolves
/// receipt-required (pass/fail); present-but-unresolvable FAILS
/// (broken install, actionable — same fail-closed stance as the
/// pair rows).
fn members_row(
    members: Option<&str>,
    dirs: &[PathBuf],
    trust: &onboard::TrustPolicy,
    search: &mut onboard::ObjectSearch,
    implicit: &dyn Fn(
        onboard::ObjectRole,
        &mut onboard::ObjectSearch,
    ) -> Result<PathBuf, onboard::OnboardError>,
) -> Check {
    use onboard::ObjectRole::Members;
    match members {
        Some(m) => {
            let r = onboard::resolve_explicit(Members, Path::new(m));
            match r {
                Ok(path) => Check::pass(
                    "objects-members",
                    format!("members object: {} (explicit, compatible)", path.display()),
                ),
                Err(e) => Check::fail("objects-members", e.message, e.remediation),
            }
        }
        None => match implicit(Members, search) {
            Ok(path) => Check::pass(
                "objects-members",
                format!("members object: {} (installed, compatible)", path.display()),
            ),
            Err(e) => {
                if onboard::role_file_in_trusted(Members, dirs, trust) {
                    Check::fail("objects-members", e.message, e.remediation)
                } else {
                    Check::info(
                        "objects-members",
                        "members object: not installed (traversal unavailable — old harvest/count pair compatible)".to_string(),
                    )
                }
            }
        },
    }
}

/// Maximum caller modules doctor scans for the address-taken
/// caveat (diagnostic bound, disclosed in the row on truncation).
const DOCTOR_SCAN_MODULES: usize = 32;
/// Maximum module file size doctor reads for the caveat scan.
const DOCTOR_SCAN_MAX_BYTES: u64 = 64 << 20;
/// Maximum total bytes doctor reads across the caveat scan.
const DOCTOR_SCAN_TOTAL_BUDGET: u64 = 256 << 20;

/// Coverage-caveat rows for a live target (all info, never fail):
/// cold-start, auto-discovery scope, and the bounded address-taken
/// summary (same scan/resolution rules as the backend plan).
fn coverage_checks(maps: &[maps::Mapping], libcrypto: &str, lib_bytes: &[u8]) -> Vec<Check> {
    let mut out = vec![
        Check::info(
            "coverage-cold-start",
            "--pid cannot see pre-attach history (cold-start gap); prefer `run --` when first-call coverage matters".into(),
        ),
        Check::info(
            "coverage-scope",
            "automatic discovery observes the in-libcrypto default provider; file providers need explicit --provider".into(),
        ),
    ];
    let modules = legacy::target_modules(maps, libcrypto);
    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    let mut skipped_io: u64 = 0;
    let mut total: u64 = 0;
    for m in modules.iter().take(DOCTOR_SCAN_MODULES) {
        // Bounded per file (oversize/I/O skips, disclosed below) plus
        // a total budget across the scan.
        match onboard::read_bounded(Path::new(m), DOCTOR_SCAN_MAX_BYTES) {
            Ok(b) if total + b.len() as u64 <= DOCTOR_SCAN_TOTAL_BUDGET => {
                total += b.len() as u64;
                owned.push((m.clone(), b));
            }
            _ => skipped_io += 1,
        }
    }
    let truncated = modules.len().saturating_sub(DOCTOR_SCAN_MODULES);
    let callers: Vec<legacy::Module> = owned
        .iter()
        .map(|(p, b)| legacy::Module {
            path: p.as_str(),
            bytes: b,
        })
        .collect();
    let lib_mod = legacy::Module {
        path: libcrypto,
        bytes: lib_bytes,
    };
    let s = legacy::address_taken_summary(&lib_mod, &callers);
    let mut message = format!(
        "{} taxonomy address-taken imports across {} scanned modules ({} resolved, {} ambiguous, {} absent, {} unknown)",
        s.taxonomy_imports, s.scanned_modules, s.resolved, s.ambiguous, s.absent, s.unknown,
    );
    let skipped = s.skipped_modules.len() as u64 + skipped_io + truncated as u64;
    if skipped > 0 {
        message.push_str(&format!(
            "; {skipped} modules skipped (unreadable/oversize/bounds)"
        ));
    }
    message.push_str(" — all stay uninstrumented gaps (see lowlevel-fallback-uninstrumented)");
    out.push(Check::info("coverage-address-taken", message));
    out
}

// ---- target assembly ----

fn base_name(p: &Path) -> String {
    p.file_name()
        .and_then(|b| b.to_str())
        .unwrap_or("?")
        .to_string()
}

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

/// Qualification inputs shared by every target byte check (one
/// construction per doctor run; the same values the backend would
/// use for this target, so rows agree with `report`/`check`).
struct TargetCtx<'a> {
    table: &'a crate::discovery::builtin::Table,
    table_explicit: bool,
    force_offset: Option<u64>,
    enrollment: &'a ProviderTable,
}

impl<'a> TargetCtx<'a> {
    fn opts(&self) -> QualifyOpts<'a> {
        QualifyOpts {
            offset_table: self.table,
            offset_table_explicit: self.table_explicit,
            force_offset: self.force_offset,
            enrollment: self.enrollment,
            builtin_asserted: true,
        }
    }
}

/// `dispatch-anchor` row from a backend qualification (pure): the
/// verdict row that agrees with what `report`/`check` would do for
/// this target — Supported (attach now), Unsupported (never
/// supportable), Unknown (needs `--table` enrollment).
fn anchor_check(qual: &TargetQualification) -> Check {
    match qual {
        TargetQualification::Supported(t) => {
            let via = t.resolution.map(|r| r.as_str()).unwrap_or("init-anchor");
            let off = t
                .query_offset
                .map(|o| format!(" (offset {o:#x})"))
                .unwrap_or_default();
            if t.resolution == Some(crate::discovery::builtin::Resolution::Forced) {
                Check::pass(
                    "dispatch-anchor",
                    format!("supported via force{off} (operator-selected; validated at attach)"),
                )
            } else {
                Check::pass("dispatch-anchor", format!("supported via {via}{off}"))
            }
        }
        TargetQualification::Unsupported {
            reason,
            remediation,
        } => Check::fail(
            "dispatch-anchor",
            format!("unsupported target: {reason}"),
            remediation.clone(),
        ),
        TargetQualification::Unknown {
            reason,
            remediation,
        } => Check::fail(
            "dispatch-anchor",
            format!("unqualified build: {reason}"),
            remediation.clone(),
        ),
    }
}

/// `provider-class` row from pinned enrollment / builtin assertion
/// (pure, never fails: an unknown class is honest, not blocking —
/// the backend observes with an opaque identity).
fn class_check(build_id: Option<&str>, enrollment: &ProviderTable) -> Check {
    let class = resolve_provider_class(&ResolutionInputs {
        build_id,
        table: enrollment,
        builtin_asserted: true,
    });
    match class {
        Some(c) => {
            let pinned = build_id.and_then(|id| enrollment.by_build_id(id)).is_some();
            let basis = if pinned {
                "pinned enrollment"
            } else {
                "operator builtin assertion"
            };
            let mut message = format!("provider class: {} ({basis})", c.as_str());
            if c == crate::discovery::provider::ProviderClass::Fips {
                message.push_str(" — provenance metadata, not a certification claim");
            }
            Check::pass("provider-class", message)
        }
        None => Check::info(
            "provider-class",
            "unknown provider class (no enrollment; runtime uses an opaque third-party identity)"
                .into(),
        ),
    }
}

fn target_file_unreadable(path: &str, e: &onboard::ReadBoundedError) -> Check {
    Check::fail(
        "libcrypto-found",
        format!("libcrypto file unreadable ({path}): {e}"),
        "check the path/permissions (deleted underfoot?)".into(),
    )
}

/// Target rows over already-read bytes (one bounded read shared
/// with coverage scans — never re-read unbounded a file that
/// qualification already bounded).
fn check_target_bytes(path: &str, bytes: &[u8], ctx: &TargetCtx) -> Vec<Check> {
    let mut out = vec![Check::pass("libcrypto-found", format!("libcrypto: {path}"))];
    out.extend(check_byte_rows(path, bytes, false, ctx));
    out
}

/// Target file checks: presence row plus the byte rows below.
fn check_target_file(path: &str, ctx: &TargetCtx) -> Vec<Check> {
    match onboard::read_bounded(Path::new(path), onboard::MAX_OBJECT_SCAN_BYTES) {
        Ok(bytes) => check_target_bytes(path, &bytes, ctx),
        Err(e) => vec![target_file_unreadable(path, &e)],
    }
}

/// Byte rows over target bytes: arch → flavor → build-id (fact) →
/// dispatch-anchor (verdict) → provider-class. Arch/flavor failures
/// stop early (Unsupported can never qualify); the anchor verdict
/// always comes from the backend qualification.
fn check_byte_rows(path: &str, bytes: &[u8], static_exe: bool, ctx: &TargetCtx) -> Vec<Check> {
    let mut out = Vec::new();
    if let Err(e) = onboard::check_arch(bytes) {
        out.push(Check::fail(
            "arch",
            e,
            "run against a 64-bit x86-64 OpenSSL build".into(),
        ));
        return out;
    }
    out.push(Check::pass("arch", "x86-64 (ELFCLASS64, EM_X86_64)".into()));
    // Static candidates classify with symtab names unioned in (same
    // rule as backend qualification — a non-rdynamic static exe
    // keeps anchors only in `.symtab`).
    let classified = if static_exe {
        crate::discovery::flavor::classify_elf_with_symtab(bytes)
    } else {
        crate::discovery::flavor::classify_elf(bytes)
    };
    match classified {
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
                        "osslscope supports genuine OpenSSL 3.x/4.x only".into(),
                    ));
                    return out;
                }
                Flavor::UnknownLookalike => {
                    out.push(Check::fail(
                        "flavor",
                        format!("unrecognized crypto library (no OpenSSL anchors, no fork prefix) — REFUSED fail-closed ({})", evidence_str(&ev)),
                        "osslscope supports genuine OpenSSL 3.x/4.x only".into(),
                    ));
                    return out;
                }
                Flavor::NotCrypto => {
                    let message = if static_exe {
                        "static exe is not OpenSSL (no libcrypto present and the exe is not a crypto library)".to_string()
                    } else {
                        "mapped libcrypto.so is not a crypto library (path confusion?)".to_string()
                    };
                    out.push(Check::fail(
                        "flavor",
                        message,
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
    // Build-id is a fact row, not the verdict: an unknown id with
    // a symtab still qualifies (see dispatch-anchor).
    let build_id = crate::discovery::elf::read_build_id(bytes);
    match &build_id {
        None => out.push(Check::info(
            "build-id",
            "no GNU build-id in target libcrypto (custom build or stripped notes?) — symtab may still qualify; see dispatch-anchor".into(),
        )),
        Some(bid) => match ctx.table.by_build_id(bid) {
            Some(e) => out.push(Check::pass(
                "build-id",
                format!("known build {bid} (OpenSSL {}, query_offset {})", e.openssl, e.query_offset),
            )),
            None => out.push(Check::info(
                "build-id",
                format!("unknown build-id {bid} (not in table of {} entries) — custom libcrypto build? see dispatch-anchor", ctx.table.entry_count()),
            )),
        },
    }
    // Backend-agreement verdict rows (same qualification the
    // backend runs for this target + flags).
    let qual = onboard::qualify_libcrypto_bytes(bytes, Path::new(path), static_exe, &ctx.opts());
    out.push(anchor_check(&qual));
    out.push(class_check(build_id.as_deref(), ctx.enrollment));
    out
}

// ---- entry point ----

const USAGE: &str = "usage: osslscope doctor [--pid PID | --libcrypto PATH | --exe PATH] [--table FILE] [--force-offset N] [--provider-table FILE] [--object O] [--count-object C] [--members-object M] [--format human|json]";

pub fn run(args: &[String]) -> ExitCode {
    let mut pid: Option<u32> = None;
    let mut libcrypto: Option<String> = None;
    let mut exe_path: Option<String> = None;
    let mut table_path: Option<String> = None;
    let mut force_offset_raw: Option<String> = None;
    let mut provider_table_path: Option<String> = None;
    let mut object: Option<String> = None;
    let mut count_object: Option<String> = None;
    let mut members_object: Option<String> = None;
    let mut format = "human".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            println!("{USAGE}");
            println!("  no target: environment + installed-objects preflight");
            println!(
                "  --pid PID | --libcrypto PATH | --exe PATH: also vet the target (same qualification as report/check)"
            );
            println!(
                "  --exe PATH: pre-exec spawn prediction (same rule as `run --` automatic discovery)"
            );
            println!(
                "  --table FILE | --force-offset N | --provider-table FILE: vet with explicit local enrollment"
            );
            println!(
                "  --object O | --count-object C | --members-object M: vet explicit BPF objects instead of installed defaults"
            );
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
                "--exe" => exe_path = Some(val(&mut it)?),
                "--table" => table_path = Some(val(&mut it)?),
                "--force-offset" => force_offset_raw = Some(val(&mut it)?),
                "--provider-table" => provider_table_path = Some(val(&mut it)?),
                "--object" => object = Some(val(&mut it)?),
                "--count-object" => count_object = Some(val(&mut it)?),
                "--members-object" => members_object = Some(val(&mut it)?),
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
            crate::report::err_line(&format!("osslscope doctor: {e}\n{USAGE}"));
            return ExitCode::from(2);
        }
    }
    if [pid.is_some(), libcrypto.is_some(), exe_path.is_some()]
        .into_iter()
        .filter(|b| *b)
        .count()
        > 1
    {
        crate::report::err_line(&format!(
            "osslscope doctor: use one target selector (--pid, --libcrypto, or --exe)\n{USAGE}"
        ));
        return ExitCode::from(2);
    }
    // Build-id table: shipped frozen, --table overrides. Needed only
    // for target byte checks; a bad override is a usage error.
    let table_src = match &table_path {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                crate::report::err_line(&format!("osslscope doctor: bad --table {p}: {e}"));
                return ExitCode::from(2);
            }
        },
        None => include_str!("../etc/build-id-table.json").to_string(),
    };
    let table = match crate::discovery::builtin::load_table_str(&table_src) {
        Ok(t) => t,
        Err(e) => {
            if table_path.is_some() {
                crate::report::err_line(&format!("osslscope doctor: bad --table file: {e:#}"));
                return ExitCode::from(2);
            }
            crate::report::err_line(&format!(
                "osslscope doctor: internal error (shipped table corrupt): {e:#}"
            ));
            return ExitCode::from(1);
        }
    };
    // Explicit local enrollment for the vetting below (same early
    // usage-error shape as report/check).
    let enrollment = match &provider_table_path {
        Some(p) => match onboard::load_enrollment_file(Path::new(p)) {
            Ok(t) => t,
            Err(e) => {
                crate::report::err_line(&format!("osslscope doctor: {}", e.full()));
                return ExitCode::from(2);
            }
        },
        None => ProviderTable::empty(),
    };
    let force_offset = match &force_offset_raw {
        Some(s) => match crate::args::parse_force_offset(s) {
            Ok(n) => Some(n),
            Err(e) => {
                crate::report::err_line(&format!("osslscope doctor: {e}"));
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let tctx = TargetCtx {
        table: &table,
        table_explicit: table_path.is_some(),
        force_offset,
        enrollment: &enrollment,
    };
    // H7-T6: bind instead of unwrap (same guard, no panic shape).
    if let Some(p) = pid.filter(|p| !std::path::Path::new(&format!("/proc/{p}")).exists()) {
        crate::report::err_line(&format!("osslscope doctor: no such process {p} (died?)"));
        return ExitCode::from(2);
    }

    let env = gather_env();
    let mut checks = vec![
        check_kernel(&env),
        check_token_support(&env),
        check_ringbuf_query(&env),
        check_caps(&env),
        check_btf(),
        check_lockdown(&env),
        check_ima(),
        check_lsm(&env),
        check_seccomp(&env),
        check_spawn_access(),
    ];
    checks.extend(objects_checks(
        object.as_deref(),
        count_object.as_deref(),
        members_object.as_deref(),
    ));

    let mut target: Option<Target> = None;
    if let Some(p) = pid {
        let exe = proc_exe_name(p).unwrap_or_else(|| "?".into());
        let tuid = proc_uid(p).unwrap_or(u32::MAX);
        checks.push(check_pidns(p));
        checks.push(check_foreign_uid(p, tuid, &env));
        match crate::discovery::maps::read_maps(p) {
            Ok(maps) => {
                checks.push(Check::pass("target-access", "target maps readable".into()));
                match onboard::libcrypto_from_maps(&maps) {
                    LibcryptoMaps::One { path } => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: Some(path.clone()),
                        });
                        // One bounded read shared by rows + coverage
                        // (never re-read unbounded a file that
                        // qualification already bounded).
                        match onboard::read_bounded(
                            Path::new(&path),
                            onboard::MAX_OBJECT_SCAN_BYTES,
                        ) {
                            Ok(bytes) => {
                                checks.extend(check_target_bytes(&path, &bytes, &tctx));
                                checks.extend(coverage_checks(&maps, &path, &bytes));
                            }
                            Err(e) => checks.push(target_file_unreadable(&path, &e)),
                        }
                    }
                    LibcryptoMaps::None => {
                        target = Some(Target {
                            exe,
                            uid: Some(tuid),
                            self_uid: self_uid(),
                            libcrypto: None,
                        });
                        // Static candidate: the exe itself may link
                        // OpenSSL (same discovery rule as the backend).
                        let exe_link = format!("/proc/{p}/exe");
                        let exe_path = Path::new(&exe_link);
                        match onboard::read_bounded(exe_path, onboard::MAX_OBJECT_SCAN_BYTES) {
                            Ok(bytes) => {
                                checks.push(Check::info(
                                    "libcrypto-found",
                                    format!("no libcrypto mapped; static candidate: {exe_link}"),
                                ));
                                checks.extend(check_byte_rows(&exe_link, &bytes, true, &tctx));
                                checks.extend(coverage_checks(&maps, &exe_link, &bytes));
                            }
                            Err(e) => {
                                checks.push(Check::fail(
                                    "libcrypto-found",
                                    format!("no libcrypto mapped and target exe unreadable: {e}"),
                                    "run as the target uid, or grant cap_sys_ptrace file cap and re-run".into(),
                                ));
                            }
                        }
                    }
                    LibcryptoMaps::Deleted => {
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
                    LibcryptoMaps::Multi { paths } => {
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
        target = Some(Target {
            exe: base_name(Path::new(&path)),
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
        checks.extend(check_target_file(&path, &tctx));
        checks.push(Check::info(
            "coverage-scope",
            "automatic discovery observes the in-libcrypto default provider; file providers need explicit --provider".into(),
        ));
    } else if let Some(exe_arg) = exe_path {
        // --exe: pre-exec spawn prediction (same rule as `run --`
        // automatic discovery). The child would inherit our
        // environment, so current PATH/LD_LIBRARY_PATH predict it.
        let path_var = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".to_string());
        let ld_var = std::env::var("LD_LIBRARY_PATH").ok();
        let spenv = onboard::SpawnEnv {
            path: &path_var,
            ld_library_path: ld_var.as_deref(),
        };
        let argv = vec![exe_arg.clone()];
        checks.push(Check::info(
            "pidns",
            "no process target (--exe predicts pre-exec)".into(),
        ));
        checks.push(Check::info(
            "foreign-uid",
            "no process target (--exe predicts pre-exec)".into(),
        ));
        match onboard::predict_spawn_lib(&argv, &spenv) {
            Err(e) => {
                target = Some(Target {
                    exe: exe_arg.clone(),
                    uid: None,
                    self_uid: self_uid(),
                    libcrypto: None,
                });
                checks.push(Check::fail("target-access", e.message, e.remediation));
            }
            Ok(pred) => {
                checks.push(Check::pass(
                    "target-access",
                    format!("spawn executable resolved: {}", pred.exe.display()),
                ));
                // Backend checks the exe arch before the lib: mirror
                // the gate so doctor cannot pass what discovery
                // rejects. (The verdict row stays single-sourced
                // from discover_spawn.)
                let exe_arch_err = onboard::check_arch(&pred.exe_bytes).err();
                if pred.libs.len() == 1 && exe_arch_err.is_none() {
                    let lib = pred.libs[0].to_string_lossy().into_owned();
                    target = Some(Target {
                        exe: base_name(&pred.exe),
                        uid: None,
                        self_uid: self_uid(),
                        libcrypto: Some(lib.clone()),
                    });
                    checks.extend(check_target_file(&lib, &tctx));
                } else {
                    target = Some(Target {
                        exe: base_name(&pred.exe),
                        uid: None,
                        self_uid: self_uid(),
                        libcrypto: None,
                    });
                    if pred.libs.is_empty()
                        && pred.unresolved.is_empty()
                        && !pred.incomplete
                        && exe_arch_err.is_none()
                    {
                        let exe_s = pred.exe.to_string_lossy().into_owned();
                        checks.push(Check::info(
                            "libcrypto-found",
                            format!("no NEEDED libcrypto; static candidate: {exe_s}"),
                        ));
                        checks.extend(check_byte_rows(&exe_s, &pred.exe_bytes, true, &tctx));
                    } else {
                        if let Some(e) = exe_arch_err {
                            checks.push(Check::fail(
                                "arch",
                                format!("{}: {e}", pred.exe.display()),
                                "run a 64-bit x86-64 binary".into(),
                            ));
                        } else {
                            checks.push(Check::info(
                                "libcrypto-found",
                                format!(
                                    "no single predicted libcrypto for {} — see dispatch-anchor",
                                    pred.exe.display()
                                ),
                            ));
                        }
                        match onboard::discover_spawn(&argv, &tctx.opts(), &spenv) {
                            Ok(qual) => {
                                checks.push(anchor_check(&qual));
                                checks.push(Check::info(
                                    "provider-class",
                                    "unknown (target unqualified)".into(),
                                ));
                            }
                            Err(e) => checks.push(Check::fail(
                                "dispatch-anchor",
                                e.message,
                                e.remediation,
                            )),
                        }
                    }
                }
                checks.push(Check::info(
                    "coverage-scope",
                    "automatic discovery observes the in-libcrypto default provider; file providers need explicit --provider".into(),
                ));
                checks.push(Check::info(
                    "coverage-spawn",
                    "run -- requests observation from exec; effective callback attachment follows discovery (fast or short-lived workloads may stay PARTIAL); a wrong libcrypto prediction degrades to zero-rows PARTIAL, never wrong attribution".into(),
                ));
            }
        }
    }

    let failed = checks.iter().any(|c| c.status == Status::Fail);
    if format == "json" {
        let doc = serde_json::json!({
            "target": target_json(&target),
            "checks": checks.iter().map(Check::json).collect::<Vec<_>>(),
            "verdict": if failed { "fail-closed" } else { "ok" },
            "exit": if failed { 4 } else { 0 },
        });
        // H7-T6: `Value` serialization is infallible; the fallback
        // exists only to shed the panic shape (never observed).
        let text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string());
        println!("{text}");
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
            cap_sys_admin: has_cap(caps, CAP_SYS_ADMIN),
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

    fn rbq_err(stage: &'static str, errno: i32, log: &str) -> RingbufQueryError {
        RingbufQueryError {
            stage,
            errno,
            log: log.into(),
        }
    }

    #[test]
    fn ringbuf_query_detail_cases() {
        let allow = ctx((1u64 << CAP_BPF) | (1u64 << CAP_PERFMON), false, &[], false);
        let none = ctx(0, false, &[], false);
        let bpf_only = ctx(1u64 << CAP_BPF, false, &[], false);
        // Unknown-helper rejection establishes absence (load stage).
        let m = ringbuf_query_detail(
            &rbq_err(
                "prog_load",
                libc::EINVAL,
                "unknown func bpf_ringbuf_query#134",
            ),
            &allow,
        );
        assert!(m.contains("absent"), "{m}");
        // Bare EINVAL (allocation/setup failure) stays unverifiable.
        let m = ringbuf_query_detail(&rbq_err("prog_load", libc::EINVAL, ""), &allow);
        assert!(m.contains("unverifiable") && !m.contains("absent"), "{m}");
        // Map-stage EINVAL (unsupported ringbuf OR page-size floor)
        // stays unverifiable — it establishes no helper fact.
        let m = ringbuf_query_detail(&rbq_err("map_create", libc::EINVAL, ""), &allow);
        assert!(
            m.contains("unverifiable") && m.contains("map creation"),
            "{m}"
        );
        // Resource errors carry the first log line.
        let m = ringbuf_query_detail(
            &rbq_err("prog_load", libc::ENOMEM, "out of memory\nsecond line"),
            &allow,
        );
        assert!(m.contains("out of memory") && !m.contains("second"), "{m}");
        // CAP_BPF-only + load EPERM: unverifiable for want of
        // CAP_PERFMON — never "denied with caps held".
        let m = ringbuf_query_detail(&rbq_err("prog_load", libc::EPERM, ""), &bpf_only);
        assert!(
            m.contains("unverifiable") && m.contains("without CAP_PERFMON ("),
            "{m}"
        );
        // Same EPERM with both held: attributed denial.
        let m = ringbuf_query_detail(&rbq_err("prog_load", libc::EPERM, ""), &allow);
        assert!(m.contains("denied"), "{m}");
        // Map-stage EPERM without CAP_BPF: unverifiable, wants BPF.
        let m = ringbuf_query_detail(&rbq_err("map_create", libc::EPERM, ""), &none);
        assert!(m.contains("without CAP_BPF ("), "{m}");
        // Map-stage EPERM with CAP_BPF held: attributed denial.
        let m = ringbuf_query_detail(&rbq_err("map_create", libc::EPERM, ""), &bpf_only);
        assert!(m.contains("denied"), "{m}");
        // Map-stage EPERM with both held: attributed denial too
        // (extra perfmon changes nothing at map stage).
        let m = ringbuf_query_detail(&rbq_err("map_create", libc::EPERM, ""), &allow);
        assert!(m.contains("denied") && !m.contains("unverifiable"), "{m}");
        // PERFMON-only + load EPERM (reachable under unprivileged
        // BPF: map creation succeeds, kprobe load still wants BPF):
        // unverifiable wanting CAP_BPF — never denied-with-caps.
        let perfmon_only = ctx(1u64 << CAP_PERFMON, false, &[], false);
        let m = ringbuf_query_detail(&rbq_err("prog_load", libc::EPERM, ""), &perfmon_only);
        assert!(
            m.contains("unverifiable") && m.contains("without CAP_BPF ("),
            "{m}"
        );
        // PERFMON-only + map EPERM: perfmon is irrelevant to map
        // creation — still wants CAP_BPF.
        let m = ringbuf_query_detail(&rbq_err("map_create", libc::EPERM, ""), &perfmon_only);
        assert!(m.contains("without CAP_BPF ("), "{m}");
        // Neither cap + load EPERM: reports both missing caps.
        let m = ringbuf_query_detail(&rbq_err("prog_load", libc::EPERM, ""), &none);
        assert!(m.contains("without CAP_BPF+CAP_PERFMON ("), "{m}");
        // CAP_SYS_ADMIN-only satisfies both stages: EPERM with
        // admin held is an attributed denial, never "unverifiable".
        let admin_only = ctx(1u64 << CAP_SYS_ADMIN, false, &[], false);
        for stage in ["map_create", "prog_load"] {
            let m = ringbuf_query_detail(&rbq_err(stage, libc::EPERM, ""), &admin_only);
            assert!(m.contains("denied") && !m.contains("unverifiable"), "{m}");
        }
        // EACCES-shaped verifier reject with "unknown func" log:
        // evidence beats errno shape — absent, not denied.
        let m = ringbuf_query_detail(
            &rbq_err(
                "prog_load",
                libc::EACCES,
                "unknown func bpf_ringbuf_query#134",
            ),
            &allow,
        );
        assert!(m.contains("absent"), "{m}");
        // Same evidence with neither cap: absence still wins over
        // missing-capability attribution.
        let m = ringbuf_query_detail(
            &rbq_err(
                "prog_load",
                libc::EACCES,
                "unknown func bpf_ringbuf_query#134",
            ),
            &none,
        );
        assert!(m.contains("absent") && !m.contains("unverifiable"), "{m}");
        // ENOSYS (no bpf() at all): unavailable, both stages.
        for stage in ["map_create", "prog_load"] {
            let m = ringbuf_query_detail(&rbq_err(stage, libc::ENOSYS, ""), &allow);
            assert!(
                m.contains("unavailable") && m.contains("bpf() missing"),
                "{m}"
            );
        }
    }

    #[test]
    fn libcrypto_find_cases() {
        // Doctor delegates to the shared onboarding discovery (same
        // rule as the backend); these pins guard the delegation.
        use crate::discovery::onboard::libcrypto_from_maps;
        let maps = vec![
            mapping("08:01", 1, "/lib/libc.so.6"),
            mapping("08:01", 2, "/opt/lib/libcrypto.so.4"),
            mapping("08:01", 2, "/opt/lib/libcrypto.so.4"),
        ];
        assert!(matches!(
            libcrypto_from_maps(&maps),
            LibcryptoMaps::One { .. }
        ));
        let maps = vec![mapping("08:01", 1, "/lib/libc.so.6")];
        assert!(matches!(libcrypto_from_maps(&maps), LibcryptoMaps::None));
        let maps = vec![
            mapping("08:01", 2, "/a/libcrypto.so.4"),
            mapping("08:01", 3, "/b/libcrypto.so.3"),
        ];
        match libcrypto_from_maps(&maps) {
            LibcryptoMaps::Multi { paths } => assert_eq!(paths.len(), 2),
            _ => panic!("want multi"),
        }
        let maps = vec![mapping("08:01", 2, "/a/libcrypto.so.4 (deleted)")];
        assert!(matches!(libcrypto_from_maps(&maps), LibcryptoMaps::Deleted));
    }

    #[test]
    fn arch_names() {
        // Single home in onboard (doctor renders the same strings).
        use crate::discovery::onboard::arch_name;
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
    fn anchor_row_maps_qualification() {
        use crate::discovery::builtin::Resolution;
        use crate::discovery::onboard::SupportedTarget;
        let supported = TargetQualification::Supported(SupportedTarget {
            provider_path: "/x/libcrypto.so.3".into(),
            builtin: true,
            query_offset: Some(0x1234),
            resolution: Some(Resolution::Symtab),
            build_id: None,
            openssl_display: "3.?".into(),
            provider_class: None,
            static_exe: false,
        });
        let c = anchor_check(&supported);
        assert_eq!(c.status, Status::Pass);
        assert!(c.message.contains("symtab"));
        let unknown = TargetQualification::Unknown {
            reason: "stripped build".into(),
            remediation: "enroll".into(),
        };
        let c = anchor_check(&unknown);
        assert_eq!((c.status, c.id), (Status::Fail, "dispatch-anchor"));
        assert_eq!(c.remediation.as_deref(), Some("enroll"));
    }

    #[test]
    fn class_row_never_fails() {
        use crate::discovery::provider::load_table_str;
        let empty = ProviderTable::empty();
        // Builtin assertion resolves even without a build-id.
        let c = class_check(None, &empty);
        assert_eq!(c.status, Status::Pass);
        assert!(c.message.contains("default"));
        let c = class_check(Some("ab".repeat(20).leak() as &str), &empty);
        assert_eq!(c.status, Status::Pass);
        // Pinned enrollment wins and names its basis.
        let id = "ab".repeat(20);
        let t = load_table_str(&format!(
            r#"{{"table_version":1,"entries":[{{"build_id":"{id}","provider_class":"fips"}}]}}"#
        ))
        .unwrap();
        let c = class_check(Some(&id), &t);
        assert!(c.message.contains("fips") && c.message.contains("pinned"));
        assert!(c.message.contains("not a certification claim"));
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
        // ringbuf_query floor probe: ld_map_fd r1, fd (slots 0-1)
        // + r2 = 0 (AVAIL_DATA) + call 134 + r0 = 0 + exit.
        let q = insns_ringbuf_query(7);
        assert_eq!(q.len(), 48);
        assert_eq!(q[0], 0x18);
        assert_eq!(q[1], 0x11);
        assert_eq!(&q[4..8], &[0x07, 0x00, 0x00, 0x00]);
        assert_eq!(&q[8..16], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&q[16..24], &[0xb7, 0x02, 0, 0, 0, 0, 0, 0]);
        assert_eq!(q[3 * 8], 0x85);
        assert_eq!(&q[3 * 8 + 4..4 * 8], &[134, 0x00, 0x00, 0x00]);
        assert_eq!(q[5 * 8], 0x95);
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

    #[test]
    fn self_dumpable_reports_prctl_state() {
        // The query must succeed (values vary: 1 unprivileged,
        // non-dumpable under filecaps/root per kernel).
        assert!(self_dumpable().is_some());
    }

    #[test]
    fn spawn_access_probe_passes_and_reaps() {
        // The probe replicates the run -- setup maps read (fork a
        // stopped child that opts itself dumpable pre-exec, then
        // read its maps): it must pass on a healthy host, and the
        // probe child must be killed and reaped (never a zombie or
        // a leftover stopped child — a second run would inherit it).
        // Reap proof: this thread's /proc children list is empty
        // after each run (zombies and live children both appear).
        let tid = unsafe { libc::gettid() };
        // The oracle must exist (a missing children file would make
        // the empty check vacuous — fail loud instead).
        std::fs::read_to_string(format!("/proc/self/task/{tid}/children"))
            .expect("per-thread children file must exist");
        let children = || {
            std::fs::read_to_string(format!("/proc/self/task/{tid}/children"))
                .unwrap_or_default()
                .split_whitespace()
                .count()
        };
        for _ in 0..2 {
            let c = check_spawn_access();
            assert_eq!(c.id, "spawn-access");
            assert!(matches!(c.status, Status::Pass), "{}", c.message);
            assert!(c.message.contains("self dumpable="), "{}", c.message);
            assert_eq!(children(), 0, "probe leaked a child (zombie or stopped)");
        }
    }

    static DOCTOR_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn doctor_scratch(test: &str) -> PathBuf {
        let n = DOCTOR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "osslscope-doctor-{}-{}-{}",
            std::process::id(),
            test,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn doctor_trust() -> onboard::TrustPolicy {
        onboard::TrustPolicy {
            // SAFETY: getuid takes no arguments and always succeeds.
            trusted_uids: vec![unsafe { libc::getuid() }],
            check_ancestry: false,
        }
    }

    /// A scratch dir the test trust accepts (root-only off, own
    /// uid allowed, tight perms cap inherited).
    fn trusted_fixture(test: &str) -> PathBuf {
        let dir = doctor_scratch(test);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&dir).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dir, perms).unwrap();
        }
        let trust = doctor_trust();
        assert!(
            onboard::is_trusted_dir_with(&dir, &trust),
            "fixture dir must be trusted"
        );
        dir
    }

    fn members_row(rows: &[Check]) -> &Check {
        rows.iter()
            .find(|c| c.id == "objects-members")
            .expect("objects-members row present")
    }

    fn built_members() -> Option<PathBuf> {
        let cand = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("crates/ebpf/target/bpfel-unknown-none/release/osslscope-members");
        cand.exists().then_some(cand)
    }

    fn built_triple() -> Option<(PathBuf, PathBuf, PathBuf)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("crates/ebpf/target/bpfel-unknown-none/release");
        let h = dir.join("osslscope-harvest");
        let c = dir.join("osslscope-count");
        let m = dir.join("osslscope-members");
        (h.exists() && c.exists() && m.exists()).then_some((h, c, m))
    }

    #[test]
    fn members_row_absent_is_info() {
        // No members object installed anywhere: INFO, never fail —
        // old pair installs stay valid (traversal unavailable).
        let dir = trusted_fixture("members-absent");
        let rows = objects_checks_in(None, None, None, &[dir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Info, "{}", m.message);
        assert!(m.message.contains("not installed"), "{}", m.message);
    }

    #[test]
    fn members_row_broken_is_fail() {
        // A members file that fails vetting: FAIL with the
        // resolution diagnostic (broken install, actionable).
        let dir = trusted_fixture("members-broken");
        std::fs::write(dir.join("osslscope-members"), b"not an elf object").unwrap();
        let rows = objects_checks_in(None, None, None, &[dir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Fail, "{}", m.message);
        assert!(m.remediation.is_some());
    }

    #[test]
    fn members_row_installed_is_pass() {
        // A vetted installed members object: PASS (needs the built
        // triple — skips loud when the BPF tree was never built,
        // fails closed in required mode like the shape suite).
        // The fixture is a full receipted prefix (all three
        // roles + install manifest, mirroring install-dev.sh),
        // so the all-implicit matched-set resolution passes —
        // the same set a run would traverse.
        let Some((h, c, m)) = built_triple() else {
            if matches!(std::env::var("OSSL_MEMBERS_REQUIRED").as_deref(), Ok("1")) {
                panic!(
                    "FAIL(members-required): no built BPF triple; \
                     required mode refuses silent skips"
                );
            }
            eprintln!("SKIP members_row_installed_is_pass: no built BPF triple");
            return;
        };
        let prefix = trusted_fixture("members-installed");
        let objdir = prefix.join("lib").join("osslscope");
        std::fs::create_dir_all(&objdir).unwrap();
        for (name, src) in [
            ("osslscope-harvest", &h),
            ("osslscope-count", &c),
            ("osslscope-members", &m),
        ] {
            std::fs::copy(src, objdir.join(name)).unwrap();
        }
        let rdir = prefix.join("share").join("osslscope");
        std::fs::create_dir_all(&rdir).unwrap();
        let arts: Vec<serde_json::Value> =
            ["osslscope-harvest", "osslscope-count", "osslscope-members"]
                .iter()
                .map(|n| {
                    let dest = objdir.join(n).display().to_string();
                    let sha = onboard::file_sha256_hex(&objdir.join(n)).unwrap();
                    serde_json::json!({"role": "bpf-object", "dest": dest, "sha256": sha})
                })
                .collect();
        std::fs::write(
            rdir.join("install-manifest.json"),
            serde_json::to_string(&serde_json::json!({
                "schema": "osslscope-install-manifest-v1",
                "artifacts": arts,
            }))
            .unwrap(),
        )
        .unwrap();
        let rows = objects_checks_in(None, None, None, &[objdir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Pass, "{}", m.message);
        assert!(m.message.contains("installed, compatible"), "{}", m.message);
    }

    #[test]
    fn members_row_receiptless_is_fail() {
        // A receiptless members file next to a pair: FAIL (a
        // hand-placed object whose matched-build identity is not
        // established — doctor refuses exactly like traversal).
        let Some((h, c, m)) = built_triple() else {
            eprintln!("SKIP members_row_receiptless_is_fail: no built BPF triple");
            return;
        };
        let dir = trusted_fixture("members-receiptless");
        std::fs::copy(&h, dir.join("osslscope-harvest")).unwrap();
        std::fs::copy(&c, dir.join("osslscope-count")).unwrap();
        std::fs::copy(&m, dir.join("osslscope-members")).unwrap();
        let rows = objects_checks_in(None, None, None, &[dir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Fail, "{}", m.message);
        assert!(m.message.contains("no install receipt"), "{}", m.message);
    }

    #[test]
    fn members_row_stale_file_blocks_pair_fallback() {
        // S1: a stale members file on a pair-receipted prefix (the
        // pre-fix reinstall state — triple prefix reinstalled
        // pair-only without removing the leftover) blocks pair
        // fallback with the mixed-set error (the unlisted file
        // refuses, exactly like traversal would).
        let Some((h, c, m)) = built_triple() else {
            eprintln!("SKIP members_row_stale_file_blocks_pair_fallback: no built BPF triple");
            return;
        };
        let prefix = trusted_fixture("members-stale");
        let objdir = prefix.join("lib").join("osslscope");
        std::fs::create_dir_all(&objdir).unwrap();
        std::fs::copy(&h, objdir.join("osslscope-harvest")).unwrap();
        std::fs::copy(&c, objdir.join("osslscope-count")).unwrap();
        std::fs::copy(&m, objdir.join("osslscope-members")).unwrap();
        write_prefix_receipt(&prefix, &objdir, &["osslscope-harvest", "osslscope-count"]);
        let rows = objects_checks_in(None, None, None, &[objdir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Fail, "{}", m.message);
        assert!(
            m.message.contains("not listed in install receipt"),
            "{}",
            m.message
        );
    }

    #[test]
    fn members_row_used_prefix_pair_after_stale_removal() {
        // S1: the post-reinstall state (pair files + pair receipt,
        // stale members file removed) resolves pair-only — INFO,
        // never fail (old installs stay valid; traversal
        // unavailable). Proves the installer's stale removal
        // restores resolution.
        let Some((h, c)) = built_triple().map(|(h, c, _)| (h, c)) else {
            eprintln!("SKIP members_row_used_prefix_pair_after_stale_removal: no built BPF triple");
            return;
        };
        let prefix = trusted_fixture("members-used-pair");
        let objdir = prefix.join("lib").join("osslscope");
        std::fs::create_dir_all(&objdir).unwrap();
        std::fs::copy(&h, objdir.join("osslscope-harvest")).unwrap();
        std::fs::copy(&c, objdir.join("osslscope-count")).unwrap();
        write_prefix_receipt(&prefix, &objdir, &["osslscope-harvest", "osslscope-count"]);
        let rows = objects_checks_in(None, None, None, &[objdir], &doctor_trust());
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Info, "{}", m.message);
        assert!(m.message.contains("not installed"), "{}", m.message);
        for id in ["objects-harvest", "objects-count"] {
            let row = rows.iter().find(|c| c.id == id).expect("pair row");
            assert_eq!(row.status, Status::Pass, "{}", row.message);
        }
    }

    fn write_prefix_receipt(prefix: &Path, objdir: &Path, names: &[&str]) {
        let rdir = prefix.join("share").join("osslscope");
        std::fs::create_dir_all(&rdir).unwrap();
        let arts: Vec<serde_json::Value> = names
            .iter()
            .map(|n| {
                let dest = objdir.join(n).display().to_string();
                let sha = onboard::file_sha256_hex(&objdir.join(n)).unwrap();
                serde_json::json!({"role": "bpf-object", "dest": dest, "sha256": sha})
            })
            .collect();
        std::fs::write(
            rdir.join("install-manifest.json"),
            serde_json::to_string(&serde_json::json!({
                "schema": "osslscope-install-manifest-v1",
                "artifacts": arts,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn members_row_mixed_set_fails_all_three() {
        // Mixed install (receipted pair in one trusted dir,
        // receipted members in another): doctor fails ALL THREE
        // rows with the shared run-set refusal — exactly what
        // capture runs (no pair fallback for a mixed triple).
        let Some((h, c, m)) = built_triple() else {
            eprintln!("SKIP members_row_mixed_set_fails_all_three: no built BPF triple");
            return;
        };
        let pair_pfx = trusted_fixture("members-mixed-pair");
        let pair_dir = pair_pfx.join("lib").join("osslscope");
        std::fs::create_dir_all(&pair_dir).unwrap();
        std::fs::copy(&h, pair_dir.join("osslscope-harvest")).unwrap();
        std::fs::copy(&c, pair_dir.join("osslscope-count")).unwrap();
        write_prefix_receipt(
            &pair_pfx,
            &pair_dir,
            &["osslscope-harvest", "osslscope-count"],
        );
        let mem_pfx = trusted_fixture("members-mixed-members");
        let mem_dir = mem_pfx.join("lib").join("osslscope");
        std::fs::create_dir_all(&mem_dir).unwrap();
        std::fs::copy(&m, mem_dir.join("osslscope-members")).unwrap();
        write_prefix_receipt(&mem_pfx, &mem_dir, &["osslscope-members"]);
        let rows = objects_checks_in(None, None, None, &[pair_dir, mem_dir], &doctor_trust());
        for id in ["objects-harvest", "objects-count", "objects-members"] {
            let row = rows.iter().find(|c| c.id == id).expect("row present");
            assert_eq!(row.status, Status::Fail, "{id}: {}", row.message);
        }
        // Same shared refusal a run surfaces (the triple error —
        // the resolve-level contract pins this message).
        let m = members_row(&rows);
        assert!(
            m.message.contains("harvest+count+members triple"),
            "mixed refusal carries the triple error: {}",
            m.message
        );
    }

    #[test]
    fn members_row_explicit_vets() {
        // Explicit paths vet pass/fail individually (garbage fails
        // naming the object — hermetic, no built objects needed).
        let dir = doctor_scratch("members-explicit");
        let bad = dir.join("bad-members.o");
        std::fs::write(&bad, b"not an elf object").unwrap();
        let rows = objects_checks_in(
            None,
            None,
            Some(bad.to_str().unwrap()),
            &[],
            &doctor_trust(),
        );
        let m = members_row(&rows);
        assert_eq!(m.status, Status::Fail, "{}", m.message);
        assert!(m.message.contains("bad-members.o"), "{}", m.message);
    }
}
