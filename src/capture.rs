//! Keyed capture engine (P2): window loop, fencing, `run --` spawn.
//!
//! Windows observe ONE tgid's crypto executions as keyed counts.
//! The window opens after harvest→plan→attach (`TARGET` programmed
//! with the tgid) and closes at `--duration` expiry, child exit, or
//! signal (`TARGET=0` stops counting in-kernel FIRST, then userspace
//! drains). Drains happen at window end + on generation fences only
//! (§3 drain-then-fence); every drop, fence, and shortfall lands in
//! a §4 counter — no silent-loss path exists by construction.
//!
//! Attach note (deviation from keyed-design §1/§6 recorded): count
//! multis use pid=target (exact filter — the child exists stopped
//! pre-exec, so pid=0 buys nothing) PLUS the `TARGET` tgid guard as
//! defense-in-depth and the in-kernel window switch. Harvest multis
//! stay pid-filtered (system-wide harvest firing would observe
//! foreign tasks' crypto — the pid=0 text predates the P4 review).
//! `TARGET=0` at expiry is the §8 mechanism, unchanged.
use crate::discovery::{elf, harvest, maps};
use crate::loader::Loaded;
use crate::{kinds, pin, plan};
use osslscope_ebpf_common::{CountValue, split_key};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Maps-fence poll cadence (frozen §5).
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Per-poll wall budget; overruns skip the round (§5).
pub const POLL_BUDGET: Duration = Duration::from_millis(50);
/// Signal-drain grace (P2 default; P3 sets final).
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);

/// Capture run configuration.
pub struct Config {
    pub harvest_object: PathBuf,
    pub count_object: PathBuf,
    pub provider: PathBuf,
    pub builtin: bool,
    pub duration: Duration,
    pub settle: Duration,
    pub harvest_timeout: Duration,
    pub grace: Duration,
    /// CI-supplied container image digest for the check
    /// actionability tuple ("" when unknown — bare metal).
    pub image_digest: String,
}

/// Capture target: spawned child (`run --`) or live pid (staging).
pub enum Target {
    Spawn { argv: Vec<String> },
    Pid(u32),
}

/// Fatal (evidence-unusable) outcomes; the CLI maps these to exit 4
/// (or 1 when the child itself failed — see report.rs precedence).
#[derive(Debug, Clone)]
pub enum FatalKind {
    /// Target recycled mid-window: all observations discarded.
    Recycled,
    /// Zero count probes attached (all planned offsets missed or
    /// kernel-rejected).
    AttachZero,
    /// Environment failure: BPF load, fork/exec, maps reads, ... —
    /// anything that is neither evidence nor a usage error.
    Env(String),
}

/// Window outcome.
#[derive(Debug, Clone)]
pub enum Outcome {
    Complete,
    Partial,
    Fatal(FatalKind),
}

/// §4 gap counters (PRD key = TOTAL; `_bpf`/`_userspace` the split).
#[derive(Debug, Clone, Default)]
pub struct Counters {
    pub dropped_bpf: u64,
    pub dropped_userspace: u64,
    pub missed_attaches: u64,
    pub unresolved_offsets: u64,
    pub table_staleness_events: u64,
    pub cold_gap_calls: u64,
    pub provider_changed: u64,
    pub scan_budget_exhaustions: u64,
    pub engine_fallback_uninstrumented: u64,
    pub drain_shortfall: u64,
    pub uninstrumented_ops: u64,
    pub fork_exec_ignored: u64,
    /// Windows expired while the target lived (0/1): post-window
    /// executions unobserved — over-budget PARTIAL (P2 exit-3).
    pub over_budget: u64,
}

/// One counted identity (current generation, all CPUs folded).
#[derive(Debug, Clone)]
pub struct Execution {
    pub cookie: u32,
    pub id: plan::Identity,
    pub aliases: Vec<plan::Identity>,
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// One fenced key's conserved counts (§3 extension: per-key detail
/// rides WITH the aggregate so exit-2 conservation joins per
/// identity instead of trusting bare totals).
#[derive(Debug, Clone)]
pub struct StaleDetail {
    pub cookie: u32,
    pub id: plan::Identity,
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// Fenced generation's counts (aggregate with the generation label, §3).
#[derive(Debug, Clone)]
pub struct StaleBucket {
    pub generation: u32,
    pub events: u64,
    pub keys: u64,
    pub detail: Vec<StaleDetail>,
}

/// Finished capture window.
#[derive(Debug, Clone)]
pub struct Capture {
    pub target_pid: u32,
    pub target_comm: String,
    pub window_planned: Duration,
    pub window_actual: Duration,
    pub outcome: Outcome,
    pub reasons: Vec<String>,
    pub executions: Vec<Execution>,
    pub stale: Vec<StaleBucket>,
    pub counters: Counters,
    pub child_exit: Option<i32>,
    pub drain_wall_us: u64,
    pub harvest_doc: serde_json::Value,
    pub legacy: serde_json::Value,
    /// Window wall-clock edges (PRD §5 window-only claims).
    /// Pre-window FATAL captures carry the acquisition instant in
    /// both (window_actual == 0 marks "no window opened").
    pub window_start_wall: SystemTime,
    pub window_end_wall: SystemTime,
    pub kernel_release: String,
    pub target_cmdline: String,
    pub target_container_id: String,
    pub provider_build_id: String,
    pub provider_path: String,
    pub image_digest: String,
}

// ---------------------------------------------------------------- signals

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

fn arm_signals() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------- spawn

/// Fork + stop pre-exec. CStrings are built BEFORE the fork so the
/// child allocates nothing (async-signal-safe; the parent may be
/// multithreaded). Returns the stopped child's pid.
fn spawn_stopped(argv: &[String]) -> anyhow::Result<u32> {
    use anyhow::Context as _;
    if argv.is_empty() {
        anyhow::bail!("run -- needs a command");
    }
    let cs: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("NUL in argv")?;
    let mut ptrs: Vec<*const libc::c_char> = cs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::raise(libc::SIGSTOP);
            libc::execvp(ptrs[0], ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            anyhow::bail!("waitpid: {}", std::io::Error::last_os_error());
        }
        if libc::WIFSTOPPED(status) {
            return Ok(pid as u32);
        }
        anyhow::bail!("child exited before stop (status {status})");
    }
}

/// Non-reaping child-death probe (`waitid` WNOWAIT keeps the zombie
/// for harvest's pin + the later reaping waitpid).
fn child_gone(pid: u32) -> bool {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if r != 0 {
            // ECHILD (reaped/never-child) = gone; EINTR = retry later.
            return std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR);
        }
        info.si_pid() != 0
    }
}

/// Reaping child poll: None = alive; Some(code or 128+sig) = dead.
fn child_status(pid: u32) -> Option<i32> {
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    if r <= 0 {
        return None;
    }
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

/// Corpse-close: a spawn target whose maps read empty is dead or
/// mid-`do_exit` (a live process always maps something — exe, stack,
/// vdso) — reap it and close cleanly. A bounded blocking wait covers
/// the `exit_mm`-to-zombie window, where maps are already empty but
/// `waitpid` still sees nothing (the pre-poll check straddles it and
/// the corpse would fence [MappingsChanged, Exec], PARTIALing a clean
/// EOF-close — exit-6 lane-a). Returns the exit code when reaped;
/// `None` (impossibly alive, or --pid) falls through to the fence.
fn reap_corpse(spawn: bool, maps_empty: bool, pid: u32) -> Option<i32> {
    if !(spawn && maps_empty) {
        return None;
    }
    let mut code = child_status(pid);
    if code.is_none() {
        let t0 = Instant::now();
        while code.is_none() && t0.elapsed() < Duration::from_millis(100) {
            std::thread::sleep(Duration::from_millis(1));
            code = child_status(pid);
        }
    }
    code
}

// ---------------------------------------------------------------- ppid scan

/// Parse (pid, ppid) from a `/proc/<pid>/stat` line; comm may hold
/// spaces and ')' — ppid is post-comm token 1 (after the LAST ')').
fn parse_stat_ppid(stat: &str) -> Option<(u32, u32)> {
    let (pid_s, rest) = stat.split_once(' ')?;
    let pid = pid_s.parse().ok()?;
    let after = rest.rsplit_once(')')?.1;
    let mut it = after.split_whitespace();
    it.next()?; // state
    let ppid = it.next()?.parse().ok()?;
    Some((pid, ppid))
}

/// Live pids whose parent is `target` (fork/exec detection, §7).
/// Poll-granularity residual: children living entirely between two
/// 250ms polls are missed (proc-connector tracking is v2+).
pub fn children_of(target: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let s = e.file_name().to_string_lossy().into_owned();
        if s.parse::<u32>().is_err() {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{s}/stat")) else {
            continue;
        };
        if let Some((pid, ppid)) = parse_stat_ppid(&stat) {
            if ppid == target {
                out.push(pid);
            }
        }
    }
    out.sort_unstable();
    out
}

// ---------------------------------------------------------------- fence snapshots

/// Fence kind (every fence is recorded; §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceKind {
    /// Mapping add/remove (dev:ino/offset set changed; base shifts
    /// are NOT fences — file-offset attach is base-independent).
    MappingsChanged,
    /// A planned provider path's (dev, ino, size) identity changed.
    ProviderChanged,
    /// Target exec'd (`/proc/<pid>/exe` link changed).
    Exec,
}

/// Window snapshot for fence comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    exe: Option<PathBuf>,
    /// (path, dev, ino, file-offset, x) — start/end deliberately
    /// excluded (pure base shifts never fence).
    mapset: BTreeSet<(String, String, u64, u64, bool)>,
    /// Planned path → (dev, ino, size?). Size None = unreadable
    /// (never a fence by itself — attached probes hold the inode).
    planned: BTreeMap<String, (String, u64, Option<u64>)>,
}

fn snapshot(pid: u32, planned_paths: &[String], live: &[maps::Mapping]) -> Snapshot {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let mapset = live
        .iter()
        .map(|m| (m.path.clone(), m.dev.clone(), m.ino, m.offset, m.x))
        .collect();
    let mut planned = BTreeMap::new();
    for p in planned_paths {
        // First sorted mapping wins (same file ⇒ same identity; a
        // deviant bind-mount alias still fences via the mapset).
        let ident = live
            .iter()
            .filter(|m| &m.path == p)
            .map(|m| (m.dev.clone(), m.ino))
            .min();
        let size = std::fs::metadata(p).map(|m| m.len()).ok();
        if let Some((dev, ino)) = ident {
            planned.insert(p.clone(), (dev, ino, size));
        }
    }
    Snapshot {
        exe,
        mapset,
        planned,
    }
}

fn detect_fence(prev: &Snapshot, next: &Snapshot) -> Vec<FenceKind> {
    let mut out = Vec::new();
    if prev.mapset != next.mapset {
        out.push(FenceKind::MappingsChanged);
    }
    for (path, (dev, ino, size)) in &next.planned {
        // Planned path unmapped mid-window: the mapset already
        // fenced; no double count.
        if let Some((pdev, pino, psize)) = prev.planned.get(path) {
            if (pdev, pino) != (dev, ino) {
                out.push(FenceKind::ProviderChanged);
                break;
            }
            if let (Some(a), Some(b)) = (psize, size) {
                if a != b {
                    out.push(FenceKind::ProviderChanged);
                    break;
                }
            }
        }
    }
    if prev.exe != next.exe {
        out.push(FenceKind::Exec);
    }
    out
}

// ---------------------------------------------------------------- drain

/// One COUNTS drain's routed output.
struct DrainOut {
    folded: HashMap<u32, CountValue>,
    stale_events: u64,
    stale_keys: u64,
    unattributed: u64,
    dropfail: u64,
    shortfall: u64,
    wall_us: u64,
}

fn debug_drain() -> bool {
    std::env::var("OSSL_DEBUG_DRAIN").is_ok()
}

/// Drain COUNTS + DROPFAIL, routing keys by (cookie, generation):
/// known cookies fold per cookie whatever their generation (a
/// superseded generation only memos `table_staleness_events` — the
/// GEN-vs-current race, counted never hidden — without diverting
/// the count); unknown cookies are `unattributed` (PARTIAL by
/// construction — unreachable on multi, defensive). Hard error on
/// unreadable maps (a failed drain must never silently fence).
/// Drains are DELTA-reads: `seen`/`last_drop` carry the previous
/// totals (map keys persist across fence drains — folding totals
/// twice would double-count; deleting keys mid-window would race
/// in-flight increments). Only the delta routes anywhere.
/// `deadline` bounds grace drains: on expiry the REST is counted
/// exactly (keys-only tail, no fold, no `seen` record — grace expiry
/// happens at the final drain only, so no later drain re-adds) into
/// `shortfall` — past-grace bookkeeping by design (exactness >
/// grace to the microsecond).
fn drain_counts(
    loaded: &Loaded,
    current_gen: u32,
    known: &HashSet<u32>,
    seen: &mut HashMap<(u32, u32), u64>,
    last_drop: &mut u64,
    deadline: Option<Instant>,
) -> anyhow::Result<DrainOut> {
    use anyhow::Context as _;
    use aya::maps::{Map, MapData};
    let t0 = Instant::now();
    let mut out = DrainOut {
        folded: HashMap::new(),
        stale_events: 0,
        stale_keys: 0,
        unattributed: 0,
        dropfail: 0,
        shortfall: 0,
        wall_us: 0,
    };
    let dup = |name: &str| -> anyhow::Result<Map> {
        let fd = loaded
            .maps
            .get(name)
            .context(format!("no {name} map"))?
            .try_clone()?;
        let data = MapData::from_fd(fd).map_err(|e| anyhow::anyhow!("{name} mapdata: {e}"))?;
        Map::from_map_data(data).map_err(|e| anyhow::anyhow!("{name} map: {e}"))
    };
    let counts = dup("COUNTS")?;
    let map = aya::maps::PerCpuHashMap::<_, u64, CountValue>::try_from(counts)
        .map_err(|e| anyhow::anyhow!("COUNTS typed: {e}"))?;
    let mut n = 0u64;
    let mut expired = false;
    for r in map.iter() {
        let (key, per_cpu) = r.map_err(|e| anyhow::anyhow!("COUNTS iter: {e}"))?;
        n += 1;
        if expired {
            out.shortfall += 1;
            continue;
        }
        if n % 64 == 0 {
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    expired = true;
                    out.shortfall += 1;
                    continue;
                }
            }
        }
        let mut total = CountValue::default();
        for v in per_cpu.iter() {
            total.fold(v);
        }
        if total.count == 0 {
            continue;
        }
        let (cookie, generation) = split_key(key);
        let prev = seen.insert((cookie, generation), total.count);
        let delta = total.count.saturating_sub(prev.unwrap_or(0));
        if delta == 0 {
            continue;
        }
        if !known.contains(&cookie) {
            // Unknown cookie (any generation): truly unattributable
            // (PARTIAL by construction — unreachable on multi).
            out.unattributed += delta;
            if debug_drain() {
                eprintln!(
                    "DRAINDBG unattributed cookie={cookie} generation={generation} delta={delta} total={}",
                    total.count
                );
            }
            continue;
        }
        if generation != current_gen {
            // Straggler: a known cookie's old-gen events landing after
            // their fence drain (the §3 GEN-vs-current race). The
            // count stays ATTRIBUTED (conservation-exact — the cookie
            // identity can't express builds anyway) while
            // table_staleness_events memos the fence crossing (a
            // memo, NOT a conservation addend — never double-added).
            out.stale_events += delta;
            out.stale_keys += 1;
            if debug_drain() {
                eprintln!(
                    "DRAINDBG stale cookie={cookie} generation={generation} delta={delta} total={}",
                    total.count
                );
            }
        }
        let piece = CountValue {
            count: delta,
            first_ns: total.first_ns,
            last_ns: total.last_ns,
        };
        out.folded.entry(cookie).or_default().fold(&piece);
    }
    let drops = dup("DROPFAIL")?;
    let drops = aya::maps::PerCpuArray::<_, u64>::try_from(drops)
        .map_err(|e| anyhow::anyhow!("DROPFAIL typed: {e}"))?;
    let mut total_drop = 0u64;
    for r in drops.iter() {
        let per_cpu = r.map_err(|e| anyhow::anyhow!("DROPFAIL iter: {e}"))?;
        total_drop += per_cpu.iter().sum::<u64>();
    }
    out.dropfail = total_drop.saturating_sub(*last_drop);
    *last_drop = total_drop;
    out.wall_us = t0.elapsed().as_micros() as u64;
    Ok(out)
}

/// Program a single-cell map (`GEN`/`TARGET`): key 0, `BPF_ANY`.
fn program(loaded: &Loaded, map: &str, value: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let fd = loaded
        .maps
        .get(map)
        .context(format!("no {map} map"))?
        .as_raw_fd();
    ossl_bpf_sys::map_update_elem(fd, &0u32.to_le_bytes(), value, ossl_bpf_sys::BPF_ANY)
        .with_context(|| format!("program {map}"))?;
    Ok(())
}

// ---------------------------------------------------------------- harvest

/// Harvest for capture, legacy tripwires included (P3: the report
/// adopts the legacy block; run-mode pre-exec images defer trip
/// planning to the first post-exec drain round).
fn harvest_target(
    cfg: &Config,
    pid: u32,
    provider: PathBuf,
    builtin: bool,
    timeout: Duration,
    on_attached: &dyn Fn() -> anyhow::Result<()>,
    should_stop: &dyn Fn() -> bool,
) -> anyhow::Result<(serde_json::Value, harvest::HarvestTotals)> {
    harvest::run_detailed(
        &harvest::Config {
            pid,
            provider,
            object: cfg.harvest_object.clone(),
            settle: cfg.settle,
            timeout,
            cmdline_marker: None,
            builtin,
            legacy: true,
            table: None,
            force_offset: None,
        },
        on_attached,
        should_stop,
    )
}

fn read_files(live: &[maps::Mapping]) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    let mut paths: Vec<&str> = live.iter().map(|m| m.path.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    for p in paths {
        if let Ok(bytes) = std::fs::read(p) {
            out.insert(p.to_string(), bytes);
        }
    }
    out
}

/// (dev, ino) backing of a harvest row, if present.
fn backing_of(r: &serde_json::Value) -> Option<(String, u64)> {
    let b = r.get("backing")?;
    let dev = b.get("dev")?.as_str()?.to_string();
    let ino = b.get("ino")?.as_u64()?;
    Some((dev, ino))
}

// Exit-4 KAT downgrade: v1 has no KAT discriminator, so any FIPS
// provider row makes counts unlabeled (self-test calls included).
fn fips_touched(rows: &[serde_json::Value]) -> bool {
    // Provider names are .so file stems ("fips.so" -> "fips");
    // accept a version suffix ("fips.so.3" -> "fips.so").
    rows.iter().any(|r| {
        matches!(r.get("provider").and_then(|p| p.as_str()),
            Some("fips") | Some("fips.so"))
    })
}

fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Container id from `/proc/<pid>/cgroup` content: the first
/// 64-hex path segment or runtime scope name (docker/crio/libpod),
/// else "" (bare metal). Best-effort identity for the check
/// actionability tuple — never a security boundary.
fn parse_container_id(cgroup: &str) -> String {
    for line in cgroup.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for mut seg in path.split('/') {
            seg = seg.strip_suffix(".scope").unwrap_or(seg);
            for prefix in ["docker-", "crio-", "libpod-"] {
                seg = seg.strip_prefix(prefix).unwrap_or(seg);
            }
            if seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
                return seg.to_string();
            }
        }
    }
    String::new()
}

fn container_id_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map(|s| parse_container_id(&s))
        .unwrap_or_default()
}

/// Render `/proc/<pid>/cmdline` bytes: NUL-joined argv → spaces,
/// lossy, capped at 8 KiB with a truncation marker (argv can be
/// huge and can carry secrets; the cap bounds artifact size).
fn render_cmdline(raw: &[u8]) -> String {
    const CAP: usize = 8192;
    let s = String::from_utf8_lossy(raw);
    let s = s.trim_matches('\0').replace('\0', " ");
    if s.len() <= CAP {
        return s;
    }
    let mut end = CAP;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}[truncated]", &s[..end])
}

fn cmdline_of(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| render_cmdline(&b))
        .unwrap_or_default()
}

/// Blind legacy entrypoints: (engine misses, PARTIAL reasons).
/// The merged block holds per-family MAX across harvest phases,
/// so read-through after each merge is the window total. ENGINE
/// misses drive the PRD `engine_fallback_uninstrumented` counter;
/// METH/low-level misses surface as reasons (+ entries states).
fn legacy_blind(legacy: &serde_json::Value) -> (u64, Vec<&'static str>) {
    let n = |ptr: &str| legacy.pointer(ptr).and_then(|v| v.as_u64()).unwrap_or(0);
    let engine = n("/engine/uninstrumented");
    let mut reasons = Vec::new();
    if engine > 0 {
        reasons.push("engine-fallback-uninstrumented");
    }
    if n("/meth_new/uninstrumented") > 0 {
        reasons.push("meth-fallback-uninstrumented");
    }
    if n("/lowlevel/uninstrumented") > 0 {
        reasons.push("lowlevel-fallback-uninstrumented");
    }
    (engine, reasons)
}

/// Merge a re-harvest `legacy` subtree into the accumulator.
/// Harvest phases are disjoint in time: numeric leaves (calls,
/// loads, queries, unreadable) SUM; findings/flags/algs UNION
/// (sorted, deduped); entries merge by (class, name) with
/// observed > uninstrumented > absent and OR'd `probed`;
/// capability takes element-wise MAX (coverage achieved).
fn merge_legacy(acc: &mut serde_json::Value, next: &serde_json::Value) {
    if acc.is_null() {
        *acc = next.clone();
        return;
    }
    if next.is_null() {
        return;
    }
    fn sum_map(acc: &mut serde_json::Value, next: &serde_json::Value, ptr: &str) {
        let Some(next_map) = next.pointer(ptr).and_then(|v| v.as_object()) else {
            return;
        };
        let Some(acc_map) = acc.pointer_mut(ptr).and_then(|v| v.as_object_mut()) else {
            return;
        };
        for (k, v) in next_map {
            let add = v.as_u64().unwrap_or(0);
            let slot = acc_map.entry(k.clone()).or_insert(serde_json::json!(0));
            let cur = slot.as_u64().unwrap_or(0);
            *slot = serde_json::json!(cur + add);
        }
    }
    fn union_list(acc: &mut serde_json::Value, next: &serde_json::Value, ptr: &str) {
        let Some(next_list) = next.pointer(ptr).and_then(|v| v.as_array()) else {
            return;
        };
        let Some(acc_list) = acc.pointer_mut(ptr).and_then(|v| v.as_array_mut()) else {
            return;
        };
        for v in next_list {
            if !acc_list.contains(v) {
                acc_list.push(v.clone());
            }
        }
        acc_list.sort_by_key(|v| serde_json::to_string(v).unwrap_or_default());
    }
    fn max_scalar(acc: &mut serde_json::Value, next: &serde_json::Value, ptr: &str) {
        let (Some(a), Some(n)) = (
            acc.pointer(ptr).and_then(|v| v.as_u64()),
            next.pointer(ptr).and_then(|v| v.as_u64()),
        ) else {
            return;
        };
        if n > a {
            *acc.pointer_mut(ptr).unwrap() = serde_json::json!(n);
        }
    }
    for ptr in [
        "/engine/calls_by_entrypoint",
        "/engine/engine_id_class",
        "/meth_new/calls_by_entrypoint",
        "/lowlevel/calls_by_family",
        "/legacy_provider/loads",
        "/unreadable",
    ] {
        sum_map(acc, next, ptr);
    }
    if let (Some(a), Some(n)) = (
        acc.pointer("/legacy_provider/executed_calls")
            .and_then(|v| v.as_u64()),
        next
            .pointer("/legacy_provider/executed_calls")
            .and_then(|v| v.as_u64()),
    ) {
        *acc.pointer_mut("/legacy_provider/executed_calls").unwrap() = serde_json::json!(a + n);
    }
    for ptr in [
        "/legacy_provider/algs",
        "/findings",
        "/flags",
        "/weak/legacy_algs",
    ] {
        union_list(acc, next, ptr);
    }
    for ptr in [
        "/capability/syms_present",
        "/capability/tripwires_attached",
        "/capability/tripwires_missed",
        "/engine/uninstrumented",
        "/meth_new/uninstrumented",
        "/lowlevel/uninstrumented",
        "/engine_fallback_uninstrumented",
    ] {
        max_scalar(acc, next, ptr);
    }
    // Entries: merge by (class, name), observed wins.
    let rank = |s: &str| match s {
        "observed" => 2,
        "uninstrumented" => 1,
        _ => 0,
    };
    if let (Some(a_list), Some(n_list)) = (
        acc.pointer_mut("/entries").and_then(|v| v.as_array_mut()),
        next.pointer("/entries").and_then(|v| v.as_array()),
    ) {
        for n in n_list {
            let key = (
                n.pointer("/class").and_then(|v| v.as_str()).unwrap_or(""),
                n.pointer("/name").and_then(|v| v.as_str()).unwrap_or(""),
            );
            match a_list.iter_mut().find(|a| {
                (a.pointer("/class").and_then(|v| v.as_str()).unwrap_or(""),
                 a.pointer("/name").and_then(|v| v.as_str()).unwrap_or(""))
                    == key
            }) {
                Some(a) => {
                    let (a_rank, n_rank) = (
                        rank(a.pointer("/state").and_then(|v| v.as_str()).unwrap_or("")),
                        rank(n.pointer("/state").and_then(|v| v.as_str()).unwrap_or("")),
                    );
                    if n_rank > a_rank {
                        a["state"] = n["state"].clone();
                    }
                    let probed = a["probed"].as_bool().unwrap_or(false)
                        || n["probed"].as_bool().unwrap_or(false);
                    a["probed"] = serde_json::json!(probed);
                }
                None => a_list.push(n.clone()),
            }
        }
        a_list.sort_by_key(|v| {
            (
                v.pointer("/class").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                v.pointer("/name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            )
        });
    }
}

// ---------------------------------------------------------------- engine

/// Attached probe site: path + backing identity + file offset. The
/// (dev, ino) half re-arms same-path upgrades (a new build at an old
/// path is a NEW site); the path+offset half keeps same-file reloads
/// on their surviving links (inode probes persist across remap —
/// re-attaching would double-fire every hit).
type AttachedSite = (String, String, u64, u64);

/// Sites of one group not yet attached (pure — unit-tested).
/// Returns (index-in-group, offset, cookie) for the pending sites.
fn pending_sites(
    attached: &HashSet<AttachedSite>,
    path: &str,
    dev: &str,
    ino: u64,
    sites: &[(u64, u64)],
) -> Vec<(usize, u64, u64)> {
    sites
        .iter()
        .enumerate()
        .filter(|(_, (off, _))| {
            !attached.contains(&(path.to_string(), dev.to_string(), ino, *off))
        })
        .map(|(i, (off, ck))| (i, *off, *ck))
        .collect()
}

struct Engine<'a> {
    cfg: &'a Config,
    pid: u32,
    pin: Option<pin::TargetPin>,
    loaded: Loaded,
    links: Vec<OwnedFd>,
    attached: HashSet<AttachedSite>,
    stable: plan::StableCookies,
    known: HashSet<u32>,
    identities: HashMap<u32, (plan::Identity, Vec<plan::Identity>)>,
    current: HashMap<u32, CountValue>,
    generation: u32,
    counters: Counters,
    reasons: HashSet<String>,
    stale: Vec<StaleBucket>,
    row_cache: HashMap<(String, u64), Vec<serde_json::Value>>,
    harvested: HashSet<(String, u64)>,
    children_seen: HashSet<u32>,
    snapshot: Snapshot,
    drain_wall_us: u64,
    /// Last folded total per (cookie, generation): drains are
    /// delta-reads (map keys persist across fence drains — folding
    /// totals twice would double-count, and deleting keys mid-window
    /// would race in-flight increments).
    seen: HashMap<(u32, u32), u64>,
    /// Last observed DROPFAIL total (same delta discipline).
    last_dropfail: u64,
    child_exit: Option<i32>,
    window_start: Instant,
    window_end: Instant,
    window_start_wall: SystemTime,
    window_end_wall: SystemTime,
    kernel_release: String,
    target_cmdline: String,
    target_container_id: String,
    provider_build_id: String,
    provider_path: String,
    image_digest: String,
    harvest_doc: serde_json::Value,
    /// Merged `legacy` subtree (initial + re-harvests, disjoint
    /// harvest phases — merge_legacy sums/unions; Null when no
    /// harvest produced one).
    legacy: serde_json::Value,
}

impl<'a> Engine<'a> {
    fn reason(&mut self, r: impl Into<String>) {
        self.reasons.insert(r.into());
    }

    fn planned_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.attached.iter().map(|(p, _, _, _)| p.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Target liveness: pin for `--pid`, non-reaping probe for spawn.
    fn target_gone(&self) -> bool {
        match &self.pin {
            Some(p) => p.verify().is_err(),
            None => child_gone(self.pid),
        }
    }

    /// Plan + attach the basis rows' not-yet-attached sites at the
    /// current generation. Re-plans skip surviving sites (their links
    /// persist across remaps — re-attaching would double-fire).
    /// Returns false when nothing is attached after this call
    /// (fatal AttachZero for the caller to raise).
    fn plan_and_attach(&mut self, basis: &serde_json::Value) -> anyhow::Result<bool> {
        let live = maps::read_maps(self.pid)?;
        let files = read_files(&live);
        let p = plan::plan_stable(basis, &live, &files, self.generation, &mut self.stable)?;
        if !p.missed.is_empty() {
            self.counters.missed_attaches += p.missed.len() as u64;
            self.reason("missed-attaches");
            for m in &p.missed {
                eprintln!(
                    "CAPTURE missed gen={} dev={} ino={} off={:#x} reason={}",
                    self.generation, m.dev, m.ino, m.offset, m.reason
                );
            }
        }
        let prog_fd = self
            .loaded
            .progs
            .get("count_entry")
            .ok_or_else(|| anyhow::anyhow!("no count_entry prog"))?
            .as_raw_fd();
        for g in plan::groups(&p) {
            // First X mapping wins (same rule as snapshot()).
            let (dev, ino) = live
                .iter()
                .filter(|m| m.path == g.path && m.x)
                .map(|m| (m.dev.clone(), m.ino))
                .next()
                .unwrap_or_default();
            let sites: Vec<(u64, u64)> = g
                .offsets
                .iter()
                .zip(g.cookies.iter())
                .map(|(o, c)| (*o, *c))
                .collect();
            let pending = pending_sites(&self.attached, &g.path, &dev, ino, &sites);
            if pending.is_empty() {
                continue;
            }
            let work: Vec<(u64, u64)> = pending.iter().map(|(_, o, c)| (*o, *c)).collect();
            let (links, bad) = plan::bisect_attach(
                &|s| {
                    let offs: Vec<u64> = s.iter().map(|t| t.0).collect();
                    let cks: Vec<u64> = s.iter().map(|t| t.1).collect();
                    plan::attach_group(prog_fd, self.pid, &g.path, &offs, &cks)
                },
                &work,
            );
            if !bad.is_empty() {
                self.counters.unresolved_offsets += bad.len() as u64;
                self.counters.missed_attaches += bad.len() as u64;
                self.reason("unresolved-offsets");
            }
            self.links.extend(links);
            for (j, (_, off, _)) in pending.iter().enumerate() {
                if bad.binary_search(&j).is_err() {
                    self.attached
                        .insert((g.path.clone(), dev.clone(), ino, *off));
                }
            }
        }
        for e in &p.entries {
            self.known.insert(e.cookie);
            self.identities
                .insert(e.cookie, (e.id.clone(), e.aliases.clone()));
        }
        Ok(!self.links.is_empty())
    }

    /// Fold one drain into the accumulator + counters.
    fn absorb(&mut self, d: DrainOut) {
        self.drain_wall_us += d.wall_us;
        for (cookie, v) in d.folded {
            self.current.entry(cookie).or_default().fold(&v);
        }
        self.counters.table_staleness_events += d.stale_events;
        self.counters.dropped_bpf += d.dropfail;
        if d.unattributed > 0 {
            self.counters.dropped_userspace += d.unattributed;
            self.reason("unattributed");
        }
        if d.shortfall > 0 {
            self.counters.drain_shortfall += d.shortfall;
            self.reason("drain-shortfall");
        }
    }

    /// §3 drain-then-fence: drain fully, bucket the generation,
    /// bump GEN, re-harvest new files, re-plan, re-attach.
    fn fence(&mut self, kinds: Vec<FenceKind>, next: &Snapshot) -> anyhow::Result<()> {
        let d = drain_counts(
            &self.loaded,
            self.generation,
            &self.known,
            &mut self.seen,
            &mut self.last_dropfail,
            None,
        )?;
        self.absorb(d);
        eprintln!(
            "CAPTURE fence kinds={kinds:?} generation={} keys={}",
            self.generation,
            self.current.len()
        );
        let mut detail: Vec<StaleDetail> = self
            .current
            .iter()
            .filter_map(|(cookie, v)| {
                let (id, _) = self.identities.get(cookie)?.clone();
                Some(StaleDetail {
                    cookie: *cookie,
                    id,
                    count: v.count,
                    first_ns: v.first_ns,
                    last_ns: v.last_ns,
                })
            })
            .collect();
        detail.sort_by_key(|d| d.cookie);
        // Aggregate FROM the detail (self-consistent by construction).
        let events = detail.iter().map(|d| d.count).sum();
        self.stale.push(StaleBucket {
            generation: self.generation,
            events,
            keys: detail.len() as u64,
            detail,
        });
        self.current.clear();
        self.generation += 1;
        program(&self.loaded, "GEN", &self.generation.to_le_bytes())?;
        if kinds.contains(&FenceKind::ProviderChanged) {
            self.counters.provider_changed += 1;
        }
        // Targeted re-harvest: new X files only (cached hits skip).
        let mut fresh: Vec<(String, String, u64)> = next
            .mapset
            .difference(&self.snapshot.mapset)
            .filter(|(_, _, ino, _, x)| *x && *ino != 0)
            .map(|(path, dev, ino, _, _)| (path.clone(), dev.clone(), *ino))
            .collect();
        fresh.sort();
        fresh.dedup();
        // Dead target with actual re-harvest work pending (TOCTOU
        // past the loop's pre-poll check): a corpse observes nothing
        // — skip LOUDLY (the new paths stay unobserved — never
        // silent). Empty-fresh fences (pure unmaps) proceed: their
        // re-plan filters to a no-op.
        if !fresh.is_empty() && self.target_gone() {
            self.reason("reharvest-skipped");
            return Ok(());
        }
        let live_now = maps::read_maps(self.pid).unwrap_or_default();
        for (path, dev, ino) in fresh {
            if !self.harvested.insert((dev.clone(), ino)) {
                continue;
            }
            let remaining = self.window_end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.reason("reharvest-skipped");
                continue;
            }
            let timeout = self.cfg.harvest_timeout.min(remaining);
            match harvest_target(
                self.cfg,
                self.pid,
                PathBuf::from(&path),
                false,
                timeout,
                &|| Ok(()),
                &interrupted,
            ) {
                Ok((doc, totals)) => {
                    // Every re-harvest query predates its rows'
                    // count-attach: cold by construction (§6).
                    eprintln!(
                        "CAPTURE re-harvest {path} rows={} queries={} truncated={}",
                        doc.get("rows")
                            .and_then(|r| r.as_array())
                            .map(|r| r.len())
                            .unwrap_or(0),
                        totals.queries_observed,
                        doc.get("truncated_ops")
                            .map(|t| serde_json::to_string(t).unwrap_or_default())
                            .unwrap_or_default()
                    );
                    self.counters.cold_gap_calls += totals.queries_observed;
                    if totals.queries_observed > 0 {
                        self.reason("cold-gap");
                    }
                    merge_legacy(
                        &mut self.legacy,
                        doc.get("legacy").unwrap_or(&serde_json::Value::Null),
                    );
                    // Blind legacy entrypoints downgrade to PARTIAL
                    // (PRD §6: engine_fallback_uninstrumented > 0
                    // is mandatory PARTIAL).
                    let (misses, blind) = legacy_blind(&self.legacy);
                    self.counters.engine_fallback_uninstrumented = misses;
                    for r in blind {
                        self.reason(r);
                    }
                    let rows = doc
                        .get("rows")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if rows.is_empty() {
                        self.reason("reharvest-no-query");
                    } else {
                        if fips_touched(&rows) {
                            self.reason("fips-unlabeled");
                        }
                        self.row_cache.insert((dev, ino), rows);
                    }
                }
                Err(e) => {
                    if e.downcast_ref::<harvest::Recycled>().is_some() {
                        return Err(e);
                    }
                    // Loud, non-fatal: the paths stay unplanned
                    // (missed_attaches at re-plan).
                    eprintln!("CAPTURE re-harvest {path} failed: {e:#}");
                    self.reason("reharvest-failed");
                }
            }
        }
        // The child may have exited DURING a long re-harvest (its
        // drain breaks early via should_stop): re-planning against a
        // zombie's empty maps would cry false "unmapped" missed for
        // healthy rows. Skip LOUDLY instead.
        if self.target_gone() {
            self.reason("replan-skipped");
            return Ok(());
        }
        // Re-plan over the mapped union (initial + cached rows).
        // Rows whose file is currently UNMAPPED are dormant, not
        // missed (their probes persist on the inode; the load fence
        // re-adds them) — excluding them here is what keeps
        // unload-fence re-plans from crying missed-attaches.
        let mapped: HashSet<(String, u64)> =
            live_now.iter().map(|m| (m.dev.clone(), m.ino)).collect();
        let mut basis_rows: Vec<serde_json::Value> = self
            .harvest_doc
            .get("rows")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| backing_of(r).is_some_and(|b| mapped.contains(&b)))
            .collect();
        for ((dev, ino), rows) in &self.row_cache {
            if mapped.contains(&(dev.clone(), *ino)) {
                basis_rows.extend(rows.iter().cloned());
            }
        }
        let basis = serde_json::json!({"rows": basis_rows});
        self.plan_and_attach(&basis)?;
        Ok(())
    }

    fn finish(mut self, outcome: Outcome, window_actual: Duration) -> Capture {
        let mut reasons: Vec<String> = self.reasons.into_iter().collect();
        reasons.sort();
        let mut executions: Vec<Execution> = self
            .current
            .into_iter()
            .filter_map(|(cookie, v)| {
                let (id, aliases) = self.identities.get(&cookie)?.clone();
                Some(Execution {
                    cookie,
                    id,
                    aliases,
                    count: v.count,
                    first_ns: v.first_ns,
                    last_ns: v.last_ns,
                })
            })
            .collect();
        // PRD §6 byte-stability: identity order, not cookie order
        // (cookies are attach-sequence numbers).
        executions.sort_by(|a, b| {
            (
                a.id.op,
                &a.id.provider,
                &a.id.alg_class,
                a.id.funcid,
            )
                .cmp(&(
                    b.id.op,
                    &b.id.provider,
                    &b.id.alg_class,
                    b.id.funcid,
                ))
        });
        // P1 inventory depth carried over the mapped union: current
        // executions PLUS fenced detail (a window that closes
        // mid-churn holds most of its coverage in stale buckets).
        let mut covered: HashSet<u32> = executions.iter().map(|e| e.id.op).collect();
        for s in &self.stale {
            for d in &s.detail {
                covered.insert(d.id.op);
            }
        }
        let uninstrumented = kinds::OPS
            .iter()
            .filter(|op| !covered.contains(&op.id))
            .count() as u64;
        self.counters.uninstrumented_ops = uninstrumented;
        Capture {
            target_pid: self.pid,
            target_comm: comm_of(self.pid),
            window_planned: self.cfg.duration,
            window_actual,
            outcome,
            reasons,
            executions,
            stale: self.stale,
            counters: self.counters,
            child_exit: self.child_exit,
            drain_wall_us: self.drain_wall_us,
            harvest_doc: self.harvest_doc,
            legacy: self.legacy,
            window_start_wall: self.window_start_wall,
            window_end_wall: self.window_end_wall,
            kernel_release: self.kernel_release,
            target_cmdline: self.target_cmdline,
            target_container_id: self.target_container_id,
            provider_build_id: self.provider_build_id,
            provider_path: self.provider_path,
            image_digest: self.image_digest,
        }
    }

    /// Discard all observations (pid recycle — harvest doctrine).
    fn discarded(mut self, window_actual: Duration) -> Capture {
        self.current.clear();
        self.stale.clear();
        self.counters = Counters::default();
        self.reasons.clear();
        self.legacy = serde_json::Value::Null;
        self.reason("pid-recycled");
        self.finish(Outcome::Fatal(FatalKind::Recycled), window_actual)
    }
}

/// Run a full capture window against `target`.
pub fn run(cfg: &Config, target: Target) -> anyhow::Result<Capture> {
    if cfg.duration.is_zero() {
        anyhow::bail!("--duration must be > 0 (no --forever in v1)");
    }
    arm_signals();
    let obj_bytes = std::fs::read(&cfg.count_object)?;
    let prep = crate::loader::prepare(
        &obj_bytes,
        &crate::loader::COUNT_MAPS,
        &crate::loader::COUNT_PROGS,
    )?;
    let loaded = crate::loader::load(&prep).map_err(|e| anyhow::anyhow!("count load: {e:#}"))?;
    program(&loaded, "GEN", &0u32.to_le_bytes())?;
    program(&loaded, "TARGET", &0u64.to_le_bytes())?;

    // Acquire the target (spawn stopped; --pid pinned).
    let (pid, pin, spawn, cmdline) = match target {
        Target::Spawn { argv } => {
            let cmdline = argv.join(" ");
            let pid = spawn_stopped(&argv).map_err(|e| anyhow::anyhow!("spawn: {e:#}"))?;
            (pid, None, true, cmdline)
        }
        Target::Pid(p) => {
            let pin = pin::pin(p).map_err(|e| anyhow::anyhow!("pin: {e:#}"))?;
            (p, Some(pin), false, cmdline_of(p))
        }
    };
    // Target-identity snapshot at acquisition (the target may be
    // dead by report time — /proc reads then would miss).
    let acq_wall = SystemTime::now();
    let container_id = container_id_of(pid);
    let kernel = crate::doctor::uname_release();
    let provider_build_id = std::fs::read(&cfg.provider)
        .ok()
        .and_then(|b| elf::read_build_id(&b))
        .unwrap_or_else(|| "unknown".to_string());
    let provider_path = cfg.provider.to_string_lossy().into_owned();
    let image_digest = cfg.image_digest.clone();
    // Non-reaping death probe during harvest (reaping would race
    // harvest's own pin); the poll loop reaps via waitpid.
    let should_stop = || interrupted() || (spawn && child_gone(pid));
    let on_attached = || -> anyhow::Result<()> {
        if spawn {
            let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
            if r != 0 {
                anyhow::bail!("SIGCONT: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    };
    let harvest_result = harvest_target(
        cfg,
        pid,
        cfg.provider.clone(),
        cfg.builtin,
        cfg.harvest_timeout,
        &on_attached,
        &should_stop,
    );
    let (doc, _totals) = match harvest_result {
        Ok(ok) => ok,
        Err(e) if e.downcast_ref::<harvest::Recycled>().is_some() => {
            let empty = Engine {
                cfg,
                pid,
                pin,
                loaded,
                links: Vec::new(),
                attached: HashSet::new(),
                stable: plan::StableCookies::default(),
                known: HashSet::new(),
                identities: HashMap::new(),
                current: HashMap::new(),
                generation: 0,
                counters: Counters::default(),
                reasons: HashSet::new(),
                stale: Vec::new(),
                row_cache: HashMap::new(),
                harvested: HashSet::new(),
                children_seen: HashSet::new(),
                snapshot: Snapshot::default(),
                drain_wall_us: 0,
                seen: HashMap::new(),
                last_dropfail: 0,
                child_exit: None,
                window_start: Instant::now(),
                window_end: Instant::now(),
                window_start_wall: acq_wall,
                window_end_wall: acq_wall,
                kernel_release: kernel.clone(),
                target_cmdline: cmdline.clone(),
                target_container_id: container_id.clone(),
                provider_build_id: provider_build_id.clone(),
                provider_path: provider_path.clone(),
                image_digest: image_digest.clone(),
                harvest_doc: serde_json::json!({}),
                legacy: serde_json::Value::Null,
            };
            return Ok(empty.discarded(Duration::ZERO));
        }
        Err(e) => return Err(anyhow::anyhow!("harvest: {e:#}")),
    };
    // NOTE: initial-harvest queries are pre-window by construction
    // (the window starts at count-ready) — only RE-harvest queries
    // feed cold_gap_calls (§6).

    let triggered = doc
        .get("trigger_observed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rows = doc
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut engine = Engine {
        cfg,
        pid,
        pin,
        loaded,
        links: Vec::new(),
        attached: HashSet::new(),
        stable: plan::StableCookies::default(),
        known: HashSet::new(),
        identities: HashMap::new(),
        current: HashMap::new(),
        generation: 0,
        counters: Counters::default(),
        reasons: HashSet::new(),
        stale: Vec::new(),
        row_cache: HashMap::new(),
        harvested: HashSet::new(),
        children_seen: HashSet::new(),
        snapshot: Snapshot::default(),
        drain_wall_us: 0,
        seen: HashMap::new(),
        last_dropfail: 0,
        child_exit: None,
        window_start: Instant::now(),
        window_end: Instant::now(),
        window_start_wall: acq_wall,
        window_end_wall: acq_wall,
        kernel_release: kernel,
        target_cmdline: cmdline,
        target_container_id: container_id,
        provider_build_id,
        provider_path,
        image_digest,
        harvest_doc: doc.clone(),
        legacy: doc.get("legacy").cloned().unwrap_or(serde_json::Value::Null),
    };
    // Initial-harvest blind spots (same PARTIAL rule as re-harvests).
    let (misses, blind) = legacy_blind(&engine.legacy);
    engine.counters.engine_fallback_uninstrumented = misses;
    for r in blind {
        engine.reason(r);
    }
    if doc.get("status").and_then(|v| v.as_str()) == Some("PARTIAL") {
        let r = doc
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("partial");
        engine.reason(format!("harvest-{r}"));
    }
    if !triggered || rows.is_empty() {
        // No trigger → PARTIAL (no-query), never COMPLETE-zero (§6).
        engine.reason(if triggered {
            "empty-inventory"
        } else {
            "no-query"
        });
        let c = engine.finish(Outcome::Partial, Duration::ZERO);
        return Ok(c);
    }
    if fips_touched(&rows) {
        engine.reason("fips-unlabeled");
    }
    // Seed the row cache with the initial rows per backing file.
    for r in &rows {
        if let Some((dev, ino)) = backing_of(r) {
            engine.harvested.insert((dev.clone(), ino));
            engine
                .row_cache
                .entry((dev, ino))
                .or_default()
                .push(r.clone());
        }
    }

    if !engine.plan_and_attach(&doc)? {
        let c = engine.finish(Outcome::Fatal(FatalKind::AttachZero), Duration::ZERO);
        return Ok(c);
    }
    // Window open (in-kernel first).
    program(&engine.loaded, "TARGET", &(pid as u64).to_le_bytes())?;
    eprintln!("CAPTURE window open pid={pid} links={}", engine.links.len());
    engine.window_start = Instant::now();
    engine.window_end = engine.window_start + cfg.duration;
    engine.window_start_wall = SystemTime::now();
    let live0 = maps::read_maps(pid).unwrap_or_default();
    engine.snapshot = snapshot(pid, &engine.planned_paths(), &live0);

    // Poll loop: expiry / signal / death / fence.
    let mut interrupted_flag = false;
    let mut expired = false;
    loop {
        let now = Instant::now();
        if now >= engine.window_end {
            expired = true;
            break;
        }
        if interrupted() {
            interrupted_flag = true;
            break;
        }
        if spawn {
            if let Some(code) = child_status(pid) {
                engine.child_exit = Some(code);
                break;
            }
        } else if let Some(p) = &engine.pin {
            if p.verify().is_err() {
                let actual = engine.window_start.elapsed();
                return Ok(engine.discarded(actual));
            }
        }
        let wait = POLL_INTERVAL.min(engine.window_end.saturating_duration_since(now));
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        // Pre-poll liveness: a child that died during the sleep must
        // close the window, not fence on its own corpse (zombie maps
        // read empty — fencing would record a bogus exit fence and
        // re-plan against nothing).
        if spawn {
            if let Some(code) = child_status(pid) {
                engine.child_exit = Some(code);
                break;
            }
        } else if let Some(p) = &engine.pin {
            if p.verify().is_err() {
                let actual = engine.window_start.elapsed();
                return Ok(engine.discarded(actual));
            }
        }
        // Budgeted fence poll (overruns skip the round, §5).
        let t0 = Instant::now();
        let live = maps::read_maps(pid).unwrap_or_default();
        let next = snapshot(pid, &engine.planned_paths(), &live);
        // Post-read liveness: close corpses, never fence them.
        if let Some(code) = reap_corpse(spawn, live.is_empty(), pid) {
            engine.child_exit = Some(code);
            break;
        }
        if t0.elapsed() > POLL_BUDGET {
            engine.counters.scan_budget_exhaustions += 1;
        } else {
            let kinds = detect_fence(&engine.snapshot, &next);
            if !kinds.is_empty() {
                match engine.fence(kinds, &next) {
                    Ok(()) => {}
                    Err(e) if e.downcast_ref::<harvest::Recycled>().is_some() => {
                        let actual = engine.window_start.elapsed();
                        return Ok(engine.discarded(actual));
                    }
                    Err(e) => return Err(e),
                }
            }
            engine.snapshot = next;
        }
        // Fork/exec detection (§7): every NEW child counted once.
        for kid in children_of(pid) {
            if engine.children_seen.insert(kid) {
                engine.counters.fork_exec_ignored += 1;
                engine.reason("fork-exec-ignored");
            }
        }
    }
    // Window close: in-kernel FIRST, then the final drain.
    program(&engine.loaded, "TARGET", &0u64.to_le_bytes())?;
    engine.window_end_wall = SystemTime::now();
    let actual = engine.window_start.elapsed();
    eprintln!("CAPTURE window closed after={:.1}s", actual.as_secs_f64());
    // Over-budget (P2 exit-3): the window expired while the target
    // lived → PARTIAL + counter, never silent truncation. A spawn
    // reaped here died in the last poll slice — its full lifetime
    // was observed, so it is NOT over-budget (child_exit records
    // the code as usual).
    if expired {
        let alive = if spawn {
            match child_status(pid) {
                Some(code) => {
                    engine.child_exit = Some(code);
                    false
                }
                None => true,
            }
        } else {
            engine
                .pin
                .as_ref()
                .map(|p| p.verify().is_ok())
                .unwrap_or(false)
        };
        if alive {
            engine.counters.over_budget += 1;
            engine.reason("over-budget");
        }
    }
    // One last ppid sweep at window end (§7).
    for kid in children_of(pid) {
        if engine.children_seen.insert(kid) {
            engine.counters.fork_exec_ignored += 1;
            engine.reason("fork-exec-ignored");
        }
    }
    // TEST HOOK (exit-3 kernel-proof): hold the final drain past
    // close so a still-counting kernel would advance last_ns beyond
    // the window edge. Production behavior unchanged when unset.
    if let Ok(ms) = std::env::var("OSSLSCOPE_DRAIN_DELAY_MS") {
        if let Ok(ms) = ms.parse::<u64>() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
    let deadline = interrupted_flag.then(|| Instant::now() + cfg.grace);
    let d = drain_counts(
        &engine.loaded,
        engine.generation,
        &engine.known,
        &mut engine.seen,
        &mut engine.last_dropfail,
        deadline,
    )?;
    engine.absorb(d);
    if interrupted_flag {
        engine.reason("interrupted");
    }
    // Reap a zombie child for its exit code (non-blocking; a live
    // child is LEFT RUNNING — observers never kill).
    if spawn && engine.child_exit.is_none() {
        engine.child_exit = child_status(pid);
    }
    let outcome = if engine.reasons.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Partial
    };
    Ok(engine.finish(outcome, actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_parse_tricky_comm() {
        // comm with spaces + parens: fields start after LAST ')'.
        assert_eq!(
            parse_stat_ppid("4242 (my (weird) proc) R 777 0 0"),
            Some((4242, 777))
        );
        assert_eq!(parse_stat_ppid("1 (systemd) S 0 0"), Some((1, 0)));
        assert!(parse_stat_ppid("garbage").is_none());
        assert!(parse_stat_ppid("9 (x) S").is_none());
    }

    #[test]
    fn self_has_no_unexpected_parent_gap() {
        // Smoke: our own pid parses out of the live scan path.
        let me = std::process::id();
        let stat = std::fs::read_to_string(format!("/proc/{me}/stat")).unwrap();
        let (pid, _) = parse_stat_ppid(&stat).unwrap();
        assert_eq!(pid, me);
    }

    fn snap(
        exe: &str,
        maps: Vec<(&str, &str, u64, u64, bool)>,
        planned: Vec<(&str, &str, u64, Option<u64>)>,
    ) -> Snapshot {
        Snapshot {
            exe: Some(PathBuf::from(exe)),
            mapset: maps
                .into_iter()
                .map(|(p, d, i, o, x)| (p.to_string(), d.to_string(), i, o, x))
                .collect(),
            planned: planned
                .into_iter()
                .map(|(p, d, i, s)| (p.to_string(), (d.to_string(), i, s)))
                .collect(),
        }
    }

    #[test]
    fn fence_matrix() {
        let base = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        // Identical: no fence.
        assert!(detect_fence(&base, &base).is_empty());
        // Mapping add: fence (dlopen).
        let added = snap(
            "/bin/app",
            vec![
                ("/lib/x.so", "08:01", 7, 0, true),
                ("/lib/y.so", "08:01", 8, 0, true),
            ],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        assert_eq!(
            detect_fence(&base, &added),
            vec![FenceKind::MappingsChanged]
        );
        // Provider identity flip: fence + provider counter kind.
        let flipped = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 9, 0, true)],
            vec![("/lib/x.so", "08:01", 9, Some(99))],
        );
        let k = detect_fence(&base, &flipped);
        assert!(k.contains(&FenceKind::MappingsChanged));
        assert!(k.contains(&FenceKind::ProviderChanged));
        // Size-only change, same file: provider fence, no maps fence.
        let grown = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(100))],
        );
        assert_eq!(
            detect_fence(&base, &grown),
            vec![FenceKind::ProviderChanged]
        );
        // Unreadable size: never a fence by itself.
        let unread = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, None)],
        );
        assert!(detect_fence(&base, &unread).is_empty());
        // Exec: fence.
        let execd = snap(
            "/bin/other",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        assert_eq!(detect_fence(&base, &execd), vec![FenceKind::Exec]);
    }

    #[test]
    fn fips_caveat_triggers_on_fips_rows_only() {
        let row = |prov: &str| serde_json::json!({"provider": prov, "op": 1});
        assert!(fips_touched(&[row("default"), row("fips")]));
        assert!(!fips_touched(&[row("default"), row("legacy")]));
        assert!(!fips_touched(&[]));
        assert!(!fips_touched(&[serde_json::json!({"op": 1})]));
        // Version-suffixed stem trips; near-misses must not.
        assert!(fips_touched(&[row("fips.so")]));
        assert!(!fips_touched(&[row("FIPS"), row("fipsy"), row("myfips")]));
    }

    #[test]
    fn reap_corpse_gating() {
        // --pid path and mapped targets never corpse-close (no wait).
        assert_eq!(reap_corpse(false, true, std::process::id()), None);
        assert_eq!(reap_corpse(true, false, std::process::id()), None);
        // Unwaitable pid (ourselves): bounded wait, then None.
        let t0 = Instant::now();
        assert_eq!(reap_corpse(true, true, std::process::id()), None);
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn reap_corpse_reaps_exited_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(7) };
        }
        // Exited child (empty maps by kernel construction): reaped
        // with its code, well inside the bound.
        assert_eq!(reap_corpse(true, true, pid as u32), Some(7));
    }

    #[test]
    fn merge_legacy_sums_unions_and_maxes() {
        let mut acc = serde_json::json!({
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 2}, "engine_id_class": {"dynamic": 1}},
            "meth_new": {"calls_by_entrypoint": {}},
            "lowlevel": {"calls_by_family": {"digest/sha": 3}},
            "legacy_provider": {"loads": {"legacy": 1}, "executed_calls": 4, "algs": ["MD4"]},
            "entries": [
                {"name": "ENGINE_init", "class": "engine", "state": "observed", "probed": true},
                {"name": "DH_meth_new", "class": "meth", "state": "absent", "probed": false},
            ],
            "capability": {"syms_present": 10, "tripwires_attached": 8, "tripwires_missed": 2},
            "findings": ["ENGINE API absent"],
            "flags": ["engine-api-absent"],
            "weak": {"legacy_algs": ["MD4"]},
            "unreadable": {"load_names": 1, "engine_ids": 0},
        });
        let next = serde_json::json!({
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 5}, "engine_id_class": {"dynamic": 2}},
            "meth_new": {"calls_by_entrypoint": {}},
            "lowlevel": {"calls_by_family": {"digest/sha": 7}},
            "legacy_provider": {"loads": {"legacy": 2}, "executed_calls": 6, "algs": ["MD4", "DES"]},
            "entries": [
                {"name": "ENGINE_init", "class": "engine", "state": "observed", "probed": true},
                {"name": "DH_meth_new", "class": "meth", "state": "observed", "probed": true},
            ],
            "capability": {"syms_present": 12, "tripwires_attached": 9, "tripwires_missed": 3},
            "findings": ["ENGINE API absent", "low-level coverage unavailable (no .dynsym)"],
            "flags": ["engine-api-absent", "lowlevel-no-dynsym"],
            "weak": {"legacy_algs": ["MD4", "DES"]},
            "unreadable": {"load_names": 2, "engine_ids": 1},
        });
        merge_legacy(&mut acc, &next);
        assert_eq!(acc["engine"]["calls_by_entrypoint"]["ENGINE_init"], 7);
        assert_eq!(acc["lowlevel"]["calls_by_family"]["digest/sha"], 10);
        assert_eq!(acc["legacy_provider"]["executed_calls"], 10);
        assert_eq!(acc["legacy_provider"]["loads"]["legacy"], 3);
        assert_eq!(acc["unreadable"]["load_names"], 3);
        assert_eq!(
            acc["legacy_provider"]["algs"],
            serde_json::json!(["DES", "MD4"])
        );
        assert_eq!(acc["findings"].as_array().unwrap().len(), 2);
        assert_eq!(acc["flags"].as_array().unwrap().len(), 2);
        // Entries: observed wins, probed ORs, order deterministic.
        let dh = acc["entries"].as_array().unwrap().iter()
            .find(|e| e["name"] == "DH_meth_new").unwrap();
        assert_eq!(dh["state"], "observed");
        assert_eq!(dh["probed"], true);
        // Capability: max, not sum.
        assert_eq!(acc["capability"]["syms_present"], 12);
        assert_eq!(acc["capability"]["tripwires_attached"], 9);
        // Null legs: adopt / keep.
        let mut n = serde_json::Value::Null;
        merge_legacy(&mut n, &next);
        assert_eq!(n["legacy_provider"]["executed_calls"], 6);
        merge_legacy(&mut acc, &serde_json::Value::Null);
        assert_eq!(acc["legacy_provider"]["executed_calls"], 10);
    }

    #[test]
    fn replan_skips_attached_sites() {
        let mut attached: HashSet<AttachedSite> = HashSet::new();
        attached.insert(("/lib/x.so".to_string(), "08:01".to_string(), 7, 0x100));
        let sites = vec![(0x100u64, 0u64), (0x200u64, 1u64)];
        // Same file: only the new offset pends (no double-fire).
        assert_eq!(
            pending_sites(&attached, "/lib/x.so", "08:01", 7, &sites),
            vec![(1, 0x200, 1)]
        );
        // Same path, new build: everything pends (re-arm).
        assert_eq!(
            pending_sites(&attached, "/lib/x.so", "08:01", 9, &sites),
            vec![(0, 0x100, 0), (1, 0x200, 1)]
        );
        // Fully attached: empty (re-plan attaches nothing).
        attached.insert(("/lib/x.so".to_string(), "08:01".to_string(), 7, 0x200));
        assert!(pending_sites(&attached, "/lib/x.so", "08:01", 7, &sites).is_empty());
    }

    #[test]
    fn legacy_blind_counts_engine_and_reasons() {
        // Null / clean legacy: no misses, no reasons.
        assert_eq!(
            legacy_blind(&serde_json::Value::Null),
            (0, Vec::new())
        );
        assert_eq!(
            legacy_blind(&serde_json::json!({"engine": {}, "capability": {}})),
            (0, Vec::new())
        );
        // ENGINE misses drive the PRD counter + reason.
        assert_eq!(
            legacy_blind(&serde_json::json!({"engine": {"uninstrumented": 2}})),
            (2, vec!["engine-fallback-uninstrumented"])
        );
        // METH/low-level blind spots add reasons (no PRD counter).
        assert_eq!(
            legacy_blind(&serde_json::json!({
                "engine": {"uninstrumented": 1},
                "meth_new": {"uninstrumented": 3},
                "lowlevel": {"uninstrumented": 4},
            })),
            (
                1,
                vec![
                    "engine-fallback-uninstrumented",
                    "meth-fallback-uninstrumented",
                    "lowlevel-fallback-uninstrumented",
                ]
            )
        );
    }

    #[test]
    fn container_id_parses_runtimes() {
        let id = "9".repeat(64);
        // Docker cgroupfs path segment.
        assert_eq!(
            parse_container_id(&format!("12:pids:/docker/{id}\n11:memory:/docker/{id}\n")),
            id
        );
        // K8s systemd scope (docker + crio runtimes).
        assert_eq!(
            parse_container_id(&format!(
                "0::/kubepods/burstable/podabc123/docker-{id}.scope\n"
            )),
            id
        );
        assert_eq!(
            parse_container_id(&format!(
                "0::/kubepods-besteffort.slice/kubepods-besteffort-poddef.slice/crio-{id}.scope\n"
            )),
            id
        );
        // Bare metal / user slice: no id.
        assert_eq!(parse_container_id("0::/user.slice/user-1000.slice\n"), "");
        assert_eq!(parse_container_id(""), "");
        // Short hex is not an id (64 required).
        assert_eq!(parse_container_id("0::/docker/abc123\n"), "");
    }

    #[test]
    fn cmdline_renders_and_truncates() {
        assert_eq!(render_cmdline(b"nginx\0-g\0daemon off;\0"), "nginx -g daemon off;");
        assert_eq!(render_cmdline(b""), "");
        // Kernel threads read empty: no crash, empty string.
        assert_eq!(render_cmdline(b"\0"), "");
        let big = vec![b'x'; 9000];
        let out = render_cmdline(&big);
        assert!(out.ends_with("[truncated]"), "tail: {}", &out[out.len() - 20..]);
        assert!(out.len() <= 8192 + "[truncated]".len() + 1);
    }

    #[test]
    fn kernel_release_nonempty() {
        assert!(!crate::doctor::uname_release().is_empty());
    }
}
