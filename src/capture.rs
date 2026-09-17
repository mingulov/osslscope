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
use crate::discovery::{harvest, maps};
use crate::loader::Loaded;
use crate::{kinds, pin, plan};
use osslscope_ebpf_common::{CountValue, split_key};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

/// Drain COUNTS + DROPFAIL, routing keys by (cookie, generation): current
/// known keys fold per cookie; superseded-generation keys feed
/// `table_staleness_events` (the GEN-vs-current race, counted never
/// hidden); unknown cookies are `unattributed` (PARTIAL by
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
        if generation != current_gen {
            out.stale_events += delta;
            out.stale_keys += 1;
            if debug_drain() {
                eprintln!(
                    "DRAINDBG stale cookie={cookie} generation={generation} delta={delta} total={}",
                    total.count
                );
            }
        } else if !known.contains(&cookie) {
            out.unattributed += delta;
            if debug_drain() {
                eprintln!(
                    "DRAINDBG unattributed cookie={cookie} delta={delta} total={}",
                    total.count
                );
            }
        } else {
            let piece = CountValue {
                count: delta,
                first_ns: total.first_ns,
                last_ns: total.last_ns,
            };
            out.folded.entry(cookie).or_default().fold(&piece);
        }
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

/// Dispatch-only harvest for capture (legacy tripwires stay a P1
/// `inspect` concern: pre-exec images can't plan them, and live
/// re-harvests would burn the window).
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
            legacy: false,
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

fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
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
    harvest_doc: serde_json::Value,
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
                    self.counters.cold_gap_calls += totals.queries_observed;
                    if totals.queries_observed > 0 {
                        self.reason("cold-gap");
                    }
                    let rows = doc
                        .get("rows")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if rows.is_empty() {
                        self.reason("reharvest-no-query");
                    } else {
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
        // Re-plan over the mapped union (initial + cached rows).
        let mut basis_rows: Vec<serde_json::Value> = self
            .harvest_doc
            .get("rows")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let mapped: HashSet<(String, u64)> =
            live_now.iter().map(|m| (m.dev.clone(), m.ino)).collect();
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
        executions.sort_by_key(|e| e.cookie);
        // P1 inventory depth carried over the mapped union.
        let covered: HashSet<u32> = executions.iter().map(|e| e.id.op).collect();
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
        }
    }

    /// Discard all observations (pid recycle — harvest doctrine).
    fn discarded(mut self, window_actual: Duration) -> Capture {
        self.current.clear();
        self.stale.clear();
        self.counters = Counters::default();
        self.reasons.clear();
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
    let (pid, pin, spawn) = match target {
        Target::Spawn { argv } => {
            let pid = spawn_stopped(&argv).map_err(|e| anyhow::anyhow!("spawn: {e:#}"))?;
            (pid, None, true)
        }
        Target::Pid(p) => {
            let pin = pin::pin(p).map_err(|e| anyhow::anyhow!("pin: {e:#}"))?;
            (p, Some(pin), false)
        }
    };
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
                harvest_doc: serde_json::json!({}),
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
        harvest_doc: doc.clone(),
    };
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
    // Seed the row cache with the initial rows per backing file.
    for r in &rows {
        if let Some(b) = r.get("backing") {
            let dev = b
                .get("dev")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ino = b.get("ino").and_then(|v| v.as_u64()).unwrap_or(0);
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
        // Budgeted fence poll (overruns skip the round, §5).
        let t0 = Instant::now();
        let live = maps::read_maps(pid).unwrap_or_default();
        let next = snapshot(pid, &engine.planned_paths(), &live);
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
}
