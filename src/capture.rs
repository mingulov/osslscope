//! SPDX-License-Identifier: GPL-3.0-or-later
//! T08 session-driven capture controller (spec R04/R05).
//!
//! One requested observation holds BOTH sessions for its complete
//! lifetime: a [`DiscoverySession`](crate::discovery::session::DiscoverySession)
//! for the dispatch/legacy planes and a
//! [`CountSession`](crate::count_session::CountSession) for keyed
//! callback counts. Discovery deltas apply incrementally through the
//! [`adapt_delta`] adapter; legacy tripwire counters baseline at the
//! declared window boundary; counting closes before the final
//! discovery drain; and the window finalizes through
//! [`evidence::finalize`] only after every counter is known.
//!
//! Window order for `run` (R05: requested begins at child release):
//! spawn stopped → attach discovery → open the kernel count window →
//! baseline discovery poll → release the child (requested start) →
//! poll loop → close counting → final discovery drain → reap/detach.
//! Opening before release keeps the happy-path startup gap at zero;
//! `--pid` (requested begins at acquisition, necessarily before the
//! window opens) stays explicitly PARTIAL, as before.
//!
//! The `Capture`/`Counters`/`Outcome` surface below is the T10/T11
//! seam: reports and policy still consume it, now mapped from the
//! finalized [`evidence::CaptureDocument`] (carried in
//! [`Capture::document`]) instead of the retired Engine. Reason
//! strings stay inside the `REASON_TAXONOMY` vocabulary in
//! `report.rs` (extended by review for the session-driven gaps).
//!
//! Lifecycle (R05): short fork/exec detection uses the EXPLICIT
//! PARTIAL polling fallback ([`PollingLifecycle`]); polling alone
//! cannot prove no such activity, so every live capture carries the
//! `lifecycle.polling_fallback` loss until the bounded kernel signal
//! path lands (recorded gap, see the T08 handoff). No multi-target
//! capture: one TGID throughout.
//!
//! The controller is generic over [`DiscoveryPort`], [`TargetPort`],
//! [`LifecyclePort`], [`ClockPort`] and [`ProcPort`] so the
//! `tests/capture_controller.rs` suite drives the real [`observe`]
//! loop with scripted sessions, an injected clock and failing I/O —
//! no timing sleeps, no privileges.
use crate::count_session::{
    CountBackend, CountDelta, CountDrain, CountSession, DiscoveredSite, FenceReason as CountFence,
};
use crate::discovery::session::{
    CoverageState, DiscoveryDelta, DiscoverySession, DiscoverySnapshot, PollBudget, TripwireDelta,
};
use crate::discovery::{coverage, elf, legacy, maps};
use crate::evidence::{
    self, CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, Completeness,
    CounterKind, CounterSource, CounterUnits, ExpectedScope, FinalizeInput, GapCounter, GapReason,
    ObjectId, ObjectRecord, ScopeCoverage, SiteExecution, SiteKey,
};
use crate::{args, kinds, pin, plan, target};
use anyhow::Context as _;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Maps-fence poll cadence (frozen §5).
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Per-poll wall budget; overruns skip the round (§5).
pub const POLL_BUDGET: Duration = Duration::from_millis(50);
/// Signal-drain grace (P2 default; P3 sets final).
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);
/// Extra discovery polls per round while `budget_exhausted` persists.
/// Backpressure, not loss — but the round stays bounded so a busy
/// ring cannot starve the deadline.
const MAX_CATCHUP_POLLS: u32 = 8;

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
    /// Finalized v2 evidence document (T08 produces it; T10/T11
    /// rewire reports/policy onto it).
    pub document: CaptureDocument,
    /// End-of-observation target disposition (T04 custody): exit
    /// status preserved, or the detached pid that was left running.
    /// `None` for foreign `--pid` targets that recycled mid-window.
    pub disposition: Option<target::TargetDisposition>,
}

/// Minimal document for test constructors outside this module (real
/// captures always carry the finalized document).
pub fn empty_document() -> CaptureDocument {
    evidence::finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
    })
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

// ---------------------------------------------------------------- ports
//
// The controller drives sessions, target custody, lifecycle, time
// and /proc reads through these ports. Live wiring sits beside each
// trait; `tests/capture_controller.rs` scripts fakes behind the same
// contracts (injected clock, failing I/O, no sleeps).

/// Persistent discovery engine, held for the complete observation.
pub trait DiscoveryPort {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta>;
    fn snapshot(&self) -> DiscoverySnapshot;
    /// Quiesce-then-PROCESS teardown: exact tail accounting for the
    /// final drain. Called once, at close.
    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot>;
}

/// Live discovery engine behind the port: `DiscoverySession::close`
/// consumes, so the wrapper holds it by option and takes it at
/// finish (RAII detaches on the drop paths).
pub struct LiveDiscovery(Option<DiscoverySession>);

impl LiveDiscovery {
    pub fn new(session: DiscoverySession) -> Self {
        Self(Some(session))
    }
}

impl DiscoveryPort for LiveDiscovery {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        match self.0.as_mut() {
            Some(session) => session.poll(budget),
            None => anyhow::bail!("discovery session already finished"),
        }
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        match self.0.as_ref() {
            Some(session) => session.snapshot(),
            None => DiscoverySnapshot::default(),
        }
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        match self.0.take() {
            Some(session) => session.close(),
            None => anyhow::bail!("discovery session already finished"),
        }
    }
}

/// Observed target custody (T04). Owned children move through
/// stopped → released → reaped/detached; foreign `--pid` targets are
/// pinned and never signaled or waited on.
pub trait TargetPort {
    fn pid(&self) -> u32;
    fn is_owned(&self) -> bool;
    /// Release a stopped owned child (strictly once); a foreign
    /// target ignores this (never signaled).
    fn release(&mut self) -> anyhow::Result<()>;
    /// Non-blocking exit poll: `Ok(None)` = alive. Foreign targets
    /// are never waited on and always answer `None`.
    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>>;
    /// Resolve custody after a setup failure (never leaves a stopped
    /// child; never kills a running application).
    fn resolve_setup_failure(&mut self) -> anyhow::Result<()>;
    /// End-of-observation disposition: reaped status or detached pid.
    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition>;
    /// Identity intact (foreign pin check; owned targets are
    /// waitpid-owned and always answer `Ok`).
    fn verify(&self) -> anyhow::Result<()>;
}

impl TargetPort for target::OwnedTarget {
    fn pid(&self) -> u32 {
        target::OwnedTarget::pid(self)
    }

    fn is_owned(&self) -> bool {
        true
    }

    fn release(&mut self) -> anyhow::Result<()> {
        target::OwnedTarget::release(self)
    }

    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        target::OwnedTarget::poll_exit(self)
    }

    fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        target::OwnedTarget::resolve_setup_failure(self)
    }

    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
        target::OwnedTarget::finish_observation(self)
    }

    fn verify(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A foreign `--pid` target: pinned identity, no custody. Every
/// signal/wait path is a deliberate no-op; liveness is the pin.
pub struct PinnedTarget {
    pid: u32,
    pin: pin::TargetPin,
}

impl PinnedTarget {
    pub fn new(pid: u32, pin: pin::TargetPin) -> Self {
        Self { pid, pin }
    }
}

impl TargetPort for PinnedTarget {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_owned(&self) -> bool {
        false
    }

    fn release(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        Ok(None)
    }

    fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
        // Never owned: "detached" here means left running and never
        // signaled (documented, not custody).
        Ok(target::TargetDisposition::Detached { pid: self.pid })
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.pin.verify().map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// One ignored fork/exec event: detected and explained, never
/// captured (no multi-target capture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    Fork,
    Exec,
}

/// One ignored child/sibling lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub kind: LifecycleKind,
    pub pid: u32,
}

/// One lifecycle poll: new events plus scan loss (failed /proc
/// reads that may have missed activity).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleDelta {
    pub events: Vec<LifecycleEvent>,
    pub loss: u64,
}

/// Short fork/exec + lifecycle-loss observer. The T08 selection is
/// the EXPLICIT PARTIAL polling fallback: `fallback_partial()` is
/// true, and the controller records the `lifecycle.polling_fallback`
/// loss on every observation using it, because polling alone cannot
/// prove no short-lived activity occurred between scans.
pub trait LifecyclePort {
    fn poll(&mut self) -> LifecycleDelta;
    fn fallback_partial(&self) -> bool;
}

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
/// scans are missed — the polling fallback is explicitly PARTIAL.
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

/// Process-group id of `pid` from `/proc/<pid>/status` (`Tgid:`):
/// a same-TGID clone is thread creation, not an ignored process.
fn tgid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Polling lifecycle fallback (explicit PARTIAL): ppid scans for
/// forked children plus an exe-link watch for same-TGID exec of the
/// target itself. Every NEW child counts once (a double-fork that
/// reparents away stays counted); same-TGID clones never count.
pub struct PollingLifecycle {
    target: u32,
    seen: HashSet<u32>,
    exe: Option<PathBuf>,
}

impl PollingLifecycle {
    pub fn new(target: u32) -> Self {
        let exe = std::fs::read_link(format!("/proc/{target}/exe")).ok();
        Self {
            target,
            seen: HashSet::new(),
            exe,
        }
    }
}

impl LifecyclePort for PollingLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        let mut delta = LifecycleDelta::default();
        if std::fs::read_dir("/proc").is_err() {
            // The scan itself failed: activity may have been missed.
            delta.loss += 1;
            return delta;
        }
        for kid in children_of(self.target) {
            if !self.seen.insert(kid) {
                continue;
            }
            // Same-TGID clone (thread creation) is not an ignored
            // process. Unreadable Tgid fails closed to Fork: a child
            // that vanished mid-scan is still ignored activity.
            let is_thread = tgid_of(kid).is_some_and(|tg| tg == self.target);
            if !is_thread {
                delta.events.push(LifecycleEvent {
                    kind: LifecycleKind::Fork,
                    pid: kid,
                });
            }
        }
        match std::fs::read_link(format!("/proc/{}/exe", self.target)) {
            Ok(exe) => {
                if self.exe.as_ref() != Some(&exe) {
                    self.exe = Some(exe);
                    delta.events.push(LifecycleEvent {
                        kind: LifecycleKind::Exec,
                        pid: self.target,
                    });
                }
            }
            Err(_) => {
                // The target may be exiting (its exe link is gone);
                // the controller's custody check owns that verdict —
                // here it is only scan loss when unreadable.
                delta.loss += 1;
            }
        }
        delta
    }

    fn fallback_partial(&self) -> bool {
        true
    }
}

/// Time: monotonic nanoseconds for the kernel window program plus
/// the requested/effective boundaries, `Instant` for loop control.
pub trait ClockPort {
    fn monotonic_ns(&self) -> u64;
    fn now(&self) -> Instant;
    fn wall_now(&self) -> SystemTime;
    fn sleep(&self, d: Duration);
}

/// Live clock: `CLOCK_MONOTONIC` for the kernel-adjacent stamps.
pub struct LiveClock;

impl ClockPort for LiveClock {
    fn monotonic_ns(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec.max(0) as u64)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Target /proc + file reads: live mappings for planning, file bytes
/// for ELF validation and object fingerprints, the exe link and file
/// sizes for fence comparison.
pub trait ProcPort {
    fn read_maps(&mut self, pid: u32) -> anyhow::Result<Vec<maps::Mapping>>;
    fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>>;
    fn read_exe(&mut self, pid: u32) -> Option<PathBuf>;
    fn file_len(&mut self, path: &str) -> Option<u64>;
}

/// Live /proc + filesystem reads.
pub struct LiveProc;

impl ProcPort for LiveProc {
    fn read_maps(&mut self, pid: u32) -> anyhow::Result<Vec<maps::Mapping>> {
        maps::read_maps(pid)
    }

    fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }

    fn read_exe(&mut self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    fn file_len(&mut self, path: &str) -> Option<u64> {
        std::fs::metadata(path).map(|m| m.len()).ok()
    }
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

fn snapshot(
    exe: Option<PathBuf>,
    live: &[maps::Mapping],
    planned_paths: &[String],
    sizes: &HashMap<String, Option<u64>>,
) -> Snapshot {
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
        if let Some((dev, ino)) = ident {
            let size = sizes.get(p).copied().flatten();
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

// ---------------------------------------------------------------- corpse close

/// Corpse-close: a spawn target whose maps read empty is dead or
/// mid-`do_exit` (a live process always maps something — exe, stack,
/// vdso) — reap it and close cleanly. A bounded blocking wait covers
/// the `exit_mm`-to-zombie window, where maps are already empty but
/// `waitpid` still sees nothing. Returns the exit code when reaped;
/// `None` (impossibly alive, or --pid) falls through to the fence.
fn reap_corpse(spawn: bool, maps_empty: bool, pid: u32) -> Option<i32> {
    if !(spawn && maps_empty) {
        return None;
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    let mut code = if r > 0 {
        if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Some(128 + libc::WTERMSIG(status))
        } else {
            None
        }
    } else {
        None
    };
    if code.is_none() {
        let t0 = Instant::now();
        while code.is_none() && t0.elapsed() < Duration::from_millis(100) {
            std::thread::sleep(Duration::from_millis(1));
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if r > 0 {
                if libc::WIFEXITED(status) {
                    code = Some(libc::WEXITSTATUS(status));
                } else if libc::WIFSIGNALED(status) {
                    code = Some(128 + libc::WTERMSIG(status));
                }
            }
        }
    }
    code
}

// ---------------------------------------------------------------- target identity

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

/// PRD §6 byte-stability: identity order, not cookie order
/// (cookies are attach-sequence numbers).
fn sort_executions(executions: &mut [Execution]) {
    executions.sort_by(|a, b| {
        (a.id.op, &a.id.provider, &a.id.alg_class, a.id.funcid).cmp(&(
            b.id.op,
            &b.id.provider,
            &b.id.alg_class,
            b.id.funcid,
        ))
    });
}

// ---------------------------------------------------------------- adapter
//
// `DiscoveryDelta` (T06 producer) → `CountDelta` (T07 consumer) plus
// the auxiliary evidence the count session never sees. Stage-2
// review decisions, frozen here:
//
// D1 — Incremental vs complete. Discovery emits each candidate once
// (plus identity refreshes); the count session REPLACES a site's
// candidate set on every emit. The adapter therefore accumulates the
// full per-site set in [`AdapterState`] and re-emits the complete
// set for every touched site on every poll. Two sites sharing one
// backing triple union; coverage only ever degrades (see D3).
//
// D2 — The nine producer fields without a `CountDelta` counterpart:
// `events_consumed`/`queries_delta`/`attaches`(ok)/`budget_exhausted`
// become Activity counters; `objects` become [`ObjectRecord`]s;
// `tables` feed per-op [`ScopeCoverage`]; `retirements` invalidate
// op completion (dirty until the new epoch proves) and re-emit
// affected sites as Unknown; `tripwire` feeds the separate legacy
// evidence with window baselining (controller-owned);
// `trigger_observed` drives the no-query verdict. Retirement gap
// losses are NOT re-counted here (the session emits them through
// `losses`); close-time snapshot residuals reconcile once.
//
// D3 — Identity/metadata synthesis. Backing and advertising object
// ids are the mapped file's build-id fingerprint when its bytes
// yield one, else an opaque `unverified-…` id — pathnames never
// become identity. `provider_class` is `default` in operator-asserted
// builtin mode and `unknown` otherwise (T09 pinned classification is
// the seam; never guessed from `fips.so` or a rename). A missing
// backing or an unparsable maps device makes the site unplannable:
// explicit loss, never a fabricated device zero. Per-site coverage
// is `Unknown` when any candidate read badly (`status != ok`), the
// op table is unterminated/dirty, or new candidates arrive after the
// op already terminated (the set proved non-closed). Session-global
// losses do NOT flip per-site coverage: they PARTIAL the window via
// Loss counters while unrelated positive evidence survives (R06).
//
// D4 — Loss classification. Every [`DiscoveryLoss`](crate::discovery::session::DiscoveryLoss)
// stays `Loss`: wire ring ids → `KernelRing`, wire map ids →
// `KernelMap`, pending/init-scan ids → `Discovery`, orphan rows →
// `TableRows`, everything else → `Events` (`HOST_DRAIN_SHORTFALL`
// sources `Drain`). Unknown ids (newer BPF than userspace) fail
// closed as `discovery.unknown_<id>` with the count preserved.

fn typed_counter(
    name: &str,
    kind: CounterKind,
    units: CounterUnits,
    source: CounterSource,
    value: u64,
) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind,
        units,
        source,
        value,
    }
}

/// Classify one discovery loss source (D4). Unknown ids fail closed:
/// the count is preserved under `discovery.unknown_<id>`, never
/// dropped.
fn classify_loss(source: u32, count: u64) -> GapCounter {
    use osslscope_ebpf_common as wire;
    let name = coverage::loss_source_name(source)
        .map(str::to_string)
        .unwrap_or_else(|| format!("unknown_{source}"));
    let (units, origin) = match source {
        wire::LOSS_RING_ALG | wire::LOSS_RING_ROW | wire::LOSS_RING_TRIP | wire::LOSS_RING_INIT => {
            (CounterUnits::Events, CounterSource::KernelRing)
        }
        wire::LOSS_MAP_QUERY_NEXT
        | wire::LOSS_MAP_TRUNC
        | wire::LOSS_MAP_CALLS
        | wire::LOSS_MAP_TRIP
        | wire::LOSS_MAP_LGCALLS
        | wire::LOSS_MAP_TERMD => (CounterUnits::Events, CounterSource::KernelMap),
        wire::LOSS_PENDING_INIT_FULL
        | wire::LOSS_PENDING_QUERY_FULL
        | wire::LOSS_PENDING_INIT_MISS
        | wire::LOSS_PENDING_QUERY_MISS
        | wire::LOSS_INIT_SCAN => (CounterUnits::Events, CounterSource::Discovery),
        coverage::HOST_ORPHAN_ROW => (CounterUnits::TableRows, CounterSource::Discovery),
        coverage::HOST_DRAIN_SHORTFALL => (CounterUnits::Events, CounterSource::Drain),
        coverage::HOST_BAD_EVENT
        | coverage::HOST_SHORT_EVENT
        | coverage::HOST_UNKNOWN_KIND
        | coverage::HOST_MAP_SNAPSHOT
        | coverage::HOST_EVICT_FAILED => (CounterUnits::Events, CounterSource::Discovery),
        _ => (CounterUnits::Events, CounterSource::Discovery),
    };
    typed_counter(
        &format!("discovery.{name}"),
        CounterKind::Loss,
        units,
        origin,
        count,
    )
}

/// Verified object identity for one mapped backing: the file's
/// build-id when its bytes yield one, else an opaque unverified id
/// (D3). `fallback` covers objects whose mapping is already gone
/// (their display locator survives as a hint, never as identity).
fn object_id_for_mapping(
    dev: &str,
    ino: u64,
    live: &[maps::Mapping],
    files: &HashMap<String, Vec<u8>>,
    fallback: Option<&str>,
) -> ObjectId {
    let locator = live
        .iter()
        .find(|m| m.dev == dev && m.ino == ino)
        .map(|m| m.path.as_str())
        .or(fallback);
    let bid = locator
        .and_then(|p| files.get(p))
        .and_then(|b| elf::read_build_id(b));
    match bid {
        Some(id) => ObjectId(format!("build:{id}")),
        None => ObjectId(format!("unverified:{dev}:{ino}")),
    }
}

/// Advertising provider object id (D3): fingerprinted from the
/// array owner's mapped bytes when available, else opaque.
fn advertising_object_id(
    advertising: &str,
    live: &[maps::Mapping],
    files: &HashMap<String, Vec<u8>>,
) -> ObjectId {
    if advertising.is_empty() {
        return ObjectId("unverified-advertising:anonymous".to_string());
    }
    let owner = live.iter().find(|m| m.path == advertising);
    let bid = owner
        .and_then(|_| files.get(advertising))
        .and_then(|b| elf::read_build_id(b));
    match bid {
        Some(id) => ObjectId(format!("build:{id}")),
        // Mapping-bound opaque identity (D3): while the path still
        // resolves, the id binds the mapping's (dev, ino) — a
        // same-path replacement changes identity instead of
        // conflating two objects, and an unresolvable path degrades
        // to anonymous. The pathname itself never becomes identity.
        None => match owner {
            Some(m) => ObjectId(format!("unverified-advertising:{}:{}", m.dev, m.ino)),
            None => ObjectId("unverified-advertising:anonymous".to_string()),
        },
    }
}

/// Provider class synthesis (D3): builtin mode observes the
/// in-libcrypto provider by operator assertion and OpenSSL
/// architecture (not a filename guess); file-provider mode stays
/// `unknown` until T09 pinned classification lands.
fn synthesize_provider_class(builtin_default: bool) -> String {
    if builtin_default {
        "default".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Legacy display partitioning: classes of candidates advertised
/// from a legacy-shaped locator. A DISPLAY hint only (R02 permits
/// filenames as locator/display hints) — never provider-class
/// authority, which stays `unknown` above.
fn is_legacy_locator(locator: &str) -> bool {
    let stem = Path::new(locator)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let stem = stem.strip_suffix(".so").unwrap_or(stem);
    stem == "legacy"
}

/// Per-op table view: termination proof plus retirement dirt. Only
/// the live epoch's proof counts; a retired epoch's completion never
/// carries over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpTable {
    epoch: u64,
    terminated: bool,
    /// Poll sequence when termination was first observed (a new
    /// candidate in a LATER poll proves the set non-closed).
    term_poll: Option<u64>,
    /// Retired without new-epoch proof yet.
    dirty: bool,
}

/// Adapter accumulation state (D1): full per-site candidate sets,
/// per-op backing census, table views, objects and loss sums.
#[derive(Debug, Default)]
pub struct AdapterState {
    poll_seq: u64,
    emitted: HashMap<(u64, u64, u64), DiscoveredSite>,
    triple_ops: HashMap<(u64, u64, u64), HashSet<u32>>,
    op_triples: HashMap<u32, HashSet<(u64, u64, u64)>>,
    op_tables: HashMap<u32, OpTable>,
    legacy_classes: BTreeSet<String>,
    objects: Vec<ObjectRecord>,
    seen_objects: HashSet<(String, u64)>,
    loss_sums: HashMap<u32, u64>,
    queries_observed: u64,
}

impl AdapterState {
    /// Distinct backing triples seen per op (coverage census).
    pub fn op_discovered(&self, op: u32) -> u64 {
        self.op_triples
            .get(&op)
            .map(|s| s.len() as u64)
            .unwrap_or(0)
    }

    /// Ops touched so far, sorted.
    pub fn ops(&self) -> Vec<u32> {
        let mut ops: Vec<u32> = self
            .op_triples
            .keys()
            .chain(self.op_tables.keys())
            .copied()
            .collect();
        ops.sort_unstable();
        ops.dedup();
        ops
    }
}

/// Per-poll adapter context: the live planning inputs plus the
/// round's classification inputs.
pub struct AdapterCtx<'a> {
    pub live: &'a [maps::Mapping],
    pub files: &'a HashMap<String, Vec<u8>>,
    pub builtin_default: bool,
    /// Backings first seen this round (fresh dlopen vs long-present).
    pub fresh: &'a HashSet<(String, u64)>,
    /// Past the settle grace: newly emitted long-present sites are
    /// late-attach loss (the settle phase is the accepted
    /// query→attach residual, documented like the drain residual).
    pub post_settle: bool,
    /// Baselining poll: tripwire news is pre-window and dropped;
    /// queries are pre-window (cold gap), never in-window arrivals.
    pub baseline: bool,
}

/// One adapted poll: the count delta plus auxiliary evidence.
pub struct AdaptedDelta {
    pub delta: CountDelta,
    pub activity: Vec<GapCounter>,
    pub objects: Vec<ObjectRecord>,
    pub pre_window_queries: u64,
    /// In-window tripwire news (`None` on the baselining poll).
    pub tripwire: Option<TripwireDelta>,
    pub trigger_observed: bool,
}

/// Adapt one discovery delta (D1–D4).
pub fn adapt_delta(
    state: &mut AdapterState,
    delta: &DiscoveryDelta,
    ctx: &AdapterCtx,
) -> AdaptedDelta {
    state.poll_seq += 1;
    let seq = state.poll_seq;
    let mut count_losses = Vec::new();
    let mut activity = Vec::new();

    // D4: every discovery loss stays Loss, forwarded exactly once.
    for loss in &delta.losses {
        if loss.count == 0 {
            continue;
        }
        let sum = state.loss_sums.entry(loss.source).or_default();
        *sum = sum.saturating_add(loss.count);
        count_losses.push(classify_loss(loss.source, loss.count));
    }

    // D2 tables: track the live epoch's proof; a rebirth resets it.
    for table in &delta.tables {
        let entry = state.op_tables.entry(table.op).or_insert(OpTable {
            epoch: table.epoch,
            terminated: false,
            term_poll: None,
            dirty: false,
        });
        if entry.epoch != table.epoch {
            *entry = OpTable {
                epoch: table.epoch,
                terminated: false,
                term_poll: None,
                dirty: false,
            };
        }
        if matches!(table.state, CoverageState::Terminated { .. }) {
            entry.terminated = true;
            entry.dirty = false;
            if entry.term_poll.is_none() {
                entry.term_poll = Some(seq);
            }
        } else {
            entry.terminated = false;
        }
    }

    // D2 retirements: the epoch's completion drops (rows survive);
    // affected emitted sites re-emit as Unknown until the new epoch
    // proves. Retirement gap losses are NOT re-counted (D2).
    let mut touched: HashMap<(u64, u64, u64), DiscoveredSite> = HashMap::new();
    for retirement in &delta.retirements {
        activity.push(typed_counter(
            "discovery.table_retired",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            1,
        ));
        let entry = state.op_tables.entry(retirement.op).or_insert(OpTable {
            epoch: 0,
            terminated: false,
            term_poll: None,
            dirty: true,
        });
        entry.terminated = false;
        entry.dirty = true;
        if let Some(triples) = state.op_triples.get(&retirement.op).cloned() {
            for triple in triples {
                if let Some(site) = state.emitted.get_mut(&triple) {
                    if site.candidates_coverage != CandidateCoverage::Unknown {
                        site.candidates_coverage = CandidateCoverage::Unknown;
                    }
                    touched.insert(triple, site.clone());
                }
            }
        }
    }

    // D1/D3 candidates: group by backing triple, union with the
    // accumulated set, degrade coverage, classify late attaches.
    let provider_class = synthesize_provider_class(ctx.builtin_default);
    let mut unbacked = 0u64;
    let mut unparsed_dev = 0u64;
    let mut late_attach = 0u64;
    let mut fresh_mapped = 0u64;
    // triple → (dev string, new candidates, ops, any bad read).
    type Group = (String, Vec<CandidateIdentity>, HashSet<u32>, bool);
    let mut groups: HashMap<(u64, u64, u64), Group> = HashMap::new();
    for candidate in &delta.candidates {
        if is_legacy_locator(&candidate.advertising) {
            state.legacy_classes.insert(candidate.class.clone());
        }
        let Some(backing) = candidate.backing.as_ref() else {
            // No file mapping: unplannable (fenced, count-only at
            // render) — explicit loss, never silent.
            unbacked += 1;
            continue;
        };
        let Some(device) = plan::device_id_of_maps_dev(&backing.dev) else {
            // Unparsable device: unplannable, never device zero.
            unparsed_dev += 1;
            continue;
        };
        let triple = (device, backing.ino, backing.offset);
        state
            .op_triples
            .entry(candidate.op)
            .or_default()
            .insert(triple);
        state
            .triple_ops
            .entry(triple)
            .or_default()
            .insert(candidate.op);
        let class = if candidate.class.is_empty() {
            "other".to_string()
        } else {
            candidate.class.clone()
        };
        let identity = CandidateIdentity::new(
            advertising_object_id(&candidate.advertising, ctx.live, ctx.files),
            provider_class.clone(),
            candidate.op,
            candidate.funcid,
            vec![class],
            candidate.weak,
        );
        let bad_read = candidate.status != "ok";
        let slot = groups
            .entry(triple)
            .or_insert_with(|| (backing.dev.clone(), Vec::new(), HashSet::new(), false));
        slot.1.push(identity);
        slot.2.insert(candidate.op);
        slot.3 |= bad_read;
    }
    // Deterministic group order (arrival order must not leak).
    let mut group_keys: Vec<(u64, u64, u64)> = groups.keys().copied().collect();
    group_keys.sort_unstable();
    for triple in group_keys {
        let (dev_str, mut fresh_identities, group_ops, bad_read) =
            groups.remove(&triple).unwrap_or_default();
        let (device, ino, offset) = triple;
        let first_emit = !state.emitted.contains_key(&triple);
        // D3 coverage: degrade on bad reads, unterminated/dirty
        // tables, or a NEW arrival for an op that already terminated
        // (the set proved non-closed — arrivals for sibling ops on
        // a shared site do not taint a closed op).
        let mut unknown = bad_read;
        if let Some(ops) = state.triple_ops.get(&triple) {
            for op in ops {
                match state.op_tables.get(op) {
                    None => unknown = true,
                    Some(t) => {
                        let closed = t.terminated && !t.dirty;
                        let fresh_arrival =
                            group_ops.contains(op) && t.term_poll.is_some_and(|p| p < seq);
                        if !closed || fresh_arrival {
                            unknown = true;
                        }
                    }
                }
            }
        }
        let coverage = if unknown {
            CandidateCoverage::Unknown
        } else {
            CandidateCoverage::Complete
        };
        let site_key = SiteKey {
            object: object_id_for_mapping(&dev_str, ino, ctx.live, ctx.files, None),
            device,
            inode: ino,
            offset,
        };
        match state.emitted.get_mut(&triple) {
            Some(prior) => {
                prior.candidates.append(&mut fresh_identities);
                prior.candidates.sort();
                prior.candidates.dedup();
                if unknown {
                    prior.candidates_coverage = CandidateCoverage::Unknown;
                }
                // A conflicting fingerprint for one triple is a
                // producer contradiction: the count session fails
                // closed on it; keep the first here so the conflict
                // surfaces there instead of flapping.
                touched.insert(triple, prior.clone());
            }
            None => {
                fresh_identities.sort();
                fresh_identities.dedup();
                let site = DiscoveredSite {
                    site: site_key,
                    candidates: fresh_identities,
                    candidates_coverage: coverage,
                };
                state.emitted.insert(triple, site.clone());
                touched.insert(triple, site);
            }
        }
        // Late-attach classification for first emits past settle.
        if first_emit && ctx.post_settle {
            if ctx.fresh.contains(&(dev_str, ino)) {
                fresh_mapped += 1;
            } else {
                late_attach += 1;
            }
        }
    }
    if unbacked > 0 {
        count_losses.push(typed_counter(
            "discovery.unbacked_candidate",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            unbacked,
        ));
    }
    if unparsed_dev > 0 {
        count_losses.push(typed_counter(
            "discovery.unparsed_device",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            unparsed_dev,
        ));
    }
    if late_attach > 0 {
        count_losses.push(typed_counter(
            "discovery.late_attach_sites",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            late_attach,
        ));
    }
    if fresh_mapped > 0 {
        activity.push(typed_counter(
            "discovery.new_mapping_sites",
            CounterKind::Activity,
            CounterUnits::Sites,
            CounterSource::Discovery,
            fresh_mapped,
        ));
    }

    // D2 objects: fingerprinted records; unparsable devices skip loud.
    let mut objects = Vec::new();
    let mut unparsed_object_dev = 0u64;
    for object in &delta.objects {
        let Some(device) = plan::device_id_of_maps_dev(&object.dev) else {
            unparsed_object_dev += 1;
            continue;
        };
        if !state.seen_objects.insert((object.dev.clone(), object.ino)) {
            continue;
        }
        let record = ObjectRecord {
            id: object_id_for_mapping(
                &object.dev,
                object.ino,
                ctx.live,
                ctx.files,
                Some(&object.display_locator),
            ),
            device,
            inode: object.ino,
            display_locator: object.display_locator.clone(),
        };
        state.objects.push(record.clone());
        objects.push(record);
    }
    if unparsed_object_dev > 0 {
        count_losses.push(typed_counter(
            "discovery.unparsed_object_dev",
            CounterKind::Loss,
            CounterUnits::Events,
            CounterSource::Discovery,
            unparsed_object_dev,
        ));
    }

    // D2 auxiliary fields.
    if delta.events_consumed > 0 {
        activity.push(typed_counter(
            "discovery.events_consumed",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            delta.events_consumed,
        ));
    }
    let mut pre_window_queries = 0u64;
    if delta.queries_delta > 0 {
        state.queries_observed = state.queries_observed.saturating_add(delta.queries_delta);
        if ctx.baseline {
            pre_window_queries = delta.queries_delta;
        } else {
            activity.push(typed_counter(
                "discovery.queries_observed",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Discovery,
                delta.queries_delta,
            ));
        }
    }
    let mut attaches_ok = 0u64;
    let mut attaches_failed = 0u64;
    for attach in &delta.attaches {
        if attach.failed.is_some() {
            attaches_failed += 1;
        } else {
            attaches_ok += 1;
        }
    }
    if attaches_ok > 0 {
        activity.push(typed_counter(
            "discovery.attaches",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            attaches_ok,
        ));
    }
    if attaches_failed > 0 {
        count_losses.push(typed_counter(
            "discovery.attach_failed",
            CounterKind::Loss,
            CounterUnits::Probes,
            CounterSource::Discovery,
            attaches_failed,
        ));
    }
    if delta.budget_exhausted {
        activity.push(typed_counter(
            "discovery.budget_exhausted",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            1,
        ));
    }

    let mut discovered: Vec<DiscoveredSite> = touched.into_values().collect();
    discovered.sort_by(|a, b| a.site.cmp(&b.site));
    AdaptedDelta {
        delta: CountDelta {
            discovered,
            losses: count_losses,
        },
        activity,
        objects,
        pre_window_queries,
        tripwire: if ctx.baseline {
            None
        } else {
            Some(delta.tripwire.clone())
        },
        trigger_observed: delta.trigger_observed,
    }
}

// ---------------------------------------------------------------- controller

/// Sessions held for the complete observation (moved into
/// [`observe`], which owns setup, the poll loop and teardown).
pub struct SessionSet<D, B: CountBackend, T, L> {
    pub discovery: D,
    pub count: CountSession<B>,
    pub target: T,
    pub lifecycle: L,
}

/// Safe target identity snapshotted at acquisition (before exit).
#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub pid: u32,
    pub owned: bool,
    pub comm: String,
    pub cmdline: String,
    pub container_id: String,
    pub kernel_release: String,
    pub provider_build_id: String,
    pub provider_path: String,
    pub image_digest: String,
    /// Monotonic nanoseconds at acquisition (requested start for
    /// `--pid`; `run` re-stamps at release).
    pub acquired_ns: u64,
    pub acquired_instant: Instant,
    pub acquired_wall: SystemTime,
}

/// One poll round's control outcome.
enum RoundAction {
    Continue,
    Expired,
    Closed,
    Recycled,
}

/// The session-driven observation: owns both sessions, target
/// custody, lifecycle, accumulation and finalization for one
/// requested window.
struct Runner<'x, D, B: CountBackend, T, L, C: ClockPort, P: ProcPort> {
    cfg: &'x Config,
    info: &'x TargetInfo,
    discovery: D,
    count: CountSession<B>,
    target: T,
    lifecycle: L,
    clock: &'x C,
    proc: &'x mut P,
    cancelled: &'x dyn Fn() -> bool,
    reasons: HashSet<String>,
    adapter: AdapterState,
    activity: Vec<GapCounter>,
    extra_loss: Vec<GapCounter>,
    in_window_trip: HashMap<u64, u64>,
    in_window_hits: Vec<legacy::TripHit>,
    in_window_lgcalls: u64,
    trigger_observed: bool,
    attached_total: u64,
    cold_gap_queries: u64,
    fork_exec_ignored: u64,
    lifecycle_loss: u64,
    maps_read_failed: u64,
    scan_budget_exhaustions: u64,
    provider_changed_fences: u64,
    planned_paths: HashSet<String>,
    site_cookies: HashMap<SiteKey, u32>,
    seen_backings: HashSet<(String, u64)>,
    snapshot: Snapshot,
    last_live: Vec<maps::Mapping>,
    child_exit: Option<i32>,
    signal_cut: bool,
    expired: bool,
    fallback_partial: bool,
    window_start_ns: u64,
    requested_start_ns: u64,
    open_instant: Instant,
    open_wall: SystemTime,
    drain_wall_us: u64,
}

impl<D, B, T, L, C, P> Runner<'_, D, B, T, L, C, P>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    fn reason(&mut self, r: &str) {
        self.reasons.insert(r.to_string());
    }

    /// Pre-read every distinct mapped path once per round. Failures
    /// skip (the planner misses those rows loud as unreadable).
    fn read_round_files(&mut self, live: &[maps::Mapping]) -> HashMap<String, Vec<u8>> {
        let mut paths: Vec<&str> = live.iter().map(|m| m.path.as_str()).collect();
        paths.sort_unstable();
        paths.dedup();
        let mut out = HashMap::new();
        for p in paths {
            if let Ok(bytes) = self.proc.read_file(p) {
                out.insert(p.to_string(), bytes);
            }
        }
        out
    }

    /// Poll discovery once, adapt, attach, and accumulate. Returns
    /// (budget_exhausted, candidates_changed).
    fn poll_and_apply(
        &mut self,
        live: &[maps::Mapping],
        files: &HashMap<String, Vec<u8>>,
        fresh: &HashSet<(String, u64)>,
        post_settle: bool,
        baseline: bool,
    ) -> anyhow::Result<(bool, bool)> {
        let builtin = self.cfg.builtin;
        let delta = self.discovery.poll(PollBudget::default())?;
        let exhausted = delta.budget_exhausted;
        let adapted = adapt_delta(
            &mut self.adapter,
            &delta,
            &AdapterCtx {
                live,
                files,
                builtin_default: builtin,
                fresh,
                post_settle,
                baseline,
            },
        );
        self.activity.extend(adapted.activity);
        self.cold_gap_queries = self
            .cold_gap_queries
            .saturating_add(adapted.pre_window_queries);
        if let Some(trip) = adapted.tripwire {
            for (cookie, n) in trip.counter_deltas {
                let slot = self.in_window_trip.entry(cookie).or_default();
                *slot = slot.saturating_add(n);
            }
            self.in_window_hits.extend(trip.hits.iter());
            self.in_window_lgcalls = self
                .in_window_lgcalls
                .saturating_add(trip.executed_legacy_queries_delta);
        }
        self.trigger_observed |= adapted.trigger_observed;
        let report = self.count.attach_delta(&adapted.delta, live, files)?;
        self.attached_total = self.attached_total.saturating_add(report.attached);
        for site in &adapted.delta.discovered {
            if let Some(cookie) =
                self.count
                    .cookie_for(site.site.device, site.site.inode, site.site.offset)
            {
                self.site_cookies.insert(site.site.clone(), cookie);
                if let Some(prov) = self.count.provenance(cookie) {
                    if !prov.link_path.is_empty() {
                        self.planned_paths.insert(prov.link_path.clone());
                    }
                }
            }
        }
        Ok((exhausted, report.candidates_changed))
    }

    /// One bounded poll round: maps, corpse check, fence compare,
    /// lifecycle sweep, discovery catch-up polls, single fence.
    fn round(&mut self, deadline: Instant, settle_end: Instant) -> anyhow::Result<RoundAction> {
        let pid = self.info.pid;
        let owned = self.info.owned;
        let t0 = self.clock.now();
        let live = match self.proc.read_maps(pid) {
            Ok(live) => live,
            Err(_) => {
                // Target gone, or /proc flakiness: custody decides.
                if owned {
                    if let Ok(Some(code)) = self.target.poll_exit() {
                        self.child_exit = Some(code);
                        return Ok(RoundAction::Closed);
                    }
                } else if self.target.verify().is_err() {
                    return Ok(RoundAction::Recycled);
                }
                self.maps_read_failed += 1;
                return Ok(RoundAction::Continue);
            }
        };
        if self.clock.now().saturating_duration_since(t0) > POLL_BUDGET {
            // Overruns skip the round (§5): the deadline still binds.
            self.scan_budget_exhaustions += 1;
            return Ok(RoundAction::Continue);
        }
        if self.clock.now() >= deadline {
            // Metadata I/O ran past the deadline: no post-deadline
            // discovery poll (its tripwire would pollute in-window
            // evidence) — the loop closes instead.
            return Ok(RoundAction::Expired);
        }
        // Post-read liveness: close corpses, never fence them.
        if live.is_empty() && owned {
            if let Ok(Some(code)) = self.target.poll_exit() {
                self.child_exit = Some(code);
                return Ok(RoundAction::Closed);
            }
            if let Some(code) = reap_corpse(true, true, pid) {
                self.child_exit = Some(code);
                return Ok(RoundAction::Closed);
            }
        }
        let mut fresh = HashSet::new();
        for m in &live {
            if self.seen_backings.insert((m.dev.clone(), m.ino)) {
                fresh.insert((m.dev.clone(), m.ino));
            }
        }
        let files = self.read_round_files(&live);
        let exe = self.proc.read_exe(pid);
        let mut sizes = HashMap::new();
        for p in &self.planned_paths {
            sizes.insert(p.clone(), self.proc.file_len(p));
        }
        let planned: Vec<String> = self.planned_paths.iter().cloned().collect();
        let next = snapshot(exe, &live, &planned, &sizes);
        let kinds = detect_fence(&self.snapshot, &next);
        self.snapshot = next;
        self.last_live = live.clone();
        // Fork/exec detection: every NEW child counted once.
        let sweep = self.lifecycle.poll();
        self.fork_exec_ignored = self
            .fork_exec_ignored
            .saturating_add(sweep.events.len() as u64);
        self.lifecycle_loss = self.lifecycle_loss.saturating_add(sweep.loss);
        // Slow metadata work above (file reads, fence snapshots,
        // lifecycle scan) may have crossed the deadline — or a
        // signal may have landed — since the pre-read check: no
        // post-deadline discovery poll (its tripwire would pollute
        // in-window evidence). The loop owns the signal cut.
        if (self.cancelled)() {
            return Ok(RoundAction::Continue);
        }
        if self.clock.now() >= deadline {
            return Ok(RoundAction::Expired);
        }
        // Discovery catch-up: backpressure re-polls, bounded, with
        // the deadline enforced even while discovery is busy.
        let post_settle = self.clock.now() >= settle_end;
        let mut fence_candidates = false;
        let mut catches = 0u32;
        loop {
            let (exhausted, fence) =
                self.poll_and_apply(&live, &files, &fresh, post_settle, false)?;
            fence_candidates |= fence;
            if !exhausted {
                break;
            }
            catches += 1;
            if catches >= MAX_CATCHUP_POLLS {
                self.scan_budget_exhaustions += 1;
                break;
            }
            if (self.cancelled)() || self.clock.now() >= deadline {
                break;
            }
        }
        // One fence per round (Exec > ProviderChanged >
        // MappingsChanged > CandidatesChanged).
        let fence_reason = if kinds.contains(&FenceKind::Exec) {
            Some(CountFence::Exec)
        } else if kinds.contains(&FenceKind::ProviderChanged) {
            Some(CountFence::ProviderChanged)
        } else if kinds.contains(&FenceKind::MappingsChanged) {
            Some(CountFence::MappingsChanged)
        } else if fence_candidates {
            Some(CountFence::CandidatesChanged)
        } else {
            None
        };
        if let Some(reason) = fence_reason {
            self.count.fence(reason)?;
        }
        if kinds.contains(&FenceKind::ProviderChanged) {
            self.provider_changed_fences += 1;
        }
        Ok(RoundAction::Continue)
    }

    /// Mid-window infrastructure failure: best-effort close (count
    /// first, then discovery), custody resolved, original error kept.
    fn fail(mut self, err: anyhow::Error) -> anyhow::Result<Capture> {
        let _ = self.count.close_and_drain(self.cfg.grace);
        let _ = self.discovery.finish();
        let _ = self.target.finish_observation();
        Err(err)
    }

    /// Setup-phase result with no window opened (fast exit, setup
    /// cut): the whole requested window is startup gap, the exit
    /// status rides along, and nothing claims COMPLETE.
    fn no_window_result(mut self) -> Capture {
        let requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        let window = CaptureWindow {
            requested_start_ns: self.requested_start_ns,
            requested_end_ns: requested_end,
            effective_start_ns: requested_end,
            effective_end_ns: requested_end,
            signal_cut: self.signal_cut,
        };
        let document = evidence::finalize(FinalizeInput {
            window,
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
        });
        self.emit_gap_reasons(document.reasons());
        if !self.trigger_observed {
            self.reason("no-query");
        }
        if self.signal_cut {
            self.reason("interrupted");
        }
        if !self.info.owned {
            self.reason("pid-prewindow-blind");
        }
        let disposition = self
            .child_exit
            .map(|code| target::TargetDisposition::Exited { code });
        self.finish_capture(
            document,
            FinishParts {
                outcome: Outcome::Partial,
                executions: Vec::new(),
                stale: Vec::new(),
                counters: Counters::default(),
                legacy: serde_json::Value::Null,
                harvest_doc: serde_json::json!({}),
                disposition,
                window_actual: Duration::ZERO,
            },
        )
    }

    /// Mid-window recycle: best-effort close, every observation
    /// discarded (pid-scoped evidence is tainted), fatal verdict.
    fn recycled(mut self) -> Capture {
        let _ = self.count.close_and_drain(self.cfg.grace);
        let _ = self.discovery.finish();
        let requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        let now_ns = self.clock.monotonic_ns();
        let document = evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: self.requested_start_ns,
                requested_end_ns: requested_end,
                effective_start_ns: self.window_start_ns,
                effective_end_ns: now_ns.min(requested_end),
                signal_cut: false,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: Some(evidence::FatalKind::Recycled),
        });
        self.reasons.clear();
        self.reason("pid-recycled");
        let window_actual = self
            .clock
            .now()
            .saturating_duration_since(self.open_instant);
        self.finish_capture(
            document,
            FinishParts {
                outcome: Outcome::Fatal(FatalKind::Recycled),
                executions: Vec::new(),
                stale: Vec::new(),
                counters: Counters::default(),
                legacy: serde_json::Value::Null,
                harvest_doc: serde_json::json!({}),
                disposition: None,
                window_actual,
            },
        )
    }
}

/// Saturating `Duration` → nanoseconds (config bounds keep this far
/// below overflow; saturation fails closed, never wraps).
fn duration_ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Run one requested observation over already-attached sessions.
/// Setup (open → baseline poll → release), the poll loop, teardown
/// (counting closes before the final discovery drain) and
/// finalization (status after counters) all live here; `run` wires
/// the live sessions around it.
pub fn observe<D, B, T, L, C, P>(
    cfg: &Config,
    info: &TargetInfo,
    sessions: SessionSet<D, B, T, L>,
    clock: &C,
    proc: &mut P,
    cancelled: &dyn Fn() -> bool,
) -> anyhow::Result<Capture>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    let SessionSet {
        discovery,
        mut count,
        mut target,
        lifecycle,
    } = sessions;
    if cfg.duration.is_zero() {
        let _ = target.resolve_setup_failure();
        anyhow::bail!("--duration must be > 0");
    }
    // Open the kernel window BEFORE release: probes arm while the
    // child is still stopped, so the happy-path startup gap is zero
    // (release instant ≥ programmed start saturates the gap).
    let start_ns = clock.monotonic_ns();
    let duration = duration_ns(cfg.duration);
    let Some(deadline_ns) = start_ns.checked_add(duration) else {
        let _ = target.resolve_setup_failure();
        anyhow::bail!("window deadline overflow");
    };
    if start_ns >= deadline_ns {
        let _ = target.resolve_setup_failure();
        anyhow::bail!("empty count window");
    }
    if let Err(e) = count.open_window(start_ns, deadline_ns) {
        let _ = count.close_and_drain(cfg.grace);
        let _ = target.resolve_setup_failure();
        return Err(e.context("count open_window"));
    }
    let mut runner = Runner {
        cfg,
        info,
        discovery,
        count,
        target,
        lifecycle,
        clock,
        proc,
        cancelled,
        reasons: HashSet::new(),
        adapter: AdapterState::default(),
        activity: Vec::new(),
        extra_loss: Vec::new(),
        in_window_trip: HashMap::new(),
        in_window_hits: Vec::new(),
        in_window_lgcalls: 0,
        trigger_observed: false,
        attached_total: 0,
        cold_gap_queries: 0,
        fork_exec_ignored: 0,
        lifecycle_loss: 0,
        maps_read_failed: 0,
        scan_budget_exhaustions: 0,
        provider_changed_fences: 0,
        planned_paths: HashSet::new(),
        site_cookies: HashMap::new(),
        seen_backings: HashSet::new(),
        snapshot: Snapshot::default(),
        last_live: Vec::new(),
        child_exit: None,
        signal_cut: false,
        expired: false,
        fallback_partial: false,
        window_start_ns: start_ns,
        requested_start_ns: start_ns,
        open_instant: clock.now(),
        open_wall: clock.wall_now(),
        drain_wall_us: 0,
    };
    runner.fallback_partial = runner.lifecycle.fallback_partial();
    runner.setup_and_run()
}

impl<D, B, T, L, C, P> Runner<'_, D, B, T, L, C, P>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    fn setup_and_run(mut self) -> anyhow::Result<Capture> {
        let pid = self.info.pid;
        let owned = self.info.owned;
        let setup_deadline = args::deadline_at(self.clock.now(), self.cfg.harvest_timeout);
        // Baseline poll: seed maps/snapshot, attach the first delta,
        // and baseline tripwire counters at the declared window
        // boundary (pre-window tripwire/query news never becomes
        // in-window evidence).
        let live = match self.proc.read_maps(pid) {
            Ok(live) => live,
            Err(e) => {
                if !owned && self.target.verify().is_err() {
                    return Ok(self.recycled());
                }
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("setup maps read"));
            }
        };
        for m in &live {
            self.seen_backings.insert((m.dev.clone(), m.ino));
        }
        let files = self.read_round_files(&live);
        let exe = self.proc.read_exe(pid);
        self.snapshot = snapshot(exe, &live, &[], &HashMap::new());
        self.last_live = live.clone();
        let fresh = HashSet::new();
        match self.poll_and_apply(&live, &files, &fresh, false, true) {
            Ok((_, fence_candidates)) => {
                if fence_candidates {
                    if let Err(e) = self.count.fence(CountFence::CandidatesChanged) {
                        let _ = self.count.close_and_drain(self.cfg.grace);
                        let _ = self.target.resolve_setup_failure();
                        return Err(e.context("setup fence"));
                    }
                }
            }
            Err(e) => {
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("setup discovery poll"));
            }
        }
        if (self.cancelled)() {
            self.signal_cut = true;
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            self.requested_start_ns = self.clock.monotonic_ns();
            return Ok(self.no_window_result());
        }
        if setup_deadline.is_some_and(|d| self.clock.now() >= d) {
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            anyhow::bail!("setup timeout");
        }
        // Release (owned): the requested window begins here.
        if owned {
            if let Err(e) = self.target.release() {
                // A child that died before release keeps its exit
                // status (never-released custody resolves around the
                // preserved code, never by killing).
                if let Ok(Some(code)) = self.target.poll_exit() {
                    self.child_exit = Some(code);
                    let _ = self.count.close_and_drain(self.cfg.grace);
                    let _ = self.target.resolve_setup_failure();
                    self.requested_start_ns = self.clock.monotonic_ns();
                    return Ok(self.no_window_result());
                }
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("release"));
            }
            self.requested_start_ns = self.clock.monotonic_ns();
            self.open_instant = self.clock.now();
        } else {
            self.requested_start_ns = self.info.acquired_ns;
        }
        let requested_instant = if owned {
            self.open_instant
        } else {
            self.info.acquired_instant
        };
        let Some(loop_deadline) = args::deadline_at(requested_instant, self.cfg.duration) else {
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            anyhow::bail!("window deadline overflow");
        };
        let settle_end =
            args::deadline_at(requested_instant, self.cfg.settle).unwrap_or(loop_deadline);

        // Poll loop: expiry / signal / death / fence.
        loop {
            let now = self.clock.now();
            if now >= loop_deadline {
                self.expired = true;
                break;
            }
            if (self.cancelled)() {
                self.signal_cut = true;
                break;
            }
            if owned {
                match self.target.poll_exit() {
                    Ok(Some(code)) => {
                        self.child_exit = Some(code);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return self.fail(e.context("poll_exit")),
                }
            } else if self.target.verify().is_err() {
                return Ok(self.recycled());
            }
            let wait = POLL_INTERVAL.min(loop_deadline.saturating_duration_since(now));
            if !wait.is_zero() {
                self.clock.sleep(wait);
            }
            // Post-sleep liveness: a child that died during the
            // sleep closes the window, never fences on its corpse.
            if owned {
                match self.target.poll_exit() {
                    Ok(Some(code)) => {
                        self.child_exit = Some(code);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return self.fail(e.context("poll_exit")),
                }
            } else if self.target.verify().is_err() {
                return Ok(self.recycled());
            }
            match self.round(loop_deadline, settle_end) {
                Ok(RoundAction::Continue) => {}
                Ok(RoundAction::Expired) => {
                    self.expired = true;
                    break;
                }
                Ok(RoundAction::Closed) => break,
                Ok(RoundAction::Recycled) => return Ok(self.recycled()),
                Err(e) => return self.fail(e),
            }
        }
        self.close_and_finalize()
    }

    fn close_and_finalize(mut self) -> anyhow::Result<Capture> {
        // Over-budget: the window expired while the target lived. A
        // spawn reaped here died in the last poll slice — its full
        // lifetime was observed, so it is NOT over-budget.
        if self.expired {
            let alive = if self.info.owned {
                match self.target.poll_exit() {
                    Ok(Some(code)) => {
                        self.child_exit = Some(code);
                        false
                    }
                    _ => true,
                }
            } else {
                self.target.verify().is_ok()
            };
            if alive {
                self.extra_loss.push(typed_counter(
                    "capture.over_budget",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Lifecycle,
                    1,
                ));
            }
        }
        // One last lifecycle sweep at window end.
        let sweep = self.lifecycle.poll();
        self.fork_exec_ignored = self
            .fork_exec_ignored
            .saturating_add(sweep.events.len() as u64);
        self.lifecycle_loss = self.lifecycle_loss.saturating_add(sweep.loss);
        // TEST HOOK (exit-3 kernel-proof): hold the final drain past
        // close so a still-counting kernel would advance last_ns
        // beyond the window edge. Production behavior unchanged when
        // unset.
        if let Ok(ms) = std::env::var("OSSLSCOPE_DRAIN_DELAY_MS") {
            if let Ok(ms) = ms.parse::<u64>() {
                self.clock.sleep(Duration::from_millis(ms));
            }
        }
        // Counting closes BEFORE the final discovery drain
        // (in-kernel TARGET=0 inside: no userspace delay can extend
        // counting past this point).
        let drain_t0 = self.clock.now();
        let drain = match self.count.close_and_drain(self.cfg.grace) {
            Ok(drain) => drain,
            Err(e) => {
                let _ = self.discovery.finish();
                let _ = self.target.finish_observation();
                return Err(e.context("close_and_drain"));
            }
        };
        self.drain_wall_us = self
            .clock
            .now()
            .checked_duration_since(drain_t0)
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let effective_end_ns = self.clock.monotonic_ns();
        let snapshot = match self.discovery.finish() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                let _ = self.target.finish_observation();
                return Err(e.context("discovery finish"));
            }
        };
        let disposition = self
            .target
            .finish_observation()
            .context("finish_observation")?;
        if let target::TargetDisposition::Exited { code } = disposition {
            self.child_exit = Some(code);
        }
        Ok(self.assemble(snapshot, drain, disposition, effective_end_ns))
    }

    /// Sites of one op with live probes (coverage attach census).
    fn op_attached(&self, op: u32) -> u64 {
        let mut attached = 0u64;
        if let Some(triples) = self.adapter.op_triples.get(&op) {
            for triple in triples {
                if let Some(cookie) = self.count.cookie_for(triple.0, triple.1, triple.2) {
                    if self
                        .count
                        .provenance(cookie)
                        .is_some_and(|p| !p.link_path.is_empty())
                    {
                        attached += 1;
                    }
                }
            }
        }
        attached
    }

    /// Finalize status AFTER counters: merge every loss/activity
    /// source, reconcile close residuals once, build coverage, and
    /// finalize through the sole finalizer.
    fn assemble(
        mut self,
        snapshot: DiscoverySnapshot,
        drain: CountDrain,
        disposition: target::TargetDisposition,
        effective_end_ns: u64,
    ) -> Capture {
        if self.cold_gap_queries > 0 {
            self.extra_loss.push(typed_counter(
                "discovery.pre_window_queries",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                self.cold_gap_queries,
            ));
        }
        if self.fork_exec_ignored > 0 {
            self.extra_loss.push(typed_counter(
                "lifecycle.fork_exec_ignored",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.fork_exec_ignored,
            ));
        }
        if self.lifecycle_loss > 0 {
            self.extra_loss.push(typed_counter(
                "lifecycle.scan_loss",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_loss,
            ));
        }
        if self.fallback_partial {
            self.extra_loss.push(typed_counter(
                "lifecycle.polling_fallback",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                1,
            ));
        }
        if self.maps_read_failed > 0 {
            self.extra_loss.push(typed_counter(
                "discovery.maps_read_failed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                self.maps_read_failed,
            ));
        }
        // Close reconcile (D2/D4): increments rode the deltas; only
        // the close-tail residual lands here, exactly once.
        for (source, total) in &snapshot.losses {
            let adapted = self.adapter.loss_sums.get(source).copied().unwrap_or(0);
            if let Some(residual) = total.checked_sub(adapted) {
                if residual > 0 {
                    self.extra_loss.push(classify_loss(*source, residual));
                }
            }
        }
        if snapshot.lossy_slots > 0 {
            self.extra_loss.push(typed_counter(
                "discovery.lossy_slots",
                CounterKind::Loss,
                CounterUnits::TableRows,
                CounterSource::Discovery,
                snapshot.lossy_slots,
            ));
        }
        if !snapshot.truncated_ops.is_empty() {
            self.extra_loss.push(typed_counter(
                "discovery.truncated_walk",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                snapshot.truncated_ops.len() as u64,
            ));
        }
        if !snapshot.dispatch.attach_failures.is_empty() {
            self.extra_loss.push(typed_counter(
                "discovery.unresolved_stage2",
                CounterKind::Loss,
                CounterUnits::Probes,
                CounterSource::Discovery,
                snapshot.dispatch.attach_failures.len() as u64,
            ));
        }
        // Retained epoch gaps stay PARTIAL even when every live table
        // terminates (rows survive; completion does not).
        for reason in &snapshot.retained_reasons {
            self.extra_loss.push(typed_counter(
                &format!("discovery.retained_{}", reason.replace('-', "_")),
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                1,
            ));
        }
        let reloads = snapshot
            .dispatch
            .reloads
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        if reloads > 0 {
            self.activity.push(typed_counter(
                "discovery.provider_reloads",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Discovery,
                reloads,
            ));
        }
        if let Some(tail) = snapshot
            .queries_observed
            .checked_sub(self.adapter.queries_observed)
        {
            if tail > 0 {
                // Post-count-close arrivals: activity, never cold gap.
                self.activity.push(typed_counter(
                    "discovery.queries_observed",
                    CounterKind::Activity,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    tail,
                ));
            }
        }
        let (engine_un, meth_un, low_un) = snapshot
            .legacy
            .set
            .as_ref()
            .map(|set| {
                (
                    set.engine_uninstrumented,
                    set.meth_uninstrumented,
                    set.lowlevel_uninstrumented,
                )
            })
            .unwrap_or((0, 0, 0));
        if engine_un > 0 {
            self.extra_loss.push(typed_counter(
                "legacy.engine_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                engine_un,
            ));
        }
        if meth_un > 0 {
            self.extra_loss.push(typed_counter(
                "legacy.meth_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                meth_un,
            ));
        }
        if low_un > 0 {
            self.extra_loss.push(typed_counter(
                "legacy.lowlevel_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                low_un,
            ));
        }

        // Coverage: per-op rows from discovery census + attach truth,
        // legacy + dispatch planes, then the sole finalizer.
        let mut snap_term: HashMap<u32, bool> = HashMap::new();
        for table in &snapshot.tables {
            snap_term.insert(
                table.op,
                matches!(table.state, CoverageState::Terminated { .. }),
            );
        }
        let mut coverage = Vec::new();
        for op in self.adapter.ops() {
            let terminated = snap_term.get(&op).copied().unwrap_or_else(|| {
                self.adapter
                    .op_tables
                    .get(&op)
                    .is_some_and(|t| t.terminated && !t.dirty)
            });
            let discovered = self.adapter.op_discovered(op);
            let attached = self.op_attached(op);
            coverage.push(ScopeCoverage {
                scope: format!("op:{op}"),
                expected: if terminated {
                    ExpectedScope::Applicable { sites: discovered }
                } else {
                    ExpectedScope::Unknown
                },
                discovered,
                attached,
            });
        }
        if let Some(set) = snapshot.legacy.set.as_ref() {
            let n = set.probes.len() as u64;
            coverage.push(ScopeCoverage {
                scope: "legacy".to_string(),
                expected: ExpectedScope::Applicable { sites: n },
                discovered: n,
                attached: n,
            });
        } else if legacy::find_libcrypto(&self.last_live).is_some() {
            coverage.push(ScopeCoverage {
                scope: "legacy".to_string(),
                expected: ExpectedScope::Unknown,
                discovered: 0,
                attached: 0,
            });
        } else {
            // No libcrypto mapping ever observed: the legacy surface
            // is not applicable (differs from unknown).
            coverage.push(ScopeCoverage {
                scope: "legacy".to_string(),
                expected: ExpectedScope::NotApplicable,
                discovered: 0,
                attached: 0,
            });
        }
        if snapshot.dispatch.attached {
            coverage.push(ScopeCoverage {
                scope: "dispatch".to_string(),
                expected: ExpectedScope::Applicable { sites: 1 },
                discovered: 1,
                attached: 1,
            });
        } else {
            coverage.push(ScopeCoverage {
                scope: "dispatch".to_string(),
                expected: ExpectedScope::Unknown,
                discovered: 0,
                attached: 0,
            });
        }

        let mut requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        if self.child_exit.is_some() {
            // Fulfilled by exit: the dead target cannot execute past
            // its death, so no tail gap accrues past the close.
            requested_end = requested_end
                .min(effective_end_ns)
                .max(self.requested_start_ns);
        }
        let fatal = if self.attached_total == 0 && !self.adapter.emitted.is_empty() {
            Some(evidence::FatalKind::AttachZero)
        } else {
            None
        };
        let mut counters = drain.counters.clone();
        counters.extend(self.activity.iter().cloned());
        counters.extend(self.extra_loss.iter().cloned());
        let document = evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: self.requested_start_ns,
                requested_end_ns: requested_end,
                effective_start_ns: self.window_start_ns,
                effective_end_ns,
                signal_cut: self.signal_cut,
            },
            sites: drain.current.clone(),
            fenced: drain.fenced.clone(),
            objects: self.adapter.objects.clone(),
            coverage,
            counters,
            fatal,
        });

        // Legacy `legacy` block from IN-WINDOW tripwire evidence only
        // (baselined at the declared boundary; the post-count-close
        // tail never becomes execution).
        let blind = legacy::blind_probe_set();
        let set = snapshot.legacy.set.as_ref().unwrap_or(&blind);
        let extra: Vec<&str> = snapshot
            .legacy
            .extra_findings
            .iter()
            .map(String::as_str)
            .collect();
        let legacy_doc = legacy::section(&legacy::SectionInputs {
            set,
            trip: &self.in_window_trip,
            trip_hits: &self.in_window_hits,
            legacy_queries: self.in_window_lgcalls,
            legacy_classes: self.adapter.legacy_classes.iter().cloned().collect(),
            extra_findings: &extra,
        });

        self.emit_gap_reasons(document.reasons());
        if !self.trigger_observed {
            self.reason("no-query");
        } else if document.sites.is_empty() && document.fenced.iter().all(|g| g.sites.is_empty()) {
            self.reason("empty-inventory");
        }
        if !self.info.owned {
            self.reason("pid-prewindow-blind");
        }
        if fips_configured(&self.cfg.provider) && document.total_calls() > 0 {
            self.reason("fips-unlabeled");
        }
        if engine_un > 0 {
            self.reason("engine-fallback-uninstrumented");
        }
        if meth_un > 0 {
            self.reason("meth-fallback-uninstrumented");
        }
        if low_un > 0 {
            self.reason("lowlevel-fallback-uninstrumented");
        }
        if snapshot.dispatch.preset_reason.is_some() {
            self.reason("harvest-anchor-unresolved");
        }

        let outcome = match &document.status {
            Completeness::Complete if self.reasons.is_empty() => Outcome::Complete,
            Completeness::Fatal { kind, .. } => Outcome::Fatal(match kind {
                evidence::FatalKind::Recycled => FatalKind::Recycled,
                evidence::FatalKind::AttachZero => FatalKind::AttachZero,
                evidence::FatalKind::Environment(msg) => FatalKind::Env(msg.clone()),
            }),
            _ => Outcome::Partial,
        };
        let mut executions = Vec::new();
        for site in &document.sites {
            if site.calls == 0 {
                continue;
            }
            let (id, aliases) = render_candidates(&site.candidates, site.site.offset);
            executions.push(Execution {
                cookie: self.cookie_for_site(site),
                id,
                aliases,
                count: site.calls,
                first_ns: site.first_ns,
                last_ns: site.last_ns,
            });
        }
        sort_executions(&mut executions);
        let mut stale = Vec::new();
        for generation in &document.fenced {
            let mut detail: Vec<StaleDetail> = Vec::new();
            for site in &generation.sites {
                if site.calls == 0 {
                    continue;
                }
                let (id, _) = render_candidates(&site.candidates, site.site.offset);
                detail.push(StaleDetail {
                    cookie: self.cookie_for_site(site),
                    id,
                    count: site.calls,
                    first_ns: site.first_ns,
                    last_ns: site.last_ns,
                });
            }
            detail.sort_by_key(|d| d.cookie);
            let events = detail.iter().map(|d| d.count).sum();
            stale.push(StaleBucket {
                generation: generation.generation,
                events,
                keys: detail.len() as u64,
                detail,
            });
        }
        let counter_value = |name: &str| {
            document
                .counters
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.value)
                .unwrap_or(0)
        };
        let mut covered: HashSet<u32> = executions.iter().map(|e| e.id.op).collect();
        for bucket in &stale {
            for row in &bucket.detail {
                covered.insert(row.id.op);
            }
        }
        let uninstrumented = kinds::OPS
            .iter()
            .filter(|op| !covered.contains(&op.id))
            .count() as u64;
        let counters = Counters {
            dropped_bpf: counter_value("count.map_insert_dropped"),
            dropped_userspace: counter_value("count.unattributed"),
            missed_attaches: counter_value("count.missed_attaches"),
            unresolved_offsets: counter_value("count.unresolved_offsets"),
            table_staleness_events: counter_value("count.stale_events"),
            cold_gap_calls: self.cold_gap_queries,
            provider_changed: self.provider_changed_fences,
            scan_budget_exhaustions: self.scan_budget_exhaustions,
            engine_fallback_uninstrumented: engine_un,
            drain_shortfall: counter_value("count.drain_shortfall"),
            uninstrumented_ops: uninstrumented,
            fork_exec_ignored: self.fork_exec_ignored,
            over_budget: counter_value("capture.over_budget"),
        };
        let status = match &outcome {
            Outcome::Complete => "COMPLETE",
            Outcome::Partial => "PARTIAL",
            Outcome::Fatal(_) => "FATAL",
        };
        let harvest_doc = serde_json::json!({
            "status": status,
            "trigger_observed": self.trigger_observed,
            "rows": [],
        });
        let window_actual = self
            .clock
            .now()
            .saturating_duration_since(self.open_instant);
        self.finish_capture(
            document,
            FinishParts {
                outcome,
                executions,
                stale,
                counters,
                legacy: legacy_doc,
                harvest_doc,
                disposition: Some(disposition),
                window_actual,
            },
        )
    }

    /// Cookie minted for a drained site (recorded at attach);
    /// defensive sentinel on miss — evidence is preserved, never
    /// dropped for a bookkeeping gap.
    fn cookie_for_site(&self, site: &SiteExecution) -> u32 {
        self.site_cookies
            .get(&site.site)
            .copied()
            .unwrap_or_else(|| {
                eprintln!("CAPTURE cookie miss for drained site (defensive sentinel)");
                u32::MAX
            })
    }

    /// Map finalized gaps onto the legacy reason vocabulary. Every
    /// arm uses an explicit literal: the taxonomy test scans these
    /// call sites, and the auditor vocabulary mirrors them.
    fn emit_gap_reasons(&mut self, gaps: &[GapReason]) {
        for gap in gaps {
            match gap {
                GapReason::UnknownDenominator { .. }
                | GapReason::UndiscoveredSites { .. }
                | GapReason::UnattachedSites { .. } => self.reason("discovery-loss"),
                GapReason::Loss { counter, .. } => self.emit_loss_reason(counter),
                GapReason::UnattributedCalls { .. } => self.reason("unattributed"),
                GapReason::StartupGap { .. } => self.reason("startup-gap"),
                GapReason::TailGap { .. } => self.reason("tail-gap"),
                GapReason::SignalCut => self.reason("interrupted"),
            }
        }
    }

    /// Map one loss counter onto the legacy reason vocabulary (same
    /// explicit-literal rule as above). Unmapped names fail closed
    /// to blind PARTIAL, never to silence.
    fn emit_loss_reason(&mut self, counter: &str) {
        match counter {
            "count.map_insert_dropped" => self.reason("dropped-events"),
            "count.unattributed" => self.reason("unattributed"),
            "count.drain_shortfall" => self.reason("drain-shortfall"),
            "count.missed_attaches" => self.reason("missed-attaches"),
            "count.unresolved_offsets" => self.reason("unresolved-offsets"),
            "capture.over_budget" => self.reason("over-budget"),
            "lifecycle.fork_exec_ignored" | "lifecycle.scan_loss" => {
                self.reason("fork-exec-ignored")
            }
            "lifecycle.polling_fallback" => self.reason("lifecycle-polling-partial"),
            "discovery.pre_window_queries" => self.reason("cold-gap"),
            "discovery.late_attach_sites" => self.reason("late-attach"),
            "legacy.engine_uninstrumented" => self.reason("engine-fallback-uninstrumented"),
            "legacy.meth_uninstrumented" => self.reason("meth-fallback-uninstrumented"),
            "legacy.lowlevel_uninstrumented" => self.reason("lowlevel-fallback-uninstrumented"),
            _ => self.reason("discovery-loss"),
        }
    }

    fn finish_capture(self, document: CaptureDocument, parts: FinishParts) -> Capture {
        let mut reasons: Vec<String> = self.reasons.into_iter().collect();
        reasons.sort();
        Capture {
            target_pid: self.info.pid,
            target_comm: self.info.comm.clone(),
            window_planned: self.cfg.duration,
            window_actual: parts.window_actual,
            outcome: parts.outcome,
            reasons,
            executions: parts.executions,
            stale: parts.stale,
            counters: parts.counters,
            child_exit: self.child_exit,
            drain_wall_us: self.drain_wall_us,
            harvest_doc: parts.harvest_doc,
            legacy: parts.legacy,
            window_start_wall: self.open_wall,
            window_end_wall: self.clock.wall_now(),
            kernel_release: self.info.kernel_release.clone(),
            target_cmdline: self.info.cmdline.clone(),
            target_container_id: self.info.container_id.clone(),
            provider_build_id: self.info.provider_build_id.clone(),
            provider_path: self.info.provider_path.clone(),
            image_digest: self.info.image_digest.clone(),
            document,
            disposition: parts.disposition,
        }
    }
}

/// Assembled window parts (kept out of the 7-argument lint).
struct FinishParts {
    outcome: Outcome,
    executions: Vec<Execution>,
    stale: Vec<StaleBucket>,
    counters: Counters,
    legacy: serde_json::Value,
    harvest_doc: serde_json::Value,
    disposition: Option<target::TargetDisposition>,
    window_actual: Duration,
}

/// Render count candidates into the legacy identity shape (T10/T11
/// seam): the first candidate rides as the primary identity with the
/// rest as aliases. Provider label is the candidate class, never a
/// filename guess.
fn render_candidates(
    candidates: &[CandidateIdentity],
    offset: u64,
) -> (plan::Identity, Vec<plan::Identity>) {
    let render = |c: &CandidateIdentity| plan::Identity {
        provider: c.provider_class.clone(),
        op: c.op,
        funcid: c.funcid,
        alg_class: c
            .algorithm_classes
            .first()
            .cloned()
            .unwrap_or_else(|| "other".to_string()),
        offset,
    };
    let mut iter = candidates.iter();
    match iter.next() {
        Some(first) => (render(first), iter.map(render).collect()),
        None => (
            plan::Identity {
                provider: "unknown".to_string(),
                op: 0,
                funcid: 0,
                alg_class: "other".to_string(),
                offset,
            },
            Vec::new(),
        ),
    }
}

/// FIPS KAT caveat trigger (display-level, operator-configured): the
/// CONFIGURED provider path is fips-shaped and provider-plane calls
/// executed. Not a filename guess about target identity — the
/// operator told us which module to watch.
fn fips_configured(provider: &Path) -> bool {
    let stem = provider.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let stem = stem.strip_suffix(".so").unwrap_or(stem);
    stem == "fips"
}

// ---------------------------------------------------------------- run

/// Pre-attach recycle capture (`--pid` only): the pin failed during
/// discovery attach, so no session was ever held.
fn recycled_capture(cfg: &Config, info: &TargetInfo) -> Capture {
    let requested_end = info.acquired_ns.saturating_add(duration_ns(cfg.duration));
    let document = evidence::finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: info.acquired_ns,
            requested_end_ns: requested_end,
            effective_start_ns: requested_end,
            effective_end_ns: requested_end,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: Some(evidence::FatalKind::Recycled),
    });
    Capture {
        target_pid: info.pid,
        target_comm: info.comm.clone(),
        window_planned: cfg.duration,
        window_actual: Duration::ZERO,
        outcome: Outcome::Fatal(FatalKind::Recycled),
        reasons: vec!["pid-recycled".to_string()],
        executions: Vec::new(),
        stale: Vec::new(),
        counters: Counters::default(),
        child_exit: None,
        drain_wall_us: 0,
        harvest_doc: serde_json::json!({}),
        legacy: serde_json::Value::Null,
        window_start_wall: info.acquired_wall,
        window_end_wall: info.acquired_wall,
        kernel_release: info.kernel_release.clone(),
        target_cmdline: info.cmdline.clone(),
        target_container_id: info.container_id.clone(),
        provider_build_id: info.provider_build_id.clone(),
        provider_path: info.provider_path.clone(),
        image_digest: info.image_digest.clone(),
        document,
        disposition: None,
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
    // Target-identity snapshot at acquisition (the target may be
    // dead by report time — /proc reads then would miss).
    let acq_clock = LiveClock;
    let acq_ns = acq_clock.monotonic_ns();
    let acq_instant = Instant::now();
    let acq_wall = SystemTime::now();
    let provider_build_id = std::fs::read(&cfg.provider)
        .ok()
        .and_then(|b| elf::read_build_id(&b))
        .unwrap_or_else(|| "unknown".to_string());
    let provider_path = cfg.provider.to_string_lossy().into_owned();
    match target {
        Target::Spawn { argv } => {
            let cmdline = args::redact_spawn_argv(&argv);
            let mut owned = target::OwnedTarget::spawn_stopped(&argv)
                .map_err(|e| anyhow::anyhow!("spawn: {e:#}"))?;
            let pid = owned.pid();
            let info = TargetInfo {
                pid,
                owned: true,
                comm: comm_of(pid),
                cmdline,
                container_id: container_id_of(pid),
                kernel_release: crate::doctor::uname_release(),
                provider_build_id,
                provider_path,
                image_digest: cfg.image_digest.clone(),
                acquired_ns: acq_ns,
                acquired_instant: acq_instant,
                acquired_wall: acq_wall,
            };
            let backend = crate::count_session::LiveBackend::new(loaded, pid);
            let count = CountSession::new(pid, backend);
            let discovery = match DiscoverySession::attach(
                &crate::discovery::session::DiscoveryConfig {
                    provider: cfg.provider.clone(),
                    object: cfg.harvest_object.clone(),
                    builtin: cfg.builtin,
                    legacy: true,
                    table: None,
                    force_offset: None,
                    cmdline_marker: None,
                },
                pid,
            ) {
                Ok(discovery) => discovery,
                Err(e) => {
                    // A stopped child can only die by an outside
                    // kill; preserve whatever status exists, resolve
                    // custody, and fail loud (no zombie, no silence).
                    let exit_note = owned
                        .poll_exit()
                        .ok()
                        .flatten()
                        .map(|code| format!(" (child status {code})"))
                        .unwrap_or_default();
                    let _ = owned.resolve_setup_failure();
                    return Err(e.context(format!("discovery attach{exit_note}")));
                }
            };
            observe(
                cfg,
                &info,
                SessionSet {
                    discovery: LiveDiscovery::new(discovery),
                    count,
                    target: owned,
                    lifecycle: PollingLifecycle::new(pid),
                },
                &LiveClock,
                &mut LiveProc,
                &interrupted,
            )
        }
        Target::Pid(p) => {
            let pin_guard = pin::pin(p).map_err(|e| anyhow::anyhow!("pin: {e:#}"))?;
            let raw = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
            let info = TargetInfo {
                pid: p,
                owned: false,
                comm: comm_of(p),
                cmdline: args::redact_proc_cmdline(&raw),
                container_id: container_id_of(p),
                kernel_release: crate::doctor::uname_release(),
                provider_build_id,
                provider_path,
                image_digest: cfg.image_digest.clone(),
                acquired_ns: acq_ns,
                acquired_instant: acq_instant,
                acquired_wall: acq_wall,
            };
            let backend = crate::count_session::LiveBackend::new(loaded, p);
            let count = CountSession::new(p, backend);
            let discovery = match DiscoverySession::attach(
                &crate::discovery::session::DiscoveryConfig {
                    provider: cfg.provider.clone(),
                    object: cfg.harvest_object.clone(),
                    builtin: cfg.builtin,
                    legacy: true,
                    table: None,
                    force_offset: None,
                    cmdline_marker: None,
                },
                p,
            ) {
                Ok(discovery) => discovery,
                Err(e) => {
                    // Mid-attach recycle: fatal verdict, no sessions
                    // held (the count object drops unused).
                    if e.downcast_ref::<crate::discovery::session::Recycled>()
                        .is_some()
                    {
                        return Ok(recycled_capture(cfg, &info));
                    }
                    return Err(e.context("discovery attach"));
                }
            };
            observe(
                cfg,
                &info,
                SessionSet {
                    discovery: LiveDiscovery::new(discovery),
                    count,
                    target: PinnedTarget::new(p, pin_guard),
                    lifecycle: PollingLifecycle::new(p),
                },
                &LiveClock,
                &mut LiveProc,
                &interrupted,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::session::{
        AttachEvent, AttachKind, BackingRef, DiscoveredCandidate, TableCoverage, TableRetirement,
    };

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
    fn fips_caveat_triggers_on_configured_path_only() {
        // Operator-configured fips-shaped module (never a target
        // filename guess): stem match with .so/version tolerance.
        assert!(fips_configured(Path::new("/usr/lib/ossl-modules/fips.so")));
        assert!(fips_configured(Path::new("fips.so.3")));
        assert!(fips_configured(Path::new("/p/fips")));
        assert!(!fips_configured(Path::new("/usr/lib/libcrypto.so.3")));
        assert!(!fips_configured(Path::new("/p/default.so")));
        assert!(!fips_configured(Path::new("/p/FIPS.so")));
        assert!(!fips_configured(Path::new("/p/myfips.so")));
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
    fn executions_sort_by_identity() {
        // PRD §6 byte-stability: (op, provider, alg, funcid) —
        // input order must not leak into output order.
        let mut v = vec![
            Execution {
                cookie: 1,
                id: plan::Identity {
                    provider: "default".into(),
                    op: 12,
                    funcid: 1,
                    alg_class: "RSA".into(),
                    offset: 0,
                },
                aliases: Vec::new(),
                count: 1,
                first_ns: 0,
                last_ns: 0,
            },
            Execution {
                cookie: 0,
                id: plan::Identity {
                    provider: "default".into(),
                    op: 1,
                    funcid: 1,
                    alg_class: "SHA256".into(),
                    offset: 0,
                },
                aliases: Vec::new(),
                count: 2,
                first_ns: 0,
                last_ns: 0,
            },
        ];
        sort_executions(&mut v);
        assert_eq!(v[0].id.op, 1);
        assert_eq!(v[1].id.op, 12);
        assert_eq!(v[0].cookie, 0);
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
    fn kernel_release_nonempty() {
        assert!(!crate::doctor::uname_release().is_empty());
    }

    // ---------------------------------------------------------------- adapter

    fn backing(dev: &str, ino: u64, offset: u64) -> Option<BackingRef> {
        Some(BackingRef {
            dev: dev.to_string(),
            ino,
            offset,
        })
    }

    fn candidate(
        advertising: &str,
        backing: Option<BackingRef>,
        op: u32,
        funcid: u32,
        class: &str,
        weak: bool,
        status: &str,
    ) -> DiscoveredCandidate {
        DiscoveredCandidate {
            advertising: advertising.to_string(),
            backing,
            op,
            funcid,
            class: class.to_string(),
            weak,
            status: status.to_string(),
            epoch: 0,
            impl_addr: 0,
            arr: 0,
        }
    }

    fn terminated(op: u32, epoch: u64) -> TableCoverage {
        TableCoverage {
            op,
            epoch,
            state: CoverageState::Terminated { len: 4 },
            trunc_bits: 0,
        }
    }

    fn in_progress(op: u32, epoch: u64) -> TableCoverage {
        TableCoverage {
            op,
            epoch,
            state: CoverageState::InProgress { walked: 2 },
            trunc_bits: 0,
        }
    }

    fn ctx_for<'a>(
        live: &'a [maps::Mapping],
        files: &'a HashMap<String, Vec<u8>>,
        fresh: &'a HashSet<(String, u64)>,
    ) -> AdapterCtx<'a> {
        AdapterCtx {
            live,
            files,
            builtin_default: false,
            fresh,
            post_settle: false,
            baseline: false,
        }
    }

    fn adapt_fresh(delta: &DiscoveryDelta, live: &[maps::Mapping]) -> (AdapterState, AdaptedDelta) {
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let adapted = adapt_delta(
            &mut state,
            delta,
            &AdapterCtx {
                live,
                files: &files,
                builtin_default: false,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
            },
        );
        (state, adapted)
    }

    #[test]
    fn adapt_accumulates_shared_site_sets() {
        // D1: two candidates sharing one backing triple (across two
        // polls) union into one complete replacement set — the later
        // poll must not clobber the earlier candidate.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(out.delta.discovered[0].candidates.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Complete
        );
        // Same triple, second op, later poll: union (2 candidates),
        // and the op-2 prefix keeps this emit Unknown.
        let second = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                2,
                21,
                "SHA-512",
                true,
                "ok",
            )],
            tables: vec![in_progress(2, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &second, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        let site = &out.delta.discovered[0];
        assert_eq!(site.candidates.len(), 2);
        assert!(site.candidates.iter().any(|c| c.weak_alias));
        assert_eq!(site.candidates_coverage, CandidateCoverage::Unknown);
        // Physical identity is the backing triple (never the path).
        let device = plan::device_id_of_maps_dev("08:01").unwrap();
        assert_eq!(site.site.device, device);
        assert_eq!(site.site.inode, 7);
        assert_eq!(site.site.offset, 0x100);
    }

    #[test]
    fn adapt_late_arrival_after_termination_is_unknown() {
        // D3: an op that already terminated, then grows a new
        // candidate in a later poll, proves its set non-closed.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let proof = DiscoveryDelta {
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &proof, &ctx_for(&live, &files, &fresh));
        assert!(out.delta.discovered.is_empty());
        let late = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &late, &ctx_for(&live, &files, &fresh));
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
    }

    #[test]
    fn adapt_retirement_reemits_unknown_without_recounting_loss() {
        // D2: retirement dirties the op and re-emits affected sites
        // as Unknown; the carried gap losses are NOT re-counted.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Complete
        );
        let retire = DiscoveryDelta {
            retirements: vec![TableRetirement {
                op: 1,
                epoch: 0,
                gap: coverage::CoverageDelta {
                    reasons: vec!["prefix-walk".to_string()],
                    losses: vec![(1, 9)],
                },
            }],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &retire, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
        // No loss counters from the carried gap (the session emits
        // those through `losses`); one retirement activity row.
        assert!(out.delta.losses.is_empty());
        assert_eq!(out.activity.len(), 1);
        assert_eq!(out.activity[0].name, "discovery.table_retired");
    }

    #[test]
    fn adapt_unplannable_sites_are_loud_loss() {
        // D3: missing backing / unparsable device → explicit loss,
        // never a fabricated site.
        let delta = DiscoveryDelta {
            candidates: vec![
                candidate("/p/x.so", None, 1, 11, "SHA-256", false, "ok"),
                candidate(
                    "/p/x.so",
                    backing("bogus", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
            ],
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert!(out.delta.discovered.is_empty());
        let names: Vec<&str> = out.delta.losses.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"discovery.unbacked_candidate"));
        assert!(names.contains(&"discovery.unparsed_device"));
        for loss in &out.delta.losses {
            assert_eq!(loss.kind, CounterKind::Loss);
            assert!(loss.forces_partial());
        }
    }

    #[test]
    fn adapt_classifies_losses_and_keeps_unknown_ids() {
        // D4: ring → KernelRing, map → KernelMap, orphan rows →
        // TableRows, unknown ids fail closed with counts kept.
        use crate::discovery::session::DiscoveryLoss;
        let delta = DiscoveryDelta {
            losses: vec![
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_RING_ROW,
                    count: 2,
                },
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_MAP_TRIP,
                    count: 3,
                },
                DiscoveryLoss {
                    source: coverage::HOST_ORPHAN_ROW,
                    count: 4,
                },
                DiscoveryLoss {
                    source: 4242,
                    count: 5,
                },
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_RING_ROW,
                    count: 0,
                },
            ],
            ..DiscoveryDelta::default()
        };
        let (state, out) = adapt_fresh(&delta, &[]);
        assert_eq!(out.delta.losses.len(), 4);
        let by_name = |n: &str| {
            out.delta
                .losses
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        let ring = by_name("discovery.ring_row");
        assert_eq!(ring.source, CounterSource::KernelRing);
        assert_eq!(ring.units, CounterUnits::Events);
        assert_eq!(ring.value, 2);
        let map = by_name("discovery.map_trip");
        assert_eq!(map.source, CounterSource::KernelMap);
        assert_eq!(map.value, 3);
        let orphan = by_name("discovery.orphan_row");
        assert_eq!(orphan.units, CounterUnits::TableRows);
        assert_eq!(orphan.value, 4);
        let unknown = by_name("discovery.unknown_4242");
        assert_eq!(unknown.kind, CounterKind::Loss);
        assert_eq!(unknown.value, 5);
        // Loss sums accumulate for the close reconcile.
        assert_eq!(
            state.loss_sums.get(&osslscope_ebpf_common::LOSS_RING_ROW),
            Some(&2)
        );
    }

    #[test]
    fn adapt_provider_class_defaults() {
        // D3: builtin mode asserts `default`; file mode stays
        // `unknown` (T09 pinned classification is the seam).
        let delta = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert_eq!(
            out.delta.discovered[0].candidates[0].provider_class,
            "unknown"
        );
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                builtin_default: true,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
            },
        );
        assert_eq!(
            out.delta.discovered[0].candidates[0].provider_class,
            "default"
        );
    }

    #[test]
    fn adapt_late_attach_splits_fresh_loads() {
        // Past settle, a first emit for a long-present backing is
        // late-attach loss; a fresh-dlopen backing is activity.
        let delta = DiscoveryDelta {
            candidates: vec![
                candidate(
                    "/p/old.so",
                    backing("08:01", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
                candidate(
                    "/p/new.so",
                    backing("08:01", 8, 0x200),
                    1,
                    12,
                    "SHA-512",
                    false,
                    "ok",
                ),
            ],
            tables: vec![in_progress(1, 0)],
            ..DiscoveryDelta::default()
        };
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh: HashSet<(String, u64)> = HashSet::from([("08:01".to_string(), 8)]);
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                builtin_default: false,
                fresh: &fresh,
                post_settle: true,
                baseline: false,
            },
        );
        assert_eq!(out.delta.discovered.len(), 2);
        let loss = out
            .delta
            .losses
            .iter()
            .find(|c| c.name == "discovery.late_attach_sites")
            .unwrap();
        assert_eq!(loss.value, 1);
        let fresh_row = out
            .activity
            .iter()
            .find(|c| c.name == "discovery.new_mapping_sites")
            .unwrap();
        assert_eq!(fresh_row.value, 1);
    }

    #[test]
    fn adapt_baseline_drops_tripwire_and_cold_queries() {
        // D2 tripwire/queries: the baselining poll drops tripwire
        // news and reports queries as pre-window (cold gap).
        let delta = DiscoveryDelta {
            queries_delta: 6,
            tripwire: crate::discovery::session::TripwireDelta {
                hits: vec![legacy::TripHit {
                    cookie: 7,
                    class: 1,
                    status: 0,
                }],
                counter_deltas: vec![(7, 3)],
                executed_legacy_queries_delta: 2,
            },
            ..DiscoveryDelta::default()
        };
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                builtin_default: false,
                fresh: &fresh,
                post_settle: false,
                baseline: true,
            },
        );
        assert!(out.tripwire.is_none());
        assert_eq!(out.pre_window_queries, 6);
        assert!(
            out.activity
                .iter()
                .all(|c| c.name != "discovery.queries_observed")
        );
    }

    #[test]
    fn adapt_auxiliary_fields_become_counters() {
        // D2: events/attaches/budget dispositions stay visible.
        let delta = DiscoveryDelta {
            events_consumed: 10,
            queries_delta: 4,
            attaches: vec![
                AttachEvent {
                    kind: AttachKind::Stage2 { cookie: 1 },
                    failed: None,
                },
                AttachEvent {
                    kind: AttachKind::Tripwires { count: 3 },
                    failed: Some("EBUSY".to_string()),
                },
            ],
            budget_exhausted: true,
            trigger_observed: true,
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert!(out.trigger_observed);
        let names: Vec<&str> = out.activity.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"discovery.events_consumed"));
        assert!(names.contains(&"discovery.queries_observed"));
        assert!(names.contains(&"discovery.attaches"));
        assert!(names.contains(&"discovery.budget_exhausted"));
        let failed = out
            .delta
            .losses
            .iter()
            .find(|c| c.name == "discovery.attach_failed")
            .unwrap();
        assert_eq!(failed.value, 1);
        assert_eq!(failed.units, CounterUnits::Probes);
    }

    #[test]
    fn adapt_objects_skip_unparsed_devices() {
        // D2 objects: fingerprinted-or-opaque records; unparsable
        // devices skip loud (never device zero).
        use crate::discovery::session::DiscoveredObject;
        let delta = DiscoveryDelta {
            objects: vec![
                DiscoveredObject {
                    dev: "08:01".to_string(),
                    ino: 7,
                    display_locator: "/p/provider.so".to_string(),
                },
                DiscoveredObject {
                    dev: "bogus".to_string(),
                    ino: 8,
                    display_locator: "/p/other.so".to_string(),
                },
            ],
            ..DiscoveryDelta::default()
        };
        let (state, out) = adapt_fresh(&delta, &[]);
        assert_eq!(out.objects.len(), 1);
        assert_eq!(out.objects[0].inode, 7);
        assert_eq!(out.objects[0].display_locator, "/p/provider.so");
        assert!(
            out.delta
                .losses
                .iter()
                .any(|c| c.name == "discovery.unparsed_object_dev")
        );
        assert_eq!(state.objects.len(), 1);
    }
}
