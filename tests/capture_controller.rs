//! SPDX-License-Identifier: GPL-3.0-or-later
//! T08 capture-controller gates (spec R04/R05).
//!
//! The real [`observe`](osslscope::capture::observe) loop drives
//! scripted discovery sessions, a real `CountSession` over a shared
//! fake backend, scripted targets, lifecycle and /proc views, and an
//! injected clock — no timing sleeps, no privileges. Live process
//! fixtures (short child, double-fork/reparent, same-TGID exec,
//! thread creation) use real pids under the polling lifecycle, and
//! every owned-child test asserts no stopped child or zombie
//! remains.

use osslscope::capture::{Capture, Outcome};
use osslscope::capture::{
    ClockPort, Config, DiscoveryPort, FileStat, LifecycleDelta, LifecycleEvent, LifecycleKind,
    LifecyclePort, ProcPort, SessionSet, TargetInfo, TargetPort, observe,
};
use osslscope::count_session::*;
use osslscope::count_session::{CountBackend, CountSession, FakeCountBackend, FakeLink};
use osslscope::discovery::maps::Mapping;
use osslscope::discovery::session::{
    AttachEvent, AttachKind, BackingRef, CoverageState, DiscoveredCandidate, DiscoveryDelta,
    DiscoveryLoss, DiscoverySnapshot, MapSnapshots, PollBudget, Recycled, SessionCore, SessionEnv,
    TableCoverage, TableRetirement, TripwireDelta,
};
use osslscope::evidence::{
    CandidateCoverage, Completeness, ExpectedScope, PredicateMatch, match_bounds,
};
use osslscope::{plan, target};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

const PID: u32 = 4242;
/// Monotonic base (1000s): the kernel window opens here unless a
/// test advances setup first.
const BASE_NS: u64 = 1_000_000_000_000;

// ---------------------------------------------------------------------------
// Injected clock (no timing sleeps).
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FakeClock {
    ns: RefCell<u64>,
    base: Instant,
    advanced: RefCell<Duration>,
    wall: SystemTime,
    checked_samples: RefCell<VecDeque<Option<u64>>>,
}

impl FakeClock {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            ns: RefCell::new(BASE_NS),
            base: Instant::now(),
            advanced: RefCell::new(Duration::ZERO),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            checked_samples: RefCell::new(VecDeque::new()),
        })
    }

    fn advance_ns(&self, n: u64) {
        let next = self.ns.borrow().saturating_add(n);
        *self.ns.borrow_mut() = next;
        let advanced = *self.advanced.borrow() + Duration::from_nanos(n);
        *self.advanced.borrow_mut() = advanced;
    }
}

impl ClockPort for FakeClock {
    fn checked_monotonic_ns(&self) -> Option<u64> {
        self.checked_samples
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Some(*self.ns.borrow()))
    }
    fn monotonic_ns(&self) -> u64 {
        *self.ns.borrow()
    }

    fn now(&self) -> Instant {
        self.base + *self.advanced.borrow()
    }

    fn wall_now(&self) -> SystemTime {
        self.wall
    }

    fn sleep(&self, d: Duration) {
        self.advance_ns(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    }
}

// ---------------------------------------------------------------------------
// Shared fake count backend: the test peers at attach/close order and
// fires scripted executions from inside the observation.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum OpenReplyFault {
    CompletedLost,
    MissingResolved,
    MismatchedActual,
}

#[derive(Debug, Default)]
struct SharedState {
    backend: FakeCountBackend,
    attached: Vec<u32>,
    log: Vec<String>,
    /// Fake-clock instant of `close_window` (R20 count-close
    /// barrier control: reap must precede this for owned exits).
    closed_at: Option<u64>,
    terminal_delay_ns: u64,
    refuse_suffix: bool,
    open_reply_fault: Option<OpenReplyFault>,
    attach_errno: Option<i32>,
}

#[derive(Clone)]
struct SharedBackend {
    ready: Ready,
    barrier: Arc<CountForkBarrier>,
    shared: Rc<RefCell<SharedState>>,
    clock: Rc<FakeClock>,
    order: Rc<RefCell<Vec<String>>>,
}

impl CountBackend for SharedBackend {
    type Link = FakeLink;
    fn ready(&self) -> &Ready {
        &self.ready
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<FakeLink>> {
        let mut st = self.shared.borrow_mut();
        if let Some(errno) = st.attach_errno {
            return Err(CommandFailure {
                seq: request.seq,
                completion: CommandCompletion::NotEntered,
                publication: CommandPublication::NotPublished,
                cleanup_ticket: None,
                failure: OwnerFailure {
                    operation: CountOperation::Attach,
                    resource: ResourceId::Engine,
                    class: FailureClass::Io,
                    errno: Some(errno),
                },
            });
        }
        let path = request.locator.clone();
        let cookies = request.cookies.clone();
        let ack = st.backend.attach(request)?;
        for (i, cookie) in cookies.iter().enumerate() {
            if !ack.value.refused.iter().any(|r| r.position == i) {
                if let Ok(cookie) = u32::try_from(*cookie) {
                    if !st.attached.contains(&cookie) {
                        st.attached.push(cookie);
                    }
                }
            }
        }
        st.log
            .push(format!("attach:{path}:{}", ack.value.links.len()));
        Ok(ack)
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        let mut st = self.shared.borrow_mut();
        st.log.push("count_open".into());
        self.order.borrow_mut().push("count_open".into());
        let Some(fault) = st.open_reply_fault else {
            return st.backend.open_window(request);
        };
        let mut actual = request;
        if matches!(fault, OpenReplyFault::MismatchedActual) {
            actual.start_ns += 1;
        }
        let _ack = st.backend.open_window(actual)?;
        if matches!(fault, OpenReplyFault::MissingResolved) {
            st.backend.terminal_faults(FakeTerminalFaults {
                omit_resolved_open: true,
                ..Default::default()
            });
        }
        Err(CommandFailure {
            seq: request.seq,
            completion: CommandCompletion::Unknown,
            publication: CommandPublication::Published,
            cleanup_ticket: None,
            failure: OwnerFailure {
                operation: CountOperation::Open,
                resource: ResourceId::Engine,
                class: FailureClass::Disconnected,
                errno: None,
            },
        })
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        let mut st = self.shared.borrow_mut();
        st.log.push(format!("gen:{}", request.generation));
        st.backend.set_generation(request)
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        self.shared.borrow_mut().backend.drain(request)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        self.shared
            .borrow_mut()
            .backend
            .terminal_request(deadline, frontier)
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        let mut st = self.shared.borrow_mut();
        st.log.push("count_closed".into());
        st.closed_at = Some(self.clock.monotonic_ns());
        self.order.borrow_mut().push("count_closed".into());
        let stop = self.clock.monotonic_ns();
        st.backend.set_modeled_seal(Some(stop), Some(stop));
        let terminal = st.backend.terminal(request);
        self.clock.advance_ns(st.terminal_delay_ns);
        terminal
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.shared.borrow().backend.progress()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        if self.shared.borrow().refuse_suffix {
            return Err(ForkBlocked::Unresolved);
        }
        self.barrier.prefix_permit(deadline)
    }
}

// ---------------------------------------------------------------------------
// Scripted discovery session with fire/cancel hooks.
// ---------------------------------------------------------------------------

struct FirePlan {
    /// (absolute monotonic ns, calls) per attached cookie.
    fires: Vec<(u64, u64)>,
    shortfall: u64,
    cancel: bool,
}

struct FakeDiscovery {
    shared: Rc<RefCell<SharedState>>,
    clock: Rc<FakeClock>,
    polls: VecDeque<DiscoveryDelta>,
    plans: HashMap<usize, FirePlan>,
    /// Tgid fires bind to (the count session's target; PID for the
    /// scripted harness, the real child for live-child runs — a
    /// mismatched tgid would silently drop every fire).
    fire_tgid: u32,
    poll_delay_ns: HashMap<usize, u64>,
    /// REAL (wall-clock) sleep per poll, never fake-advancing
    /// (F-D/A13): live-child tests need real time to pass for the
    /// real target while the injected clock stays scripted. Zero
    /// everywhere except live_observe.
    poll_real_delay: Duration,
    poll_err_at: HashSet<usize>,
    snapshot: DiscoverySnapshot,
    finish_err: bool,
    finish_recycled: bool,
    finish_final: Option<DiscoverySnapshot>,
    cancel_flag: Option<Rc<Cell<bool>>>,
    polls_done: usize,
    finished: bool,
    traversal_setup_error: bool,
}

impl DiscoveryPort for FakeDiscovery {
    fn poll(&mut self, _budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        let idx = self.polls_done;
        self.polls_done += 1;
        // Scripted poll latency (deadline-straddle model): the poll
        // starts pre-deadline and completes after advancing the clock.
        // Runs before the injected failure (a failing poll consumes
        // time too — a death-during-poll schedule needs the clock to
        // advance past the exit even though the poll fails).
        if let Some(ns) = self.poll_delay_ns.get(&idx) {
            self.clock.sleep(Duration::from_nanos(*ns));
        }
        if self.poll_err_at.contains(&idx) {
            anyhow::bail!("injected poll failure");
        }
        if let Some(plan) = self.plans.remove(&idx) {
            let mut st = self.shared.borrow_mut();
            if plan.shortfall > 0 {
                st.backend.set_shortfall(plan.shortfall);
            }
            let cookies = st.attached.clone();
            let tgid = self.fire_tgid;
            for (ns, n) in &plan.fires {
                for cookie in &cookies {
                    st.backend.fire(tgid, *cookie, *ns, *n);
                }
            }
            if plan.cancel {
                if let Some(flag) = &self.cancel_flag {
                    flag.set(true);
                }
            }
        }
        // Wall-clock pacing for live-child tests (zero elsewhere):
        // lets a real target run while fake time stays scripted.
        if !self.poll_real_delay.is_zero() {
            std::thread::sleep(self.poll_real_delay);
        }
        Ok(self.polls.pop_front().unwrap_or_default())
    }

    fn traversal_active(&self) -> bool {
        self.traversal_setup_error
    }
    fn poll_traversal(
        &mut self,
        _baseline: bool,
    ) -> anyhow::Result<osslscope::capture::TraversalDelta> {
        if self.traversal_setup_error {
            self.clock.advance_ns(300);
            let mut state = self.shared.borrow_mut();
            let cookie = state.attached[0];
            state
                .backend
                .fire(PID, cookie, self.clock.monotonic_ns(), 1);
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        Ok(osslscope::capture::TraversalDelta::default())
    }
    fn snapshot(&self) -> DiscoverySnapshot {
        self.snapshot.clone()
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        self.finished = true;
        self.shared
            .borrow_mut()
            .log
            .push("discovery_finished".to_string());
        if self.finish_recycled {
            // Mirror SessionCore::close on a dead /proc entry: typed
            // recycle over discarded state, with the staged pre-wipe
            // final when the test provides one.
            return Err(anyhow::Error::new(Recycled {
                snapshot: DiscoverySnapshot::default(),
                final_snapshot: self.finish_final.clone(),
            }));
        }
        if self.finish_err {
            anyhow::bail!("injected finish failure");
        }
        Ok(self.snapshot.clone())
    }
}

// ---------------------------------------------------------------------------
// Scripted target with shared custody log (assertable after observe).
// ---------------------------------------------------------------------------

/// Proc-side read log (F-D/A13): every `read_file_bound` path and
/// every `stat_file` path, in call order. Lets relevance/cache
/// tests assert WHAT was read, not just the adapted outcome.
/// (R14: `read_allowances` additionally records the per-read byte
/// allowance each read carried, so budget tests prove the runner
/// passed shrinking cumulative allowances.)
#[derive(Debug, Default)]
struct ProcLog {
    reads: Vec<String>,
    stats: Vec<String>,
    read_allowances: Vec<(String, usize)>,
}

#[derive(Debug, Default)]
struct TargetLog {
    released: bool,
    resolved: bool,
    finished: bool,
    polls: usize,
    verify_calls: usize,
    /// Fake-clock instant `poll_exit` first reported an exit (R20
    /// count-close barrier control: this must precede `closed_at`).
    reaped_at: Option<u64>,
}

struct FakeTarget {
    clock: Rc<FakeClock>,
    log: Rc<RefCell<TargetLog>>,
    order: Rc<RefCell<Vec<String>>>,
    pid: u32,
    owned: bool,
    release_err: bool,
    exit_at_ns: Option<u64>,
    exit_code: i32,
    poll_err: bool,
    verify_err_after: Option<usize>,
    exited: bool,
    /// Calls executing AT the release boundary (R20-fix finding 7):
    /// (index into the attached-cookie vec, calls). Only attached
    /// cookies fire — production-faithful (no probe → no hit);
    /// attempts against unattached indexes record
    /// `fire-missed:no-probe` instead of firing.
    release_fires: Vec<(usize, u64)>,
    release_timing: Option<(u64, u64)>,
    shared: Option<Rc<RefCell<SharedState>>>,
}

impl TargetPort for FakeTarget {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_owned(&self) -> bool {
        self.owned
    }

    fn release(&mut self) -> anyhow::Result<()> {
        if self.release_err {
            anyhow::bail!("injected release failure");
        }
        if let Some((before, _)) = self.release_timing {
            self.clock.advance_ns(before);
        }
        self.log.borrow_mut().released = true;
        self.order.borrow_mut().push("released".to_string());
        // Release-boundary calls (R20-fix finding 7): the child acts
        // the instant release returns; only attached probes can hit.
        if let Some(shared) = &self.shared {
            let mut st = shared.borrow_mut();
            let cookies = st.attached.clone();
            let now = self.clock.monotonic_ns();
            for (idx, n) in &self.release_fires {
                match cookies.get(*idx) {
                    Some(cookie) => {
                        st.backend.fire(PID, *cookie, now, *n);
                        self.order.borrow_mut().push(format!("fired:{cookie}"));
                    }
                    None => {
                        self.order
                            .borrow_mut()
                            .push("fire-missed:no-probe".to_string());
                    }
                }
            }
        }
        if let Some((_, after)) = self.release_timing {
            self.clock.advance_ns(after);
        }
        Ok(())
    }

    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        self.log.borrow_mut().polls += 1;
        if self.poll_err {
            anyhow::bail!("injected poll failure");
        }
        if self.exited {
            return Ok(Some(self.exit_code));
        }
        if self
            .exit_at_ns
            .is_some_and(|t| self.clock.monotonic_ns() >= t)
        {
            self.exited = true;
            let mut log = self.log.borrow_mut();
            if log.reaped_at.is_none() {
                log.reaped_at = Some(self.clock.monotonic_ns());
                self.order.borrow_mut().push("reaped".to_string());
            }
            return Ok(Some(self.exit_code));
        }
        Ok(None)
    }

    fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        self.log.borrow_mut().resolved = true;
        if self.owned && !self.exited {
            // Mirror OwnedTarget: a never-released child is SIGKILLed
            // and reaped (128+SIGKILL); an already-exited child keeps
            // its status; foreign targets are untouched.
            self.exited = true;
            self.exit_code = 137;
        }
        Ok(())
    }

    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
        self.log.borrow_mut().finished = true;
        if self.exited
            || self
                .exit_at_ns
                .is_some_and(|t| self.clock.monotonic_ns() >= t)
        {
            self.exited = true;
            Ok(target::TargetDisposition::Exited {
                code: self.exit_code,
            })
        } else {
            Ok(target::TargetDisposition::Detached { pid: self.pid })
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        let mut log = self.log.borrow_mut();
        log.verify_calls += 1;
        if self.verify_err_after.is_some_and(|n| log.verify_calls >= n) {
            anyhow::bail!("injected recycle");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scripted lifecycle and /proc views.
// ---------------------------------------------------------------------------

struct FakeLifecycle {
    polls: VecDeque<LifecycleDelta>,
    fallback: bool,
    /// Scripted close-time ring drain (R20): `None` is the polling
    /// shape (no close witness); `Some` is the kernel-signal shape
    /// (drained through the tail even after the target exited).
    close_drain: Option<LifecycleDelta>,
    /// Fake clock advanced by `advance_ns` on every poll (R20-fix
    /// round 2, F3): models a slow lifecycle scan crossing the
    /// deadline mid-round (production scans take real time).
    clock: Option<Rc<FakeClock>>,
    advance_ns: u64,
    order: Option<Rc<RefCell<Vec<String>>>>,
}

impl LifecyclePort for FakeLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        if let Some(clock) = &self.clock {
            clock.advance_ns(self.advance_ns);
        }
        self.polls.pop_front().unwrap_or_default()
    }

    fn fallback_partial(&self) -> bool {
        self.fallback
    }

    fn timing_trust(&self) -> osslscope::capture::LifecycleTimingTrust {
        osslscope::capture::LifecycleTimingTrust::ReviewedMonotonic
    }

    fn close_drain(
        &mut self,
        _edge: osslscope::capture::LifecycleEdge,
        permit: Option<&CountForkPermit<'_>>,
    ) -> osslscope::capture::LifecycleClose {
        if let Some(order) = &self.order {
            order.borrow_mut().push(
                if permit.is_some() {
                    "lifecycle_suffix"
                } else {
                    "lifecycle_prefix"
                }
                .into(),
            );
        }
        osslscope::capture::LifecycleClose {
            delta: self.close_drain.clone(),
            suffix_witness: permit.is_some() && self.close_drain.is_some(),
        }
    }
}

struct FakeProc {
    clock: Rc<FakeClock>,
    maps: Vec<Mapping>,
    maps_seq: VecDeque<Vec<Mapping>>,
    files: HashMap<String, plan::FileBytes>,
    file_err: HashSet<String>,
    exe: Option<PathBuf>,
    /// Scripted exe-link values, popped per `read_exe` call (R20
    /// exec-fence tests); exhausted falls back to `exe`.
    exe_seq: VecDeque<Option<PathBuf>>,
    /// Scripted file contents, popped per `read_file_bound` call
    /// (R20 implementation-only replacement: bytes change while
    /// the triple stays); exhausted falls back to `files`.
    file_read_seq: VecDeque<HashMap<String, plan::FileBytes>>,
    maps_err_at: HashSet<usize>,
    maps_delay_ns: u64,
    file_delay_ns: u64,
    maps_calls: usize,
    comm: Option<String>,
    /// Post-exec comm once the clock reaches `comm_settle_at_ns`
    /// (scripted exec timing — deliberately clock-driven, never
    /// read-count-driven, so added settle reads cannot shift it).
    comm_settle_at_ns: Option<u64>,
    comm_settled: Option<String>,
    comm_hook: Option<Rc<dyn Fn()>>,
    comm_read_hook: Option<Rc<dyn Fn()>>,
    proc_log: Rc<RefCell<ProcLog>>,
    /// Scripted stats, popped in call order (F-D/A13 F3 + R20
    /// freshness): `Some(FileStat)` overrides the staged stat once
    /// (a scripted replacement race or in-place edit),
    /// `None`/exhausted falls back to the staged identity with the
    /// staged bytes' length and mtime 0.
    stat_seq: VecDeque<Option<FileStat>>,
    /// Per-poll byte budget (R14): small values prove cumulative
    /// overflow without huge allocations; the harness default
    /// mirrors the production round budget.
    read_budget: usize,
}

impl ProcPort for FakeProc {
    fn read_maps(&mut self, _pid: u32) -> anyhow::Result<Vec<Mapping>> {
        self.maps_calls += 1;
        self.clock.advance_ns(self.maps_delay_ns);
        if self.maps_err_at.contains(&self.maps_calls) {
            anyhow::bail!("injected maps failure");
        }
        if let Some(next) = self.maps_seq.pop_front() {
            return Ok(next);
        }
        Ok(self.maps.clone())
    }

    fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>> {
        self.clock.advance_ns(self.file_delay_ns);
        if self.file_err.contains(path) {
            anyhow::bail!("injected file failure for {path}");
        }
        self.files
            .get(path)
            .map(|f| f.bytes.to_vec())
            .ok_or_else(|| anyhow::anyhow!("no such staged file {path}"))
    }

    fn read_file_bound(
        &mut self,
        path: &str,
        max_bytes: usize,
    ) -> std::io::Result<(std::sync::Arc<[u8]>, (u64, u64))> {
        self.clock.advance_ns(self.file_delay_ns);
        self.proc_log.borrow_mut().reads.push(path.to_string());
        self.proc_log
            .borrow_mut()
            .read_allowances
            .push((path.to_string(), max_bytes));
        if self.file_err.contains(path) {
            return Err(std::io::Error::other(format!(
                "injected file failure for {path}"
            )));
        }
        if let Some(seq) = self.file_read_seq.pop_front() {
            let f = seq.get(path).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no such staged file {path}"),
                )
            })?;
            if f.bytes.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    format!("{path}: file exceeds {max_bytes}-byte read bound"),
                ));
            }
            return Ok((f.bytes.clone(), (f.dev, f.ino)));
        }
        let staged = self.files.get(path).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such staged file {path}"),
            )
        })?;
        // Production-faithful budget refusal (R14): the live reader
        // refuses past the allowance before allocating; the fake
        // mirrors that contract so runner tests prove the
        // skip-and-count-loss path (plan-level tests prove the live
        // reader itself).
        if staged.bytes.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("{path}: file exceeds {max_bytes}-byte read bound"),
            ));
        }
        Ok((staged.bytes.clone(), (staged.dev, staged.ino)))
    }

    fn read_budget(&self) -> usize {
        self.read_budget
    }

    fn stat_file(&mut self, path: &str) -> Option<FileStat> {
        self.proc_log.borrow_mut().stats.push(path.to_string());
        if let Some(scripted) = self.stat_seq.pop_front().flatten() {
            return Some(scripted);
        }
        self.files.get(path).map(|f| FileStat {
            dev: f.dev,
            ino: f.ino,
            size: f.bytes.len() as u64,
            mtime_ns: 0,
        })
    }

    fn read_exe(&mut self, _pid: u32) -> Option<PathBuf> {
        if !self.exe_seq.is_empty() {
            return self.exe_seq.pop_front().flatten();
        }
        self.exe.clone()
    }

    fn file_len(&mut self, path: &str) -> Option<u64> {
        self.files.get(path).map(|f| f.bytes.len() as u64)
    }

    fn read_comm(&mut self, _pid: u32) -> Option<String> {
        if let Some(hook) = &self.comm_read_hook {
            hook();
        }
        if let Some(hook) = self.comm_hook.take() {
            hook();
        }
        if self
            .comm_settle_at_ns
            .is_some_and(|t| self.clock.monotonic_ns() >= t)
        {
            if let Some(settled) = self.comm_settled.clone() {
                return Some(settled);
            }
        }
        self.comm.clone()
    }
}

// ---------------------------------------------------------------------------
// Staged provider files (real ELF bytes, real identities).
// ---------------------------------------------------------------------------

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

struct Staged {
    path: String,
    device: u64,
    ino: u64,
}

struct Stage {
    dir: PathBuf,
}

impl Stage {
    fn fresh(test: &str) -> Self {
        let seq = STAGE_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "osslscope-t08-{}-{}-{}-{:?}",
            test,
            std::process::id(),
            seq,
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Staged {
        use std::os::unix::fs::MetadataExt as _;
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        Staged {
            path: path.to_str().unwrap().to_string(),
            device: plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
            ino: meta.ino(),
        }
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn self_bytes() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

fn x_offset(bytes: &[u8]) -> u64 {
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let ph = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
        .unwrap();
    ph.p_offset + 8
}

/// Minimal valid ELF64 (~200 bytes) with a GNU build-id note, for
/// multi-file fixtures: staging the 70MB+ test binary twice
/// overflows the 128MiB round budget (R14 refuses the second read
/// loud), so tests that need every staged file READ use these for
/// their companion files. Distinct seeds give distinct build-ids
/// (distinct fingerprints); parse/build-id/flip behavior matches
/// the real binary (pinned by `small_elf_fixture_is_valid`).
fn small_elf(seed: u8) -> Vec<u8> {
    let mut v = vec![0u8; 212];
    // ELF header.
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2; // 64-bit
    v[5] = 1; // little-endian
    v[6] = 1; // version
    v[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    v[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
    v[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
    v[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    v[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
    v[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
    v[56..58].copy_from_slice(&2u16.to_le_bytes()); // phnum
    // PH0: PT_LOAD + R|X covering the whole image.
    v[64..68].copy_from_slice(&1u32.to_le_bytes());
    v[68..72].copy_from_slice(&5u32.to_le_bytes());
    v[72..80].copy_from_slice(&0u64.to_le_bytes()); // offset
    v[80..88].copy_from_slice(&0x1000u64.to_le_bytes()); // vaddr
    v[96..104].copy_from_slice(&212u64.to_le_bytes()); // filesz
    v[104..112].copy_from_slice(&212u64.to_le_bytes()); // memsz
    v[112..120].copy_from_slice(&0x1000u64.to_le_bytes()); // align
    // PH1: PT_NOTE holding the build-id note at 176.
    v[120..124].copy_from_slice(&4u32.to_le_bytes());
    v[124..128].copy_from_slice(&4u32.to_le_bytes());
    v[128..136].copy_from_slice(&176u64.to_le_bytes()); // offset
    v[136..144].copy_from_slice(&0x10b0u64.to_le_bytes()); // vaddr
    v[152..160].copy_from_slice(&36u64.to_le_bytes()); // filesz
    v[160..168].copy_from_slice(&36u64.to_le_bytes()); // memsz
    v[168..176].copy_from_slice(&4u64.to_le_bytes()); // align
    // Note: namesz 4, descsz 20, type NT_GNU_BUILD_ID.
    v[176..180].copy_from_slice(&4u32.to_le_bytes());
    v[180..184].copy_from_slice(&20u32.to_le_bytes());
    v[184..188].copy_from_slice(&3u32.to_le_bytes());
    v[188..192].copy_from_slice(b"GNU\0");
    for (i, b) in v[192..212].iter_mut().enumerate() {
        *b = seed
            .wrapping_add((i as u8).wrapping_mul(31))
            .wrapping_add(1);
    }
    v
}

#[test]
fn small_elf_fixture_is_valid() {
    // The companion-file fixture parses, fingerprints distinctly
    // per seed, and flips like the real binary.
    for seed in [0xA1u8, 0xB2, 0xC3, 0xD4] {
        let bytes = small_elf(seed);
        let id = osslscope::discovery::elf::read_build_id(&bytes)
            .unwrap_or_else(|| panic!("seed {seed:#x} must carry a build-id"));
        assert_eq!(id.len(), 40, "20-byte descriptor hex: {id}");
        let _ = x_offset(&bytes);
        let flipped = flipped_build_id(&bytes);
        assert_ne!(
            osslscope::discovery::elf::read_build_id(&flipped).unwrap(),
            id,
            "flip must change the build-id"
        );
    }
    let a = osslscope::discovery::elf::read_build_id(&small_elf(0xA1)).unwrap();
    let b = osslscope::discovery::elf::read_build_id(&small_elf(0xB2)).unwrap();
    assert_ne!(a, b, "distinct seeds fingerprint distinctly");
}

fn mapping(staged: &Staged) -> Mapping {
    Mapping {
        start: 0x7f00_0000_0000,
        end: 0x7f00_0000_1000,
        x: true,
        offset: 0,
        dev: plan::render_device(staged.device),
        ino: staged.ino,
        path: staged.path.clone(),
    }
}

// ---------------------------------------------------------------------------
// Delta builders.
// ---------------------------------------------------------------------------

fn backing_of(staged: &Staged, offset: u64) -> Option<BackingRef> {
    Some(BackingRef {
        dev: plan::render_device(staged.device),
        ino: staged.ino,
        offset,
    })
}

#[allow(clippy::too_many_arguments)]
fn cand(
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
        advertising_dev: String::new(),
        advertising_ino: 0,
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

fn counter_value(capture: &Capture, name: &str) -> u64 {
    capture
        .document
        .counters
        .iter()
        .filter(|c| c.name == name)
        .map(|c| c.value)
        .sum()
}

fn has_reason(capture: &Capture, reason: &str) -> bool {
    capture.reasons.iter().any(|r| r == reason)
}

fn has_counter(capture: &Capture, name: &str) -> bool {
    capture.document.counters.iter().any(|c| c.name == name)
}

// ---------------------------------------------------------------------------
// Harness: staged files + wired fakes, driven through real `observe`.
// ---------------------------------------------------------------------------

struct PostCtx {
    shared: Rc<RefCell<SharedState>>,
    target_log: Rc<RefCell<TargetLog>>,
    proc_log: Rc<RefCell<ProcLog>>,
    order: Rc<RefCell<Vec<String>>>,
}

struct Harness {
    stage: Stage,
    staged: Staged,
    bytes: Vec<u8>,
    off: u64,
    clock: Rc<FakeClock>,
    shared: Rc<RefCell<SharedState>>,
    target_log: Rc<RefCell<TargetLog>>,
    proc_log: Rc<RefCell<ProcLog>>,
    order: Rc<RefCell<Vec<String>>>,
    stat_seq: VecDeque<Option<FileStat>>,
    cfg: Config,
    owned: bool,
    acquired_ns: u64,
    polls: VecDeque<DiscoveryDelta>,
    plans: HashMap<usize, FirePlan>,
    poll_delay_ns: HashMap<usize, u64>,
    poll_err_at: HashSet<usize>,
    snapshot: DiscoverySnapshot,
    finish_err: bool,
    finish_recycled: bool,
    finish_final: Option<DiscoverySnapshot>,
    release_err: bool,
    traversal_setup_error: bool,
    exit_at_ns: Option<u64>,
    exit_code: i32,
    poll_err: bool,
    verify_err_after: Option<usize>,
    lifecycle_polls: VecDeque<LifecycleDelta>,
    lifecycle_fallback: bool,
    lifecycle_close_drain: Option<LifecycleDelta>,
    maps: Vec<Mapping>,
    maps_seq: VecDeque<Vec<Mapping>>,
    files: HashMap<String, plan::FileBytes>,
    file_err: HashSet<String>,
    exe: Option<PathBuf>,
    exe_seq: VecDeque<Option<PathBuf>>,
    file_read_seq: VecDeque<HashMap<String, plan::FileBytes>>,
    maps_err_at: HashSet<usize>,
    maps_delay_ns: u64,
    file_delay_ns: u64,
    comm: Option<String>,
    comm_settle_at_ns: Option<u64>,
    comm_settled: Option<String>,
    comm_hook: Option<Rc<dyn Fn()>>,
    comm_read_hook: Option<Rc<dyn Fn()>>,
    cancelled: Rc<Cell<bool>>,
    cancel_on_poll: bool,
    /// Calls executing AT the release boundary (R20-fix finding 7),
    /// wired into the fake target's release hook.
    release_fires: Vec<(usize, u64)>,
    release_timing: Option<(u64, u64)>,
    /// Fake ns advanced by every lifecycle poll (R20-fix round 2,
    /// F3): models a slow lifecycle scan crossing the deadline
    /// mid-round (production scans take real time).
    lifecycle_advance_ns: u64,
    /// Custom cancellation hook (R20-fix round 2, F3): replaces the
    /// flag closure, modelling an async signal landing mid-round
    /// (call-counted in tests — production signals are async).
    cancel_hook: Option<Rc<dyn Fn() -> bool>>,
    read_budget: usize,
}

impl Harness {
    fn fresh(test: &str) -> Self {
        let stage = Stage::fresh(test);
        let bytes = self_bytes();
        let off = x_offset(&bytes);
        let staged = stage.write("prov.so", &bytes);
        let clock = FakeClock::new();
        let maps = vec![mapping(&staged)];
        let mut files = HashMap::new();
        files.insert(
            staged.path.clone(),
            plan::FileBytes {
                bytes: bytes.clone().into(),
                dev: staged.device,
                ino: staged.ino,
            },
        );
        Self {
            stage,
            staged,
            bytes,
            off,
            clock: clock.clone(),
            shared: Rc::new(RefCell::new(SharedState::default())),
            target_log: Rc::new(RefCell::new(TargetLog::default())),
            proc_log: Rc::new(RefCell::new(ProcLog::default())),
            order: Rc::new(RefCell::new(Vec::new())),
            stat_seq: VecDeque::new(),
            cfg: Config {
                harvest_object: Some(PathBuf::new()),
                count_object: Some(PathBuf::new()),
                members_object: Some(PathBuf::new()),
                dev_bundle: None,
                provider: Some(PathBuf::from("/p/provider.so")),
                builtin: false,
                table: None,
                force_offset: None,
                provider_enrollment: None,
                resolved_provider: None,
                duration: Duration::from_secs(2),
                settle: Duration::from_millis(500),
                harvest_timeout: Duration::from_secs(30),
                grace: Duration::from_secs(5),
                image_digest: String::new(),
            },
            owned: true,
            acquired_ns: BASE_NS,
            polls: VecDeque::new(),
            plans: HashMap::new(),
            poll_delay_ns: HashMap::new(),
            poll_err_at: HashSet::new(),
            snapshot: DiscoverySnapshot::default(),
            finish_err: false,
            finish_recycled: false,
            finish_final: None,
            release_err: false,
            traversal_setup_error: false,
            exit_at_ns: None,
            exit_code: 0,
            poll_err: false,
            verify_err_after: None,
            lifecycle_polls: VecDeque::new(),
            lifecycle_fallback: false,
            // Kernel-signal shape by default: a clean close witness
            // (drained, nothing happened). Tests modeling absent
            // close evidence set this to None explicitly.
            lifecycle_close_drain: Some(LifecycleDelta::default()),
            maps,
            maps_seq: VecDeque::new(),
            files,
            file_err: HashSet::new(),
            exe: Some(PathBuf::from("/bin/app")),
            exe_seq: VecDeque::new(),
            file_read_seq: VecDeque::new(),
            maps_err_at: HashSet::new(),
            maps_delay_ns: 0,
            file_delay_ns: 0,
            comm: None,
            comm_settle_at_ns: None,
            comm_settled: None,
            comm_hook: None,
            comm_read_hook: None,
            cancelled: Rc::new(Cell::new(false)),
            cancel_on_poll: false,
            release_fires: Vec::new(),
            release_timing: None,
            lifecycle_advance_ns: 0,
            cancel_hook: None,
            // Production round budget (128 MiB); R14 tests inject
            // small values to prove budget behavior.
            read_budget: 128 * 1024 * 1024,
        }
    }

    /// Steady-state snapshot: dispatch attached, legacy unplanned
    /// with no libcrypto mapped (sequenced per test as needed).
    fn snapshot_attached(&mut self) {
        self.snapshot.dispatch.attached = true;
        self.snapshot.dispatch.trigger_observed = true;
    }

    fn run(self) -> (anyhow::Result<Capture>, PostCtx) {
        let info = TargetInfo {
            pid: PID,
            owned: self.owned,
            comm: "test-target".to_string(),
            cmdline: "<redacted>".to_string(),
            container_id: String::new(),
            kernel_release: "test-kernel".to_string(),
            provider_build_id: "unknown".to_string(),
            provider_path: "/p/provider.so".to_string(),
            image_digest: String::new(),
            acquired_ns: self.acquired_ns,
            acquired_instant: self.clock.now(),
            acquired_wall: self.clock.wall_now(),
        };
        let discovery = FakeDiscovery {
            shared: self.shared.clone(),
            clock: self.clock.clone(),
            polls: self.polls,
            plans: self.plans,
            fire_tgid: PID,
            poll_delay_ns: self.poll_delay_ns,
            poll_real_delay: Duration::ZERO,
            poll_err_at: self.poll_err_at,
            snapshot: self.snapshot,
            finish_err: self.finish_err,
            finish_recycled: self.finish_recycled,
            finish_final: self.finish_final,
            cancel_flag: self.cancel_on_poll.then(|| self.cancelled.clone()),
            polls_done: 0,
            finished: false,
            traversal_setup_error: self.traversal_setup_error,
        };
        let count = CountSession::new(
            PID,
            SharedBackend {
                ready: *self.shared.borrow().backend.ready(),
                barrier: Arc::new(CountForkBarrier::new()),
                shared: self.shared.clone(),
                clock: self.clock.clone(),
                order: self.order.clone(),
            },
        );
        let target = FakeTarget {
            clock: self.clock.clone(),
            log: self.target_log.clone(),
            order: self.order.clone(),
            release_fires: self.release_fires,
            release_timing: self.release_timing,
            shared: Some(self.shared.clone()),
            pid: PID,
            owned: self.owned,
            release_err: self.release_err,
            exit_at_ns: self.exit_at_ns,
            exit_code: self.exit_code,
            poll_err: self.poll_err,
            verify_err_after: self.verify_err_after,
            exited: false,
        };
        let lifecycle = FakeLifecycle {
            polls: self.lifecycle_polls,
            fallback: self.lifecycle_fallback,
            close_drain: self.lifecycle_close_drain,
            clock: Some(self.clock.clone()),
            advance_ns: self.lifecycle_advance_ns,
            order: Some(self.order.clone()),
        };
        let mut proc = FakeProc {
            clock: self.clock.clone(),
            maps: self.maps,
            maps_seq: self.maps_seq,
            files: self.files,
            file_err: self.file_err,
            exe: self.exe,
            exe_seq: self.exe_seq,
            file_read_seq: self.file_read_seq,
            maps_err_at: self.maps_err_at,
            maps_delay_ns: self.maps_delay_ns,
            file_delay_ns: self.file_delay_ns,
            maps_calls: 0,
            comm: self.comm,
            comm_settle_at_ns: self.comm_settle_at_ns,
            comm_settled: self.comm_settled,
            comm_hook: self.comm_hook,
            comm_read_hook: self.comm_read_hook,
            proc_log: self.proc_log.clone(),
            stat_seq: self.stat_seq,
            read_budget: self.read_budget,
        };
        let flag = self.cancelled.clone();
        let hook = self.cancel_hook.clone();
        let fallback = || flag.get();
        let cancelled: &dyn Fn() -> bool = match &hook {
            Some(h) => &**h,
            None => &fallback,
        };
        let out = observe(
            &self.cfg,
            &info,
            SessionSet {
                discovery,
                count,
                target,
                lifecycle,
            },
            &*self.clock,
            &mut proc,
            cancelled,
        );
        (
            out,
            PostCtx {
                shared: self.shared,
                target_log: self.target_log,
                proc_log: self.proc_log,
                order: self.order,
            },
        )
    }
}

fn burst(delta: DiscoveryDelta, n: usize) -> VecDeque<DiscoveryDelta> {
    std::iter::repeat_with(|| delta.clone()).take(n).collect()
}

// ---------------------------------------------------------------------------
// Window, custody and setup paths.
// ---------------------------------------------------------------------------

#[test]
fn clean_exit_yields_complete() {
    // Happy path: terminated table, attached site, executed calls, a
    // mid-window exit (no over-budget, no tail gap) — COMPLETE with
    // exit and disposition preserved.
    let mut h = Harness::fresh("complete");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    // Baseline attach (pre-release ready — the production-faithful
    // ready-window shape under F7).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
    assert!(c.reasons.is_empty(), "{:?}", c.reasons);
    assert!(matches!(c.document.status, Completeness::Complete));
    assert_eq!(c.child_exit, Some(0));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 0 })
    ));
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.executions.len(), 1);
    assert_eq!(c.executions[0].count, 7);
    // No close-tail legacy residual on the clean path: the tail
    // counters stay absent, never zero-valued noise.
    assert!(!has_counter(&c, "legacy.close_tail_trip"));
    assert!(!has_counter(&c, "legacy.close_tail_lgcalls"));
    // No owned stopped child remains: released, finished, resolved
    // only via the normal exit path.
    let log = post.target_log.borrow();
    assert!(log.released);
    assert!(log.finished);
    assert_eq!(post.shared.borrow().attached.len(), 1);
}

#[test]
fn h2_t1_close_tail_residual_downgrades_denominators_and_sites() {
    // A-6: a close-tail loss residual (snapshot counters beyond
    // what polls adapted) must propagate through taint into
    // per-op denominators AND already-emitted site coverages —
    // not sit in extra_counters while Complete claims stand.
    // The target exits cleanly here, so this also pins that the
    // H2/T5 exemption is source-scoped (maps only): a ring-row
    // residual under an exited target still taints.
    let mut h = Harness::fresh("h2-t1");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    // Close-tail: three ring-row drops the final join observed
    // after the last poll adapted (snapshot-only increment).
    h.snapshot.losses = vec![(osslscope_ebpf_common::LOSS_RING_ROW, 3)];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    assert!(!c.document.coverage.is_empty());
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            // H2 leaves the legacy scope untouched (H8 owns
            // legacy-call semantics): no libcrypto was ever
            // observed here, so NotApplicable stands — taint must
            // not conflate "surface absent" with "unobserved".
            assert!(
                matches!(scope.expected, ExpectedScope::NotApplicable),
                "legacy scope must be untouched by H2: {scope:?}"
            );
        } else {
            assert!(
                matches!(scope.expected, ExpectedScope::Unknown),
                "close-tail loss must taint denominators: {scope:?}"
            );
        }
    }
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "close-tail loss must revise emitted sites"
        );
    }
}

#[test]
fn h2_t5_exited_target_maps_residual_is_exempt() {
    // H2/T5: the benign post-exit single — a HOST_MAPS_READ close
    // residual under an exited target (reaped child, /proc gone,
    // nothing missable) — taints no denominator and revises no
    // site. Mid-run maps failures already rode the deltas (op
    // None → poll-global taint), so the residual is close-only.
    // Premise change (justified — R21-F1 round 2: the benign
    // single is inapplicable, not missed, so it is an Activity
    // counter, never a Loss): the D4 record is preserved as
    // Activity, and the old PARTIAL-via-`discovery-loss` premise
    // (the production COMPLETE blocker the review established)
    // is gone — this shape stays PARTIAL only via its honest
    // independent gap (the poll-2 candidate is a late attach).
    let mut h = Harness::fresh("h2-t5");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.snapshot.losses = vec![(osslscope::discovery::coverage::HOST_MAPS_READ, 1)];
    // Round 3, residual D: the benign single is close-phase loss
    // (recorded by the post-reap close read — the child was
    // reaped mid-window, before the close).
    h.snapshot.maps_loss_close = 1;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(
        matches!(
            c.disposition,
            Some(target::TargetDisposition::Exited { code: 0 })
        ),
        "exemption requires an exited target: {:?}",
        c.disposition
    );
    assert_eq!(
        counter_value(&c, "discovery.maps_read"),
        1,
        "the benign single must still land as a D4 record: {:?}",
        c.document.counters
    );
    let maps = c
        .document
        .counters
        .iter()
        .find(|c| c.name == "discovery.maps_read")
        .expect("D4 record preserved");
    assert_eq!(
        maps.kind,
        osslscope::evidence::CounterKind::Activity,
        "the benign single is audit trail, not Loss: {maps:?}"
    );
    assert_eq!(
        c.reasons,
        vec!["late-attach".to_string()],
        "only the honest late-attach gap remains (no discovery-loss): {c:?}"
    );
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            assert!(
                matches!(scope.expected, ExpectedScope::NotApplicable),
                "legacy scope must be untouched by H2: {scope:?}"
            );
        } else {
            assert!(
                matches!(scope.expected, ExpectedScope::Applicable { .. }),
                "benign maps single must not taint denominators: {scope:?}"
            );
        }
    }
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Complete,
            "benign maps single must not revise sites"
        );
    }
}

#[test]
fn close_new_site_taints_denominator_without_fabricating_site() {
    // P6 §6ii sol blocker 2 (capture half, new-site case): a site
    // first joined by close's tail ingest never rode a poll delta,
    // so the adapter never saw it — yet the final table proof is
    // complete. The op's denominator must go Unknown (the window
    // census is short) with an explicit gap record, the window
    // census itself stays poll-only (attached==discovered still
    // pins attach completeness), and the unmeasured site must NOT
    // render as a zero-count site.
    let mut h = Harness::fresh("close-new-site");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    // Final proof complete — but a second site joined only at close.
    h.snapshot.tables = vec![terminated(1, 0)];
    h.snapshot.close_candidates = vec![cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off + 0x40),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    )];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.close_candidates"),
        1,
        "close-joined candidates need an explicit gap record: {:?}",
        c.document.counters
    );
    let scope = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .expect("op:1 must keep its coverage row");
    assert!(
        matches!(scope.expected, ExpectedScope::Unknown),
        "window census is short a close-joined site: {scope:?}"
    );
    assert_eq!(
        (scope.discovered, scope.attached),
        (1, 1),
        "window census stays poll-only and attach-complete: {scope:?}"
    );
    assert_eq!(
        c.document.sites.len(),
        1,
        "the unmeasured close site must not render: {:?}",
        c.document.sites
    );
}

#[test]
fn close_alias_revises_attached_site_to_unknown() {
    // P6 §6ii sol blocker 2 (capture half, alias case): a second
    // identity for an attached triple arrives only at close — the
    // emitted set is missing an alias. The site must revise to
    // Unknown (triple-touched, even though no op-localized loss
    // names it) and the op's denominator with it.
    let mut h = Harness::fresh("close-alias");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.snapshot.tables = vec![terminated(1, 0)];
    h.snapshot.close_candidates = vec![cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        12,
        "SHA-512",
        false,
        "ok",
    )];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(
        c.document.sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "attached site misses its close-joined alias: {:?}",
        c.document.sites[0]
    );
    let scope = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .expect("op:1 must keep its coverage row");
    assert!(
        matches!(scope.expected, ExpectedScope::Unknown),
        "op with a close-joined alias claims no census: {scope:?}"
    );
    assert_eq!(
        (scope.discovered, scope.attached),
        (1, 1),
        "same triple stays one window site, attach-complete: {scope:?}"
    );
}

#[test]
fn close_unbacked_candidate_taints_globally() {
    // P6 §6ii sol round-2 hole 1: a close-joined candidate with no
    // backing (impl mapping gone, array still mapped) cannot be
    // localized to any triple — its alias could belong to ANY
    // emitted site. Unlocalizable ⟹ global taint (F-B/A7: the
    // missing evidence could be anyone's), plus the explicit
    // volume counter. A second, clean op pins the GLOBAL scope:
    // op-local taint alone would leave it Applicable.
    let mut h = Harness::fresh("close-unbacked");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let cand2 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off + 0x80),
        2,
        21,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1, cand2],
        tables: vec![terminated(1, 0), terminated(2, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.snapshot.tables = vec![terminated(1, 0), terminated(2, 0)];
    h.snapshot.close_candidates = vec![cand("/p/provider.so", None, 1, 11, "SHA-256", false, "ok")];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.unbacked_candidate"),
        1,
        "unbacked close volume needs its explicit record: {:?}",
        c.document.counters
    );
    for op in ["op:1", "op:2"] {
        let scope = c
            .document
            .coverage
            .iter()
            .find(|s| s.scope == op)
            .unwrap_or_else(|| panic!("{op} must keep its coverage row"));
        assert!(
            matches!(scope.expected, ExpectedScope::Unknown),
            "unlocalizable close evidence taints every op: {scope:?}"
        );
    }
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "unlocalizable close evidence revises every site"
        );
    }
}

#[test]
fn close_fallback_alias_revises_by_ino_offset_despite_device_flip() {
    // P6 §6ii sol round-2 hole 2: `backing_dev` falls back to maps
    // text when unstatable, so an unlink between poll and close
    // flips the close-candidate's device facet (stat "08:01" →
    // maps "00:22") for the SAME file — a device-triple match
    // misses. (ino, offset) are flip-proof (maps ino is stable
    // across unlink — the dual-facet doctrine of `bindings_alive`),
    // so the site revision matches on them and ignores device.
    // Cross-op shape: the alias's op never appears in the site's
    // adapted identities, so ONLY the (ino, offset) match can
    // revise it — and the close-only op keeps no coverage row.
    let mut h = Harness::fresh("close-fallback");
    h.snapshot_attached();
    let staged_dev = plan::render_device(h.staged.device);
    let staged_ino = h.staged.ino;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.snapshot.tables = vec![terminated(1, 0)];
    // Same file (same ino + offset), maps-facet device string,
    // cross-op identity: the triple match must not need device.
    h.snapshot.close_candidates = vec![DiscoveredCandidate {
        advertising: "/p/provider.so".to_string(),
        advertising_dev: staged_dev,
        advertising_ino: staged_ino,
        backing: Some(BackingRef {
            dev: "00:22".to_string(),
            ino: staged_ino,
            offset: h.off,
        }),
        op: 2,
        funcid: 21,
        class: "SHA-256".to_string(),
        weak: false,
        status: "ok".to_string(),
        epoch: 0,
        impl_addr: 0,
        arr: 0,
    }];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(
        c.document.sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "facet-flipped alias must still revise its site: {:?}",
        c.document.sites[0]
    );
    assert!(
        c.document.coverage.iter().all(|s| s.scope != "op:2"),
        "close-only op keeps no coverage row: {:?}",
        c.document.coverage
    );
}

#[test]
fn close_remembered_backing_revises_old_counted_site() {
    // P6 §6ii sol round-3 remap variant: a first-cross-op ROW for
    // an impl joins at close under a NEW backing (silent M4
    // first-cell adoption — the impl may have remapped since the
    // record was queued, so the record may belong to the OLD
    // backing instead). Discovery reports the remembered old
    // (ino, offset); capture revises that old counted site (its
    // set may miss the alias) WITHOUT tainting the old op's
    // denominator (no triple is missing FOR IT — the precise
    // split: Applicable census, Unknown set).
    let mut h = Harness::fresh("close-remembered");
    h.snapshot_attached();
    let staged_ino = h.staged.ino;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.snapshot.tables = vec![terminated(1, 0)];
    // Cross-op ROW under a NEW backing (device string ignored —
    // the match is (ino, offset)); the remembered OLD backing
    // arrives alongside.
    h.snapshot.close_candidates = vec![DiscoveredCandidate {
        advertising: "/p/provider.so".to_string(),
        advertising_dev: String::new(),
        advertising_ino: 0,
        backing: Some(BackingRef {
            dev: "00:22".to_string(),
            ino: staged_ino + 1,
            offset: h.off,
        }),
        op: 2,
        funcid: 21,
        class: "SHA-256".to_string(),
        weak: false,
        status: "ok".to_string(),
        epoch: 0,
        impl_addr: 0,
        arr: 0,
    }];
    h.snapshot.close_remembered = vec![(staged_ino, h.off)];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.close_remembered"),
        1,
        "remembered remap evidence needs its explicit record: {:?}",
        c.document.counters
    );
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(
        c.document.sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "old site may miss the remapped alias: {:?}",
        c.document.sites[0]
    );
    let scope = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .expect("op:1 must keep its coverage row");
    assert!(
        matches!(scope.expected, ExpectedScope::Applicable { sites: 1 }),
        "old op loses no triple — census stays exact: {scope:?}"
    );
    assert!(
        c.document.coverage.iter().all(|s| s.scope != "op:2"),
        "close-only op keeps no coverage row: {:?}",
        c.document.coverage
    );
}

#[test]
fn h2_t5b_capture_maps_failure_always_taints() {
    // H2/T5b: the capture-side `maps_read_failed` counter has no
    // post-exit increment site (round() reaps-or-continues first),
    // so every count is mid-window turnover blindness — it taints
    // even when the target later exits cleanly. Asymmetry with T5
    // is the point: discovery-side maps residual (close-only,
    // benign) vs capture-side maps failure (live-round, real).
    let mut h = Harness::fresh("h2-t5b");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    // Fail a loop-round maps read (1-based; 1-2 are setup): the
    // round skips, later rounds proceed, the target exits.
    h.maps_err_at = HashSet::from([3]);
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(
        matches!(
            c.disposition,
            Some(target::TargetDisposition::Exited { code: 0 })
        ),
        "T5b needs the exited-target asymmetry: {:?}",
        c.disposition
    );
    assert_eq!(
        counter_value(&c, "discovery.maps_read_failed"),
        1,
        "the staged maps failure must land: {:?}",
        c.document.counters
    );
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            assert!(
                matches!(scope.expected, ExpectedScope::NotApplicable),
                "legacy scope must be untouched by H2: {scope:?}"
            );
        } else {
            assert!(
                matches!(scope.expected, ExpectedScope::Unknown),
                "capture-side maps failure must taint: {scope:?}"
            );
        }
    }
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "capture-side maps failure must revise sites"
        );
    }
}

#[test]
fn h2_t2_close_truncation_taints_only_its_op() {
    // H2/T2: a close-time truncated walk is OP-LOCALIZED
    // (`truncated_ops` carries op ids): op:1 goes Unknown while
    // op:2 stays Applicable/Complete, and the dispatch anchor
    // claim stands (a truncated op walk does not un-observe the
    // dispatch table — only global evidence taint moves dispatch).
    let mut h = Harness::fresh("h2-t2");
    h.snapshot_attached();
    // Companion file is small-ELF: two full test-binary copies
    // overflow the 128MiB round budget (R14 refuses the second
    // read), and this test needs both files read (size is
    // incidental to the op-localized taint it proves). Its
    // backing offset is its own X offset (plan rows validate the
    // offset against the file's bytes: past-EOF misses attach).
    let small2 = small_elf(0xA1);
    let staged2 = h.stage.write("prov2.so", &small2);
    h.maps.push(mapping(&staged2));
    h.files.insert(
        staged2.path.clone(),
        plan::FileBytes {
            bytes: small2.clone().into(),
            dev: staged2.device,
            ino: staged2.ino,
        },
    );
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let cand2 = cand(
        "/p/provider.so",
        backing_of(&staged2, x_offset(&small2)),
        2,
        12,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1, cand2],
        tables: vec![terminated(1, 0), terminated(2, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    // Close-time: op 1's final walk truncated (snapshot-only).
    h.snapshot.truncated_ops = vec![(1, 2)];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    assert_eq!(
        counter_value(&c, "discovery.truncated_walk"),
        1,
        "truncation must land as a D4 record: {:?}",
        c.document.counters
    );
    let mut saw_op1 = false;
    let mut saw_op2 = false;
    for scope in &c.document.coverage {
        match scope.scope.as_str() {
            "op:1" => {
                saw_op1 = true;
                assert!(
                    matches!(scope.expected, ExpectedScope::Unknown),
                    "truncated op must taint: {scope:?}"
                );
            }
            "op:2" => {
                saw_op2 = true;
                assert!(
                    matches!(scope.expected, ExpectedScope::Applicable { .. }),
                    "untruncated op must stand: {scope:?}"
                );
            }
            "dispatch" => {
                assert!(
                    matches!(scope.expected, ExpectedScope::Applicable { .. }),
                    "op-localized trunc leaves dispatch standing: {scope:?}"
                );
            }
            "legacy" => {}
            other => panic!("unexpected scope: {other}"),
        }
    }
    assert!(saw_op1 && saw_op2, "both ops must report");
    assert_eq!(c.document.sites.len(), 2, "one site per op");
    for site in &c.document.sites {
        let ops: Vec<u32> = site.candidates.iter().map(|id| id.op).collect();
        if ops.contains(&1) {
            assert_eq!(
                site.candidates_coverage,
                CandidateCoverage::Unknown,
                "op-1 site must revise"
            );
        } else {
            assert!(ops.contains(&2), "every site belongs to an op: {ops:?}");
            assert_eq!(
                site.candidates_coverage,
                CandidateCoverage::Complete,
                "op-2 site must stand"
            );
        }
    }
}

#[test]
fn h2_t6_relevance_cap_migrates_to_global_taint() {
    // H2/T6 (A13 migration): a capped relevance round may hide
    // any backing, so `relevance_capped > 0` taints GLOBALLY
    // (op denominators + dispatch + sites) — while the counter
    // itself stays as the D4 record. One cand references the
    // staged backing (attachable → real site); 256 more overflow
    // the 256 cap (staged sorts first, so it is kept).
    let mut h = Harness::fresh("h2-t6");
    h.snapshot_attached();
    let dev = plan::render_device(h.staged.device);
    let mut maps = vec![mapping(&h.staged)];
    let mut cands = vec![cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    )];
    for i in 0..256u64 {
        maps.push(Mapping {
            start: 0x7f00_0000_0000,
            end: 0x7f00_0000_1000,
            x: true,
            offset: 0,
            dev: dev.clone(),
            ino: 1_000_000 + i,
            path: format!("/x/mod{i:03}.so"),
        });
        cands.push(cand(
            "/p/provider.so",
            Some(BackingRef {
                dev: dev.clone(),
                ino: 1_000_000 + i,
                offset: h.off,
            }),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        ));
    }
    h.maps = maps;
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: cands,
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "257 backings over a 256 cap must report 1 dropped: {:?}",
        c.document.counters
    );
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            assert!(
                matches!(scope.expected, ExpectedScope::NotApplicable),
                "legacy scope must be untouched by H2: {scope:?}"
            );
        } else {
            assert!(
                matches!(scope.expected, ExpectedScope::Unknown),
                "relevance cap must taint globally: {scope:?}"
            );
        }
    }
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "relevance cap must revise sites"
        );
    }
}

#[test]
fn h2_t4_fenced_complete_revised_by_later_poll_taint() {
    // H2/T4 (B-3b): a generation sealed Complete is revisited
    // against final taint at close. A maps change fences gen 0
    // (3 calls, Complete — no taint exists yet); a LATER poll
    // localizes orphan-row loss to op 1; at close the fenced
    // site revises to Unknown. Poll order guarantees the fence
    // precedes the taint (one poll per round; fence at end of
    // round 3, loss adapted in round 4).
    let mut h = Harness::fresh("h2-t4");
    h.snapshot_attached();
    let newso = h.stage.write("new.so", &h.bytes.clone());
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&h.staged), mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        losses: vec![DiscoveryLoss {
            source: osslscope::discovery::coverage::HOST_ORPHAN_ROW,
            count: 1,
            op: Some(1),
        }],
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        5,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_500_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    // Two fences: the maps change seals gen 0 with real evidence;
    // the taint round itself stages an Unknown coverage update,
    // which (coverage ∈ meaning) fences an empty gen 1. The
    // gen-0 seal predates all taint — the revision target.
    assert_eq!(c.document.fenced.len(), 2);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites.len(), 1);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    assert_eq!(c.document.fenced[1].generation, 1);
    assert!(c.document.fenced[1].sites.is_empty());
    // Poll-time op-localized taint reaches the sealed claim.
    assert_eq!(
        c.document.fenced[0].sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "fenced Complete must revise under later poll taint"
    );
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "current site of a tainted op must not stand Complete"
        );
    }
    for scope in &c.document.coverage {
        match scope.scope.as_str() {
            "op:1" => assert!(
                matches!(scope.expected, ExpectedScope::Unknown),
                "tainted op keeps no denominator: {scope:?}"
            ),
            "dispatch" => assert!(
                matches!(scope.expected, ExpectedScope::Applicable { .. }),
                "op-localized poll taint leaves dispatch standing: {scope:?}"
            ),
            "legacy" => {}
            other => panic!("unexpected scope: {other}"),
        }
    }
}

#[test]
fn h2_t3_stale_seal_revised_at_close() {
    // H2/T3 (B-3a): a non-empty bucket sealed while a staged
    // Unknown re-emit pends. The seal reads live provenance
    // (Complete — pending applies post-seal), so the sealed
    // claim is stale at birth; close-time revision (B-3b) owns
    // final truth and the doc still reads Unknown. No fence
    // reorder: pending mixes identity changes (new generation's
    // meaning — must seal old) with coverage downgrades, so a
    // blanket pre-seal apply would smear new identity onto old
    // counts; the seal-time value is unobservable except via
    // the revised doc (see H2 design §2c amendment).
    let mut h = Harness::fresh("h2-t3");
    h.snapshot_attached();
    let newso = h.stage.write("new.so", &h.bytes.clone());
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&h.staged), mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        losses: vec![DiscoveryLoss {
            source: osslscope::discovery::coverage::HOST_ORPHAN_ROW,
            count: 1,
            op: Some(1),
        }],
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    // Fires during the taint round land in gen 1 under Complete
    // provenance (the plan fires before the loss delta adapts),
    // then the staged Unknown fences a NON-EMPTY bucket.
    h.plans.insert(
        4,
        FirePlan {
            fires: vec![(BASE_NS + 900_000_000, 2)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        5,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_500_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    assert_eq!(c.document.fenced.len(), 2);
    // The stale seal: non-empty, fenced by the taint round.
    assert_eq!(c.document.fenced[1].generation, 1);
    assert_eq!(c.document.fenced[1].sites.len(), 1);
    assert_eq!(c.document.fenced[1].sites[0].calls, 2);
    assert_eq!(
        c.document.fenced[1].sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "stale Complete seal must revise at close"
    );
    assert_eq!(
        c.document.fenced[0].sites[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "pre-taint seal must revise at close"
    );
}

#[test]
fn h3_t2_mixed_arrival_withholds_definite_claim_sticky() {
    // H3: a mixed-status arrival forces Unknown coverage with the
    // min label + weak preserved, sticky across re-walks (a
    // same-triple single re-walk never flips back — window
    // soundness: in-window ambiguity poisons the site's claim),
    // and counted once in discovery.mixed_classes (set
    // semantics, not per-arrival). Pre-split this degrades via
    // bad_read; the counter leg is the split's tripwire (RED
    // until the adapter re-homes mixed into sites_mixed).
    let mut h = Harness::fresh("h3-t2");
    h.snapshot_attached();
    let cand_mixed = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        true,
        "mixed",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_mixed],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    // Same-triple single re-walk: must not flip back, must not
    // double-count.
    let cand_single = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        true,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_single],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        3,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.mixed_classes"),
        1,
        "one mixed triple withheld exactly once: {:?}",
        c.document.counters
    );
    assert!(!c.document.sites.is_empty());
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "mixed site must not claim Complete"
        );
        // Min label + weak preserved (withheld, not dropped).
        assert!(
            site.candidates
                .iter()
                .any(|id| id.algorithm_classes.contains(&"SHA-256".to_string())),
            "min label must render: {:?}",
            site.candidates
        );
        assert!(
            site.candidates.iter().any(|id| id.weak_alias),
            "weak must survive mixed: {:?}",
            site.candidates
        );
    }
    // Denominators stand: ambiguity withholds definiteness, it
    // hides no sites (mixed is not loss).
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            continue;
        }
        assert!(
            matches!(scope.expected, ExpectedScope::Applicable { .. }),
            "mixed must not taint denominators: {scope:?}"
        );
    }
}

#[test]
fn h3_t6_fenced_mixed_survives_retrospective_revision_intact() {
    // H3 (extra, beyond design §4): the H2-T4 fence setup with
    // a MIXED gen-0 site. Mixed is already Unknown, so
    // retrospective revision is a no-op for it — and taint
    // composes, not flips: the fenced leg keeps its min label
    // + weak flag, calls intact, and the mixed_classes activity
    // survives alongside the taint.
    let mut h = Harness::fresh("h3-t4");
    h.snapshot_attached();
    let newso = h.stage.write("new.so", &h.bytes.clone());
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&h.staged), mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        true,
        "mixed",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        losses: vec![DiscoveryLoss {
            source: osslscope::discovery::coverage::HOST_ORPHAN_ROW,
            count: 1,
            op: Some(1),
        }],
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        5,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_500_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    // ONE fence, not H2-T4's two: the taint round's Unknown
    // update lands on an already-Unknown mixed site
    // (Unknown→Unknown is no coverage change, so it stages no
    // second fence — mixed absorbs taint silently). The gen-0
    // seal predates all taint — the revision target.
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites.len(), 1);
    let leg = &c.document.fenced[0].sites[0];
    assert_eq!(leg.calls, 3);
    assert_eq!(
        leg.candidates_coverage,
        CandidateCoverage::Unknown,
        "fenced mixed leg stays Unknown under later taint"
    );
    assert!(
        leg.candidates
            .iter()
            .any(|id| id.algorithm_classes.contains(&"SHA-256".to_string())),
        "revision must not strip the min label: {:?}",
        leg.candidates
    );
    assert!(
        leg.candidates.iter().any(|id| id.weak_alias),
        "revision must not strip weak: {:?}",
        leg.candidates
    );
    assert_eq!(
        counter_value(&c, "discovery.mixed_classes"),
        1,
        "mixed activity survives alongside taint: {:?}",
        c.document.counters
    );
}

#[test]
fn h3_t5_mixed_counter_counts_distinct_triples() {
    // H3: discovery.mixed_classes counts DISTINCT withheld
    // triples (two mixed triples → 2, one mixed + one clean →
    // 1); clean runs show zero. Activity (ambiguity audit),
    // never loss — mixed must not force PARTIAL by itself.
    for (name, statuses, want) in [
        ("h3-t5-two", ["mixed", "mixed"], 2),
        ("h3-t5-one", ["mixed", "ok"], 1),
        ("h3-t5-clean", ["ok", "ok"], 0),
    ] {
        let mut h = Harness::fresh(name);
        h.snapshot_attached();
        // Both staged files share IDENTICAL small-ELF bytes at the
        // SAME X offset (distinct inodes): the counter counts
        // physical triples, so a (fingerprint, offset)-pair counter
        // must NOT satisfy 2/1/0. (Two full test-binary copies
        // overflow the 128MiB round budget; plan rows validate the
        // offset against the file's bytes.)
        let small = small_elf(0xB2);
        let off = x_offset(&small);
        h.files.insert(
            h.staged.path.clone(),
            plan::FileBytes {
                bytes: small.clone().into(),
                dev: h.staged.device,
                ino: h.staged.ino,
            },
        );
        let staged2 = h.stage.write("prov2.so", &small);
        h.maps.push(mapping(&staged2));
        h.files.insert(
            staged2.path.clone(),
            plan::FileBytes {
                bytes: small.clone().into(),
                dev: staged2.device,
                ino: staged2.ino,
            },
        );
        // Validity pin: this test proves nothing unless the served
        // companions share fingerprint bytes AND offset at distinct
        // inodes — a silent drift here stays green on the 2/1/0
        // assertions while unproving the physical-triple claim.
        let f1 = h.files.get(&h.staged.path).unwrap();
        let f2 = h.files.get(&staged2.path).unwrap();
        assert_eq!(
            osslscope::discovery::elf::read_build_id(&f1.bytes).unwrap(),
            osslscope::discovery::elf::read_build_id(&f2.bytes).unwrap(),
            "{name}: staged companions must share fingerprint bytes"
        );
        assert_eq!(
            x_offset(&f1.bytes),
            x_offset(&f2.bytes),
            "{name}: staged companions must share the X offset"
        );
        assert_ne!(
            h.staged.ino, staged2.ino,
            "{name}: staged companions must keep distinct inodes"
        );
        let cand1 = cand(
            "/p/provider.so",
            backing_of(&h.staged, off),
            1,
            11,
            "SHA-256",
            false,
            statuses[0],
        );
        let cand2 = cand(
            "/p/provider.so",
            backing_of(&staged2, off),
            2,
            12,
            "SHA-256",
            false,
            statuses[1],
        );
        // Baseline attach (pre-release ready — F7: post-release
        // attaches of pre-release mappings gap now).
        h.polls.push_back(DiscoveryDelta {
            candidates: vec![cand1, cand2],
            tables: vec![terminated(1, 0), terminated(2, 0)],
            trigger_observed: true,
            ..DiscoveryDelta::default()
        });
        h.polls.push_back(DiscoveryDelta::default());
        h.plans.insert(
            2,
            FirePlan {
                fires: vec![(BASE_NS + 600_000_000, 7)],
                shortfall: 0,
                cancel: false,
            },
        );
        h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
        h.exit_code = 0;
        let (out, _) = h.run();
        let c = out.unwrap();
        assert_eq!(
            counter_value(&c, "discovery.mixed_classes"),
            want,
            "{name}: withheld distinct triples"
        );
        if want == 0 {
            assert!(
                matches!(c.document.status, Completeness::Complete),
                "{name}: clean runs keep prior behavior"
            );
        }
    }
}

#[test]
fn untracked_epoch_executions_are_unattributed_partial() {
    // F3: op 1 provably terminates epoch 0 while a same-window
    // candidate arrives for epoch 9 with zero table proof for
    // epoch 9 anywhere. The unproven site must NOT inherit
    // Complete: its executed calls are unattributed PARTIAL (the
    // op row stays Applicable — coverage alone cannot catch an
    // epoch the tables never observed).
    let mut h = Harness::fresh("untracked-exec");
    h.snapshot_attached();
    // Companion file is small-ELF (two full test-binary copies
    // overflow the 128MiB round budget; plan rows validate the
    // offset against the file's bytes).
    let small2 = small_elf(0xC3);
    let prov2 = h.stage.write("prov2.so", &small2);
    h.files.insert(
        prov2.path.clone(),
        plan::FileBytes {
            bytes: small2.clone().into(),
            dev: prov2.device,
            ino: prov2.ino,
        },
    );
    h.maps = vec![mapping(&h.staged), mapping(&prov2)];
    let cand_a = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let mut cand_b = cand(
        "/p/prov2.so",
        backing_of(&prov2, x_offset(&small2)),
        1,
        12,
        "SHA-512",
        false,
        "ok",
    );
    cand_b.epoch = 9;
    // Baseline attach (pre-release ready — F7 keeps this test's
    // focus on epoch coverage, not attach timing).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_a, cand_b],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(has_reason(&c, "unattributed"), "{:?}", c.reasons);
    assert!(
        matches!(c.document.status, Completeness::Partial { .. }),
        "{:?}",
        c.document.status
    );
    assert_eq!(c.document.total_calls(), 14);
    assert!(!has_reason(&c, "late-attach"), "{:?}", c.reasons);
    let unknown: Vec<_> = c
        .document
        .sites
        .iter()
        .filter(|s| s.candidates_coverage == CandidateCoverage::Unknown)
        .collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].calls, 7);
    let cov1 = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .unwrap();
    assert!(
        matches!(cov1.expected, ExpectedScope::Applicable { .. }),
        "{cov1:?}"
    );
}

#[test]
fn startup_gap_pid_target_reports_gap() {
    // Requested (acquisition) precedes the programmed window start:
    // explicit startup gap, never a silent late clock.
    let mut h = Harness::fresh("startup-gap");
    h.owned = false;
    h.acquired_ns = BASE_NS - 500_000_000;
    h.snapshot_attached();
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(has_reason(&c, "startup-gap"), "{:?}", c.reasons);
    assert!(has_reason(&c, "pid-prewindow-blind"), "{:?}", c.reasons);
    assert_eq!(c.document.window.requested_start_ns, BASE_NS - 500_000_000);
    assert_eq!(c.document.window.effective_start_ns, BASE_NS);
    assert_eq!(c.document.window.startup_gap_ns(), 500_000_000);
}

#[test]
fn already_exited_child_preserves_status() {
    // Fast command: exits right after release — exit 7 preserved,
    // disposition Exited, no tail gap, no zombie (fake custody log
    // shows the normal finish path).
    let mut h = Harness::fresh("fast-exit");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 1);
    h.exit_code = 7;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert!(!has_reason(&c, "tail-gap"), "{:?}", c.reasons);
    // No trigger ever observed: clean no-query PARTIAL, not a fatal
    // and not a silent empty COMPLETE.
    assert!(has_reason(&c, "no-query"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial));
    let log = post.target_log.borrow();
    assert!(log.released);
    assert!(log.finished);
    assert!(log.polls >= 1);
}

#[test]
fn failed_attach_diagnostic_reaches_document() {
    // R06 (attach diagnostics, end-to-end): a failed attach's
    // diagnostic text flows poll → adapter → document (the
    // systematic-1 attach failure identifies itself in JSON).
    let mut h = Harness::fresh("attach-diag");
    h.snapshot_attached();
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        attaches: vec![AttachEvent {
            kind: AttachKind::Stage2 { cookie: 7 },
            failed: Some("EBUSY".to_string()),
        }],
        ..DiscoveryDelta::default()
    });
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.attach_diagnostics, vec!["EBUSY".to_string()]);
}

#[test]
fn live_maps_loss_before_predelta_failure_stays_loss() {
    // Round 3, residual D (review's schedule): a live poll
    // records a maps-read loss, then fails planning pre-delta
    // (nothing adapts); salvage runs; the target — dead during
    // the failing poll — dispositions Exited. The poll-phase
    // loss is genuine live loss: it must stay a Loss counter
    // (and keep its `discovery-loss` taint), never relabel as
    // Activity from the eventual Exited disposition. (Runtime
    // fatal still prevents false COMPLETE — this pins the
    // classification half.)
    let mut h = Harness::fresh("d-live-loss");
    h.snapshot_attached();
    // Setup poll (idx 0) succeeds; the first round poll (idx 1)
    // fails pre-delta while live. Its scripted latency carries
    // the clock past the exit — death during the failing poll —
    // so salvage dispositions Exited.
    h.poll_err_at.insert(1);
    h.poll_delay_ns.insert(1, 1_500_000_000);
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    // The failed poll's maps loss: poll-phase (no close-phase
    // tag — the close never recorded it).
    h.snapshot.losses = vec![(osslscope::discovery::coverage::HOST_MAPS_READ, 1)];
    assert_eq!(h.snapshot.maps_loss_close, 0);
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(
        matches!(
            c.disposition,
            Some(target::TargetDisposition::Exited { code: 0 })
        ),
        "schedule must salvage under Exited: {:?}",
        c.disposition
    );
    assert!(
        matches!(c.outcome, Outcome::Fatal(_)),
        "salvage stays fatal: {:?}",
        c.outcome
    );
    let maps = c
        .document
        .counters
        .iter()
        .find(|c| c.name == "discovery.maps_read")
        .expect("D4 record preserved");
    assert_eq!(
        maps.kind,
        osslscope::evidence::CounterKind::Loss,
        "live poll-phase maps loss is Loss, never Activity: {maps:?}"
    );
    assert!(
        has_reason(&c, "discovery-loss"),
        "poll-phase residual keeps its taint: {:?}",
        c.reasons
    );
}

#[test]
fn owned_exit_close_join_skip_is_not_a_gap() {
    // R21-F1: a reaped owned child cannot execute past its death,
    // so the skipped final join (the pin check misreads the gone
    // /proc entry as a recycle) is inapplicable, not missed — the
    // clean owned-exit shape reaches COMPLETE with the skip
    // recorded as an Activity counter (audit trail), never a Loss.
    // (The over-budget and --pid startup-gap forcers stand: expiry
    // is PARTIAL by PRD, pre-window --pid blindness is honest.)
    // Round 2: the fixture carries the production post-reap maps
    // residual too (HOST_MAPS_READ close single — every clean
    // owned exit produces it; a COMPLETE pin without it is
    // vacuous) — also Activity, never Loss.
    let mut h = Harness::fresh("exit-recycle-complete");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.finish_recycled = true;
    // Production post-reap residual: the discovery close reads
    // maps after the child is reaped (/proc gone) — the benign
    // close-only single. Round 3, residual D: seeded with its
    // close-phase tag (the production close recorded it before
    // erroring with the staged final).
    h.snapshot.losses = vec![(osslscope::discovery::coverage::HOST_MAPS_READ, 1)];
    h.snapshot.maps_loss_close = 1;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
    assert!(c.reasons.is_empty(), "{:?}", c.reasons);
    assert!(matches!(c.document.status, Completeness::Complete));
    assert_eq!(counter_value(&c, "discovery.close_join_skipped"), 1);
    assert_eq!(counter_value(&c, "discovery.maps_read"), 1);
    let maps = c
        .document
        .counters
        .iter()
        .find(|c| c.name == "discovery.maps_read")
        .expect("D4 record preserved");
    assert_eq!(
        maps.kind,
        osslscope::evidence::CounterKind::Activity,
        "the benign post-reap single is audit trail, not Loss: {maps:?}"
    );
}

#[test]
fn owned_exit_survives_spurious_recycle_at_finish() {
    // Owned child exits mid-window and is reaped before the
    // discovery close, whose pin check then misreads the gone
    // /proc entry as a recycle. The capture survives on the
    // pre-close snapshot: exit and disposition preserved, the
    // skipped final join an explicit Activity counter — never a
    // lost capture. (PARTIAL here via no-query: no trigger ever
    // observed — not via the skipped join; see
    // owned_exit_close_join_skip_is_not_a_gap.)
    let mut h = Harness::fresh("exit-recycle");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.exit_code = 7;
    h.finish_recycled = true;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert_eq!(counter_value(&c, "discovery.close_join_skipped"), 1);
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(post.target_log.borrow().finished);
}

#[test]
fn spurious_recycle_prefers_close_time_final() {
    // Same spurious recycle, but the backend stages a close-time
    // final (pre-wipe joins + tail count): the capture assembles
    // from the final, not the pre-close snapshot, so the close-time
    // magnitude reaches the doc instead of dying with the wipe.
    let mut h = Harness::fresh("exit-recycle-final");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.exit_code = 7;
    h.finish_recycled = true;
    h.finish_final = Some(DiscoverySnapshot {
        queries_observed: 9,
        ..DiscoverySnapshot::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert_eq!(counter_value(&c, "discovery.close_join_skipped"), 1);
    assert_eq!(counter_value(&c, "discovery.queries_observed"), 9);
    assert!(matches!(c.outcome, Outcome::Partial));
}

#[test]
fn lifecycle_exec_is_fence_tracked_not_ignored() {
    // One round observes a Fork and an Exec sweep event: only the
    // fork counts as ignored (untracked child); the target's own
    // exec is fence-tracked by the snapshot generation, so counting
    // it here would double-book the observed spawn-exec as ignored.
    let mut h = Harness::fresh("fork-exec-count");
    h.snapshot_attached();
    // Exit lands in the second sleep: exactly one round runs (the
    // sweep under test), then the loop breaks and closes.
    h.exit_at_ns = Some(BASE_NS + 250_000_001);
    h.exit_code = 0;
    h.lifecycle_polls.push_back(LifecycleDelta {
        events: vec![
            LifecycleEvent {
                kind: LifecycleKind::Fork,
                pid: 99991,
                timestamp_ns: Some(BASE_NS + 1),
            },
            LifecycleEvent {
                kind: LifecycleKind::Exec,
                pid: PID,
                timestamp_ns: Some(BASE_NS + 1),
            },
        ],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(counter_value(&c, "lifecycle.fork_exec_ignored"), 1);
}

#[test]
fn final_sweep_skipped_after_owned_exit() {
    // The owned child exits after one round; the close-time sweep
    // is skipped (the child is reaped: nothing to scan but the
    // sweep's own unreadable-exe loss), so a loss-bearing staged
    // final poll never reaches the doc.
    let mut h = Harness::fresh("skip-sweep-exited");
    h.snapshot_attached();
    // Exit lands in the first sleep: zero rounds run, so the only
    // lifecycle consumer is the close-time sweep — which must skip
    // (the child is reaped), leaving the staged loss poll unread.
    h.exit_at_ns = Some(BASE_NS + 1);
    h.exit_code = 0;
    h.lifecycle_polls.push_back(LifecycleDelta {
        events: vec![],
        loss: 1,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(0));
    assert_eq!(counter_value(&c, "lifecycle.scan_loss"), 0);
}

#[test]
fn final_sweep_runs_while_target_lives() {
    // Guard: the window cut by a signal (no rounds run, child
    // alive) still sweeps at close — the skip above must not starve
    // the live path.
    let mut h = Harness::fresh("sweep-alive");
    h.snapshot_attached();
    // Cancel lands during the first round's discovery poll (idx 1;
    // idx 0 is the setup baseline): the round's sweep consumes the
    // clean poll, the loop cuts, and the close-time sweep consumes
    // the loss poll — the skip above must not starve this path.
    h.cancel_on_poll = true;
    h.plans.insert(
        1,
        FirePlan {
            fires: Vec::new(),
            shortfall: 0,
            cancel: true,
        },
    );
    h.lifecycle_polls.push_back(LifecycleDelta::default());
    h.lifecycle_polls.push_back(LifecycleDelta {
        events: vec![],
        loss: 1,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(c.document.window.signal_cut);
    assert_eq!(counter_value(&c, "lifecycle.scan_loss"), 1);
}

#[test]
fn corpse_close_goes_through_custody() {
    // Empty maps with an exit landing inside the bounded wait: the
    // round closes through custody (no raw waitpid, no fence on the
    // corpse, no discovery poll past the death).
    let mut h = Harness::fresh("corpse");
    h.snapshot_attached();
    let mapped = vec![mapping(&h.staged)];
    h.maps_seq = VecDeque::from([mapped, vec![]]);
    h.exit_at_ns = Some(BASE_NS + 255_000_000);
    h.exit_code = 7;
    h.polls.push_back(DiscoveryDelta::default());
    // Poll 1 runs only if the round polls past the corpse.
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert!(has_reason(&c, "no-query"), "{:?}", c.reasons);
}

#[test]
fn setup_failure_resolves_custody() {
    // Release fails with a live child: loud error, custody resolved
    // (never a stopped child left behind).
    let mut h = Harness::fresh("setup-fail");
    h.release_err = true;
    let (out, post) = h.run();
    assert!(out.is_err(), "release failure must be loud");
    let log = post.target_log.borrow();
    assert!(!log.released);
    assert!(log.resolved);
}

#[test]
fn known_dead_child_preserves_exit_without_release_or_resolution() {
    // The pre-release status poll already reaped this child. Neither an
    // attempted release nor another custody resolution is necessary.
    let mut h = Harness::fresh("dead-release");
    h.release_err = true;
    h.exit_at_ns = Some(0);
    h.exit_code = 7;
    let (out, post) = h.run();
    let error = out.unwrap_err();
    let failure = error
        .downcast_ref::<osslscope::capture::PreObservationFailure>()
        .unwrap();
    assert_eq!(
        failure.cause,
        osslscope::capture::PreObservationCause::NeverReleasedExit
    );
    assert_eq!(failure.custody.child_exit, Some(7));
    assert!(matches!(
        failure.custody.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert!(matches!(
        failure.count,
        osslscope::capture::PreObservationCount::Terminal(_)
    ));
    assert!(failure.release.is_none());
    assert!(failure.failure.is_none());
    assert!(!post.target_log.borrow().released);
    assert!(!post.target_log.borrow().resolved);
}

#[test]
fn owned_comm_settles_post_release() {
    // Acquisition snapshots comm while the child is stopped
    // pre-exec; the post-release refresh settles the application
    // identity instead of reporting the observer's comm.
    let mut h = Harness::fresh("comm-settle");
    h.snapshot_attached();
    h.comm = Some("sleep-app".to_string());
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.target_comm, "sleep-app");
}

#[test]
fn corpse_close_keeps_settled_comm() {
    // F9: exec settles the comm after release but before a fast
    // exit; the corpse path reaps, after which no post-hoc comm
    // read exists. The pre-reap settle must capture the post-exec
    // comm through observe() — never the pre-exec observer comm.
    // (Non-static fake comm: the flip is clock-driven.)
    let mut h = Harness::fresh("comm-corpse");
    h.snapshot_attached();
    h.comm = Some("test-target".to_string());
    h.comm_settle_at_ns = Some(BASE_NS + 100_000_000);
    h.comm_settled = Some("fast-app".to_string());
    let mapped = vec![mapping(&h.staged)];
    h.maps_seq = VecDeque::from([mapped, vec![]]);
    h.exit_at_ns = Some(BASE_NS + 255_000_000);
    h.exit_code = 7;
    h.polls.push_back(DiscoveryDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert_eq!(c.target_comm, "fast-app");
}

#[test]
fn comm_settling_during_corpse_wait_is_observed() {
    // F9: the exec settles while the corpse wait is already
    // polling and the exit lands later in the same wait. Only a
    // settle before each wait poll observes it — a post-reap read
    // cannot exist.
    let mut h = Harness::fresh("comm-wait");
    h.snapshot_attached();
    h.comm = Some("test-target".to_string());
    h.comm_settle_at_ns = Some(BASE_NS + 260_000_000);
    h.comm_settled = Some("late-app".to_string());
    let mapped = vec![mapping(&h.staged)];
    h.maps_seq = VecDeque::from([mapped, vec![]]);
    h.exit_at_ns = Some(BASE_NS + 300_000_000);
    h.exit_code = 7;
    h.polls.push_back(DiscoveryDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert_eq!(c.target_comm, "late-app");
}

#[test]
fn owned_comm_late_settle_observed_through_observe() {
    // F9: a slow exec settles several rounds after release while
    // the child lives on. The per-round settle must pick the
    // post-exec comm up through observe() with a non-static fake
    // comm (clock-driven flip, not a read-count script).
    let mut h = Harness::fresh("comm-late");
    h.snapshot_attached();
    h.comm = Some("test-target".to_string());
    h.comm_settle_at_ns = Some(BASE_NS + 600_000_000);
    h.comm_settled = Some("slow-app".to_string());
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.polls.push_back(DiscoveryDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(0));
    assert_eq!(c.target_comm, "slow-app");
}

#[test]
fn setup_discovery_failure_is_loud() {
    // Baseline discovery poll fails: loud error, sessions dropped,
    // custody resolved.
    let mut h = Harness::fresh("setup-poll");
    h.poll_err_at.insert(0);
    let (out, post) = h.run();
    assert!(out.is_err());
    assert!(post.target_log.borrow().resolved);
}

#[test]
fn signal_during_setup_cuts_cleanly() {
    // Cancelled before release: the never-released child resolves
    // (never left stopped), with typed cancellation, actual SIGKILL status and retained custody.
    let h = Harness::fresh("setup-cancel");
    h.cancelled.set(true);
    let (out, post) = h.run();
    let error = out.unwrap_err();
    let failure = error
        .downcast_ref::<osslscope::capture::PreObservationFailure>()
        .unwrap();
    assert_eq!(
        failure.cause,
        osslscope::capture::PreObservationCause::Cancelled
    );
    assert!(failure.failure.is_none());
    assert!(failure.release.is_none());
    assert_eq!(failure.custody.child_exit, Some(137));
    assert!(matches!(
        failure.custody.disposition,
        Some(target::TargetDisposition::Exited { code: 137 })
    ));
    assert!(matches!(
        failure.count,
        osslscope::capture::PreObservationCount::Terminal(_)
    ));
    let log = post.target_log.borrow();
    assert!(!log.released);
    assert!(log.resolved);
}

#[test]
fn zero_setup_timeout_resolves_without_window() {
    // R06: a zero setup timeout (admitted `--timeout 0`) fails setup
    // before release: loud error, custody resolved, never released.
    let mut h = Harness::fresh("setup-timeout");
    h.cfg.harvest_timeout = Duration::ZERO;
    let (out, post) = h.run();
    let error = out.expect_err("zero setup timeout must fail");
    let failure = error
        .downcast_ref::<osslscope::capture::PreObservationFailure>()
        .unwrap();
    let boundary = failure.failure.as_ref().unwrap();
    assert_eq!(boundary.stage, osslscope::capture::BoundaryStage::Setup);
    assert_eq!(
        boundary.class,
        osslscope::capture::BoundaryFailureClass::Timeout
    );
    assert_eq!(boundary.errno, None);
    let log = post.target_log.borrow();
    assert!(!log.released);
    assert!(log.resolved);
}

#[test]
fn signal_cut_mid_window_is_partial() {
    // Cancelled mid-window: counting still closes before the final
    // discovery drain, SignalCut recorded, running child detached
    // (left running, never killed).
    let mut h = Harness::fresh("sigcut");
    h.snapshot_attached();
    h.cancel_on_poll = true;
    h.plans.insert(
        2,
        FirePlan {
            fires: Vec::new(),
            shortfall: 0,
            cancel: true,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(has_reason(&c, "interrupted"), "{:?}", c.reasons);
    assert!(c.document.window.signal_cut);
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Detached { pid: PID })
    ));
    // Close order: counting closed before the discovery finish.
    let log = post.shared.borrow();
    let closed = log.log.iter().position(|l| l == "count_closed").unwrap();
    let finished = log
        .log
        .iter()
        .position(|l| l == "discovery_finished")
        .unwrap();
    assert!(closed < finished, "{:?}", log.log);
    let tlog = post.target_log.borrow();
    assert!(tlog.released);
    assert!(tlog.finished);
}

#[test]
fn recycled_pid_is_fatal_and_discarded() {
    // Foreign pin fails mid-window: fatal recycle, every observation
    // discarded, no disposition for a target never owned.
    let mut h = Harness::fresh("recycled");
    h.owned = false;
    h.snapshot_attached();
    h.verify_err_after = Some(3);
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(post.target_log.borrow().verify_calls >= 3);
    assert!(matches!(c.outcome, Outcome::Fatal(_)), "{:?}", c.outcome);
    assert!(matches!(c.document.status, Completeness::Fatal { .. }));
    assert!(has_reason(&c, "pid-recycled"), "{:?}", c.reasons);
    assert!(c.document.sites.is_empty());
    assert!(c.executions.is_empty());
    assert!(c.disposition.is_none());
}

#[test]
fn no_query_without_trigger() {
    // Nothing ever fires: clean no-query PARTIAL (never AttachZero
    // fatal — nothing was expected to attach).
    let mut h = Harness::fresh("noquery");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert_eq!(c.reasons, vec!["no-query".to_string()]);
}

#[test]
fn attach_zero_when_nothing_attaches() {
    // A discovered site that never plans (backing absent from every
    // mapping) is fatal AttachZero with loud misses.
    let mut h = Harness::fresh("attachzero");
    h.snapshot_attached();
    let orphan = cand(
        "/p/gone.so",
        Some(osslscope::discovery::session::BackingRef {
            dev: "08:01".to_string(),
            ino: 999_999,
            offset: 0x100,
        }),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![orphan],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Fatal(_)), "{:?}", c.outcome);
    assert!(has_reason(&c, "missed-attaches"), "{:?}", c.reasons);
    assert!(c.counters.missed_attaches > 0);
}

// ---------------------------------------------------------------------------
// Incremental discovery, legacy baselining, deadlines.
// ---------------------------------------------------------------------------

#[test]
fn late_provider_operation_attaches_with_loss() {
    // A new op on a long-present mapping past settle: still attached
    // (evidence preserved) but explicit late-attach loss; a fresh
    // dlopen in the same window is activity, not loss.
    let mut h = Harness::fresh("late-op");
    h.snapshot_attached();
    let prov2 = h.stage.write("prov2.so", &h.bytes.clone());
    let newso = h.stage.write("new.so", &h.bytes.clone());
    h.files.insert(
        prov2.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: prov2.device,
            ino: prov2.ino,
        },
    );
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let steady = vec![mapping(&h.staged), mapping(&prov2)];
    let dlopen = vec![mapping(&h.staged), mapping(&prov2), mapping(&newso)];
    h.maps_seq = VecDeque::from([
        steady.clone(),
        steady.clone(),
        steady.clone(),
        steady.clone(),
        steady.clone(),
        dlopen.clone(),
    ]);
    h.maps = dlopen;
    let cand_a = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let cand_b = cand(
        "/p/prov2.so",
        backing_of(&prov2, h.off),
        9,
        91,
        "ML-KEM",
        false,
        "ok",
    );
    let cand_c = cand(
        "/p/new.so",
        backing_of(&newso, h.off),
        9,
        92,
        "ML-DSA",
        false,
        "ok",
    );
    // Poll index == round index (one poll per round): the op-9
    // candidates arrive post-settle (round ≥4 ≈ 1s, settle 500ms).
    // The op-1 site attaches at the BASELINE poll (pre-release
    // ready — R20-fix round 2, F7: a post-release attach of a
    // pre-release mapping gaps even inside the settle grace).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_a],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_b],
        tables: vec![in_progress(9, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_c],
        tables: vec![in_progress(9, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert_eq!(counter_value(&c, "discovery.late_attach_sites"), 1);
    assert!(has_reason(&c, "late-attach"), "{:?}", c.reasons);
    assert_eq!(counter_value(&c, "discovery.new_mapping_sites"), 1);
    // Both late sites still attached (evidence preserved).
    let cov = |scope: &str| {
        c.document
            .coverage
            .iter()
            .find(|s| s.scope == scope)
            .unwrap()
            .clone()
    };
    assert_eq!(cov("op:1").attached, 1);
    assert_eq!(cov("op:9").attached, 2);
    assert_eq!(cov("op:9").discovered, 2);
}

#[test]
fn prewindow_vs_inwindow_engine() {
    // Baseline-poll ENGINE tripwire is pre-window (dropped);
    // in-window tripwire becomes legacy evidence. Cumulative
    // snapshot decoys prove the controller uses its own baselined
    // accumulation, never the snapshot totals.
    use osslscope::discovery::legacy::{Probe, ProbeSet};
    use osslscope_ebpf_common as wire;
    let mut h = Harness::fresh("engine-window");
    h.owned = false;
    h.snapshot_attached();
    let set = ProbeSet {
        probes: vec![Probe {
            cookie: 7,
            symbol: "ENGINE_by_id".to_string(),
            offset: 0x100,
            module: "/p/libcrypto.so.3".to_string(),
            family: None,
            str_arg: None,
            program: "trip_count",
        }],
        engine_uninstrumented: 0,
        meth_uninstrumented: 0,
        lowlevel_uninstrumented: 0,
        unprobed_engine_syms: Vec::new(),
        unprobed_meth_syms: Vec::new(),
        unprobed_lowlevel_syms: Vec::new(),
        findings: Vec::new(),
        address_taken: Vec::new(),
        by_id_cookies: HashSet::from([7]),
        load_cookies: HashSet::new(),
        libcrypto: None,
    };
    h.snapshot.legacy.set = Some(set);
    h.snapshot.legacy.planned = true;
    h.snapshot.legacy.trip = HashMap::from([(7, 999)]);
    h.snapshot.legacy.executed_queries = 999;
    let hit = || osslscope::discovery::legacy::TripHit {
        cookie: 7,
        class: wire::ENGINE_DYNAMIC,
        status: wire::TRIP_OK,
    };
    h.polls.push_back(DiscoveryDelta {
        queries_delta: 9,
        tripwire: TripwireDelta {
            hits: vec![hit(), hit(), hit()],
            counter_deltas: vec![(7, 3)],
            executed_legacy_queries_delta: 2,
        },
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta {
        tripwire: TripwireDelta {
            hits: vec![hit(), hit(), hit(), hit(), hit()],
            counter_deltas: vec![(7, 5)],
            executed_legacy_queries_delta: 4,
        },
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        c.legacy["engine"]["calls_by_entrypoint"]["ENGINE_by_id"],
        serde_json::json!(5)
    );
    assert_eq!(
        c.legacy["legacy_provider"]["executed_queries"],
        serde_json::json!(4)
    );
    assert_eq!(
        c.legacy["engine"]["engine_id_class"]["dynamic"],
        serde_json::json!(5)
    );
    // Pre-window queries are cold gap (loud), never in-window.
    assert_eq!(c.counters.cold_gap_calls, 9);
    assert!(has_reason(&c, "cold-gap"), "{:?}", c.reasons);
    // The same snapshot decoys pin the close-tail residual: snapshot
    // minus baseline minus in-window becomes explicit loss (never
    // silent execution, never a silent drop).
    assert_eq!(counter_value(&c, "legacy.close_tail_trip"), 999 - 3 - 5);
    assert_eq!(counter_value(&c, "legacy.close_tail_lgcalls"), 999 - 2 - 4);
}

#[test]
fn transient_load_hits_are_loads_not_executions() {
    // Provider-load tripwire hits (a transient load witness) count
    // as loads; only the executed-query ledger becomes execution.
    use osslscope::discovery::legacy::{Probe, ProbeSet};
    use osslscope_ebpf_common as wire;
    let mut h = Harness::fresh("loads");
    h.snapshot_attached();
    let set = ProbeSet {
        probes: vec![Probe {
            cookie: 9,
            symbol: "OSSL_PROVIDER_load".to_string(),
            offset: 0x200,
            module: "/p/libcrypto.so.3".to_string(),
            family: None,
            str_arg: Some(0),
            program: "trip_str0",
        }],
        engine_uninstrumented: 0,
        meth_uninstrumented: 0,
        lowlevel_uninstrumented: 0,
        unprobed_engine_syms: Vec::new(),
        unprobed_meth_syms: Vec::new(),
        unprobed_lowlevel_syms: Vec::new(),
        findings: Vec::new(),
        address_taken: Vec::new(),
        by_id_cookies: HashSet::new(),
        load_cookies: HashSet::from([9]),
        libcrypto: None,
    };
    h.snapshot.legacy.set = Some(set);
    h.snapshot.legacy.planned = true;
    let hit = || osslscope::discovery::legacy::TripHit {
        cookie: 9,
        class: wire::LOAD_LEGACY,
        status: wire::TRIP_OK,
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        tripwire: TripwireDelta {
            hits: vec![hit(), hit()],
            counter_deltas: vec![(9, 2)],
            executed_legacy_queries_delta: 0,
        },
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        c.legacy["legacy_provider"]["loads"]["legacy"],
        serde_json::json!(2)
    );
    assert_eq!(
        c.legacy["legacy_provider"]["executed_queries"],
        serde_json::json!(0)
    );
}

#[test]
fn deadline_during_busy_discovery() {
    // A permanently busy ring cannot starve the deadline: catch-up
    // polls stay capped, the programmed kernel deadline drops
    // post-deadline executions, and teardown still runs.
    let mut h = Harness::fresh("busy");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let busy = DiscoveryDelta {
        budget_exhausted: true,
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.extend(burst(busy, 200));
    h.plans.insert(
        1,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 5)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        20,
        FirePlan {
            fires: vec![(BASE_NS + 1_500_000_000, 7), (BASE_NS + 2_000_000_001, 99)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    // Post-deadline executions are forbidden (kernel-admission proof).
    assert_eq!(c.document.total_calls(), 12);
    assert_eq!(c.counters.over_budget, 1);
    assert!(c.counters.scan_budget_exhaustions >= 1);
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(post.target_log.borrow().finished);
    // The kernel deadline was programmed exactly.
    let programmed = post.shared.borrow().backend.programmed().to_vec();
    assert_eq!(
        programmed,
        vec![(PID as u64, 0, BASE_NS, BASE_NS + 2_000_000_000)]
    );
}

#[test]
fn delayed_metadata_io_still_meets_deadline() {
    // 300ms metadata reads mid-round: the loop still closes at the
    // deadline, and no post-deadline execution is admitted. A second
    // cell pins the over-budget skip path (300ms /proc reads exceed
    // the 50ms round budget): skipped rounds still terminate.
    let mut h = Harness::fresh("slow-io");
    h.snapshot_attached();
    h.file_delay_ns = 300_000_000;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        1,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 5)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        3,
        FirePlan {
            fires: vec![(BASE_NS + 1_500_000_000, 2), (BASE_NS + 2_000_000_001, 50)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.counters.over_budget, 1);
    assert_eq!(c.document.total_calls(), 7);
    assert!(post.target_log.borrow().finished);

    let mut slow = Harness::fresh("slow-io-skip");
    slow.snapshot_attached();
    slow.maps_delay_ns = 300_000_000;
    let (out, _) = slow.run();
    let c = out.unwrap();
    assert!(c.counters.scan_budget_exhaustions >= 1);
    assert_eq!(c.counters.over_budget, 1);
    assert!(matches!(c.outcome, Outcome::Partial));
}

#[test]
fn slow_metadata_past_deadline_admits_no_tripwire() {
    // 300ms metadata reads cross the 1900ms deadline mid-round (at
    // ~1650ms the sleep has not crossed, the maps read does): the
    // round expires BEFORE polling, so the scripted post-deadline
    // ENGINE tripwire never becomes in-window legacy evidence.
    // `--pid` keeps the loop deadline fixed (no clamp interaction):
    // this pins the mid-round recheck alone.
    use osslscope::discovery::legacy::{Probe, ProbeSet};
    use osslscope_ebpf_common as wire;
    let mut h = Harness::fresh("slow-trip");
    h.owned = false;
    h.cfg.duration = Duration::from_millis(1900);
    h.snapshot_attached();
    // Slow metadata via the maps read (F-D/A13): file reads are
    // relevance-gated now and these polls reference nothing, so
    // file_delay would no longer advance the clock here. The maps
    // read is unconditional every round — same cadence, same
    // 300ms/round crossing.
    h.maps_delay_ns = 300_000_000;
    let set = ProbeSet {
        probes: vec![Probe {
            cookie: 7,
            symbol: "ENGINE_by_id".to_string(),
            offset: 0x100,
            module: "/p/libcrypto.so.3".to_string(),
            family: None,
            str_arg: None,
            program: "trip_count",
        }],
        engine_uninstrumented: 0,
        meth_uninstrumented: 0,
        lowlevel_uninstrumented: 0,
        unprobed_engine_syms: Vec::new(),
        unprobed_meth_syms: Vec::new(),
        unprobed_lowlevel_syms: Vec::new(),
        findings: Vec::new(),
        address_taken: Vec::new(),
        by_id_cookies: HashSet::from([7]),
        load_cookies: HashSet::new(),
        libcrypto: None,
    };
    h.snapshot.legacy.set = Some(set);
    h.snapshot.legacy.planned = true;
    let hit = || osslscope::discovery::legacy::TripHit {
        cookie: 7,
        class: wire::ENGINE_DYNAMIC,
        status: wire::TRIP_OK,
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    // Poll 3 runs only if the round polls past the deadline.
    h.polls.push_back(DiscoveryDelta {
        tripwire: TripwireDelta {
            hits: vec![hit(), hit(), hit(), hit(), hit()],
            counter_deltas: vec![(7, 5)],
            executed_legacy_queries_delta: 5,
        },
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        c.legacy["legacy_provider"]["executed_queries"],
        serde_json::json!(0)
    );
    assert_eq!(
        c.legacy["engine"]["calls_by_entrypoint"]["ENGINE_by_id"],
        serde_json::json!(0)
    );
    assert_eq!(c.counters.over_budget, 1);
}

#[test]
fn pid_kernel_deadline_measured_from_acquisition() {
    // F-D/A10: for --pid the requested window starts at acquisition,
    // so the kernel deadline is acquisition + duration — not window
    // open + duration. Post-requested-end executions must drop
    // in-BPF even though the kernel window opened later.
    let mut h = Harness::fresh("pid-deadline");
    h.owned = false;
    h.acquired_ns = BASE_NS - 500_000_000;
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    // Requested end is BASE + 1.5s: the 1.0s fires count, the 1.6s
    // fires are post-requested-end (but pre-open+duration).
    h.plans.insert(
        1,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 5)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 1_600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    let programmed = post.shared.borrow().backend.programmed().to_vec();
    assert_eq!(
        programmed,
        vec![(PID as u64, 0, BASE_NS, BASE_NS + 1_500_000_000)],
        "kernel deadline must measure from acquisition: {programmed:?}"
    );
    assert_eq!(c.document.total_calls(), 5, "{:?}", c.document.sites);
    assert!(has_reason(&c, "startup-gap"), "{:?}", c.reasons);
}

#[test]
fn pid_setup_outlasts_window_fails_closed() {
    // F-D/A10: setup consumed the whole requested window before the
    // kernel window could open (acquisition + duration predates the
    // open) — loud failure, never an open + duration window that
    // would launder post-window executions as in-window evidence.
    let mut h = Harness::fresh("pid-elapsed");
    h.owned = false;
    h.acquired_ns = BASE_NS - 3_000_000_000;
    h.snapshot_attached();
    let (out, post) = h.run();
    let capture = out.unwrap();
    let w = &capture.document.window;
    assert_eq!(w.requested_start_ns, BASE_NS - 3_000_000_000);
    assert_eq!(w.requested_end_ns, BASE_NS - 1_000_000_000);
    assert_eq!(w.effective_start_ns, w.requested_end_ns);
    assert_eq!(w.effective_end_ns, w.requested_end_ns);
    assert!(w.count_admission.is_none());
    assert!(capture.programmed_admission.is_none());
    assert!(capture.document.sites.is_empty());
    assert_eq!(w.startup_gap_ns(), 2_000_000_000);
    assert!(matches!(
        capture.document.status,
        Completeness::Partial { .. }
    ));
    let context = capture.failure_context.as_ref().unwrap();
    assert_eq!(
        context.custody.resolution,
        osslscope::capture::CustodyResolution::NotOwned
    );
    assert!(matches!(
        context.count,
        osslscope::capture::PreObservationCount::Terminal(_)
    ));
    assert!(!post.target_log.borrow().released);
    assert!(
        !post
            .shared
            .borrow()
            .log
            .iter()
            .any(|line| line == "count_open")
    );
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn straddling_poll_tripwire_is_loss_not_evidence() {
    // F-D/A10: a discovery poll that starts pre-deadline but
    // completes post-deadline straddles the window edge — its
    // tripwire/query deltas are window-ambiguous, so they report as
    // explicit loss, never as in-window legacy evidence.
    use osslscope::discovery::legacy::{Probe, ProbeSet};
    use osslscope_ebpf_common as wire;
    let mut h = Harness::fresh("straddle-trip");
    h.owned = false;
    h.cfg.duration = Duration::from_millis(300);
    h.snapshot_attached();
    let set = ProbeSet {
        probes: vec![Probe {
            cookie: 7,
            symbol: "ENGINE_by_id".to_string(),
            offset: 0x100,
            module: "/p/libcrypto.so.3".to_string(),
            family: None,
            str_arg: None,
            program: "trip_count",
        }],
        engine_uninstrumented: 0,
        meth_uninstrumented: 0,
        lowlevel_uninstrumented: 0,
        unprobed_engine_syms: Vec::new(),
        unprobed_meth_syms: Vec::new(),
        unprobed_lowlevel_syms: Vec::new(),
        findings: Vec::new(),
        address_taken: Vec::new(),
        by_id_cookies: HashSet::from([7]),
        load_cookies: HashSet::new(),
        libcrypto: None,
    };
    h.snapshot.legacy.set = Some(set);
    h.snapshot.legacy.planned = true;
    let hit = || osslscope::discovery::legacy::TripHit {
        cookie: 7,
        class: wire::ENGINE_DYNAMIC,
        status: wire::TRIP_OK,
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        tripwire: TripwireDelta {
            hits: vec![hit(), hit(), hit(), hit(), hit()],
            counter_deltas: vec![(7, 5)],
            executed_legacy_queries_delta: 5,
        },
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    // The single round runs at 250ms; its poll takes 100ms, crossing
    // the 300ms deadline mid-poll.
    h.poll_delay_ns.insert(1, 100_000_000);
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        c.legacy["legacy_provider"]["executed_queries"],
        serde_json::json!(0)
    );
    assert_eq!(
        c.legacy["engine"]["calls_by_entrypoint"]["ENGINE_by_id"],
        serde_json::json!(0)
    );
    assert_eq!(counter_value(&c, "legacy.straddling_poll_trip"), 5);
    assert_eq!(counter_value(&c, "legacy.straddling_poll_lgcalls"), 5);
    assert_eq!(c.counters.over_budget, 1);
}

#[test]
fn blind_legacy_renders_history_with_unknown_coverage() {
    // F-D/A11: anchors superseded mid-window (planned=false) with
    // a retained last-good set — pre-replacement in-window evidence
    // still renders (it happened), but legacy coverage is Unknown
    // (nothing further observable): PARTIAL, never stale-Applicable.
    use osslscope::discovery::legacy::{Probe, ProbeSet};
    use osslscope_ebpf_common as wire;
    let mut h = Harness::fresh("blind-legacy");
    h.snapshot_attached();
    let set = ProbeSet {
        probes: vec![Probe {
            cookie: 7,
            symbol: "ENGINE_by_id".to_string(),
            offset: 0x100,
            module: "/p/libcrypto.so.3".to_string(),
            family: None,
            str_arg: None,
            program: "trip_count",
        }],
        engine_uninstrumented: 0,
        meth_uninstrumented: 0,
        lowlevel_uninstrumented: 0,
        unprobed_engine_syms: Vec::new(),
        unprobed_meth_syms: Vec::new(),
        unprobed_lowlevel_syms: Vec::new(),
        findings: Vec::new(),
        address_taken: Vec::new(),
        by_id_cookies: HashSet::from([7]),
        load_cookies: HashSet::new(),
        libcrypto: None,
    };
    h.snapshot.legacy.set = Some(set);
    // NOTE: planned stays false — the blind-with-history shape.
    let hit = || osslscope::discovery::legacy::TripHit {
        cookie: 7,
        class: wire::ENGINE_DYNAMIC,
        status: wire::TRIP_OK,
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        tripwire: TripwireDelta {
            hits: vec![hit()],
            counter_deltas: vec![(7, 1)],
            executed_legacy_queries_delta: 1,
        },
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(
        c.legacy["engine"]["calls_by_entrypoint"]["ENGINE_by_id"],
        serde_json::json!(1)
    );
    assert_eq!(
        c.legacy["legacy_provider"]["executed_queries"],
        serde_json::json!(1)
    );
    let leg = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "legacy")
        .expect("legacy scope");
    assert!(
        matches!(leg.expected, ExpectedScope::Unknown),
        "blind legacy must be Unknown: {leg:?}"
    );
    assert!(matches!(c.outcome, Outcome::Partial), "{:?}", c.outcome);
}

#[test]
fn setup_slice_reports_exact_tail_gap() {
    // The kernel window opens pre-setup while the requested window
    // starts at release: the 300ms setup slice is uncounted time
    // inside the requested window, so it reports as an exact 300ms
    // tail gap — never hidden, never inflated by drain time.
    let mut h = Harness::fresh("setup-tail");
    h.snapshot_attached();
    // 300ms setup slice via the maps read (F-D/A13): the setup
    // poll references no files so file_delay no longer advances
    // the clock; the setup maps read carries the same 300ms.
    h.maps_delay_ns = 300_000_000;
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.window.tail_gap_ns(), 300_000_000);
    assert!(has_reason(&c, "tail-gap"), "{:?}", c.reasons);
    assert_eq!(c.counters.over_budget, 1);
}

#[test]
fn loop_clamps_to_kernel_deadline() {
    // 600ms setup with a 2s window: the loop ends at the kernel
    // deadline (open + 2s), so the poll that would run past it
    // never does — and the tail gap is exactly the setup slice.
    let mut h = Harness::fresh("clamp");
    h.snapshot_attached();
    // 600ms setup via the maps read (F-D/A13): file reads are
    // relevance-gated and these polls reference nothing; the
    // unconditional maps read carries the same 600ms slice.
    h.maps_delay_ns = 600_000_000;
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    // Poll 2 runs only if the loop passes the kernel deadline.
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(has_reason(&c, "no-query"), "{:?}", c.reasons);
    assert_eq!(c.document.window.tail_gap_ns(), 600_000_000);
    assert!(has_reason(&c, "tail-gap"), "{:?}", c.reasons);
    assert_eq!(c.counters.over_budget, 1);
}

#[test]
fn partial_final_delta_reconciles_once() {
    // Lossy final polls plus a close-tail residual: each increment
    // counts exactly once, and attached evidence survives.
    let mut h = Harness::fresh("partial-final");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta {
        losses: vec![DiscoveryLoss {
            source: osslscope_ebpf_common::LOSS_RING_ROW,
            count: 2,
            op: None,
        }],
        budget_exhausted: true,
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.snapshot.losses = vec![(osslscope_ebpf_common::LOSS_RING_ROW, 5)];
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(has_reason(&c, "discovery-loss"), "{:?}", c.reasons);
    // 2 (deltas) + 3 (close residual): single-counted, never doubled.
    assert_eq!(counter_value(&c, "discovery.ring_row"), 5);
    let row = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .unwrap();
    assert_eq!((row.discovered, row.attached), (1, 1));
}

#[test]
fn orphan_loss_taints_op_denominator() {
    // A7: op 1 terminates, but an orphan ROW localizes to it — the
    // discovered-site count is no longer the expected denominator
    // (a site may be missing), so expected stays Unknown. The
    // sibling op 2 (terminated, no loss) keeps its denominator.
    let mut h = Harness::fresh("orphan-taint");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0), terminated(2, 0)],
        losses: vec![DiscoveryLoss {
            source: osslscope::discovery::coverage::HOST_ORPHAN_ROW,
            count: 1,
            op: Some(1),
        }],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    let row1 = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .unwrap();
    assert!(
        matches!(row1.expected, ExpectedScope::Unknown),
        "tainted op keeps no denominator: {row1:?}"
    );
    let row2 = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:2")
        .unwrap();
    assert!(
        matches!(row2.expected, ExpectedScope::Applicable { .. }),
        "untainted sibling keeps its denominator: {row2:?}"
    );
}

#[test]
fn drain_shortfall_is_partial() {
    // Grace-expiry shortfall: explicit PARTIAL with executed
    // evidence preserved.
    let mut h = Harness::fresh("shortfall");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        3,
        FirePlan {
            fires: Vec::new(),
            shortfall: 3,
            cancel: false,
        },
    );
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert_eq!(counter_value(&c, "count.drain_shortfall"), 3);
    assert!(has_reason(&c, "drain-shortfall"), "{:?}", c.reasons);
    assert_eq!(c.document.total_calls(), 4);
}

#[test]
fn count_terminal_runtime_failure_keeps_positive_calls() {
    let mut h = Harness::fresh("count-terminal-runtime");
    h.snapshot_attached();
    let candidate = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![candidate],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..Default::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.shared
        .borrow_mut()
        .backend
        .terminal_faults(FakeTerminalFaults {
            read_error: true,
            ..Default::default()
        });
    let (out, _) = h.run();
    let capture = out.unwrap();
    assert!(
        matches!(capture.outcome, Outcome::Fatal(_)),
        "{:?}",
        capture.outcome
    );
    assert_eq!(capture.document.total_calls(), 4);
    assert_eq!(counter_value(&capture, "count.drain_read_failed"), 1);
    assert_eq!(counter_value(&capture, "count.owner_failed"), 1);
    assert_eq!(
        capture.document.sites[0].candidates_coverage,
        CandidateCoverage::Complete
    );
}

#[test]
fn count_fd_admission_refuses_insufficient_and_contradictory_inventory() {
    use osslscope::capture::CountFdAdmission;
    for (soft_limit, non_count_open, non_count_reserved, want) in [
        (20, 1, 1, 18),
        (16402, 1, 1, 16400),
        (u64::MAX, 9, 7, 16400),
    ] {
        assert_eq!(
            CountFdAdmission {
                soft_limit,
                non_count_open,
                non_count_reserved
            }
            .allowance()
            .unwrap(),
            want
        );
    }
    for (soft_limit, non_count_open, non_count_reserved) in [
        (19, 1, 1),
        (0, 1, 0),
        (u64::MAX, u64::MAX, 1),
        (u64::MAX, 1, u64::MAX),
    ] {
        assert!(
            CountFdAdmission {
                soft_limit,
                non_count_open,
                non_count_reserved
            }
            .allowance()
            .is_err()
        );
    }
}

#[test]
fn positive_rule_on_unrelated_partial_coverage() {
    // A definite match on a complete site survives alongside an
    // unrelated unknown-coverage op: gaps PARTIAL the window without
    // erasing positive evidence (R06).
    let mut h = Harness::fresh("unrelated");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta {
        tables: vec![in_progress(2, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        3,
        FirePlan {
            fires: vec![(BASE_NS + 1_000_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(has_reason(&c, "discovery-loss"), "{:?}", c.reasons);
    let bounds = match_bounds(&c.document.sites, &|cand| {
        if cand.algorithm_classes.iter().any(|a| a == "SHA-256") {
            PredicateMatch::Yes
        } else {
            PredicateMatch::No
        }
    });
    assert_eq!(bounds.definite, 7);
    assert_eq!(bounds.possible, Some(7));
}

#[test]
fn finalize_requires_all_live_epochs_terminated() {
    // The closing snapshot carries two live epochs for op 1 — one
    // in progress, one terminated: the op stays Unknown-denominator
    // (a single terminated table must not close the op).
    let mut h = Harness::fresh("final-epochs");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![in_progress(1, 5)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.snapshot.tables = vec![in_progress(1, 5), terminated(1, 6)];
    // Exit after the first round polled (250ms), so the op is known.
    h.exit_at_ns = Some(BASE_NS + 300_000_000);
    let (out, _) = h.run();
    let c = out.unwrap();
    let row = c
        .document
        .coverage
        .iter()
        .find(|s| s.scope == "op:1")
        .unwrap();
    assert_eq!(row.expected, ExpectedScope::Unknown);
    assert_eq!(row.discovered, 1);
}

#[test]
fn maps_fence_versions_generation() {
    // A mid-window mapping change fences exactly once: the fenced
    // generation keeps gen-0 counts under gen-0 meaning, later
    // counts land in gen 1, and the total is conserved.
    let mut h = Harness::fresh("fence");
    h.snapshot_attached();
    let newso = h.stage.write("new.so", &h.bytes.clone());
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&h.staged), mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        4,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites.len(), 1);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].generation, 1);
    assert_eq!(c.document.sites[0].calls, 4);
    // Exactly one fence (one generation bump past 0).
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1]);
}

#[test]
fn polling_fallback_is_explicit_partial() {
    // The T08 lifecycle selection: polling cannot prove absence, so
    // the fallback rides as explicit loss + reason on every window.
    let mut h = Harness::fresh("fallback");
    h.snapshot_attached();
    h.lifecycle_fallback = true;
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(has_counter(&c, "lifecycle.polling_fallback"));
    assert_eq!(counter_value(&c, "lifecycle.polling_fallback"), 1);
    assert!(
        has_reason(&c, "lifecycle-polling-partial"),
        "{:?}",
        c.reasons
    );
}

// ---------------------------------------------------------------------------
// Adapter pins: direct `adapt_delta` contract checks.
// ---------------------------------------------------------------------------

use osslscope::capture::{AdaptedDelta, AdapterCtx, AdapterState, PinnedProvider, adapt_delta};
use osslscope::discovery::elf;

/// Minimal ELF64 with one PT_NOTE holding a GNU build-id note —
/// distinct descriptors fingerprint distinct objects.
fn fake_elf_with_build_id(desc: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    v.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
    v.extend_from_slice(&62u16.to_le_bytes()); // x86-64
    v.extend_from_slice(&1u32.to_le_bytes()); // version
    v.extend_from_slice(&0u64.to_le_bytes()); // entry
    v.extend_from_slice(&64u64.to_le_bytes()); // phoff
    v.extend_from_slice(&0u64.to_le_bytes()); // shoff
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&64u16.to_le_bytes()); // ehsize
    v.extend_from_slice(&56u16.to_le_bytes()); // phentsize
    v.extend_from_slice(&1u16.to_le_bytes()); // phnum
    v.extend_from_slice(&0u16.to_le_bytes()); // shentsize
    v.extend_from_slice(&0u16.to_le_bytes()); // shnum
    v.extend_from_slice(&0u16.to_le_bytes()); // shstrndx
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes()); // namesz
    note.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    note.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(desc);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    v.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&120u64.to_le_bytes()); // offset
    v.extend_from_slice(&0u64.to_le_bytes()); // vaddr
    v.extend_from_slice(&0u64.to_le_bytes()); // paddr
    v.extend_from_slice(&(note.len() as u64).to_le_bytes());
    v.extend_from_slice(&(note.len() as u64).to_le_bytes());
    v.extend_from_slice(&4u64.to_le_bytes()); // align
    v.extend_from_slice(&note);
    v
}

#[test]
fn advertising_fallback_binds_mapping_not_path() {
    // No build-id bytes: the opaque fallback binds the advertised
    // (stat-domain) triple. A same-path replacement (new inode)
    // changes identity instead of conflating two objects.
    let stage = Stage::fresh("adv-map");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let dev = plan::render_device(staged.device);
    let live1 = vec![mapping(&staged)];
    let mut live2 = live1.clone();
    live2[0].ino += 1;
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let files: HashMap<String, plan::FileBytes> = HashMap::new();
    let run = |live: &[Mapping], ino: u64| {
        let mut state = AdapterState::default();
        // The candidate carries the array's discovery-time owner
        // (refreshed by discovery on remap, like the backing):
        // the array address joins the exact VMA.
        let mut c = cand(
            staged.path.as_str(),
            Some(BackingRef {
                dev: dev.clone(),
                ino,
                offset: 0x100,
            }),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        );
        c.arr = live[0].start + 8;
        c.advertising_dev = dev.clone();
        c.advertising_ino = ino;
        let delta = DiscoveryDelta {
            candidates: vec![c],
            ..DiscoveryDelta::default()
        };
        let adapted = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                post_release: false,
                baseline: false,
            },
        );
        assert_eq!(adapted.delta.discovered.len(), 1);
        adapted.delta.discovered[0].candidates[0].provider.0.clone()
    };
    let first = run(&live1, staged.ino);
    let second = run(&live2, staged.ino + 1);
    assert_eq!(first, format!("unverified:{dev}:{}", staged.ino));
    assert_eq!(second, format!("unverified:{dev}:{}", staged.ino + 1));
    assert_ne!(first, second);
}

#[test]
fn advertising_fallback_unresolved_is_anonymous() {
    // An advertising path with no live mapping degrades to
    // anonymous: the pathname never leaks into identity.
    let stage = Stage::fresh("adv-anon");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let files: HashMap<String, plan::FileBytes> = HashMap::new();
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let delta = DiscoveryDelta {
        candidates: vec![cand(
            "/p/gone.so",
            backing_of(&staged, 0x100),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        ..DiscoveryDelta::default()
    };
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live: &live,
            files: &files,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(adapted.delta.discovered.len(), 1);
    let id = adapted.delta.discovered[0].candidates[0].provider.0.clone();
    assert_eq!(id, "unverified-advertising:anonymous");
    assert!(!id.contains("gone"));
}

#[test]
fn provider_class_resolves_per_advertising_object() {
    // F-A/A6: the run's pin labels ONE verified object — a mixed
    // window's other object stays `unknown`, never borrowed.
    let stage = Stage::fresh("a6-mixed");
    let bytes_a = fake_elf_with_build_id(&[0xA1; 20]);
    let bytes_b = fake_elf_with_build_id(&[0xB2; 20]);
    let id_a = elf::read_build_id(&bytes_a).expect("fixture A parses");
    let id_b = elf::read_build_id(&bytes_b).expect("fixture B parses");
    assert_ne!(id_a, id_b, "fixtures must fingerprint apart");
    let sa = stage.write("a.so", &bytes_a);
    let sb = stage.write("b.so", &bytes_b);
    let ma = mapping(&sa);
    let mut mb = mapping(&sb);
    mb.start = 0x7f01_0000_0000;
    mb.end = 0x7f01_0000_1000;
    let live = vec![ma.clone(), mb.clone()];
    let files: HashMap<String, plan::FileBytes> = HashMap::from([
        (
            sa.path.clone(),
            plan::FileBytes {
                bytes: bytes_a.into(),
                dev: sa.device,
                ino: sa.ino,
            },
        ),
        (
            sb.path.clone(),
            plan::FileBytes {
                bytes: bytes_b.into(),
                dev: sb.device,
                ino: sb.ino,
            },
        ),
    ]);
    let mut ca = cand(
        sa.path.as_str(),
        backing_of(&sa, 0x100),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    ca.arr = ma.start + 8;
    ca.advertising_dev = ma.dev.clone();
    ca.advertising_ino = ma.ino;
    let mut cb = cand(
        sb.path.as_str(),
        backing_of(&sb, 0x100),
        1,
        12,
        "SHA-256",
        false,
        "ok",
    );
    cb.arr = mb.start + 8;
    cb.advertising_dev = mb.dev.clone();
    cb.advertising_ino = mb.ino;
    let delta = DiscoveryDelta {
        candidates: vec![ca, cb],
        ..DiscoveryDelta::default()
    };
    let mut state = AdapterState::default();
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live: &live,
            files: &files,
            pinned_provider: Some(PinnedProvider {
                object: format!("build:{id_a}"),
                class: "enrolled-a".to_string(),
            }),
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    let mut seen = 0;
    for site in &adapted.delta.discovered {
        for c in &site.candidates {
            seen += 1;
            if c.provider.0 == format!("build:{id_a}") {
                assert_eq!(c.provider_class, "enrolled-a");
            } else if c.provider.0 == format!("build:{id_b}") {
                assert_eq!(
                    c.provider_class, "unknown",
                    "unpinned object must not borrow the run's pin"
                );
            } else {
                panic!("unexpected advertising {}", c.provider.0);
            }
        }
    }
    assert_eq!(seen, 2);
}

#[test]
fn stale_path_fingerprint_is_unverified() {
    // A3: the files read raced a same-path replacement — the bytes
    // (and identity) are the NEW file's while the mapping is the
    // old file's. The site must degrade to unverified, never wear
    // the new file's fingerprint.
    let stage = Stage::fresh("fp-stale");
    let bytes_old = self_bytes();
    let bytes_new = flipped_build_id(&bytes_old);
    let staged = stage.write("prov.so", &bytes_old);
    let dev = plan::render_device(staged.device);
    // Replacement: same path, new inode — via create-then-rename
    // (never remove-then-recreate: freed inodes are reused
    // immediately on some filesystems — observed in CI).
    use std::os::unix::fs::MetadataExt as _;
    let path = PathBuf::from(&staged.path);
    let tmp = path.with_extension("swap");
    std::fs::write(&tmp, &bytes_new).unwrap();
    let meta_new = std::fs::metadata(&tmp).unwrap();
    assert_ne!(meta_new.ino(), staged.ino);
    std::fs::rename(&tmp, &path).unwrap();
    // Round artifacts: maps still show the old file (the VMA pins
    // it), files were read after the replacement.
    let live = vec![mapping(&staged)];
    let files: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes_new.clone().into(),
            dev: staged.device,
            ino: meta_new.ino(),
        },
    )]);
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let delta = DiscoveryDelta {
        candidates: vec![cand(
            staged.path.as_str(),
            backing_of(&staged, 0x100),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live: &live,
            files: &files,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(adapted.delta.discovered.len(), 1);
    let site = &adapted.delta.discovered[0].site;
    assert_eq!(
        site.object.0,
        format!("unverified:{dev}:{}", staged.ino),
        "stale mapping must not wear the replacement fingerprint"
    );
}

#[test]
fn advertising_joins_exact_vma_not_first_path() {
    // A3: old and new objects simultaneously live under one path —
    // the array address joins the EXACT VMA (never first-pathname
    // match), and each candidate fingerprints only against bytes
    // bound to its own mapping. The files round read the new file.
    let stage = Stage::fresh("adv-vma");
    let bytes_v1 = self_bytes();
    let bytes_v2 = flipped_build_id(&bytes_v1);
    let v1 = stage.write("v1.so", &bytes_v1);
    let v2 = stage.write("v2.so", &bytes_v2);
    let dev = plan::render_device(v1.device);
    // Two live VMAs under ONE path string (same-path old+new):
    // the old mapping keeps the path text, the new mapping reuses
    // it (faithful shape of a live replacement pair).
    let mut m1 = mapping(&v1);
    m1.start = 0x7f00_0000_0000;
    m1.end = 0x7f00_0000_1000;
    let mut m2 = mapping(&v2);
    m2.path = v1.path.clone();
    m2.start = 0x7f00_1000_0000;
    m2.end = 0x7f00_1000_1000;
    let live = vec![m1, m2];
    let files: HashMap<String, plan::FileBytes> = HashMap::from([(
        v1.path.clone(),
        plan::FileBytes {
            bytes: bytes_v2.clone().into(),
            dev: v2.device,
            ino: v2.ino,
        },
    )]);
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let mut c1 = cand(
        v1.path.as_str(),
        backing_of(&v1, 0x100),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    c1.arr = 0x7f00_0000_0100;
    c1.advertising_dev = plan::render_device(v1.device);
    c1.advertising_ino = v1.ino;
    let mut c2 = cand(
        v1.path.as_str(),
        backing_of(&v2, 0x100),
        1,
        12,
        "SHA-256",
        false,
        "ok",
    );
    c2.arr = 0x7f00_1000_0100;
    c2.advertising_dev = plan::render_device(v2.device);
    c2.advertising_ino = v2.ino;
    let delta = DiscoveryDelta {
        candidates: vec![c1, c2],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live: &live,
            files: &files,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(adapted.delta.discovered.len(), 2);
    let prov: Vec<&str> = adapted
        .delta
        .discovered
        .iter()
        .map(|s| s.candidates[0].provider.0.as_str())
        .collect();
    // Old array, new bytes on the shared path: the old candidate
    // stays opaque (its bytes are unavailable), never build:v2.
    assert!(
        prov.iter()
            .any(|p| *p == format!("unverified:{dev}:{}", v1.ino)),
        "old candidate conflated: {prov:?}"
    );
    // New array, bound bytes: the true v2 fingerprint.
    let build_v2 = format!(
        "build:{}",
        osslscope::discovery::elf::read_build_id(&bytes_v2).unwrap()
    );
    assert!(
        prov.iter().any(|p| *p == build_v2),
        "new candidate must fingerprint v2: {prov:?}"
    );
}

#[test]
fn advertising_turnover_is_anonymous() {
    // A3: the candidate's class was decoded from the old file's
    // array, but the array's address now maps the new file
    // (same-address remap). Neither fingerprint fits: anonymous.
    let stage = Stage::fresh("adv-turn");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let files: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes.clone().into(),
            dev: staged.device,
            ino: staged.ino,
        },
    )]);
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let mut c = cand(
        staged.path.as_str(),
        backing_of(&staged, 0x100),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    c.arr = live[0].start + 8;
    // Discovery-time owner is the OLD file; live shows the new.
    c.advertising_dev = plan::render_device(staged.device);
    c.advertising_ino = staged.ino.wrapping_add(1);
    let delta = DiscoveryDelta {
        candidates: vec![c],
        ..DiscoveryDelta::default()
    };
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live: &live,
            files: &files,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(adapted.delta.discovered.len(), 1);
    let id = adapted.delta.discovered[0].candidates[0].provider.0.clone();
    assert_eq!(id, "unverified-advertising:anonymous");
}

/// Same ELF with a different build-id (one flipped descriptor byte
/// in the GNU build-id note): simulates in-place content change for
/// the identity-refresh pin. Scans every PT_NOTE segment for the
/// NT_GNU_BUILD_ID note instead of assuming the first note's
/// layout, mirroring `parse_build_id_notes` padding/bounds; the
/// build-id before/after assertion stays loud.
fn flipped_build_id(bytes: &[u8]) -> Vec<u8> {
    use goblin::elf::program_header::PT_NOTE;
    /// Note type `NT_GNU_BUILD_ID` (3); owner name is `GNU\0`
    /// (mirrors `osslscope::discovery::elf`).
    const NT_GNU_BUILD_ID: u32 = 3;
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let mut desc_at = None;
    for ph in elf.program_headers.iter().filter(|ph| ph.p_type == PT_NOTE) {
        let off = ph.p_offset as usize;
        let len = ph.p_filesz as usize;
        let Some(end) = off.checked_add(len) else {
            continue;
        };
        let Some(seg) = bytes.get(off..end) else {
            continue;
        };
        let mut cur = seg;
        let mut cur_off = off;
        while cur.len() >= 12 {
            let namesz = u32::from_le_bytes(cur[0..4].try_into().unwrap()) as usize;
            let descsz = u32::from_le_bytes(cur[4..8].try_into().unwrap()) as usize;
            let ntype = u32::from_le_bytes(cur[8..12].try_into().unwrap());
            let name_end = 12usize + namesz.next_multiple_of(4);
            let desc_end = name_end + descsz.next_multiple_of(4);
            if desc_end > cur.len() {
                break;
            }
            if ntype == NT_GNU_BUILD_ID
                && descsz > 0
                && cur.get(12..12 + namesz) == Some(b"GNU\0".as_slice())
            {
                desc_at = Some(cur_off + name_end);
                break;
            }
            cur = &cur[desc_end..];
            cur_off += desc_end;
        }
        if desc_at.is_some() {
            break;
        }
    }
    let at = desc_at.expect("test binary must carry a GNU build-id note");
    let mut out = bytes.to_vec();
    out[at] ^= 0x01;
    let before = osslscope::discovery::elf::read_build_id(bytes).unwrap();
    let after = osslscope::discovery::elf::read_build_id(&out).unwrap();
    assert_ne!(before, after, "flip must change the build-id");
    out
}

#[test]
fn refreshed_site_fingerprint_is_forwarded() {
    // Same backing triple, new file bytes on the second poll: the
    // adapter re-emits the site with the NEW fingerprint (so the
    // count session versions it at the next fence) instead of
    // silently reusing the stale identity.
    let stage = Stage::fresh("refresh-fwd");
    let bytes_a = self_bytes();
    let bytes_b = flipped_build_id(&bytes_a);
    let staged = stage.write("prov.so", &bytes_a);
    let live = vec![mapping(&staged)];
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let delta = || DiscoveryDelta {
        candidates: vec![cand(
            staged.path.as_str(),
            backing_of(&staged, 0x100),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let files_a: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes_a.clone().into(),
            dev: staged.device,
            ino: staged.ino,
        },
    )]);
    let first = adapt_delta(
        &mut state,
        &delta(),
        &AdapterCtx {
            live: &live,
            files: &files_a,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(first.delta.discovered.len(), 1);
    let fp_a = first.delta.discovered[0].site.object.0.clone();
    assert!(fp_a.starts_with("build:"), "{fp_a}");
    let files_b: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev: staged.device,
            ino: staged.ino,
        },
    )]);
    let second = adapt_delta(
        &mut state,
        &delta(),
        &AdapterCtx {
            live: &live,
            files: &files_b,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        },
    );
    assert_eq!(second.delta.discovered.len(), 1);
    let fp_b = second.delta.discovered[0].site.object.0.clone();
    assert!(fp_b.starts_with("build:"), "{fp_b}");
    assert_ne!(fp_a, fp_b, "stale fingerprint must not be reused");
    assert!(
        second
            .activity
            .iter()
            .any(|c| c.name == "discovery.site_identity_refreshed" && c.value == 1),
        "{:?}",
        second.activity
    );
}

/// Direct-adapter driver: staged bytes, one live mapping, fresh
/// adapter state.
struct AdaptHarness {
    staged: Staged,
    live: Vec<Mapping>,
    files: HashMap<String, plan::FileBytes>,
    fresh: HashSet<(String, u64)>,
    state: AdapterState,
}

impl AdaptHarness {
    fn fresh(test: &str) -> Self {
        let stage = Stage::fresh(test);
        let bytes = self_bytes();
        let staged = stage.write("prov.so", &bytes);
        let live = vec![mapping(&staged)];
        let files = HashMap::from([(
            staged.path.clone(),
            plan::FileBytes {
                bytes: bytes.into(),
                dev: staged.device,
                ino: staged.ino,
            },
        )]);
        // `stage` drops here: the temp dir is gone but every byte the
        // adapter reads is already staged in `files`.
        Self {
            staged,
            live,
            files,
            fresh: HashSet::new(),
            state: AdapterState::default(),
        }
    }

    fn cand(&self, op: u32, epoch: u64, offset: u64) -> DiscoveredCandidate {
        let mut c = cand(
            self.staged.path.as_str(),
            backing_of(&self.staged, offset),
            op,
            11,
            "SHA-256",
            false,
            "ok",
        );
        c.epoch = epoch;
        c
    }

    fn adapt(&mut self, delta: &DiscoveryDelta) -> AdaptedDelta {
        adapt_delta(
            &mut self.state,
            delta,
            &AdapterCtx {
                live: &self.live,
                files: &self.files,
                pinned_provider: None,
                fresh: &self.fresh,
                post_settle: false,
                post_release: false,
                baseline: false,
            },
        )
    }
}

#[test]
fn table_only_new_epoch_degrades_emitted_sites() {
    // Epoch 5 terminates and its site emits Complete; a table-only
    // delta then reports a new unproven epoch 6 for the same op —
    // the emitted site re-emits as Unknown (no silent Complete).
    let mut h = AdaptHarness::fresh("epoch-degrade");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(first.delta.discovered.len(), 1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        tables: vec![in_progress(1, 6)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

#[test]
fn terminated_sibling_cannot_overwrite_unfinished_epoch() {
    // Epoch 6 in progress; a late terminated table for epoch 5 in
    // the SAME delta as a new epoch-6 candidate must not resurrect
    // closure: the new site emits Unknown.
    let mut h = AdaptHarness::fresh("sibling-epoch");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 6, 0x100)],
        tables: vec![in_progress(1, 6)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d2 = DiscoveryDelta {
        candidates: vec![h.cand(1, 6, 0x200)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(second.delta.discovered[0].site.offset, 0x200);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

#[test]
fn untracked_epoch_candidate_does_not_inherit_complete() {
    // F3: epoch 5 terminates and its site emits Complete; a later
    // candidate for epoch 6 arrives with zero table proof for
    // epoch 6 in any delta. The new site must NOT inherit
    // Complete — an op closed on sibling epochs never vouches for
    // an epoch it never observed.
    let mut h = AdaptHarness::fresh("untracked-epoch");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(first.delta.discovered.len(), 1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        candidates: vec![h.cand(1, 6, 0x200)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(second.delta.discovered[0].site.offset, 0x200);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "untracked epoch must fail closed, never inherit Complete"
    );
}

#[test]
fn trunc_bits_degrade_emitted_sites() {
    // Terminated table, Complete site; a table-only delta then
    // carries sticky walk-shape bits — the site re-emits Unknown.
    use osslscope_ebpf_common as wire;
    let mut h = AdaptHarness::fresh("trunc-degrade");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 0, 0x100)],
        tables: vec![terminated(1, 0)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let mut t = terminated(1, 0);
    t.trunc_bits = wire::TRUNC_WALK_READ;
    let d2 = DiscoveryDelta {
        tables: vec![t],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

fn retirement(op: u32, epoch: u64) -> TableRetirement {
    TableRetirement {
        op,
        epoch,
        gap: osslscope::discovery::coverage::CoverageDelta::default(),
    }
}

#[test]
fn retirement_with_rebirth_degrades_until_proven() {
    // Same-delta retirement + rebirth: the site re-emits Unknown
    // (proof dropped); when the rebirth later terminates, nothing
    // re-emits — coverage degrades, never upgrades.
    let mut h = AdaptHarness::fresh("retire-rebirth");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        tables: vec![in_progress(1, 7)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    assert!(
        second
            .activity
            .iter()
            .any(|c| c.name == "discovery.table_retired" && c.value == 1),
        "{:?}",
        second.activity
    );
    let d3 = DiscoveryDelta {
        tables: vec![terminated(1, 7)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert!(third.delta.discovered.is_empty());
}

#[test]
fn retired_epoch_table_cannot_resurrect_closure() {
    // Epoch 5 retires unproven (unload, no rebirth); a stale
    // terminated table for it later must not resurrect closure: a
    // new site still emits Unknown.
    let mut h = AdaptHarness::fresh("tombstone");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![in_progress(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d3 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x200)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert_eq!(third.delta.discovered.len(), 1);
    assert_eq!(third.delta.discovered[0].site.offset, 0x200);
    assert_eq!(
        third.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

#[test]
fn sibling_table_prunes_unload_dirt() {
    // F-A/A4: epoch 5 retires with NO rebirth (unload). A newer
    // epoch's table prunes the older dirt (sibling isolation —
    // the unload cannot veto a live array's proof), so the live
    // epoch's rows close on their own proof. Stale-epoch arrivals
    // still fail closed via the untracked-epoch arm.
    let mut h = AdaptHarness::fresh("sibling-prune");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    // Sibling epoch 7 terminates and its rows arrive: the pruned
    // tombstone no longer vetoes the live epoch's closure.
    let d3 = DiscoveryDelta {
        candidates: vec![h.cand(1, 7, 0x100)],
        tables: vec![terminated(1, 7)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert_eq!(third.delta.discovered.len(), 1);
    assert_eq!(
        third.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    // But a stale-epoch arrival (pruned tombstone, no entry) still
    // fails closed.
    let d4 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x200)],
        ..DiscoveryDelta::default()
    };
    let fourth = h.adapt(&d4);
    assert_eq!(fourth.delta.discovered.len(), 1);
    assert_eq!(
        fourth.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

#[test]
fn h1_t2_retired_epoch_duplicate_never_regains_complete() {
    // A-2: a duplicate identity carrying a retired epoch must not
    // flip its site back to Complete after a sibling pruned the
    // tombstone. Epoch validation covers every arrival — novel or
    // duplicate — so a retired stamp can never re-close a site.
    let mut h = AdaptHarness::fresh("h1-t2");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    // Sibling epoch 7 terminates with rows at ANOTHER site: the
    // (1,5) tombstone prunes (sibling isolation) while op 1 closes
    // via the live epoch.
    let d3 = DiscoveryDelta {
        candidates: vec![h.cand(1, 7, 0x200)],
        tables: vec![terminated(1, 7)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert_eq!(
        third.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    // The d1 identity re-arrives verbatim (duplicate) carrying the
    // retired epoch 5: the site must stay Unknown, never Complete.
    let d4 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        ..DiscoveryDelta::default()
    };
    let fourth = h.adapt(&d4);
    assert_eq!(fourth.delta.discovered.len(), 1);
    assert_eq!(fourth.delta.discovered[0].site.offset, 0x100);
    assert_eq!(
        fourth.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "retired-epoch duplicate must not re-close the site"
    );
}

#[test]
fn h1_t3_untracked_epoch_duplicate_enters_validation() {
    // A-2 coverage: a duplicate carrying an epoch with zero table
    // proof (never tracked — no table, no retirement) still enters
    // the validation set and taints its own site. Skipping it
    // would let proof-less stamps ride a sibling-closed op.
    let mut h = AdaptHarness::fresh("h1-t3");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        candidates: vec![h.cand(1, 9, 0x100)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "proof-less duplicate stamp must taint its site"
    );
}

#[test]
fn h1_t4_duplicate_validation_boundary_pins() {
    // A-2 boundary (pins the F-H/H1 novelty split in both
    // directions — characterization of the fix's edge, RED-carried
    // by H1-T2/T3):
    // (a) a duplicate for a standing retired tombstone stays
    // Unknown via the explicit dirt arm;
    // (b) a duplicate for a live terminated epoch still recovers
    // Complete (the post-proof trip stays novel-only — naive
    // validate-everything would break legitimate re-walks).
    let mut h = AdaptHarness::fresh("h1-t4");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    // (b) first: live re-walk duplicate, no retirement anywhere.
    let d2 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete,
        "live-epoch duplicate must keep closure"
    );
    // (a): retire (tombstone stands — no sibling table), then the
    // same duplicate for the retired epoch.
    let d3 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert_eq!(
        third.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d4 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        ..DiscoveryDelta::default()
    };
    let fourth = h.adapt(&d4);
    assert_eq!(fourth.delta.discovered.len(), 1);
    assert_eq!(
        fourth.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown,
        "retired-tombstone duplicate must not re-close"
    );
}

#[test]
fn rebirth_reproof_recovers_closure() {
    // F-A/A4 recovery: epoch 5 retires as 7 rebirths; once 7
    // terminates AND its rows re-arrive (re-walk refresh), the
    // site returns to Complete. Proof alone still re-emits
    // nothing — only arrivals render.
    let mut h = AdaptHarness::fresh("rebirth-recover");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        tables: vec![in_progress(1, 7)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d3 = DiscoveryDelta {
        tables: vec![terminated(1, 7)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert!(third.delta.discovered.is_empty());
    // Re-walked rows re-arrive under the live epoch: identical
    // identities (duplicates, not news) + proven rebirth.
    let d4 = DiscoveryDelta {
        candidates: vec![h.cand(1, 7, 0x100)],
        tables: vec![terminated(1, 7)],
        ..DiscoveryDelta::default()
    };
    let fourth = h.adapt(&d4);
    assert_eq!(fourth.delta.discovered.len(), 1);
    assert_eq!(
        fourth.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
}

#[test]
fn chained_rebirths_recover_through_prune() {
    // F-A/A4: chained retirements (5, then 7 — e.g. double suspect
    // in one drain) clear transitively: each newer table prunes
    // older dirt, so only the tail's proof counts.
    let mut h = AdaptHarness::fresh("rebirth-chain");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    h.adapt(&d1);
    let d2 = DiscoveryDelta {
        retirements: vec![retirement(1, 5)],
        tables: vec![in_progress(1, 7)],
        ..DiscoveryDelta::default()
    };
    h.adapt(&d2);
    let d3 = DiscoveryDelta {
        retirements: vec![retirement(1, 7)],
        tables: vec![in_progress(1, 9)],
        ..DiscoveryDelta::default()
    };
    let third = h.adapt(&d3);
    assert_eq!(
        third.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    let d4 = DiscoveryDelta {
        candidates: vec![h.cand(1, 9, 0x100)],
        tables: vec![terminated(1, 9)],
        ..DiscoveryDelta::default()
    };
    let fourth = h.adapt(&d4);
    assert_eq!(fourth.delta.discovered.len(), 1);
    assert_eq!(
        fourth.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
}

#[test]
fn duplicate_arrivals_do_not_reopen_closure() {
    // F-A/A4: a duplicate arrival (multi-libctx re-query, re-walk
    // refresh) after termination is not news — the non-closed
    // guard fires on novel identities only.
    let mut h = AdaptHarness::fresh("dup-no-reopen");
    let d1 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
    let d2 = DiscoveryDelta {
        candidates: vec![h.cand(1, 5, 0x100)],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Complete
    );
}

#[test]
fn bad_read_gap_never_heals_by_recompute() {
    // F-A/A4: an unreadable arrival permanently gaps its site —
    // later clean arrivals (even duplicates of the bad row)
    // re-emit Unknown. Same stickiness as the old coverage latch
    // (per-identity healing is future work).
    let mut h = AdaptHarness::fresh("bad-sticky");
    let mut bad = cand(
        h.staged.path.as_str(),
        backing_of(&h.staged, 0x100),
        1,
        99,
        "SHA-256",
        false,
        "error",
    );
    bad.epoch = 5;
    let d1 = DiscoveryDelta {
        candidates: vec![bad],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let first = h.adapt(&d1);
    assert_eq!(
        first.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    // Same row re-read clean: duplicate identity, no guard trip —
    // but the read gap persists.
    let mut clean = cand(
        h.staged.path.as_str(),
        backing_of(&h.staged, 0x100),
        1,
        99,
        "SHA-256",
        false,
        "ok",
    );
    clean.epoch = 5;
    let d2 = DiscoveryDelta {
        candidates: vec![clean],
        tables: vec![terminated(1, 5)],
        ..DiscoveryDelta::default()
    };
    let second = h.adapt(&d2);
    assert_eq!(second.delta.discovered.len(), 1);
    assert_eq!(
        second.delta.discovered[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}

// ---------------------------------------------------------------------------
// Live lifecycle fixtures: real pids, real custody, no privileges.
// ---------------------------------------------------------------------------

use osslscope::capture::{LiveProc, PollingLifecycle};
use osslscope::target::{
    __test_set_prestop_pid_sink, __test_set_prestop_stall_ms, OwnedTarget, WorkloadDest,
};

/// Parent pid from `/proc/<pid>/stat` (fields start after the LAST
/// ')'; ppid is post-comm token 1).
fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    let mut toks = after.split_whitespace();
    toks.next()?;
    toks.next()?.parse().ok()
}

/// Assert `pid` has no waitable status left (reaped, never a zombie).
fn assert_reaped(pid: u32) {
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "child {pid} still waitable (zombie/leak)");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "child {pid} waitpid surprise"
    );
}

/// Real owned child through the real `observe` loop (scripted
/// sessions/proc, injected clock): fast commands keep their status
/// and leave no zombie.
fn live_observe(
    test: &str,
    argv: &[&str],
    duration: Duration,
    finish_recycled: bool,
) -> (anyhow::Result<Capture>, Option<u32>) {
    let idle = AtomicBool::new(false);
    live_observe_inner(
        test,
        argv,
        duration,
        finish_recycled,
        Duration::from_secs(30),
        &idle,
    )
}

/// [`live_observe`] with an explicit setup timeout (R06 fix round 1: the
/// helper spawns through the cancellable control entrypoint with the
/// checked harvest-timeout deadline — the same shape as production
/// `run()` — so spawn-level custody is exercised, not just `observe()`'s
/// own timeout handling). `None` pid = the spawn itself failed (no child).
fn live_observe_inner(
    test: &str,
    argv: &[&str],
    duration: Duration,
    finish_recycled: bool,
    harvest_timeout: Duration,
    cancel: &AtomicBool,
) -> (anyhow::Result<Capture>, Option<u32>) {
    let stage = Stage::fresh(test);
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let setup_deadline = osslscope::args::deadline_at(Instant::now(), harvest_timeout)
        .expect("test harvest timeout");
    let owned = match OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::Null,
        setup_deadline,
        cancel,
    ) {
        Ok(t) => t,
        Err(e) => return (Err(e), None),
    };
    let pid = owned.pid();
    let clock = FakeClock::new();
    let shared = Rc::new(RefCell::new(SharedState::default()));
    let mut snapshot = DiscoverySnapshot::default();
    snapshot.dispatch.attached = true;
    snapshot.dispatch.trigger_observed = true;
    let discovery = FakeDiscovery {
        shared: shared.clone(),
        clock: clock.clone(),
        polls: VecDeque::new(),
        plans: HashMap::new(),
        fire_tgid: PID,
        poll_delay_ns: HashMap::new(),
        // 5ms real per poll (~120 polls over the 30s window):
        // the real child needs wall-clock time to exec+exit while
        // the fake clock spins instantly (F-D/A13 made rounds too
        // fast to rely on incidental I/O latency).
        poll_real_delay: Duration::from_millis(5),
        poll_err_at: HashSet::new(),
        snapshot,
        finish_err: false,
        finish_recycled,
        finish_final: None,
        cancel_flag: None,
        polls_done: 0,
        finished: false,
        traversal_setup_error: false,
    };
    let count = CountSession::new(
        pid,
        SharedBackend {
            ready: *shared.borrow().backend.ready(),
            barrier: Arc::new(CountForkBarrier::new()),
            shared: shared.clone(),
            clock: clock.clone(),
            order: Rc::new(RefCell::new(Vec::new())),
        },
    );
    let lifecycle = FakeLifecycle {
        polls: VecDeque::new(),
        fallback: false,
        close_drain: None,
        clock: None,
        advance_ns: 0,
        order: None,
    };
    let mut files = HashMap::new();
    files.insert(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes.into(),
            dev: staged.device,
            ino: staged.ino,
        },
    );
    let mut proc = FakeProc {
        clock: clock.clone(),
        maps: vec![mapping(&staged)],
        maps_seq: VecDeque::new(),
        files,
        file_err: HashSet::new(),
        exe: Some(PathBuf::from("/bin/sh")),
        exe_seq: VecDeque::new(),
        file_read_seq: VecDeque::new(),
        maps_err_at: HashSet::new(),
        maps_delay_ns: 0,
        file_delay_ns: 0,
        maps_calls: 0,
        comm: None,
        comm_settle_at_ns: None,
        comm_settled: None,
        comm_hook: None,
        comm_read_hook: None,
        proc_log: Rc::new(RefCell::new(ProcLog::default())),
        stat_seq: VecDeque::new(),
        read_budget: 128 * 1024 * 1024,
    };
    let info = TargetInfo {
        pid,
        owned: true,
        comm: "sh".to_string(),
        cmdline: "<redacted>".to_string(),
        container_id: String::new(),
        kernel_release: "test-kernel".to_string(),
        provider_build_id: "unknown".to_string(),
        provider_path: "/p/provider.so".to_string(),
        image_digest: String::new(),
        acquired_ns: BASE_NS,
        acquired_instant: clock.now(),
        acquired_wall: clock.wall_now(),
    };
    let cfg = Config {
        harvest_object: Some(PathBuf::new()),
        count_object: Some(PathBuf::new()),
        members_object: Some(PathBuf::new()),
        dev_bundle: None,
        provider: Some(PathBuf::from("/p/provider.so")),
        builtin: false,
        table: None,
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration,
        settle: Duration::from_millis(500),
        harvest_timeout,
        grace: Duration::from_secs(5),
        image_digest: String::new(),
    };
    let out = observe(
        &cfg,
        &info,
        SessionSet {
            discovery,
            count,
            target: owned,
            lifecycle,
        },
        &*clock,
        &mut proc,
        &|| false,
    );
    (out, Some(pid))
}

#[test]
fn live_fast_child_exit7_no_zombie() {
    // Exit 7 survives the full observe loop; the child is reaped
    // exactly once (no zombie afterwards).
    let (out, pid) = live_observe(
        "live-exit7",
        &["/bin/sh", "-c", "exit 7"],
        Duration::from_secs(30),
        false,
    );
    let pid = pid.expect("spawned");
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert_reaped(pid);
}

#[test]
fn live_20ms_target_exit_no_zombie() {
    // A 20ms target exits inside the window: status preserved,
    // reaped exactly once.
    let (out, pid) = live_observe(
        "live-20ms",
        &["/bin/sh", "-c", "sleep 0.02"],
        Duration::from_secs(30),
        false,
    );
    let pid = pid.expect("spawned");
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(0));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 0 })
    ));
    assert_reaped(pid);
}

#[test]
fn live_owned_exit_survives_pin_recycle_at_finish() {
    // Pin-aware controller exit: a real owned child really exits
    // (custody reaps it, so /proc goes away) and the discovery
    // close reports the spurious pin recycle — the capture still
    // lands with the exit preserved and no zombie left behind.
    // R21-F4: the kernel window opens pre-release (real setup
    // time passes), but observation coverage starts at release —
    // the document's effective start never predates the requested
    // start (the semantic validator's containment rule).
    let (out, pid) = live_observe(
        "live-exit-recycle",
        &["/bin/sh", "-c", "exit 7"],
        Duration::from_secs(30),
        true,
    );
    let pid = pid.expect("spawned");
    let c = out.unwrap();
    assert!(
        c.document.window.effective_start_ns >= c.document.window.requested_start_ns,
        "effective start escapes the requested window: {:?}",
        c.document.window
    );
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert_eq!(counter_value(&c, "discovery.close_join_skipped"), 1);
    assert!(matches!(c.outcome, Outcome::Partial));
    assert_reaped(pid);
}

#[test]
fn live_zero_setup_timeout_spawns_nothing() {
    // R06 fix round 1: zero setup timeout fails the capture-helper spawn
    // itself (pre-fork deadline, via the control entrypoint — the same
    // shape as production `run()`): no child, no window, and the sentinel
    // never runs. (The post-fork kill+reap proof is the next test.)
    let dir = std::env::temp_dir().join(format!("r06-live-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sentinel = dir.join("SENTINEL");
    let script = format!("touch '{}'; sleep 30", sentinel.display());
    let argv_owned = ["/bin/sh".to_string(), "-c".to_string(), script];
    let argv_refs: Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
    let idle = AtomicBool::new(false);
    let (out, pid) = live_observe_inner(
        "live-zero-timeout",
        &argv_refs,
        Duration::from_secs(30),
        false,
        Duration::ZERO,
        &idle,
    );
    assert!(pid.is_none(), "nothing may fork");
    let msg = out.expect_err("zero setup timeout must fail").to_string();
    assert!(msg.contains("deadline"), "{msg}");
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Independent exact-PID teardown (fix round 2 / F4; mirrors the
/// lifecycle suite's guard — this file is a separate crate): RAII rescue
/// of one observed pid, armed before any fallible assertion and effective
/// on panic paths too. `Drop` is best-effort SIGKILL + bounded reap of
/// the exact pid only (ECHILD-tolerant, never panics).
struct R06PidGuard {
    pid: u32,
    armed: bool,
}

impl R06PidGuard {
    fn arm(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for R06PidGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            let mut status = 0;
            let r = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if r > 0 {
                return;
            }
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Independent PID custody for the capture spawn test (mirrors the
/// lifecycle suite's helper; this file is a separate crate): SIGKILL +
/// reap one exact pid, tolerating the ECHILD race where the spawn worker
/// reaped it first. Bounded, and never touches any other pid.
fn r06_capture_rescue_pid(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if r > 0 {
            return;
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        assert!(Instant::now() < end, "rescue: pid {pid} would not die");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn live_prestop_cancel_reaps_real_child() {
    // R06 fix round 1: the capture helper spawns through the control
    // entrypoint, so a cancellation landing deterministically post-fork
    // (after the fork is observed; 10s stall) kills + reaps the real
    // child before `observe()` ever runs: no window, no zombie, and the
    // sentinel never runs. Supervised exactly like the lifecycle suite
    // (worker + join bound + exact-pid rescue): a regressed hang fails
    // the test instead of the runner, on every path.
    let dir = std::env::temp_dir().join(format!("r06-live-cancel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sentinel = dir.join("SENTINEL");
    let script = format!("touch '{}'; sleep 30", sentinel.display());
    let argv_owned = ["/bin/sh".to_string(), "-c".to_string(), script];
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_c = cancel.clone();
    let sink = Arc::new(AtomicU32::new(0));
    let sink_c = sink.clone();
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        __test_set_prestop_stall_ms(10_000);
        __test_set_prestop_pid_sink(Some(sink_c));
        let argv_refs: Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
        let r = live_observe_inner(
            "live-prestop-cancel",
            &argv_refs,
            Duration::from_secs(30),
            false,
            Duration::from_secs(30),
            &cancel_c,
        );
        __test_set_prestop_pid_sink(None);
        __test_set_prestop_stall_ms(0);
        let _ = tx.send(r);
    });
    let pid = {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let p = sink.load(Ordering::SeqCst);
            if p != 0 {
                break p;
            }
            assert!(Instant::now() < end, "no fork observed within 10s");
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    // F4: independent teardown armed before any fallible step — panics
    // below still rescue the exact observed pid on unwinding.
    let mut r06_guard = R06PidGuard::arm(pid);
    cancel.store(true, Ordering::SeqCst);
    let (out, helper_pid) = match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(r) => {
            worker.join().unwrap();
            r
        }
        Err(_) => {
            r06_capture_rescue_pid(pid);
            assert_reaped(pid);
            panic!("capture spawn hung beyond 20s; rescued pid {pid}");
        }
    };
    // The helper must never get a child (its spawn fails): the only
    // pid is the independently observed one. On the unexpected-Ok
    // regression the helper ran a full window and may have detached a
    // live child — retain the exact observed pid and guarantee cleanup
    // before failing.
    let msg = match out {
        Err(e) => {
            assert!(helper_pid.is_none(), "helper spawn must fail");
            e.to_string()
        }
        Ok(c) => {
            r06_capture_rescue_pid(pid);
            assert_reaped(pid);
            panic!("cancelled capture spawn must fail, got {:?}", c.outcome);
        }
    };
    assert!(msg.contains("cancel"), "names cancellation: {msg}");
    assert!(
        msg.contains(&format!("owned child {pid} killed and reaped")),
        "confirmed cleanup of the observed pid: {msg}"
    );
    assert!(msg.contains("(status 137)"), "SIGKILL status: {msg}");
    assert_reaped(pid);
    r06_guard.disarm();
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn live_short_children_are_detected() {
    // Back-to-back short-lived grandchildren: polling is
    // best-effort (the fallback stays explicitly PARTIAL either
    // way), but sustained children must surface at least one Fork.
    // Round 2, residual S (flake-hardening): adaptive within a
    // bounded budget — poll until first detection or 50 rounds
    // (early exit keeps healthy runs fast; the ~6s children span
    // outlasts the ~5s budget even when parallel-suite load
    // stretches sleeps). The detection assertion stays: a
    // detection-dropping mutant exhausts the budget and fails
    // (mutant-proven — see the fix-wave report).
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "i=0; while [ $i -lt 120 ]; do sleep 0.05; i=$((i+1)); done".to_string(),
    ];
    let mut owned = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    let pid = owned.pid();
    owned.release().unwrap();
    let mut lc = PollingLifecycle::new(pid);
    assert!(lc.fallback_partial());
    let mut forks = 0u64;
    for _ in 0..50 {
        let delta = lc.poll();
        forks += delta
            .events
            .iter()
            .filter(|e| e.kind == LifecycleKind::Fork)
            .count() as u64;
        if forks >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        forks >= 1,
        "fifty scans across ~6s of 50ms children saw nothing"
    );
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert!(r > 0);
    assert_reaped(pid);
}

#[test]
fn live_double_fork_reparent_stays_counted() {
    // A forked child counted once stays counted after it reparents
    // away (killed target): never double-counted, never dropped.
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep 30 & wait".to_string(),
    ];
    let mut owned = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    let pid = owned.pid();
    owned.release().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let mut lc = PollingLifecycle::new(pid);
    let first = lc.poll();
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].kind, LifecycleKind::Fork);
    let kid = first.events[0].pid;
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert!(r > 0);
    assert_reaped(pid);
    std::thread::sleep(Duration::from_millis(100));
    let second = lc.poll();
    assert!(
        second.events.is_empty(),
        "reparented child must not recount: {second:?}"
    );
    // The reparented sleeper belongs to init now: stop it, cannot reap it.
    unsafe {
        libc::kill(kid as libc::pid_t, libc::SIGKILL);
    }
}

#[test]
fn live_double_fork_grandchild_reparents_past_target() {
    // TRUE double fork: the target's child forks a grandchild and
    // exits while the TARGET LIVES — the grandchild reparents past
    // the target (never its child), counted once via the
    // intermediate, never recounted, never a ghost.
    let stage = Stage::fresh("dblfork");
    let pidfile = stage.dir.join("grandchild.pid");
    let pidfile = pidfile.to_str().unwrap().to_string();
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("(sleep 30 & echo $! > '{pidfile}'; sleep 0.5); exec sleep 60"),
    ];
    let mut owned = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    let pid = owned.pid();
    owned.release().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let mut lc = PollingLifecycle::new(pid);
    // The intermediate is alive (0.5s): exactly one Fork for it.
    let first = lc.poll();
    assert_eq!(first.events.len(), 1, "{first:?}");
    assert_eq!(first.events[0].kind, LifecycleKind::Fork);
    let middle = first.events[0].pid;
    // Wait for the true reparent (intermediate gone, grandchild past
    // the live target) instead of a fixed sleep.
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let t0 = Instant::now();
    loop {
        let ppid = ppid_of(grandchild);
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "grandchild {grandchild} never reparented (ppid {ppid:?})"
        );
        if ppid.is_some_and(|p| p != middle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(
        ppid_of(grandchild),
        Some(pid),
        "grandchild must reparent past the live target"
    );
    assert_eq!(
        unsafe { libc::kill(pid as libc::pid_t, 0) },
        0,
        "target must outlive the intermediate"
    );
    // After the reparent: no Fork recount, no ghost (a same-TGID
    // Exec from the target's own exec is allowed).
    let second = lc.poll();
    assert!(
        second.events.iter().all(|e| e.kind != LifecycleKind::Fork),
        "reparent must not recount: {second:?}"
    );
    unsafe {
        libc::kill(grandchild as libc::pid_t, libc::SIGKILL);
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert!(r > 0);
    assert_reaped(pid);
}

#[test]
fn live_same_tgid_exec_is_detected() {
    // Same-pid `exec` (sh → sleep): the exe-link watch reports one
    // Exec event, distinct from fork activity.
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep 0.4; exec sleep 30".to_string(),
    ];
    let mut owned = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    let pid = owned.pid();
    // v0.2 flake hardening, construct-before-release: the child is
    // SIGSTOP-stopped pre-exec, so this baseline snapshots the pre-exec
    // image deterministically — zero race with either exec.
    let mut lc = PollingLifecycle::new(pid);
    owned.release().unwrap();
    // Phase 1 — settle the initial `sh` exec: the baseline above is the
    // pre-exec image, so the first Exec to surface is the stopped-child
    // → sh transition; drain it before targeting `sh → sleep` below.
    let t_settle = Instant::now();
    let mut settled = false;
    while t_settle.elapsed() < Duration::from_secs(10) {
        let sample = lc.poll();
        if sample.events.iter().any(|e| e.kind == LifecycleKind::Exec) {
            settled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(settled, "initial sh exec must surface within 10 s");
    // Phase 2 — target the `sh → sleep` exec quiet-first.
    // `PollingLifecycle::new` snapshots /proc/pid/exe at construction and
    // Exec fires only on an exe-link change; the initial exec already
    // settled in phase 1, so this baseline is the post-sh image and polls
    // stay quiet until the 400 ms exec point.
    let mut lc = PollingLifecycle::new(pid);
    let t0 = Instant::now();
    let mut saw_pre_exec_quiet = false;
    let mut exec_seen = false;
    while t0.elapsed() < Duration::from_secs(10) {
        let sample = lc.poll();
        let execs: Vec<_> = sample
            .events
            .iter()
            .filter(|e| e.kind == LifecycleKind::Exec)
            .collect();
        if execs.is_empty() {
            saw_pre_exec_quiet = true;
        } else {
            assert_eq!(execs.len(), 1, "exactly one Exec surfaces: {sample:?}");
            assert_eq!(execs[0].pid, pid, "exec belongs to the target: {sample:?}");
            exec_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        saw_pre_exec_quiet,
        "at least one quiet poll before the exec point"
    );
    assert!(exec_seen, "exec must surface within 10 s");
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert!(r > 0);
    assert_reaped(pid);
}

#[test]
fn live_comm_settles_post_exec() {
    // Acquisition reads comm while the child is stopped pre-exec
    // (the observer's inherited comm); after release + exec the
    // live read reports the application ("sleep").
    let argv = vec!["/bin/sleep".to_string(), "30".to_string()];
    let mut owned = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    let pid = owned.pid();
    let mut proc = LiveProc;
    let pre = proc.read_comm(pid);
    assert_ne!(
        pre.as_deref(),
        Some("sleep"),
        "pre-exec comm must not be the app: {pre:?}"
    );
    owned.release().unwrap();
    let t0 = Instant::now();
    let mut settled = None;
    while t0.elapsed() < Duration::from_secs(5) {
        settled = proc.read_comm(pid);
        if settled.as_deref() == Some("sleep") {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        settled.as_deref(),
        Some("sleep"),
        "post-exec comm never settled: {settled:?}"
    );
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert!(r > 0);
    assert_reaped(pid);
}

/// Multithreaded-holder subprocess for the thread test below: two
/// worker threads plus main, parked. Ignored in the normal suite;
/// the live test below runs it via an exact filtered subprocess.
#[test]
#[ignore]
#[allow(non_snake_case)]
fn live__thread_holder() {
    let _held: Vec<_> = (0..2)
        .map(|_| std::thread::spawn(|| std::thread::sleep(Duration::from_secs(60))))
        .collect();
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn live_thread_creation_is_not_ignored_process() {
    // A three-task target (main + two threads, zero forked
    // children): the lifecycle scan reports no fork events — thread
    // creation alone is not an ignored process.
    use std::process::Stdio;
    let mut kid = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "live__thread_holder", "--ignored", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = kid.id();
    let tasks = || {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    let t0 = Instant::now();
    while tasks() < 3 && t0.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(tasks() >= 3, "holder never went multithreaded");
    let mut lc = PollingLifecycle::new(pid);
    let delta = lc.poll();
    assert!(
        delta.events.is_empty(),
        "threads must not report as forks: {delta:?}"
    );
    kid.kill().unwrap();
    let _ = kid.wait();
}

// ---------------------------------------------------------------------------
// F-D/A13: relevance-scoped file reads + verified-identity cache.
// ---------------------------------------------------------------------------

#[test]
fn round_reads_only_relevant_files() {
    // F1: per-poll file reads are scoped to the poll's delta
    // (candidate backings, array owners, new objects) — a
    // mapped-but-unreferenced file is never read nor stat'ed.
    let mut h = Harness::fresh("relevant-reads");
    h.snapshot_attached();
    let decoy = h.stage.write("decoy.so", &h.bytes.clone());
    h.files.insert(
        decoy.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone().into(),
            dev: decoy.device,
            ino: decoy.ino,
        },
    );
    let decoy_path = decoy.path.clone();
    h.maps = vec![mapping(&h.staged), mapping(&decoy)];
    let staged_path = h.staged.path.clone();
    let c = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![c],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    let (out, post) = h.run();
    out.unwrap();
    let log = post.proc_log.borrow();
    assert!(
        !log.reads.iter().any(|p| p == &decoy_path),
        "unreferenced decoy must never be read: {:?}",
        log.reads
    );
    assert!(
        !log.stats.iter().any(|p| p == &decoy_path),
        "unreferenced decoy must never be stat'ed: {:?}",
        log.stats
    );
    assert!(
        log.reads.iter().any(|p| p == &staged_path),
        "referenced provider must be read: {:?}",
        log.reads
    );
}

#[test]
fn unchanged_files_are_read_once_then_stat_validated() {
    // F2: an unchanged relevant file is read once (first poll)
    // and validated by stat afterwards — N polls, 1 read.
    let mut h = Harness::fresh("read-once");
    h.snapshot_attached();
    let staged_path = h.staged.path.clone();
    for _ in 0..4 {
        let c = cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        );
        h.polls.push_back(DiscoveryDelta {
            candidates: vec![c],
            trigger_observed: true,
            ..DiscoveryDelta::default()
        });
    }
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    let (out, post) = h.run();
    out.unwrap();
    let log = post.proc_log.borrow();
    let reads = log.reads.iter().filter(|p| *p == &staged_path).count();
    let stats = log.stats.iter().filter(|p| *p == &staged_path).count();
    assert_eq!(
        reads, 1,
        "unchanged provider must be read exactly once: {:?} / {:?}",
        log.reads, log.stats
    );
    assert!(
        stats >= 2,
        "expected setup + round stat validations, got {stats}: {:?}",
        log.stats
    );
}

#[test]
fn stat_identity_change_forces_reread() {
    // F3: a stat identity that differs from the cached entry
    // forces a re-read (scripted transient race on the 3rd stat);
    // afterwards the cache converges again (exactly 2 reads).
    let mut h = Harness::fresh("stat-reread");
    h.snapshot_attached();
    let staged_path = h.staged.path.clone();
    let (dev, ino) = (h.staged.device, h.staged.ino);
    for _ in 0..6 {
        let c = cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        );
        h.polls.push_back(DiscoveryDelta {
            candidates: vec![c],
            trigger_observed: true,
            ..DiscoveryDelta::default()
        });
    }
    h.stat_seq = VecDeque::from([
        None,
        None,
        Some(FileStat {
            dev,
            ino: ino + 1000,
            size: h.bytes.len() as u64,
            mtime_ns: 0,
        }),
    ]);
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    let (out, post) = h.run();
    out.unwrap();
    let log = post.proc_log.borrow();
    let reads = log.reads.iter().filter(|p| *p == &staged_path).count();
    assert_eq!(
        reads, 2,
        "setup read + one race re-read expected: {:?} / {:?}",
        log.reads, log.stats
    );
}

#[test]
fn pathological_relevance_set_is_capped_and_loud() {
    // F4: a pathological delta (257 distinct backings) reads at
    // most MAX_RELEVANT_FILES_PER_ROUND paths and reports the
    // dropped remainder as discovery.relevance_capped loss —
    // bounded memory, loud degradation.
    let mut h = Harness::fresh("relevance-cap");
    h.snapshot_attached();
    let dev = plan::render_device(h.staged.device);
    let mut maps = vec![mapping(&h.staged)];
    let mut cands = Vec::new();
    for i in 0..257u64 {
        maps.push(Mapping {
            start: 0x7f00_0000_0000,
            end: 0x7f00_0000_1000,
            x: true,
            offset: 0,
            dev: dev.clone(),
            ino: 1_000_000 + i,
            path: format!("/x/mod{i:03}.so"),
        });
        cands.push(cand(
            "/p/provider.so",
            Some(BackingRef {
                dev: dev.clone(),
                ino: 1_000_000 + i,
                offset: h.off,
            }),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        ));
    }
    h.maps = maps;
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: cands,
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "257 backings over a 256 cap must report 1 dropped: {:?}",
        c.document.counters
    );
    let log = post.proc_log.borrow();
    assert!(
        log.reads.len() <= 257,
        "reads must stay bounded: {}",
        log.reads.len()
    );
}

// ---------------------------------------------------------------------------
// R20 lifecycle/readiness + count-close assurance.
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_scan_loss_withholds_complete() {
    // Lost lifecycle witness (failed /proc scan mid-window): the
    // seven executed calls survive as positive evidence, but the
    // window cannot claim COMPLETE — the census is tainted and the
    // loss rides loud with its reason.
    let mut h = Harness::fresh("scan-loss-partial");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    // First round sweep loses its scan; later sweeps stay clean.
    h.lifecycle_polls.push_back(LifecycleDelta {
        events: vec![],
        loss: 1,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(counter_value(&c, "lifecycle.scan_loss"), 1);
    assert!(has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn lifecycle_signal_dropped_withholds_complete() {
    // Kernel-side lifecycle overflow (signals known-dropped between
    // drains) is its own attributable loss — never silent, never
    // folded into the host scan count — and withholds COMPLETE.
    let mut h = Harness::fresh("signal-dropped");
    h.snapshot_attached();
    h.polls.push_back(DiscoveryDelta {
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.lifecycle_polls.push_back(LifecycleDelta {
        events: vec![],
        loss: 0,
        dropped: 3,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    // Exit lands in the second sleep: exactly one round runs, so the
    // round sweep consumes the overflow poll.
    h.exit_at_ns = Some(BASE_NS + 250_000_001);
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(counter_value(&c, "lifecycle.signal_dropped"), 3);
    assert_eq!(counter_value(&c, "lifecycle.signal_prefix_unwitnessed"), 0);
    assert_eq!(counter_value(&c, "lifecycle.scan_loss"), 0);
    assert!(has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
}

#[test]
fn lifecycle_close_drain_folds_after_owned_exit() {
    // The owned child exits before any round runs, so the close-time
    // /proc sweep stays skipped — but a kernel-signal port's ring
    // drain still folds: its fork witness lands loud (no /proc scan
    // needed, so corpses are safe).
    let mut h = Harness::fresh("close-drain-folds");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 1);
    h.exit_code = 0;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: vec![LifecycleEvent {
            kind: LifecycleKind::Fork,
            pid: 99991,
            timestamp_ns: Some(BASE_NS + 1),
        }],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(0));
    assert_eq!(counter_value(&c, "lifecycle.fork_exec_ignored"), 1);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
}

#[test]
fn lifecycle_close_drain_loss_is_loud() {
    // A loss-bearing close drain (ring overflow at the tail) rides
    // loud even on the zero-round fast-exit path.
    let mut h = Harness::fresh("close-drain-loss");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 1);
    h.exit_code = 0;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: vec![],
        loss: 1,
        dropped: 2,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(counter_value(&c, "lifecycle.scan_loss"), 1);
    assert_eq!(counter_value(&c, "lifecycle.signal_dropped"), 2);
    assert_eq!(counter_value(&c, "lifecycle.signal_prefix_unwitnessed"), 0);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
}

#[test]
fn lifecycle_empty_close_drain_preserves_complete() {
    // Kernel-signal shape with a clean tail (drained, nothing
    // happened): the COMPLETE path is undisturbed — the close drain
    // adds evidence handling, not an unconditional PARTIAL.
    let mut h = Harness::fresh("close-drain-clean");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    // Baseline attach (pre-release ready — F7).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.lifecycle_close_drain = Some(LifecycleDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Complete));
    assert_eq!(c.document.total_calls(), 7);
}

#[test]
fn lifecycle_missing_close_drain_withholds_complete() {
    // Kernel-signal shape (fallback=false) with NO close witness
    // (close_drain None): the observer never proved it covered the
    // requested interval's tail — PARTIAL with explicit no-witness
    // loss, never silent COMPLETE on absent evidence.
    let mut h = Harness::fresh("no-witness-partial");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.lifecycle_fallback = false;
    h.lifecycle_close_drain = None;
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(counter_value(&c, "lifecycle.no_witness"), 1);
    assert!(has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn lifecycle_truncated_close_drain_withholds_complete() {
    // The close drain stopped with records still queued
    // (bounded-drain residual): the tail past the bound is
    // uncovered — PARTIAL with explicit drain-pending loss, never
    // silent COMPLETE on a nonempty ring tail.
    let mut h = Harness::fresh("drain-pending-partial");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.lifecycle_fallback = false;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: vec![],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 1,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(counter_value(&c, "lifecycle.drain_pending"), 1);
    assert!(has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn lifecycle_exec_fences_generation_and_conserves() {
    // The target's own exec (exe link flips mid-window, mappings
    // unchanged): exactly one Exec fence — the fenced generation
    // keeps gen-0 counts under gen-0 meaning, later counts land in
    // gen 1, the total is conserved, and the exec is NOT double-booked
    // as ignored fork/exec activity.
    let mut h = Harness::fresh("exec-fence");
    h.snapshot_attached();
    h.exe = Some(PathBuf::from("/bin/app-next"));
    h.exe_seq = VecDeque::from([
        Some(PathBuf::from("/bin/app")),
        Some(PathBuf::from("/bin/app")),
        Some(PathBuf::from("/bin/app")),
        Some(PathBuf::from("/bin/app-next")),
    ]);
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        4,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].generation, 1);
    assert_eq!(c.document.sites[0].calls, 4);
    assert_eq!(counter_value(&c, "lifecycle.fork_exec_ignored"), 0);
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1]);
}

#[test]
fn lifecycle_kernel_shape_fast_noquery_is_honest_partial() {
    // Ordinary-window qualification (fast/no-query program): the
    // kernel-signal shape (fallback=false, clean close witness)
    // carries NO unconditional polling fallback — the fast exit
    // yields the honest no-query PARTIAL (no trigger observed),
    // with zero lifecycle loss and zero lifecycle reasons.
    let mut h = Harness::fresh("kernel-fast-noquery");
    h.snapshot_attached();
    h.exit_at_ns = Some(BASE_NS + 1);
    h.exit_code = 0;
    h.lifecycle_fallback = false;
    h.lifecycle_close_drain = Some(LifecycleDelta::default());
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(0));
    assert!(has_reason(&c, "no-query"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(
        !has_reason(&c, "lifecycle-polling-partial"),
        "{:?}",
        c.reasons
    );
    assert!(!has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    for name in [
        "lifecycle.fork_exec_ignored",
        "lifecycle.scan_loss",
        "lifecycle.signal_dropped",
        "lifecycle.signal_prefix_unwitnessed",
        "lifecycle.polling_fallback",
        "lifecycle.no_witness",
        "lifecycle.drain_pending",
        "lifecycle.exec_gap",
    ] {
        assert_eq!(counter_value(&c, name), 0, "{name} must be absent");
    }
}

#[test]
fn lifecycle_exec_witness_fences_without_snapshot_change() {
    // Same-path exec: the exe link and mappings NEVER change, so the
    // snapshot comparison detects nothing — but the lifecycle sweep
    // delivers the kernel Exec witness for the target. The witness
    // must drive exactly one Exec fence (no double-book as ignored):
    // gen-0 counts stay fenced under gen-0 meaning, later counts
    // land in gen 1, the total is conserved.
    let mut h = Harness::fresh("exec-witness-fence");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        4,
        FirePlan {
            fires: vec![(BASE_NS + 1_200_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    // Rounds 1-2 sweep clean; round 3 delivers the Exec witness for
    // the target itself (exe snapshot unchanged throughout).
    h.lifecycle_polls = VecDeque::from([
        LifecycleDelta::default(),
        LifecycleDelta::default(),
        LifecycleDelta {
            events: vec![LifecycleEvent {
                kind: LifecycleKind::Exec,
                pid: PID,
                timestamp_ns: Some(BASE_NS + 1),
            }],
            loss: 0,
            dropped: 0,
            prefix_unwitnessed: 0,
            pending: 0,
        },
    ]);
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].generation, 1);
    assert_eq!(c.document.sites[0].calls, 4);
    assert_eq!(counter_value(&c, "lifecycle.fork_exec_ignored"), 0);
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1]);
}

#[test]
fn lifecycle_close_drain_exec_withholds_complete() {
    // An Exec witness arriving in the close drain (after the last
    // round's fence opportunity): the tail may mix pre/post-exec
    // identity under one fingerprint, and no fence can version it
    // anymore — an explicit continuity gap (PARTIAL), never silent
    // COMPLETE.
    let mut h = Harness::fresh("close-exec-gap");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    h.lifecycle_fallback = false;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: vec![LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid: PID,
            timestamp_ns: Some(BASE_NS + 1),
        }],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    });
    let (out, _) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(counter_value(&c, "lifecycle.exec_gap"), 1);
    assert_eq!(counter_value(&c, "lifecycle.fork_exec_ignored"), 0);
    assert!(has_reason(&c, "fork-exec-ignored"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn lifecycle_subpoll_object_replacement_fences_provenance() {
    // P6 sub-poll object replacement: between two polls the provider
    // file is replaced (old mapping gone, new inode mapped). The
    // replacement fences exactly once: gen-0 counts stay fenced under
    // the OLD object fingerprint, the replacement's counts land in
    // gen 1 under the NEW fingerprint, nothing is relabeled, and the
    // conserved total reaches the document.
    let mut h = Harness::fresh("replacement");
    h.snapshot_attached();
    let bytes_b = flipped_build_id(&h.bytes.clone());
    let newso = h.stage.write("new.so", &bytes_b);
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand_old = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let new_off = x_offset(&bytes_b);
    let cand_new = cand(
        "/p/provider.so",
        backing_of(&newso, new_off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_old],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_new],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    // Post-fence fire hits every still-bound cookie: the replacement
    // cookie legitimately (mapped) plus the old cookie (the fake
    // fires bound cookies without consulting mappings — production
    // cannot execute unmapped code, so the old-cookie row is a fake
    // over-fire, honestly routed under the old meaning, never
    // relabeled as the replacement).
    h.plans.insert(
        5,
        FirePlan {
            fires: vec![(BASE_NS + 1_500_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites.len(), 1);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    let fp_old = c.document.fenced[0].sites[0].site.object.0.clone();
    assert!(fp_old.starts_with("build:"), "{fp_old}");
    let fp_new_sites: Vec<_> = c
        .document
        .sites
        .iter()
        .filter(|s| s.site.object.0 != fp_old)
        .collect();
    assert_eq!(fp_new_sites.len(), 1, "{:?}", c.document.sites);
    assert_eq!(fp_new_sites[0].generation, 1);
    assert_eq!(fp_new_sites[0].calls, 4);
    assert!(
        fp_new_sites[0].site.object.0.starts_with("build:"),
        "{:?}",
        fp_new_sites[0].site.object.0
    );
    // Conserved: 3 fenced + 4 replacement + 4 fake over-fire on the
    // still-bound old cookie (old meaning, gen 1).
    assert_eq!(c.document.total_calls(), 11);
    assert_eq!(counter_value(&c, "count.missed_attaches"), 0);
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1]);
}

#[test]
fn lifecycle_stale_queued_record_creates_no_evidence() {
    // P6 stale queued records: after the replacement fences, a queued
    // (stale) redelivery of the OLD triple arrives. Its mapping is
    // gone, so the bytes are unverifiable: the adapter downgrades
    // the meaning to an unverified fingerprint at a versioning fence
    // (fail-closed) instead of reusing the stale verified identity —
    // no new site, no relabel, no fabricated evidence: the fenced
    // counts stand alone under the old fingerprint.
    let mut h = Harness::fresh("stale-queue");
    h.snapshot_attached();
    let bytes_b = flipped_build_id(&h.bytes.clone());
    let newso = h.stage.write("new.so", &bytes_b);
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    let before = vec![mapping(&h.staged)];
    let after = vec![mapping(&newso)];
    h.maps_seq = VecDeque::from([before.clone(), before.clone(), before, after.clone()]);
    h.maps = after;
    let cand_old = || {
        cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_old()],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta::default());
    // Stale redelivery of the pre-replacement triple, post-fence.
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_old()],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.fenced.len(), 2);
    assert_eq!(c.document.fenced[0].generation, 0);
    assert_eq!(c.document.fenced[0].sites.len(), 1);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    assert!(
        c.document.fenced[0].sites[0]
            .site
            .object
            .0
            .starts_with("build:"),
        "{:?}",
        c.document.fenced[0].sites[0].site.object.0
    );
    // The downgrade fence seals an empty gen-1 bucket (no counts
    // arrived under the replacement generation): evidence-free.
    assert_eq!(c.document.fenced[1].generation, 1);
    assert!(c.document.fenced[1].sites.is_empty());
    assert!(c.document.sites.is_empty(), "{:?}", c.document.sites);
    assert_eq!(c.document.total_calls(), 3);
    assert_eq!(
        counter_value(&c, "discovery.site_identity_refreshed"),
        1,
        "{:?}",
        c.document.counters
    );
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1, 2]);
}

#[test]
fn lifecycle_impl_only_replacement_versions_and_conserves() {
    // P6 implementation-only backing replacement: same (dev, ino,
    // offset) triple, new bytes (new build-id, SAME size — only the
    // mtime moves). The file cache must notice the freshness change,
    // re-read, and forward the new fingerprint so the count session
    // versions at a fence: gen-0 counts stay fenced under the old
    // fingerprint, later counts land in gen 1 under the new one.
    // (R20-fix finding 5: the scripted redelivery below models
    // production's freshness re-emit — real discovery re-delivers
    // the tracked candidate when its backing file's size/mtime
    // moves, pinned by
    // `discovery::session::tests::r20fix_backing_freshness_change_reemits_candidate`.
    // Capture-side, the redelivered delta is what runs the stat
    // check for the already-counted site.)
    let mut h = Harness::fresh("impl-only");
    h.snapshot_attached();
    let bytes_a = h.bytes.clone();
    let bytes_b = flipped_build_id(&bytes_a);
    assert_eq!(bytes_a.len(), bytes_b.len());
    let (dev, ino) = (h.staged.device, h.staged.ino);
    let staged_path = h.staged.path.clone();
    let files_a: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged_path.clone(),
        plan::FileBytes {
            bytes: bytes_a.clone().into(),
            dev,
            ino,
        },
    )]);
    let files_b: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged_path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev,
            ino,
        },
    )]);
    // Round-1 read serves A; the round-2 re-read serves B. (The
    // baseline carries the default delta: no relevant paths, so no
    // stats and no reads there.)
    h.file_read_seq = VecDeque::from([files_a, files_b]);
    let stat_new = FileStat {
        dev,
        ino,
        size: bytes_b.len() as u64,
        mtime_ns: 1,
    };
    // Round-1 stat + re-stat, round-2 miss + re-stat. (Round 3
    // carries the default delta: no relevant paths, no stats.)
    h.stat_seq = VecDeque::from([None, None, Some(stat_new), Some(stat_new)]);
    let cand1 = || {
        cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )
    };
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1()],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1()],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 3)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.plans.insert(
        3,
        FirePlan {
            fires: vec![(BASE_NS + 900_000_000, 4)],
            shortfall: 0,
            cancel: false,
        },
    );
    // Three rounds run (exit lands in the fourth sleep): attach in
    // round 1, refresh + fence in round 2, gen-1 fire in round 3.
    h.exit_at_ns = Some(BASE_NS + 750_000_001);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    let gens: Vec<u32> = post
        .shared
        .borrow()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("gen:")?.parse().ok())
        .collect();
    assert_eq!(gens, vec![1], "stale bytes must not suppress the fence");
    assert_eq!(c.document.fenced.len(), 1);
    assert_eq!(c.document.fenced[0].sites[0].calls, 3);
    let fp_old = c.document.fenced[0].sites[0].site.object.0.clone();
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].generation, 1);
    assert_eq!(c.document.sites[0].calls, 4);
    let fp_new = c.document.sites[0].site.object.0.clone();
    assert_ne!(fp_old, fp_new, "fingerprint must version, not relabel");
    assert_eq!(c.document.total_calls(), 7);
    let log = post.proc_log.borrow();
    let reads = log.reads.iter().filter(|p| *p == &staged_path).count();
    assert_eq!(reads, 2, "baseline read + exactly one freshness re-read");
}

#[test]
fn lifecycle_never_snapshotted_backing_misses_loud() {
    // R20-fix finding 4 (capture half): replacement activity that
    // disappears between snapshots — discovery attests a B-backed
    // candidate (its own maps saw B), but capture's snapshots
    // NEVER contain B (maps-vs-discovery TOCTOU). B's path never
    // resolves, its bytes never read, no probe ever binds it: the
    // miss rides loud (missed attach + PARTIAL), never relabeled
    // onto A's fingerprint, while A's positive evidence survives.
    let mut h = Harness::fresh("never-mapped");
    h.snapshot_attached();
    let bytes_b = flipped_build_id(&h.bytes.clone());
    let newso = h.stage.write("new.so", &bytes_b);
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev: newso.device,
            ino: newso.ino,
        },
    );
    // NOTE: B is staged (bytes exist) but NEVER mapped — every
    // snapshot shows A only.
    let new_off = x_offset(&bytes_b);
    let cand_a = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let cand_b = cand(
        "/p/provider.so",
        backing_of(&newso, new_off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_a, cand_b],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    // A's positive evidence survives under its verified build-id;
    // B attaches nothing (never relabeled onto A), and the miss
    // rides loud (unattached-sites + missed-attaches gaps).
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].calls, 7);
    assert!(
        c.document.sites[0].site.object.0.starts_with("build:"),
        "{:?}",
        c.document.sites[0].site.object.0
    );
    assert_eq!(counter_value(&c, "count.missed_attaches"), 1);
    assert!(has_reason(&c, "missed-attaches"), "{:?}", c.reasons);
    assert!(has_reason(&c, "discovery-loss"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn lifecycle_raced_file_read_is_discarded_loud() {
    // Freshness race on one of two sites (pre-stat A, bound read
    // under A identity, post stat moved): the raced bytes may be
    // torn across a same-size edit — they must be DISCARDED (never
    // fingerprinted, never attached), with explicit
    // unverified-read loss (PARTIAL). The clean sibling's positive
    // evidence survives under its verified fingerprint.
    let mut h = Harness::fresh("raced-read");
    h.snapshot_attached();
    // Raced companion is small-ELF (already distinct from the
    // staged bytes): two full test-binary copies overflow the
    // 128MiB round budget and the raced read would refuse before
    // its race is detected. Same-size-edit shape preserved via
    // the scripted pre/post stats below.
    let bytes_b = small_elf(0xD4);
    let raced = h.stage.write("raced.so", &bytes_b);
    h.files.insert(
        raced.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone().into(),
            dev: raced.device,
            ino: raced.ino,
        },
    );
    h.maps = vec![mapping(&h.staged), mapping(&raced)];
    let (dev, ino) = (raced.device, raced.ino);
    let raced_path = raced.path.clone();
    // Reads run in relevant-path (sorted) order: prov.so first
    // (clean staged bytes), raced.so second (B bytes under the A
    // identity — a same-size edit the fd-pinned read could not
    // see — with a moved post-read stat proving the race).
    h.file_read_seq = VecDeque::from([
        HashMap::from([(
            h.staged.path.clone(),
            plan::FileBytes {
                bytes: h.bytes.clone().into(),
                dev: h.staged.device,
                ino: h.staged.ino,
            },
        )]),
        HashMap::from([(
            raced_path.clone(),
            plan::FileBytes {
                bytes: bytes_b.clone().into(),
                dev,
                ino,
            },
        )]),
    ]);
    let stat_pre = FileStat {
        dev,
        ino,
        size: bytes_b.len() as u64,
        mtime_ns: 0,
    };
    let stat_post = FileStat {
        dev,
        ino,
        size: bytes_b.len() as u64,
        mtime_ns: 1,
    };
    // prov.so stats fall back to the staged identity (clean);
    // raced.so pre/post stats prove the race.
    h.stat_seq = VecDeque::from([None, None, Some(stat_pre), Some(stat_post)]);
    let cand_clean = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    let cand_raced = cand(
        "/p/provider.so",
        backing_of(&raced, x_offset(&bytes_b)),
        1,
        12,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_clean, cand_raced],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _) = h.run();
    let c = out.unwrap();
    // The clean site counts under its verified fingerprint; the
    // raced site attaches nothing (withheld, never torn).
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(c.document.sites.len(), 1);
    assert!(
        c.document.sites[0].site.object.0.starts_with("build:"),
        "{:?}",
        c.document.sites[0].site.object.0
    );
    assert_eq!(c.document.sites[0].calls, 7);
    assert_eq!(counter_value(&c, "discovery.unverified_read"), 1);
    assert_eq!(counter_value(&c, "count.missed_attaches"), 1);
    assert!(has_reason(&c, "discovery-loss"), "{:?}", c.reasons);
    assert!(has_reason(&c, "missed-attaches"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
}

#[test]
fn startup_release_boundary_call_is_captured_in_order() {
    // The first call executes AT the release boundary. The site was
    // discovered in the BASELINE poll (pre-release) and attached
    // before release, so the boundary call is captured — with
    // explicit ordering evidence (sequence log: count programmed →
    // released → first-call hit). Sequence, not timestamps: open,
    // release, and the boundary call share one fake instant by
    // construction — asserting on timestamps would be vacuous.
    let mut h = Harness::fresh("boundary-capture");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.release_fires = vec![(0, 1)];
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.document.total_calls(), 1);
    assert_eq!(c.document.sites.len(), 1);
    assert_eq!(c.document.sites[0].calls, 1);
    let order = post.order.borrow();
    let open = order.iter().position(|e| e == "count_open");
    let released = order.iter().position(|e| e == "released");
    let fired = order.iter().position(|e| e.starts_with("fired:"));
    assert!(
        open.is_some() && released.is_some() && fired.is_some(),
        "missing ordering evidence: {order:?}"
    );
    assert!(
        open.unwrap() < released.unwrap() && released.unwrap() < fired.unwrap(),
        "count must program before release before first hit: {order:?}"
    );
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
}

#[test]
fn startup_missing_readiness_misses_boundary_call_loud() {
    // Missing-readiness control: NO baseline candidate — nothing is
    // attached at release, so the release-boundary call executes
    // with no probe and is MISSED (the attempt records
    // `fire-missed:no-probe`; production has no uprobe to hit).
    // The site first appears post-settle, so the late attach rides
    // loud (late-attach PARTIAL), and only post-attach calls count.
    let mut h = Harness::fresh("boundary-miss");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta::default());
    for _ in 0..4 {
        h.polls.push_back(DiscoveryDelta::default());
    }
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        6,
        FirePlan {
            fires: vec![(BASE_NS + 1_600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.release_fires = vec![(0, 1)];
    h.exit_at_ns = Some(BASE_NS + 1_800_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    // The boundary call missed (no probe); only post-attach calls
    // count.
    assert_eq!(c.document.total_calls(), 7);
    assert_eq!(counter_value(&c, "discovery.late_attach_sites"), 1);
    assert!(has_reason(&c, "late-attach"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial), "{c:?}");
    let order = post.order.borrow();
    assert!(
        order.iter().any(|e| e == "fire-missed:no-probe"),
        "boundary attempt must record its miss: {order:?}"
    );
    assert!(
        !order.iter().any(|e| e.starts_with("fired:")),
        "no probe — no hit: {order:?}"
    );
}

#[test]
fn startup_count_window_programmed_before_release() {
    // NOTE (R20-fix finding 7): this pins post-release capture with
    // late (+600ms) calls; the actual first-call readiness proof is
    // `startup_release_boundary_call_is_captured_in_order` (boundary
    // capture + order) and `startup_missing_readiness_misses_…`
    // (missing-readiness control).
    // Startup first-call evidence (owned spawn): the kernel window is
    // programmed before the stopped child is released, so the
    // requested window (starting at release) is covered from its
    // first nanosecond — zero startup gap, COMPLETE-capable.
    let mut h = Harness::fresh("startup-order");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    // Baseline attach (pre-release ready — F7: the programmed-
    // before-release contract needs a ready boundary).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
    let programmed = post.shared.borrow().backend.programmed().to_vec();
    assert_eq!(programmed.len(), 1);
    let (_, _, start_ns, _) = programmed[0];
    assert!(
        start_ns <= c.document.window.requested_start_ns,
        "window must open at or before release: {start_ns} vs {}",
        c.document.window.requested_start_ns
    );
    assert_eq!(c.document.window.startup_gap_ns(), 0);
    assert!(post.target_log.borrow().released);
}

#[test]
fn count_close_reap_precedes_drain_for_owned_exit() {
    // Count-close barrier control (owned exit): the child is reaped
    // BEFORE the count window closes and drains — dead threads run
    // no further uprobes, so no hit can land after the drain. The
    // order is structural (reap in the loop, close after it), pinned
    // here against future reordering.
    let mut h = Harness::fresh("reap-before-close");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    // Baseline attach (pre-release ready — F7 keeps this test's
    // focus on the reap/close order, not attach timing).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Complete), "{c:?}");
    assert_eq!(c.document.total_calls(), 7);
    let order = post.order.borrow();
    let reap = order.iter().position(|e| e == "reaped");
    let closed = order.iter().position(|e| e == "count_closed");
    assert_eq!(
        order.as_slice(),
        &[
            "count_open".to_string(),
            "released".to_string(),
            "reaped".to_string(),
            "count_closed".to_string(),
            "lifecycle_suffix".to_string()
        ],
        "count programs before release; reap precedes count close, then lifecycle suffix"
    );
    assert!(reap < closed);
}

// ---------------------------------------------------------------------------
// R20-fix round 2, finding 1: ordinary production capture qualified with
// the real kernel lifecycle adapter (no fakes on the lifecycle path).
// ---------------------------------------------------------------------------

/// Connector facility gate (R20-fix rounds 2-4 MINOR — tier 1
/// lives in target_lifecycle.rs; this file needs tier 2 only):
/// probed once per process (subscribing runs the initial watermark
/// burst, so probing per test would spam). Tier 2 needs a working
/// subscription AND a readable socket Drops row AND a clean
/// watermark burst (every online CPU pinned — restricted-affinity
/// hosts record pinning loss by design). COMPLETE/zero-loss tests
/// use it, so supported PARTIAL (drops-blind or pin-limited)
/// environments skip them instead of failing. Skips (pass) unless
/// `OSSLSCOPE_REQUIRE_CONNECTOR=1` forces a hard failure.
/// `OSSLSCOPE_CONNECTOR_TEST=force-absent` simulates absence;
/// `=force-no-drops` simulates a drops-blind environment;
/// `=force-no-watermark` simulates restricted affinity (test
/// hooks — prove the skip paths where the facility is present).
/// The probe subscribe/unsubscribe pair is balanced (Drop unsubscribes).
fn connector_facility_cached() -> (bool, bool, bool) {
    use std::sync::OnceLock;
    static PROBE: OnceLock<(bool, bool, bool)> = OnceLock::new();
    *PROBE.get_or_init(|| {
        let hook = std::env::var("OSSLSCOPE_CONNECTOR_TEST").unwrap_or_default();
        if hook == "force-absent" {
            return (false, false, false);
        }
        let f = osslscope::capture::connector_facility();
        if hook == "force-no-drops" {
            return (f.subscribes, false, f.watermark_clean);
        }
        if hook == "force-no-watermark" {
            return (f.subscribes, f.drops_readable, false);
        }
        (f.subscribes, f.drops_readable, f.watermark_clean)
    })
}

fn connector_clean() -> bool {
    connector_facility_cached() == (true, true, true)
}

fn require_clean_connector(test: &str) -> bool {
    if connector_clean() {
        return true;
    }
    assert!(
        std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() != Ok("1"),
        "{test} requires a working proc connector with readable Drops and clean watermark pinning (OSSLSCOPE_REQUIRE_CONNECTOR=1)"
    );
    let (_, drops, _) = connector_facility_cached();
    if !drops {
        eprintln!("SKIP {test}: connector drops-blind here (supported PARTIAL, not zero-loss)");
    } else {
        eprintln!(
            "SKIP {test}: watermark pinning limited here (restricted affinity records loss by design; supported PARTIAL, not zero-loss)"
        );
    }
    false
}

// ---------------------------------------------------------------------------
// R20-fix round 3, F1-shape: an unprivileged no-query controller
// composition pin (NOT the F1 qualification — that is the live
// lane `ordinary_production_run_…` in target_lifecycle.rs, which
// runs production `run()` on a supported crypto target). A plain
// sleep runs through the production `observe` loop with REAL
// discovery logic (SessionCore), REAL mappings (live /proc via the
// production maps reader), REAL time (LiveClock), REAL lifecycle
// (kernel connector), and REAL counting logic (CountSession) — no
// fabricated provider mapping, no pre-release attach, no scripted
// calls. Sleep executes no provider code, so the honest verdict is
// no-query PARTIAL with genuinely zero calls; every link of that
// chain is asserted from observed state, not fixtures. This pins
// the real exec witness + fallback-free + honest-PARTIAL shape
// where BPF privileges are absent.
// Facility boundary (honest, explicit): the BPF event/attach
// surface is absent without privileges, so the ring feed is empty
// and nothing installs — the no-query verdict reports exactly
// that blindness. Resolution is likewise bypassed (production
// `run` refuses non-crypto targets at resolve time — observed
// live by the F1 control). The plan's checkbox 4 explicitly
// includes fast/no-query programs with honest gaps.
// ---------------------------------------------------------------------------

/// SessionEnv over LIVE target state with no BPF ring (F1): mappings
/// via the production maps reader (every snapshot recorded for the
/// genuineness assertions), identity via a real target pin, file
/// stats via real metadata. Install/reinstall entry points are
/// loud tripwires (`unreachable!`): nothing is installable without
/// the ring, and this window maps no provider (asserted post-hoc
/// from the recorded snapshots with the core's own predicate) — a
/// call there fails the test instead of faking an attach.
struct LiveMapsNoBpfEnv {
    pid: u32,
    pin: osslscope::pin::TargetPin,
    provider: PathBuf,
    maps_log: Rc<RefCell<Vec<Vec<Mapping>>>>,
}

impl SessionEnv for LiveMapsNoBpfEnv {
    fn next_event(&mut self) -> Option<Vec<u8>> {
        // No BPF ring on this host: genuinely no events (nothing
        // installed without BPF attach).
        None
    }

    fn current_maps(&mut self) -> Option<Vec<Mapping>> {
        let maps = osslscope::discovery::maps::read_maps(self.pid).ok()?;
        self.maps_log.borrow_mut().push(maps.clone());
        Some(maps)
    }

    fn join_maps(&mut self) -> MapSnapshots {
        MapSnapshots::default()
    }

    fn install_stage2(
        &mut self,
        _cookie: u64,
        _offset: u64,
        _path: &std::path::Path,
        _pid: u32,
        _expected: Option<(u64, u64)>,
    ) -> anyhow::Result<()> {
        unreachable!("no stage-2 installs without ring INITs");
    }

    fn install_trips(
        &mut self,
        _set: &osslscope::discovery::legacy::ProbeSet,
        _pid: u32,
        _maps: &[Mapping],
    ) -> anyhow::Result<Option<String>> {
        unreachable!("no tripwires without a mapped libcrypto");
    }

    fn plan_trips(
        &mut self,
        maps: &[Mapping],
    ) -> anyhow::Result<Option<osslscope::discovery::legacy::ProbeSet>> {
        unreachable!(
            "plan_trips is gated on mapped libcrypto ({} mappings)",
            maps.len()
        );
    }

    fn pretouch(&mut self, _cookie: u64, _addr: u64) {}

    fn evict_array_state(&mut self, _arr: u64) -> anyhow::Result<()> {
        Ok(())
    }

    fn install_generation(&mut self, _arr: u64, _generation: u64) -> anyhow::Result<()> {
        Ok(())
    }

    fn verify_pin(&self) -> anyhow::Result<()> {
        self.pin.verify().map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn quiesce(&mut self) {}

    fn link_counts(&self) -> (u64, u64) {
        (0, 0)
    }

    fn detach_trips(&mut self) {}

    fn detach_dispatch_anchors(&mut self) {}

    fn detach_stage2(&mut self, _cookie: u64) {}

    fn reinstall_dispatch(
        &mut self,
    ) -> anyhow::Result<osslscope::discovery::session::DispatchReinstall> {
        unreachable!("no dispatch anchor without BPF bootstrap");
    }

    fn provider_stat(&self) -> Option<(String, u64)> {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(&self.provider).ok()?;
        Some((plan::render_device(md.dev()), md.ino()))
    }

    fn backing_stat(&mut self, path: &str) -> Option<(u64, u64)> {
        let md = std::fs::metadata(path).ok()?;
        let mtime_ns = md
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        Some((md.len(), mtime_ns))
    }
}

/// Production discovery logic behind the port: the real
/// `SessionCore` state machine (poll/refresh/reconcile/flap and
/// freshness machinery — not a script).
struct CoreDiscovery {
    core: SessionCore,
    env: LiveMapsNoBpfEnv,
}

impl DiscoveryPort for CoreDiscovery {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        self.core.poll(&mut self.env, budget)
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        self.core.snapshot()
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        self.core.close(&mut self.env)
    }
}

/// Lifecycle spy: forwards to the real port while recording every
/// delta, so the test proves the exec came through the ordinary
/// witness sweep (not the exe-link snapshot arm alone).
struct SpyLifecycle<L: LifecyclePort> {
    inner: L,
    deltas: Rc<RefCell<Vec<LifecycleDelta>>>,
}

impl<L: LifecyclePort> LifecyclePort for SpyLifecycle<L> {
    fn poll(&mut self) -> LifecycleDelta {
        let d = self.inner.poll();
        self.deltas.borrow_mut().push(d.clone());
        d
    }

    fn fallback_partial(&self) -> bool {
        self.inner.fallback_partial()
    }

    fn timing_trust(&self) -> osslscope::capture::LifecycleTimingTrust {
        self.inner.timing_trust()
    }

    fn close_drain(
        &mut self,
        edge: osslscope::capture::LifecycleEdge,
        permit: Option<&CountForkPermit<'_>>,
    ) -> osslscope::capture::LifecycleClose {
        let d = self.inner.close_drain(edge, permit);
        if let Some(x) = &d.delta {
            self.deltas.borrow_mut().push(x.clone());
        }
        d
    }

    fn mark_released(&mut self) {
        self.inner.mark_released();
    }
}

fn real_kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "unknown".to_string();
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_bytes();
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery() {
    run_connector_driver(
        "connector-controller:ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery",
    );
}
pub(crate) fn connector_body_ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery()
 {
    // F1-shape (round 3 composition pin — NOT the F1
    // qualification; see the live lane in target_lifecycle.rs).
    // A plain `/bin/sleep 1` runs the production loop with real
    // discovery/mappings/time/lifecycle/counting; the test
    // asserts the whole evidence chain from observed state:
    // live maps never contain a provider (the core's own
    // predicate, every poll) → zero candidates → zero attaches →
    // zero calls → honest no-query PARTIAL, free of polling
    // fallback, with the real exec witnessed through the
    // ordinary sweep. Tier 2: the zero-ignored-activity shape
    // needs readable Drops plus clean watermark pinning
    // (blindness or pin limits would add loss).
    use osslscope::capture::{LiveClock, LiveLifecycle, LiveProc};
    use osslscope::target::{OwnedTarget, WorkloadDest};
    if !require_clean_connector(
        "ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery",
    ) {
        return;
    }
    let provider = PathBuf::from("/usr/lib/x86_64-linux-gnu/libcrypto.so.3");
    assert!(
        provider.is_file(),
        "the genuine provider path must exist: {}",
        provider.display()
    );
    let owned = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "1".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = owned.pid();
    let pin = osslscope::pin::pin(pid).expect("pin live child");
    let canon = std::fs::canonicalize(&provider)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let core = SessionCore::new(provider.clone(), canon, true, pid);
    let maps_log: Rc<RefCell<Vec<Vec<Mapping>>>> = Rc::new(RefCell::new(Vec::new()));
    let discovery = CoreDiscovery {
        core,
        env: LiveMapsNoBpfEnv {
            pid,
            pin,
            provider: provider.clone(),
            maps_log: maps_log.clone(),
        },
    };
    let shared = Rc::new(RefCell::new(SharedState::default()));
    // Zero offered fires: sleep executes no provider code (the
    // backend only counts at attached sites, and none attach —
    // the zero is structural, asserted via the chain below).
    let count = CountSession::new(
        pid,
        SharedBackend {
            ready: *shared.borrow().backend.ready(),
            barrier: Arc::new(CountForkBarrier::new()),
            shared: shared.clone(),
            clock: FakeClock::new(),
            order: Rc::new(RefCell::new(Vec::new())),
        },
    );
    let lifecycle = LiveLifecycle::select(
        pid,
        false,
        &CountForkBarrier::new()
            .prefix_permit(Instant::now())
            .unwrap(),
    );
    assert!(
        !lifecycle.fallback_partial(),
        "ordinary window must select kernel signals, not the PARTIAL fallback"
    );
    let deltas: Rc<RefCell<Vec<LifecycleDelta>>> = Rc::new(RefCell::new(Vec::new()));
    let lifecycle = SpyLifecycle {
        inner: lifecycle,
        deltas: deltas.clone(),
    };
    let info = TargetInfo {
        pid,
        owned: true,
        comm: "sleep".to_string(),
        cmdline: "<redacted>".to_string(),
        container_id: String::new(),
        kernel_release: real_kernel_release(),
        // Resolution bypassed (R20 owns window-time, not
        // resolve-time): honestly unknown, never fabricated.
        provider_build_id: "unknown".to_string(),
        provider_path: provider.to_string_lossy().into_owned(),
        image_digest: String::new(),
        acquired_ns: LiveClock.monotonic_ns(),
        acquired_instant: LiveClock.now(),
        acquired_wall: LiveClock.wall_now(),
    };
    let cfg = Config {
        harvest_object: Some(PathBuf::new()),
        count_object: Some(PathBuf::new()),
        members_object: None,
        dev_bundle: None,
        provider: Some(provider),
        builtin: false,
        table: None,
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: Duration::from_secs(10),
        settle: Duration::from_millis(500),
        harvest_timeout: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        image_digest: String::new(),
    };
    let out = observe(
        &cfg,
        &info,
        SessionSet {
            discovery,
            count,
            target: owned,
            lifecycle,
        },
        &LiveClock,
        &mut LiveProc,
        &|| false,
    );
    let c = out.unwrap();
    // The genuine chain, link by link.
    assert!(
        matches!(c.outcome, Outcome::Partial),
        "sleep with no queries is honestly PARTIAL, never COMPLETE: {c:?}"
    );
    // Exact honest shape: no-query (zero observed queries) plus
    // discovery-loss (the reaped-owned close join — the child
    // exited mid-window and was reaped before count close, so the
    // discovery tail join is skipped explicitly per the
    // exited-and-reaped design). Nothing else: in particular no
    // polling fallback, no definite ignored activity, no exec/prefix/
    // terminal gaps, no late attach, no over-budget. The unreviewed
    // producer clock retains the actual Exec as timing uncertainty.
    assert_eq!(
        c.reasons,
        vec![
            "discovery-loss".to_string(),
            "fork-exec-ignored".to_string(),
            "no-query".to_string()
        ],
        "exact honest reason set: {c:?}"
    );
    assert!(
        c.document
            .counters
            .iter()
            .any(|counter| counter.name == "lifecycle.scan_loss" && counter.value > 0),
        "unreviewed producer clock must remain uncertain"
    );
    assert_eq!(c.document.total_calls(), 0, "genuine zero calls: {c:?}");
    assert_eq!(c.child_exit, Some(0));
    assert!(
        !c.document.fenced.is_empty(),
        "the real exec must fence through the ordinary loop: {c:?}"
    );
    assert!(
        deltas
            .borrow()
            .iter()
            .flat_map(|d| d.events.iter())
            .any(|e| e.kind == LifecycleKind::Exec),
        "the real exec must witness through the ordinary sweep: {c:?}"
    );
    // Mappings genuineness: sampled every poll (baseline pre-exec
    // plus rounds), never containing a provider by the core's own
    // predicate — and the post-exec image genuinely observed.
    let log = maps_log.borrow();
    assert!(
        log.len() >= 2,
        "mappings must be sampled across the window (baseline + rounds): {}",
        log.len()
    );
    for (i, snap) in log.iter().enumerate() {
        assert!(
            osslscope::discovery::legacy::find_libcrypto(snap).is_none(),
            "poll {i}: live maps must contain no provider: {:?}",
            snap.iter().map(|m| &m.path).collect::<Vec<_>>()
        );
    }
    assert!(
        log.iter()
            .any(|snap| snap.iter().any(|m| m.path.contains("sleep"))),
        "post-exec sleep image must be genuinely observed in some poll"
    );
    assert_reaped(pid);
}

// ---------------------------------------------------------------------------
// R20-fix round 2, finding 3: the outstanding exec obligation persists
// past cancellation/deadline returns to the close drain.
// ---------------------------------------------------------------------------

#[test]
fn exec_witness_consumed_before_deadline_return_survives_to_close() {
    // F3 RED: round 1's sweep consumes an Exec witness, then the
    // slow scan crosses the deadline — the round returns Expired
    // before applying the fence. The obligation must persist to
    // the close drain (consumed witness → exec gap), never
    // evaporate with the local kinds. The owned target exits past
    // the deadline (3s exit, 2s window) and is reaped at close —
    // over-budget records per the alive-at-expiry contract (a
    // post-expiry reap cannot prove pre-expiry death).
    let mut h = Harness::fresh("exec-obligation-expired");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.lifecycle_polls = VecDeque::from([LifecycleDelta {
        events: vec![LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid: PID,
            timestamp_ns: Some(BASE_NS + 1),
        }],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    }]);
    // Slow scan: cross the 2s deadline inside round 1's sweep
    // (production scans take real time).
    h.lifecycle_advance_ns = 3_000_000_000;
    h.exit_at_ns = Some(BASE_NS + 3_000_000_000);
    h.exit_code = 0;
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "lifecycle.exec_gap"),
        1,
        "consumed exec witness must survive the deadline return: {c:?}"
    );
    assert!(
        matches!(c.outcome, Outcome::Partial),
        "lost transition must withhold COMPLETE: {c:?}"
    );
    assert!(
        has_reason(&c, "fork-exec-ignored"),
        "gap rides the exec-continuity reason: {c:?}"
    );
    assert_eq!(
        c.counters.over_budget, 1,
        "reaped-at-expiry is still over-budget (reap cannot prove pre-expiry death): {c:?}"
    );
}

#[test]
fn exec_witness_consumed_before_signal_cut_survives_to_close() {
    // F3 RED (cancellation twin): the sweep consumes an Exec
    // witness, then the async signal lands — the round returns
    // Continue without fencing; the loop breaks on the cut. The
    // obligation must still reach the close drain as an exec gap.
    // (The verdict is already Partial via interrupted — the gap
    // preserves the LOST TRANSITION, not the verdict.)
    let mut h = Harness::fresh("exec-obligation-cut");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.lifecycle_polls = VecDeque::from([LifecycleDelta {
        events: vec![LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid: PID,
            timestamp_ns: Some(BASE_NS + 1),
        }],
        loss: 0,
        dropped: 0,
        prefix_unwitnessed: 0,
        pending: 0,
    }]);
    // Async-signal model: alive through setup(1) + loop-top(2),
    // cut from the round's mid-sweep check(3) on.
    let calls = Rc::new(Cell::new(0u32));
    let seen = calls.clone();
    h.cancel_hook = Some(Rc::new(move || {
        let n = seen.get() + 1;
        seen.set(n);
        n >= 3
    }) as Rc<dyn Fn() -> bool>);
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert!(
        has_reason(&c, "interrupted"),
        "hook must fire in-window (signal cut): {c:?}"
    );
    assert_eq!(
        counter_value(&c, "lifecycle.exec_gap"),
        1,
        "consumed exec witness must survive the signal cut: {c:?}"
    );
}

// ---------------------------------------------------------------------------
// R20-fix round 2, finding 7: release-boundary readiness — a
// post-release first-attach of a pre-release mapping gaps even
// inside the settle grace (the settle suppresses only genuinely
// fresh mappings).
// ---------------------------------------------------------------------------

#[test]
fn missing_readiness_during_settle_withholds_complete() {
    // F7 RED: the boundary call executes without a probe (no
    // baseline attach — the window is unready at release), THEN
    // discovery arrives during settle. The [release, attach]
    // sub-window is uncovered for a site whose mapping predates
    // release — a readiness gap (late-attach loss), even inside
    // the settle grace. Post-attach calls still count.
    let mut h = Harness::fresh("readiness-during-settle");
    h.snapshot_attached();
    let cand1 = cand(
        "/p/provider.so",
        backing_of(&h.staged, h.off),
        1,
        11,
        "SHA-256",
        false,
        "ok",
    );
    // Baseline poll: nothing attached (boundary-unready).
    h.polls.push_back(DiscoveryDelta::default());
    // Round 1 (~250ms, inside the 500ms settle): discovery arrives.
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand1],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    // Boundary call (no probe — missed) + post-attach calls.
    h.release_fires = vec![(0, 1)];
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.late_attach_sites"),
        1,
        "during-settle attach of a pre-release mapping must gap: {c:?}"
    );
    assert!(
        has_reason(&c, "late-attach"),
        "readiness gap rides the late-attach reason: {c:?}"
    );
    assert!(
        matches!(c.outcome, Outcome::Partial),
        "unready boundary must withhold COMPLETE: {c:?}"
    );
    assert_eq!(
        c.document.total_calls(),
        7,
        "boundary call missed, post-attach calls counted: {c:?}"
    );
}

// ---------------------------------------------------------------------------
// R14: object-read budgets bind before allocation (covers F17).
// ---------------------------------------------------------------------------

#[test]
fn r14_first_oversized_object_cannot_bypass_cap() {
    // F17: the old loop always read at least one path unbounded;
    // now the FIRST relevant object carries the budget allowance
    // like any other — its refusal skips loud (rows miss,
    // `discovery.relevance_capped` loss, PARTIAL) while the rest
    // of the round succeeds. Two paths only, so the file-count
    // cap is provably uninvolved.
    let mut h = Harness::fresh("r14-first");
    h.snapshot_attached();
    // Oversized decoy sorts FIRST, so it is the round's first
    // read: staged junk larger than the budget (never parsed —
    // refused before allocation). The real file stays tiny (its
    // identity is all the fake serves from disk).
    let elf_len = h.bytes.len();
    let budget = elf_len + 512;
    let big = h.stage.write("a-huge.so", &[0x7fu8; 64]);
    h.files.insert(
        big.path.clone(),
        plan::FileBytes {
            bytes: vec![0x7fu8; elf_len + 1024].into(),
            dev: big.device,
            ino: big.ino,
        },
    );
    h.read_budget = budget;
    h.maps = vec![mapping(&big), mapping(&h.staged)];
    let staged_path = h.staged.path.clone();
    let big_path = big.path.clone();
    assert!(
        big_path < staged_path,
        "decoy must sort first: {big_path} vs {staged_path}"
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![
            cand(
                "/p/provider.so",
                backing_of(&big, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&h.staged, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    // The first object was refused, not bypassed: exactly one
    // loud budget drop, both paths attempted in sorted order.
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "one budget refusal: {:?}",
        c.document.counters
    );
    let log = post.proc_log.borrow();
    assert_eq!(
        log.reads,
        vec![big_path.clone(), staged_path.clone()],
        "both paths attempted, oversized first"
    );
    assert_eq!(
        log.read_allowances,
        vec![(big_path.clone(), budget), (staged_path.clone(), budget)],
        "first read carries the budget (no exemption); the refused object consumed nothing"
    );
    // The round otherwise succeeds: the surviving site attaches
    // with its calls intact, but the window is PARTIAL — skipped
    // evidence is typed loss, never a completeness claim.
    assert_eq!(post.shared.borrow().attached.len(), 1);
    assert_eq!(c.document.total_calls(), 7);
    assert!(matches!(c.outcome, Outcome::Partial), "{:?}", c.outcome);
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    for scope in &c.document.coverage {
        if scope.scope == "legacy" {
            assert!(
                matches!(scope.expected, ExpectedScope::NotApplicable),
                "legacy scope must be untouched: {scope:?}"
            );
        } else {
            assert!(
                matches!(scope.expected, ExpectedScope::Unknown),
                "budget loss must taint globally: {scope:?}"
            );
        }
    }
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "budget loss must revise emitted sites"
        );
    }
}

#[test]
fn r14_cumulative_two_file_overflow_skips_second() {
    // Two individually fine objects whose sum exceeds the round
    // budget: the second read carries the REMAINDER (exact
    // checked arithmetic, asserted below) and refuses loud. Two
    // paths only, so the byte cap trips independently of the
    // file-count cap.
    let mut h = Harness::fresh("r14-cumulative");
    h.snapshot_attached();
    // Budget inputs are validated miniature ELFs, independent of this test binary.
    let elf = small_elf(0xE5);
    let off = x_offset(&elf);
    let elf_len = elf.len();
    let budget = elf_len + elf_len / 2;
    assert!(elf_len < budget && budget < 2 * elf_len);
    assert!(budget < plan::MAX_OBJECT_BYTES);
    let staged = h.stage.write("z-primary.so", &elf);
    h.files.insert(
        staged.path.clone(),
        plan::FileBytes {
            bytes: elf.clone().into(),
            dev: staged.device,
            ino: staged.ino,
        },
    );
    let other = h.stage.write("a-second.so", &elf);
    h.files.insert(
        other.path.clone(),
        plan::FileBytes {
            bytes: elf.clone().into(),
            dev: other.device,
            ino: other.ino,
        },
    );
    h.read_budget = budget;
    h.maps = vec![mapping(&other), mapping(&staged)];
    let staged_path = staged.path.clone();
    let other_path = other.path.clone();
    assert!(
        other_path < staged_path,
        "second ELF must sort first: {other_path} vs {staged_path}"
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![
            cand(
                "/p/provider.so",
                backing_of(&other, off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&staged, off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "one cumulative overflow: {:?}",
        c.document.counters
    );
    let log = post.proc_log.borrow();
    assert_eq!(
        log.reads,
        vec![other_path.clone(), staged_path.clone()],
        "both paths attempted (byte cap, not file-count cap, fired)"
    );
    assert_eq!(
        log.read_allowances,
        vec![
            (other_path.clone(), budget),
            (staged_path.clone(), budget - elf_len)
        ],
        "second read carries the exact remainder"
    );
    assert_eq!(post.shared.borrow().attached.len(), 1);
    assert_eq!(c.document.total_calls(), 7);
    assert!(matches!(c.outcome, Outcome::Partial), "{:?}", c.outcome);
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "cumulative overflow must revise emitted sites"
        );
    }
}

#[test]
fn r14_single_oversized_object_yields_loud_fatal() {
    // One relevant object past the budget: refused on the first
    // (only) read — loud misses plus the typed cap loss, fatal
    // AttachZero, never a completeness claim.
    let mut h = Harness::fresh("r14-single");
    h.snapshot_attached();
    h.read_budget = 64;
    let staged_path = h.staged.path.clone();
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "sole object refused loud: {:?}",
        c.document.counters
    );
    let log = post.proc_log.borrow();
    assert_eq!(log.reads, vec![staged_path.clone()]);
    assert_eq!(
        log.read_allowances,
        vec![(staged_path.clone(), 64)],
        "even the only read is budgeted"
    );
    assert!(post.shared.borrow().attached.is_empty());
    assert!(matches!(c.outcome, Outcome::Fatal(_)), "{:?}", c.outcome);
    assert!(has_reason(&c, "missed-attaches"), "{:?}", c.reasons);
    assert!(c.counters.missed_attaches > 0);
}

#[test]
fn r14_within_budget_round_reads_fully() {
    // Negative control: a budget that fits the round reads
    // everything — no refusal, no cap loss, COMPLETE (mirrors
    // clean_exit with budget injection active).
    let mut h = Harness::fresh("r14-within");
    h.snapshot_attached();
    let budget = h.bytes.len() + 1024;
    h.read_budget = budget;
    let staged_path = h.staged.path.clone();
    // Baseline attach (pre-release ready): a post-release first
    // attach of this long-present mapping is late-attach loss
    // (R20-F7), which would withhold the COMPLETE this budget
    // control asserts — attach timing is incidental here (same
    // triage R20-F7 applied to clean_exit et al.).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.polls.push_back(DiscoveryDelta::default());
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    let log = post.proc_log.borrow();
    assert_eq!(log.reads, vec![staged_path.clone()]);
    assert_eq!(
        log.read_allowances,
        vec![(staged_path.clone(), budget)],
        "injection plumbing reaches the read"
    );
    assert!(
        !has_counter(&c, "discovery.relevance_capped"),
        "no cap loss within budget: {:?}",
        c.document.counters
    );
    assert!(matches!(c.outcome, Outcome::Complete), "{:?}", c.outcome);
    assert!(matches!(c.document.status, Completeness::Complete));
    assert_eq!(c.document.total_calls(), 7);
}

#[test]
fn r14_fix_cached_payload_over_remaining_budget_skips_loud() {
    // R14 fix round 1 (finding 1): a cache hit past the REMAINING
    // round allowance skips loud — like a fresh-read refusal its
    // rows miss and `discovery.relevance_capped` counts it
    // (PARTIAL, never a completeness claim). The pre-fix loop
    // admitted cached payloads unconditionally, so a cached entry
    // last in sort order inflated the output past the round budget
    // with no loss recorded anywhere.
    //
    // Sequence the cumulative test missed: poll 1 caches z-old
    // (fits the full budget); poll 2 reads a-new fresh FIRST
    // (sorts first, consumes most of the budget), then the cached
    // z-old no longer fits the remainder and must be refused.
    let mut h = Harness::fresh("r14-mixed");
    h.snapshot_attached();
    // Budget inputs are validated miniature ELFs, independent of this test binary.
    let elf = small_elf(0xE5);
    let off = x_offset(&elf);
    let elf_len = elf.len();
    let budget = elf_len + elf_len / 2;
    assert!(elf_len < budget && budget < 2 * elf_len);
    assert!(budget < plan::MAX_OBJECT_BYTES);
    let fresh = h.stage.write("a-new.so", &elf);
    h.files.insert(
        fresh.path.clone(),
        plan::FileBytes {
            bytes: elf.clone().into(),
            dev: fresh.device,
            ino: fresh.ino,
        },
    );
    let old = h.stage.write("z-old.so", &elf);
    h.files.insert(
        old.path.clone(),
        plan::FileBytes {
            bytes: elf.clone().into(),
            dev: old.device,
            ino: old.ino,
        },
    );
    h.read_budget = budget;
    h.maps = vec![mapping(&fresh), mapping(&old)];
    let fresh_path = fresh.path.clone();
    let old_path = old.path.clone();
    assert!(
        fresh_path < old_path,
        "fresh file must sort first: {fresh_path} vs {old_path}"
    );
    // Baseline poll caches z-old alone (fits the full budget).
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand(
            "/p/provider.so",
            backing_of(&old, off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    // Round poll: a-new reads fresh first, then cached z-old no
    // longer fits the remainder.
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![
            cand(
                "/p/provider.so",
                backing_of(&fresh, off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&old, off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, post) = h.run();
    let c = out.unwrap();
    // The cached entry was refused, not bypassed: exactly one loud
    // budget drop, and the cache hit caused no re-read.
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "one cached-over-budget refusal: {:?}",
        c.document.counters
    );
    assert_eq!(
        c.document.refusal_diagnostics.len(),
        1,
        "exactly one refusal entry: {:?}",
        c.document.refusal_diagnostics
    );
    assert!(
        c.document.refusal_diagnostics[0].contains("kind=over_allowance"),
        "cached refusal names over_allowance: {:?}",
        c.document.refusal_diagnostics
    );
    assert_refusal_shape(&c.document.refusal_diagnostics[0]);
    let log = post.proc_log.borrow();
    assert_eq!(
        log.reads,
        vec![old_path.clone(), fresh_path.clone()],
        "z-old cached in poll 1, only a-new read in poll 2"
    );
    assert_eq!(
        log.read_allowances,
        vec![(old_path.clone(), budget), (fresh_path.clone(), budget)],
        "each poll's first read carries the full round budget"
    );
    assert!(matches!(c.outcome, Outcome::Partial), "{:?}", c.outcome);
    assert!(matches!(c.document.status, Completeness::Partial { .. }));
    for site in &c.document.sites {
        assert_eq!(
            site.candidates_coverage,
            CandidateCoverage::Unknown,
            "cached overflow must revise emitted sites"
        );
    }
}

// ---------------------------------------------------------------------------
// R14 minor: bounded numeric refusal diagnostics ride the document
// alongside the `discovery.relevance_capped` aggregate.
// ---------------------------------------------------------------------------

/// Shape pin for one refusal entry (no regex crate in dev-deps,
/// so the `^dev=\d+ ino=\d+ kind=[a-z_]+ bytes=\d+
/// allowance=\d+$` grammar is checked by hand): numeric-only, no
/// paths.
fn assert_refusal_shape(entry: &str) {
    let parts: Vec<&str> = entry.split(' ').collect();
    assert_eq!(parts.len(), 5, "five space-separated fields: {entry:?}");
    fn num(v: &str) -> bool {
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
    }
    fn kind(v: &str) -> bool {
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    }
    let (k, v) = parts[0].split_once('=').unwrap_or(("", ""));
    assert_eq!(k, "dev", "field 1 key: {entry:?}");
    assert!(num(v), "dev numeric: {entry:?}");
    let (k, v) = parts[1].split_once('=').unwrap_or(("", ""));
    assert_eq!(k, "ino", "field 2 key: {entry:?}");
    assert!(num(v), "ino numeric: {entry:?}");
    let (k, v) = parts[2].split_once('=').unwrap_or(("", ""));
    assert_eq!(k, "kind", "field 3 key: {entry:?}");
    assert!(kind(v), "kind token: {entry:?}");
    let (k, v) = parts[3].split_once('=').unwrap_or(("", ""));
    assert_eq!(k, "bytes", "field 4 key: {entry:?}");
    assert!(num(v), "bytes numeric: {entry:?}");
    let (k, v) = parts[4].split_once('=').unwrap_or(("", ""));
    assert_eq!(k, "allowance", "field 5 key: {entry:?}");
    assert!(num(v), "allowance numeric: {entry:?}");
}

#[test]
fn refusal_diagnostics_records_one_refusal() {
    // Mirrors `r14_first_oversized_object_cannot_bypass_cap`:
    // the oversized decoy sorts first and refuses loud; the
    // aggregate counts it AND the document names it once.
    let mut h = Harness::fresh("refusal-diag-one");
    h.snapshot_attached();
    let elf_len = h.bytes.len();
    let budget = elf_len + 512;
    let big = h.stage.write("a-huge.so", &[0x7fu8; 64]);
    h.files.insert(
        big.path.clone(),
        plan::FileBytes {
            bytes: vec![0x7fu8; elf_len + 1024].into(),
            dev: big.device,
            ino: big.ino,
        },
    );
    h.read_budget = budget;
    h.maps = vec![mapping(&big), mapping(&h.staged)];
    let staged_path = h.staged.path.clone();
    let big_path = big.path.clone();
    assert!(
        big_path < staged_path,
        "decoy must sort first: {big_path} vs {staged_path}"
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![
            cand(
                "/p/provider.so",
                backing_of(&big, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&h.staged, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "one budget refusal: {:?}",
        c.document.counters
    );
    assert_eq!(
        c.document.refusal_diagnostics.len(),
        1,
        "exactly one refusal entry: {:?}",
        c.document.refusal_diagnostics
    );
    assert_refusal_shape(&c.document.refusal_diagnostics[0]);
}

#[test]
fn refusal_diagnostics_bounded_sorted_sixteen() {
    // Twenty oversized objects in one round: all refuse loud
    // (aggregate counts every one), but the document retains only
    // the first sixteen entries in sorted order.
    let mut h = Harness::fresh("refusal-diag-cap");
    h.snapshot_attached();
    let budget = 1024;
    let mut staged_all = Vec::new();
    for i in 0..20u32 {
        let name = format!("a-huge-{i:02}.so");
        let s = h.stage.write(&name, &[0x7fu8; 64]);
        h.files.insert(
            s.path.clone(),
            plan::FileBytes {
                bytes: vec![0x7fu8; budget + 512].into(),
                dev: s.device,
                ino: s.ino,
            },
        );
        staged_all.push(s);
    }
    h.read_budget = budget;
    h.maps = staged_all.iter().map(mapping).collect();
    let off = h.off;
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: staged_all
            .iter()
            .map(|s| {
                cand(
                    "/p/provider.so",
                    backing_of(s, off),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                )
            })
            .collect(),
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        20,
        "every refusal counted: {:?}",
        c.document.counters
    );
    assert_eq!(
        c.document.refusal_diagnostics.len(),
        16,
        "retention is capped at sixteen: {:?}",
        c.document.refusal_diagnostics
    );
    let mut sorted = c.document.refusal_diagnostics.clone();
    sorted.sort();
    assert_eq!(
        c.document.refusal_diagnostics, sorted,
        "retained entries are sorted"
    );
    for entry in &c.document.refusal_diagnostics {
        assert_refusal_shape(entry);
    }
}

#[test]
fn refusal_diagnostics_unstatable_path_falls_back_to_zero_zero() {
    // Mirrors `refusal_diagnostics_records_one_refusal`: the
    // oversized decoy sorts first and refuses loud — but its path
    // lives under a removed dir (never stated), so the entry
    // carries the `refusal_tag` (0, 0) fallback identity instead
    // of a device number.
    let mut h = Harness::fresh("refusal-diag-unstatable");
    h.snapshot_attached();
    let elf_len = h.bytes.len();
    let budget = elf_len + 512;
    let seed = h.stage.write("a-huge.so", &[0x7fu8; 64]);
    let ghost = Staged {
        path: h
            .stage
            .dir
            .join("a-removed")
            .join("a-huge.so")
            .to_str()
            .unwrap()
            .to_string(),
        device: seed.device,
        ino: seed.ino,
    };
    assert!(
        std::fs::metadata(&ghost.path).is_err(),
        "ghost path must not stat: {}",
        ghost.path
    );
    h.files.insert(
        ghost.path.clone(),
        plan::FileBytes {
            bytes: vec![0x7fu8; elf_len + 1024].into(),
            dev: ghost.device,
            ino: ghost.ino,
        },
    );
    h.read_budget = budget;
    h.maps = vec![mapping(&ghost), mapping(&h.staged)];
    let staged_path = h.staged.path.clone();
    let ghost_path = ghost.path.clone();
    assert!(
        ghost_path < staged_path,
        "decoy must sort first: {ghost_path} vs {staged_path}"
    );
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![
            cand(
                "/p/provider.so",
                backing_of(&ghost, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&h.staged, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.plans.insert(
        2,
        FirePlan {
            fires: vec![(BASE_NS + 600_000_000, 7)],
            shortfall: 0,
            cancel: false,
        },
    );
    h.exit_at_ns = Some(BASE_NS + 1_000_000_000);
    h.exit_code = 0;
    let (out, _post) = h.run();
    let c = out.unwrap();
    assert_eq!(
        counter_value(&c, "discovery.relevance_capped"),
        1,
        "one budget refusal: {:?}",
        c.document.counters
    );
    assert_eq!(
        c.document.refusal_diagnostics.len(),
        1,
        "exactly one refusal entry: {:?}",
        c.document.refusal_diagnostics
    );
    let entry = &c.document.refusal_diagnostics[0];
    assert_refusal_shape(entry);
    assert_eq!(
        *entry,
        format!("dev=0 ino=0 kind=file_too_large bytes=0 allowance={budget}"),
        "unstatable path falls back to (0, 0): {entry:?}"
    );
}

#[test]
fn g1_initial_terminal_suffix_follows_count_cleanup() {
    let mut h = Harness::fresh("g1-suffix-order");
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    let (result, post) = h.run();
    result.expect("ordinary capture");
    let log = post.order.borrow();
    let count = log
        .iter()
        .position(|s| s == "count_closed")
        .expect("count close");
    let suffix = log
        .iter()
        .position(|s| s == "lifecycle_suffix")
        .expect("suffix attempt");
    assert!(
        count < suffix,
        "count cleanup must precede lifecycle suffix: {log:?}"
    );
}

#[test]
fn g1_terminal_lifecycle_uses_original_half_open_edge() {
    let mut h = Harness::fresh("g1-original-edge");
    h.cfg.duration = Duration::from_secs(1);
    h.shared.borrow_mut().terminal_delay_ns = 400_000_000;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: [
            Some(BASE_NS + 900_000_000),
            Some(BASE_NS + 1_000_000_000),
            Some(BASE_NS + 1_300_000_000),
            None,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, timestamp_ns)| LifecycleEvent {
            kind: LifecycleKind::Fork,
            pid: 6000 + i as u32,
            timestamp_ns,
        })
        .collect(),
        ..LifecycleDelta::default()
    });
    let (result, _) = h.run();
    let capture = result.unwrap();
    let value = |name: &str| {
        capture
            .document
            .counters
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value)
            .unwrap_or(0)
    };
    assert_eq!(
        value("lifecycle.fork_exec_ignored"),
        1,
        "only the original half-open interval is positive"
    );
    assert_eq!(
        value("lifecycle.scan_loss"),
        1,
        "untimed arrivals remain uncertain"
    );
    assert_eq!(
        capture.document.window.effective_end_ns,
        BASE_NS + 1_000_000_000
    );
}

fn assert_fwr_i2_early_close_edge(finish_err: bool) {
    let mut h = Harness::fresh("fwr-i2-early-comm");
    h.cfg.duration = Duration::from_secs(1);
    h.finish_err = finish_err;
    h.comm = Some("test-target".into()); // remains unsettled at close
    let selected_close = Rc::new(Cell::new(false));
    let initial_comm = Rc::new(Cell::new(false));
    let delayed_comm = Rc::new(Cell::new(false));
    let clock = h.clock.clone();
    h.comm_read_hook = Some(Rc::new({
        let selected_close = selected_close.clone();
        let initial_comm = initial_comm.clone();
        let delayed_comm = delayed_comm.clone();
        move || {
            if selected_close.get() {
                assert!(!delayed_comm.replace(true), "close comm read repeated");
                clock.advance_ns(400);
            } else if !initial_comm.replace(true) {
                clock.advance_ns(100);
            }
        }
    }));
    h.cancel_hook = Some(Rc::new({
        let selected_close = selected_close.clone();
        move || {
            if initial_comm.get() {
                selected_close.set(true);
                true
            } else {
                false
            }
        }
    }));
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: [LifecycleKind::Fork, LifecycleKind::Exec]
            .into_iter()
            .flat_map(|kind| {
                [99, 100, 101].into_iter().map(move |ns| LifecycleEvent {
                    kind,
                    pid: if kind == LifecycleKind::Exec {
                        PID
                    } else {
                        6000
                    },
                    timestamp_ns: Some(BASE_NS + ns),
                })
            })
            .collect(),
        ..LifecycleDelta::default()
    });
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert!(selected_close.get() && delayed_comm.get());
    assert_eq!(capture.window_actual, Duration::from_nanos(500));
    assert_eq!(
        counter_value(&capture, "lifecycle.fork_exec_ignored"),
        1,
        "only the fork strictly before the loop close decision is definite; finish_err={finish_err}"
    );
    assert_eq!(counter_value(&capture, "lifecycle.exec_gap"), 1);
    let shared = post.shared.borrow();
    assert_eq!(
        shared.log.iter().filter(|s| *s == "count_closed").count(),
        1
    );
    assert_eq!(
        shared.closed_at,
        Some(BASE_NS + 500),
        "actual count seal remains later than the lifecycle decision"
    );
    assert!(
        !shared.log.iter().any(|s| s.starts_with("gen:")),
        "terminal exec cannot start a generation: {:?}",
        shared.log
    );
    assert_eq!(
        capture.programmed_admission.unwrap().deadline_ns(),
        BASE_NS + 1_000_000_000
    );
    assert_eq!(capture.document.total_calls(), 0);
    println!(
        "FWR-I2 finish_err={finish_err}: loop edge={}, delayed comm end={}, definite fork=1, exec=1",
        BASE_NS + 100,
        BASE_NS + 500
    );
}
#[test]
fn fwr_i2_early_close_freezes_edge_before_comm() {
    assert_fwr_i2_early_close_edge(false);
}
#[test]
fn fwr_i2_early_close_salvage_reuses_edge_before_comm() {
    assert_fwr_i2_early_close_edge(true);
}

#[test]
fn g1_terminal_refused_suffix_keeps_lifecycle_prefix() {
    let mut h = Harness::fresh("g1-refused-suffix");
    h.shared.borrow_mut().refuse_suffix = true;
    h.exit_at_ns = Some(BASE_NS + 100_000_000);
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: vec![LifecycleEvent {
            kind: LifecycleKind::Fork,
            pid: 6000,
            timestamp_ns: Some(BASE_NS + 1),
        }],
        loss: 2,
        dropped: 3,
        prefix_unwitnessed: 4,
        pending: 1,
    });
    let (result, post) = h.run();
    let c = result.unwrap();
    let value = |name: &str| {
        c.document
            .counters
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value)
            .unwrap_or(0)
    };
    assert_eq!(value("lifecycle.fork_exec_ignored"), 1);
    assert_eq!(value("lifecycle.scan_loss"), 2);
    assert_eq!(value("lifecycle.signal_dropped"), 3);
    assert_eq!(value("lifecycle.signal_prefix_unwitnessed"), 4);
    assert_eq!(value("lifecycle.drain_pending"), 1);
    assert_eq!(value("lifecycle.no_witness"), 1);
    let log = post.order.borrow();
    assert!(!log.iter().any(|s| s == "lifecycle_suffix"), "{log:?}");
    assert_eq!(log.iter().filter(|s| *s == "lifecycle_prefix").count(), 1);
}

#[test]
fn g1_terminal_execs_never_reopen_count_generation() {
    let mut h = Harness::fresh("g1-terminal-exec");
    h.cfg.duration = Duration::from_secs(1);
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: [
            Some(BASE_NS + 900_000_000),
            Some(BASE_NS + 1_000_000_000),
            Some(BASE_NS + 1_300_000_000),
            None,
        ]
        .into_iter()
        .map(|timestamp_ns| LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid: PID,
            timestamp_ns,
        })
        .collect(),
        ..LifecycleDelta::default()
    });
    let (result, post) = h.run();
    let c = result.unwrap();
    let value = |name: &str| {
        c.document
            .counters
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value)
            .unwrap_or(0)
    };
    assert_eq!(value("lifecycle.exec_gap"), 1);
    assert_eq!(value("lifecycle.scan_loss"), 1);
    let shared = post.shared.borrow();
    let terminal = shared.log.iter().position(|s| s == "count_closed").unwrap();
    assert!(
        !shared.log[terminal..].iter().any(|s| s.starts_with("gen:")),
        "{:?}",
        shared.log
    );
}

/// Catches post-release/post-comm restamping: two actual early callbacks must
/// keep their timestamps while the requested clock starts before release.
#[test]
fn g1_owned_release_clock_precedes_running_target() {
    for early in [true, false] {
        let mut h = Harness::fresh("g1-release-clock");
        *h.clock.ns.borrow_mut() = 1000;
        h.acquired_ns = 1000;
        h.cfg.duration = Duration::from_nanos(1000);
        h.poll_delay_ns.insert(0, 100);
        h.snapshot_attached();
        h.polls.push_back(DiscoveryDelta {
            objects: vec![osslscope::discovery::session::DiscoveredObject {
                dev: backing_of(&h.staged, h.off).unwrap().dev,
                ino: h.staged.ino,
                display_locator: h.staged.path.clone(),
            }],
            candidates: vec![cand(
                "/p/provider.so",
                backing_of(&h.staged, h.off),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            trigger_observed: true,
            ..DiscoveryDelta::default()
        });
        h.release_timing = Some((10, 10));
        if early {
            h.release_fires = vec![(0, 1)];
        }
        let clock = h.clock.clone();
        let shared = h.shared.clone();
        h.comm_hook = Some(Rc::new(move || {
            clock.advance_ns(if early { 30 } else { 180 });
            let mut st = shared.borrow_mut();
            let cookie = st.attached[0];
            st.backend.fire(PID, cookie, clock.monotonic_ns(), 1);
            if early {
                clock.advance_ns(50);
            }
        }));
        let (result, _) = h.run();
        let c = result.unwrap();
        assert_eq!(c.programmed_admission.unwrap().start_ns(), 1000);
        assert_eq!(c.programmed_admission.unwrap().deadline_ns(), 2000);
        let release = c.release_attempt.unwrap();
        assert_eq!(release.before.monotonic_ns, 1100);
        assert_eq!(release.after_ns, Some(1120));
        assert_eq!(
            release.outcome,
            osslscope::capture::ReleaseOutcome::Succeeded
        );
        let bounds = match_bounds(&c.document.sites, &|_| PredicateMatch::Yes);
        assert_eq!(bounds.definite, if early { 2 } else { 1 });
        assert_eq!(c.document.window.requested_start_ns, 1100);
        assert_eq!(c.document.window.effective_start_ns, 1100);
        assert_eq!(c.document.window.requested_end_ns, 2100);
        assert_eq!(
            c.document.sites[0].first_ns,
            if early { 1110 } else { 1300 }
        );
        assert_eq!(c.document.sites[0].last_ns, if early { 1150 } else { 1300 });
        let bytes = osslscope::report::render_json(&c.document).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        osslscope::schema::validate_v2(&json).unwrap();
        osslscope::schema::check_v2_semantics(&json).unwrap();
    }
}

#[test]
fn g1_checked_release_and_open_failures_retain_terminal_custody() {
    for (samples, stage) in [
        (vec![None], osslscope::capture::BoundaryStage::Open),
        (
            vec![Some(BASE_NS), None],
            osslscope::capture::BoundaryStage::Release,
        ),
    ] {
        let h = Harness::fresh("g1-clock-failure");
        *h.clock.checked_samples.borrow_mut() = VecDeque::from(samples);
        let (out, post) = h.run();
        let error = out.unwrap_err();
        let failure = error
            .downcast_ref::<osslscope::capture::PreObservationFailure>()
            .unwrap();
        assert_eq!(failure.failure.as_ref().unwrap().stage, stage);
        assert_eq!(failure.failure.as_ref().unwrap().errno, None);
        assert!(failure.release.is_none());
        assert_eq!(
            failure.custody.resolution,
            osslscope::capture::CustodyResolution::Resolved
        );
        assert!(matches!(
            failure.count,
            osslscope::capture::PreObservationCount::Terminal(_)
        ));
        assert!(!post.target_log.borrow().released);
        assert!(post.target_log.borrow().resolved);
        if stage == osslscope::capture::BoundaryStage::Open {
            assert!(
                !post
                    .shared
                    .borrow()
                    .log
                    .iter()
                    .any(|line| line == "count_open")
            );
        }
    }
    let h = Harness::fresh("g1-after-clock-failure");
    *h.clock.checked_samples.borrow_mut() = VecDeque::from([Some(BASE_NS), Some(BASE_NS), None]);
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert!(post.target_log.borrow().released);
    assert_eq!(capture.release_attempt.unwrap().after_ns, None);
    assert_eq!(capture.document.window.requested_start_ns, BASE_NS);
    assert!(has_counter(&capture, "count.close_time_uncertain"));
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_owned_empty_overlap_keeps_full_requested_gap() {
    let mut h = Harness::fresh("g1-empty-overlap");
    *h.clock.ns.borrow_mut() = 1000;
    h.acquired_ns = 1000;
    h.cfg.duration = Duration::from_nanos(50);
    h.poll_delay_ns.insert(0, 100);
    let (out, _) = h.run();
    let capture = out.unwrap();
    let w = &capture.document.window;
    assert_eq!((w.requested_start_ns, w.requested_end_ns), (1100, 1150));
    assert_eq!((w.effective_start_ns, w.effective_end_ns), (1100, 1100));
    assert_eq!(
        (
            capture.programmed_admission.unwrap().start_ns(),
            capture.programmed_admission.unwrap().deadline_ns()
        ),
        (1000, 1050)
    );
    assert_eq!(w.tail_gap_ns(), 50);
    assert!(w.count_admission.is_none());
    assert_eq!(capture.document.total_calls(), 0);
    assert!(matches!(
        capture.document.status,
        Completeness::Partial { .. }
    ));
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_binding_failure_retains_original_prefix_and_runtime_salvage() {
    let mut h = Harness::fresh("g1-binding-prefix");
    *h.clock.ns.borrow_mut() = 1000;
    h.acquired_ns = 1000;
    h.cfg.duration = Duration::from_nanos(1000);
    h.poll_delay_ns.insert(0, 100);
    h.snapshot_attached();
    let backing = backing_of(&h.staged, h.off).unwrap();
    h.polls.push_back(DiscoveryDelta {
        objects: vec![osslscope::discovery::session::DiscoveredObject {
            dev: backing.dev.clone(),
            ino: h.staged.ino,
            display_locator: h.staged.path.clone(),
        }],
        candidates: vec![
            cand(
                "/p/provider.so",
                Some(backing.clone()),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            ),
            cand(
                "/p/provider.so",
                backing_of(&h.staged, h.off + 16),
                1,
                12,
                "SHA-256",
                false,
                "ok",
            ),
        ],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let clock = h.clock.clone();
    let shared = h.shared.clone();
    h.comm_hook = Some(Rc::new(move || {
        clock.advance_ns(200);
        let mut state = shared.borrow_mut();
        let cookies = state.attached.clone();
        // Deliberately contradictory retained input: valid under actual Open,
        // before requested release. The controller must refuse binding it.
        state.backend.fire(PID, cookies[0], 1050, 1);
        state.backend.fire(PID, cookies[1], 1300, 1);
    }));
    let (out, _) = h.run();
    let error = out.unwrap_err();
    let binding = error
        .downcast_ref::<osslscope::capture::WindowBindingFailure>()
        .unwrap();
    assert_eq!(
        binding.reason,
        osslscope::capture::WindowBindingReason::PreRequestedRow
    );
    let runtime = error
        .downcast_ref::<osslscope::capture::CaptureRuntimeFailure>()
        .unwrap();
    let terminal = runtime.terminal.as_ref().unwrap();
    assert_eq!(terminal.retained_drain.total_calls(), 2);
    assert_eq!(terminal.retained_drain.current[0].first_ns, 1050);
    assert_eq!(runtime.capture.document.total_calls(), 1);
    assert_eq!(runtime.capture.document.sites[0].first_ns, 1300);
    assert!(matches!(
        runtime.capture.document.status,
        Completeness::Fatal {
            kind: osslscope::evidence::FatalKind::Runtime(_),
            ..
        }
    ));
    assert_eq!(
        runtime.capture.release_attempt.unwrap().before.monotonic_ns,
        1100
    );
    assert_eq!(
        runtime.capture.programmed_admission.unwrap().start_ns(),
        1000
    );
    let context = runtime.capture.failure_context.as_ref().unwrap();
    assert_eq!(context.rejected.known_rows, Some(2));
    assert_eq!(context.rejected.known_calls, Some(2));
    assert!(std::sync::Arc::ptr_eq(
        terminal,
        binding.terminal.as_ref().unwrap()
    ));
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&runtime.capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_public_open_error_routes_only_actual_completed_binding() {
    use osslscope::capture::{
        BoundaryFailureClass, PreObservationCause, PreObservationCount, PreObservationFailure,
    };
    for owned in [false, true] {
        for fault in [
            OpenReplyFault::CompletedLost,
            OpenReplyFault::MissingResolved,
            OpenReplyFault::MismatchedActual,
        ] {
            let mut h = Harness::fresh("g1-open-error");
            h.owned = owned;
            h.shared.borrow_mut().open_reply_fault = Some(fault);
            let (out, post) = h.run();
            if !owned && matches!(fault, OpenReplyFault::CompletedLost) {
                let capture = out.unwrap();
                assert!(matches!(
                    capture.document.status,
                    Completeness::Fatal {
                        kind: osslscope::evidence::FatalKind::Runtime(_),
                        ..
                    }
                ));
                assert_eq!(capture.programmed_admission.unwrap().start_ns(), BASE_NS);
                assert_eq!(
                    capture.programmed_admission.unwrap().deadline_ns(),
                    BASE_NS + 2_000_000_000
                );
                assert!(capture.release_attempt.is_none());
                let context = capture.failure_context.as_ref().unwrap();
                assert_eq!(
                    context.failure.as_ref().unwrap().class,
                    BoundaryFailureClass::Disconnected
                );
                assert!(matches!(context.count, PreObservationCount::Terminal(_)));
                let value: serde_json::Value = serde_json::from_slice(
                    &osslscope::report::render_json(&capture.document).unwrap(),
                )
                .unwrap();
                osslscope::schema::validate_v2(&value).unwrap();
                osslscope::schema::check_v2_semantics(&value).unwrap();
            } else {
                let error = out.unwrap_err();
                let failure = error.downcast_ref::<PreObservationFailure>().unwrap();
                assert_eq!(failure.cause, PreObservationCause::OpenUnresolved);
                assert!(failure.release.is_none());
                let PreObservationCount::Terminal(terminal) = &failure.count else {
                    panic!("missing canonical terminal")
                };
                assert_eq!(terminal.retained_drain.total_calls(), 0);
                assert!(failure.failure.is_some());
                assert!(failure.failure.as_ref().unwrap().detail.len() <= 200);
            }
            assert!(!post.target_log.borrow().released);
        }
    }
}

#[test]
fn g1_external_completed_open_positive_before_loop_flag_salvages() {
    let mut h = Harness::fresh("g1-external-setup-positive");
    h.owned = false;
    h.snapshot_attached();
    let backing = backing_of(&h.staged, h.off).unwrap();
    h.polls.push_back(DiscoveryDelta {
        objects: vec![osslscope::discovery::session::DiscoveredObject {
            dev: backing.dev.clone(),
            ino: h.staged.ino,
            display_locator: h.staged.path.clone(),
        }],
        candidates: vec![cand(
            "/p/provider.so",
            Some(backing),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    h.traversal_setup_error = true;
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert!(matches!(
        capture.document.status,
        Completeness::Fatal {
            kind: osslscope::evidence::FatalKind::Runtime(_),
            ..
        }
    ));
    assert_eq!(capture.document.total_calls(), 1);
    assert_eq!(capture.document.sites[0].last_ns, BASE_NS + 300);
    assert_eq!(capture.programmed_admission.unwrap().start_ns(), BASE_NS);
    assert!(capture.release_attempt.is_none());
    assert!(!post.target_log.borrow().released);
    let context = capture.failure_context.as_ref().unwrap();
    let failure = context.failure.as_ref().unwrap();
    assert_eq!(failure.stage, osslscope::capture::BoundaryStage::Traversal);
    assert_eq!(failure.class, osslscope::capture::BoundaryFailureClass::Io);
    assert_eq!(failure.errno, Some(libc::EIO));
    let bounds = match_bounds(&capture.document.sites, &|_| PredicateMatch::Yes);
    assert_eq!(bounds.definite, 1);
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_owned_fulfilled_omits_projection_only_after_pre_read_reap() {
    let mut h = Harness::fresh("g1-strict-fulfilled");
    *h.clock.ns.borrow_mut() = 1000;
    h.acquired_ns = 1000;
    h.cfg.duration = Duration::from_nanos(1000);
    h.poll_delay_ns.insert(0, 100);
    h.exit_at_ns = Some(1500);
    h.snapshot_attached();
    let backing = backing_of(&h.staged, h.off).unwrap();
    h.polls.push_back(DiscoveryDelta {
        objects: vec![osslscope::discovery::session::DiscoveredObject {
            dev: backing.dev.clone(),
            ino: h.staged.ino,
            display_locator: h.staged.path.clone(),
        }],
        candidates: vec![cand(
            "/p/provider.so",
            Some(backing),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
    let shared = h.shared.clone();
    let clock = h.clock.clone();
    h.comm_hook = Some(Rc::new(move || {
        clock.advance_ns(100);
        let mut state = shared.borrow_mut();
        let cookie = state.attached[0];
        state.backend.fire(PID, cookie, clock.monotonic_ns(), 1);
        clock.advance_ns(300);
    }));
    let (out, post) = h.run();
    let capture = out.unwrap();
    let w = &capture.document.window;
    assert_eq!((w.requested_start_ns, w.requested_end_ns), (1100, 1500));
    assert_eq!((w.effective_start_ns, w.effective_end_ns), (1100, 1500));
    assert!(w.count_admission.is_none());
    assert_eq!(capture.document.sites[0].last_ns, 1200);
    assert_eq!(capture.programmed_admission.unwrap().deadline_ns(), 2000);
    assert_eq!(post.target_log.borrow().reaped_at, Some(1500));
    let order = post.order.borrow();
    assert!(
        order.iter().position(|e| e == "reaped").unwrap()
            < order.iter().position(|e| e == "count_closed").unwrap()
    );
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    assert!(value["window"].get("count_admission").is_none());
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_suffix_keeps_original_lifecycle_edge() {
    // The salvage route after count cleanup must retain the loop edge too.
    let mut h = Harness::fresh("g1-salvage-original-edge");
    h.cfg.duration = Duration::from_secs(1);
    h.finish_err = true;
    h.shared.borrow_mut().terminal_delay_ns = 400_000_000;
    h.lifecycle_close_drain = Some(LifecycleDelta {
        events: [
            Some(BASE_NS + 900_000_000),
            Some(BASE_NS + 1_000_000_000),
            Some(BASE_NS + 1_300_000_000),
            None,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, timestamp_ns)| LifecycleEvent {
            kind: LifecycleKind::Fork,
            pid: 6000 + i as u32,
            timestamp_ns,
        })
        .collect(),
        loss: 2,
        dropped: 3,
        prefix_unwitnessed: 4,
        pending: 1,
    });
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert_eq!(counter_value(&capture, "lifecycle.fork_exec_ignored"), 1);
    assert_eq!(counter_value(&capture, "lifecycle.scan_loss"), 3);
    assert_eq!(counter_value(&capture, "lifecycle.signal_dropped"), 3);
    assert_eq!(
        counter_value(&capture, "lifecycle.signal_prefix_unwitnessed"),
        4
    );
    assert_eq!(counter_value(&capture, "lifecycle.drain_pending"), 1);
    assert_eq!(
        capture.document.window.effective_end_ns,
        BASE_NS + 1_000_000_000
    );
    let order = post.order.borrow();
    assert!(
        order.iter().position(|s| s == "count_closed").unwrap()
            < order.iter().position(|s| s == "lifecycle_suffix").unwrap()
    );
    assert_eq!(
        post.shared
            .borrow()
            .log
            .iter()
            .filter(|s| *s == "count_closed")
            .count(),
        1
    );
}

#[test]
fn g1_count_fd_admission_is_explicit() {
    let admission = osslscope::capture::CountFdAdmission {
        soft_limit: 16420,
        non_count_open: 12,
        non_count_reserved: 8,
    };
    assert_eq!(admission.allowance().unwrap(), 16400);
    let mut h = Harness::fresh("g1-emfile-after-admission");
    h.owned = false;
    h.snapshot_attached();
    h.shared.borrow_mut().attach_errno = Some(libc::EMFILE);
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand(
            "/p/provider.so",
            backing_of(&h.staged, h.off),
            1,
            11,
            "SHA-256",
            false,
            "ok",
        )],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..Default::default()
    });
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert!(matches!(
        capture.document.status,
        Completeness::Fatal {
            kind: osslscope::evidence::FatalKind::Runtime(_),
            ..
        }
    ));
    let failure = capture
        .failure_context
        .as_ref()
        .unwrap()
        .failure
        .as_ref()
        .unwrap();
    assert_eq!(failure.errno, Some(libc::EMFILE));
    assert!(!post.target_log.borrow().released && !post.target_log.borrow().resolved);
    let value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&capture.document).unwrap())
            .unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_recycle_count_cleanup_cannot_extend_window() {
    let mut h = Harness::fresh("g1-recycle-edge");
    h.owned = false;
    h.cfg.duration = Duration::from_secs(1);
    h.verify_err_after = Some(1);
    h.shared.borrow_mut().terminal_delay_ns = 400_000_000;
    let (out, post) = h.run();
    let capture = out.unwrap();
    assert!(matches!(
        capture.document.status,
        Completeness::Fatal {
            kind: osslscope::evidence::FatalKind::Recycled,
            ..
        }
    ));
    assert_eq!(
        capture.document.window.effective_end_ns, BASE_NS,
        "terminal cleanup time is never recycled-target coverage"
    );
    assert!(capture.document.sites.is_empty() && capture.document.fenced.is_empty());
    assert!(capture.executions.is_empty());
    assert!(!post.target_log.borrow().released && !post.target_log.borrow().resolved);
    assert_eq!(
        post.shared
            .borrow()
            .log
            .iter()
            .filter(|s| *s == "count_closed")
            .count(),
        1
    );
}

#[path = "support/lifecycle_driver.rs"]
mod lifecycle_driver;
use lifecycle_driver::run_connector_driver;

pub(crate) fn connector_dispatch(case: &str) -> i32 {
    match case {
        "connector-controller:ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery" =>
        {
            connector_body_ordinary_production_capture_genuinely_observed_sleep_is_honest_noquery();
            0
        }
        _ => panic!("unknown connector test case"),
    }
}
