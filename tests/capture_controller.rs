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
    ClockPort, Config, DiscoveryPort, LifecycleDelta, LifecycleEvent, LifecycleKind, LifecyclePort,
    ProcPort, SessionSet, TargetInfo, TargetPort, observe,
};
use osslscope::count_session::{
    CountBackend, CountSession, DrainedCounts, FakeCountBackend, FakeLink,
};
use osslscope::discovery::maps::Mapping;
use osslscope::discovery::session::{
    BackingRef, CoverageState, DiscoveredCandidate, DiscoveryDelta, DiscoveryLoss,
    DiscoverySnapshot, PollBudget, Recycled, TableCoverage, TableRetirement, TripwireDelta,
};
use osslscope::evidence::{
    CandidateCoverage, Completeness, ExpectedScope, PredicateMatch, match_bounds,
};
use osslscope::{plan, target};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl FakeClock {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            ns: RefCell::new(BASE_NS),
            base: Instant::now(),
            advanced: RefCell::new(Duration::ZERO),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
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

#[derive(Debug, Default)]
struct SharedState {
    backend: FakeCountBackend,
    attached: Vec<u32>,
    log: Vec<String>,
}

#[derive(Clone)]
struct SharedBackend(Rc<RefCell<SharedState>>);

impl CountBackend for SharedBackend {
    type Link = FakeLink;

    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<Self::Link>, Vec<usize>) {
        let mut st = self.0.borrow_mut();
        let (links, bad) = st.backend.attach(path, offsets, cookies);
        for (i, cookie) in cookies.iter().enumerate() {
            if !bad.contains(&i) {
                if let Ok(cookie) = u32::try_from(*cookie) {
                    if !st.attached.contains(&cookie) {
                        st.attached.push(cookie);
                    }
                }
            }
        }
        st.log.push(format!("attach:{path}:{}", links.len()));
        (links, bad)
    }

    fn open_window(
        &mut self,
        tgid: u64,
        generation: u32,
        start_ns: u64,
        deadline_ns: u64,
    ) -> anyhow::Result<()> {
        let mut st = self.0.borrow_mut();
        st.log.push("count_open".to_string());
        st.backend
            .open_window(tgid, generation, start_ns, deadline_ns)
    }

    fn set_generation(&mut self, generation: u32) -> anyhow::Result<()> {
        let mut st = self.0.borrow_mut();
        st.log.push(format!("gen:{generation}"));
        st.backend.set_generation(generation)
    }

    fn close_window(&mut self) -> anyhow::Result<()> {
        let mut st = self.0.borrow_mut();
        st.log.push("count_closed".to_string());
        st.backend.close_window()
    }

    fn drain(&mut self, deadline: Option<Instant>) -> anyhow::Result<DrainedCounts> {
        self.0.borrow_mut().backend.drain(deadline)
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
}

impl DiscoveryPort for FakeDiscovery {
    fn poll(&mut self, _budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        let idx = self.polls_done;
        self.polls_done += 1;
        if self.poll_err_at.contains(&idx) {
            anyhow::bail!("injected poll failure");
        }
        if let Some(plan) = self.plans.remove(&idx) {
            let mut st = self.shared.borrow_mut();
            if plan.shortfall > 0 {
                st.backend.set_shortfall(plan.shortfall);
            }
            let cookies = st.attached.clone();
            for (ns, n) in &plan.fires {
                for cookie in &cookies {
                    st.backend.fire(PID, *cookie, *ns, *n);
                }
            }
            if plan.cancel {
                if let Some(flag) = &self.cancel_flag {
                    flag.set(true);
                }
            }
        }
        // Scripted poll latency (deadline-straddle model): the poll
        // starts pre-deadline and completes after advancing the clock.
        if let Some(ns) = self.poll_delay_ns.get(&idx) {
            self.clock.sleep(Duration::from_nanos(*ns));
        }
        // Wall-clock pacing for live-child tests (zero elsewhere):
        // lets a real target run while fake time stays scripted.
        if !self.poll_real_delay.is_zero() {
            std::thread::sleep(self.poll_real_delay);
        }
        Ok(self.polls.pop_front().unwrap_or_default())
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
#[derive(Debug, Default)]
struct ProcLog {
    reads: Vec<String>,
    stats: Vec<String>,
}

#[derive(Debug, Default)]
struct TargetLog {
    released: bool,
    resolved: bool,
    finished: bool,
    polls: usize,
    verify_calls: usize,
}

struct FakeTarget {
    clock: Rc<FakeClock>,
    log: Rc<RefCell<TargetLog>>,
    pid: u32,
    owned: bool,
    release_err: bool,
    exit_at_ns: Option<u64>,
    exit_code: i32,
    poll_err: bool,
    verify_err_after: Option<usize>,
    exited: bool,
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
        self.log.borrow_mut().released = true;
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
}

impl LifecyclePort for FakeLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        self.polls.pop_front().unwrap_or_default()
    }

    fn fallback_partial(&self) -> bool {
        self.fallback
    }
}

struct FakeProc {
    clock: Rc<FakeClock>,
    maps: Vec<Mapping>,
    maps_seq: VecDeque<Vec<Mapping>>,
    files: HashMap<String, plan::FileBytes>,
    file_err: HashSet<String>,
    exe: Option<PathBuf>,
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
    proc_log: Rc<RefCell<ProcLog>>,
    /// Scripted stat identities, popped in call order (F-D/A13 F3):
    /// `Some((dev, ino))` overrides the staged identity once (a
    /// scripted replacement race), `None`/exhausted falls back to
    /// the staged identity.
    stat_seq: VecDeque<Option<(u64, u64)>>,
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
            .map(|f| f.bytes.clone())
            .ok_or_else(|| anyhow::anyhow!("no such staged file {path}"))
    }

    fn read_file_bound(&mut self, path: &str) -> anyhow::Result<(Vec<u8>, (u64, u64))> {
        self.clock.advance_ns(self.file_delay_ns);
        self.proc_log.borrow_mut().reads.push(path.to_string());
        if self.file_err.contains(path) {
            anyhow::bail!("injected file failure for {path}");
        }
        self.files
            .get(path)
            .map(|f| (f.bytes.clone(), (f.dev, f.ino)))
            .ok_or_else(|| anyhow::anyhow!("no such staged file {path}"))
    }

    fn stat_file(&mut self, path: &str) -> Option<(u64, u64)> {
        self.proc_log.borrow_mut().stats.push(path.to_string());
        if let Some(scripted) = self.stat_seq.pop_front().flatten() {
            return Some(scripted);
        }
        self.files.get(path).map(|f| (f.dev, f.ino))
    }

    fn read_exe(&mut self, _pid: u32) -> Option<PathBuf> {
        self.exe.clone()
    }

    fn file_len(&mut self, path: &str) -> Option<u64> {
        self.files.get(path).map(|f| f.bytes.len() as u64)
    }

    fn read_comm(&mut self, _pid: u32) -> Option<String> {
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
    stat_seq: VecDeque<Option<(u64, u64)>>,
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
    exit_at_ns: Option<u64>,
    exit_code: i32,
    poll_err: bool,
    verify_err_after: Option<usize>,
    lifecycle_polls: VecDeque<LifecycleDelta>,
    lifecycle_fallback: bool,
    maps: Vec<Mapping>,
    maps_seq: VecDeque<Vec<Mapping>>,
    files: HashMap<String, plan::FileBytes>,
    file_err: HashSet<String>,
    exe: Option<PathBuf>,
    maps_err_at: HashSet<usize>,
    maps_delay_ns: u64,
    file_delay_ns: u64,
    comm: Option<String>,
    comm_settle_at_ns: Option<u64>,
    comm_settled: Option<String>,
    cancelled: Rc<Cell<bool>>,
    cancel_on_poll: bool,
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
                bytes: bytes.clone(),
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
            stat_seq: VecDeque::new(),
            cfg: Config {
                harvest_object: Some(PathBuf::new()),
                count_object: Some(PathBuf::new()),
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
            exit_at_ns: None,
            exit_code: 0,
            poll_err: false,
            verify_err_after: None,
            lifecycle_polls: VecDeque::new(),
            lifecycle_fallback: false,
            maps,
            maps_seq: VecDeque::new(),
            files,
            file_err: HashSet::new(),
            exe: Some(PathBuf::from("/bin/app")),
            maps_err_at: HashSet::new(),
            maps_delay_ns: 0,
            file_delay_ns: 0,
            comm: None,
            comm_settle_at_ns: None,
            comm_settled: None,
            cancelled: Rc::new(Cell::new(false)),
            cancel_on_poll: false,
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
        };
        let count = CountSession::new(PID, SharedBackend(self.shared.clone()));
        let target = FakeTarget {
            clock: self.clock.clone(),
            log: self.target_log.clone(),
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
        };
        let mut proc = FakeProc {
            clock: self.clock.clone(),
            maps: self.maps,
            maps_seq: self.maps_seq,
            files: self.files,
            file_err: self.file_err,
            exe: self.exe,
            maps_err_at: self.maps_err_at,
            maps_delay_ns: self.maps_delay_ns,
            file_delay_ns: self.file_delay_ns,
            maps_calls: 0,
            comm: self.comm,
            comm_settle_at_ns: self.comm_settle_at_ns,
            comm_settled: self.comm_settled,
            proc_log: self.proc_log.clone(),
            stat_seq: self.stat_seq,
        };
        let flag = self.cancelled.clone();
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
            &|| flag.get(),
        );
        (
            out,
            PostCtx {
                shared: self.shared,
                target_log: self.target_log,
                proc_log: self.proc_log,
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
    // not sit in extra_loss while Complete claims stand.
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
    // The D4 counter record is preserved: the exemption is
    // taint-only (status stays PARTIAL via the loss counter —
    // finalize is unchanged by H2).
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
    let staged2 = h.stage.write("prov2.so", &h.bytes.clone());
    h.maps.push(mapping(&staged2));
    h.files.insert(
        staged2.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone(),
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
        backing_of(&staged2, h.off),
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
            bytes: h.bytes.clone(),
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
            bytes: h.bytes.clone(),
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
            bytes: h.bytes.clone(),
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
        let staged2 = h.stage.write("prov2.so", &h.bytes.clone());
        h.maps.push(mapping(&staged2));
        h.files.insert(
            staged2.path.clone(),
            plan::FileBytes {
                bytes: h.bytes.clone(),
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
            statuses[0],
        );
        let cand2 = cand(
            "/p/provider.so",
            backing_of(&staged2, h.off),
            2,
            12,
            "SHA-256",
            false,
            statuses[1],
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
    let prov2 = h.stage.write("prov2.so", &h.bytes.clone());
    h.files.insert(
        prov2.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone(),
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
        backing_of(&prov2, h.off),
        1,
        12,
        "SHA-512",
        false,
        "ok",
    );
    cand_b.epoch = 9;
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
fn owned_exit_survives_spurious_recycle_at_finish() {
    // Owned child exits mid-window and is reaped before the
    // discovery close, whose pin check then misreads the gone
    // /proc entry as a recycle. The capture survives on the
    // pre-close snapshot: exit and disposition preserved, the
    // skipped final join explicit loss — never a lost capture.
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
            },
            LifecycleEvent {
                kind: LifecycleKind::Exec,
                pid: PID,
            },
        ],
        loss: 0,
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
fn release_failure_on_dead_child_preserves_exit() {
    // Release fails but the child already died: actionable
    // startup-gap result with the preserved status (not a fatal).
    let mut h = Harness::fresh("dead-release");
    h.release_err = true;
    h.exit_at_ns = Some(0);
    h.exit_code = 7;
    let (out, post) = h.run();
    let c = out.unwrap();
    assert_eq!(c.child_exit, Some(7));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 7 })
    ));
    assert!(has_reason(&c, "startup-gap"), "{:?}", c.reasons);
    assert!(has_reason(&c, "no-query"), "{:?}", c.reasons);
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(post.target_log.borrow().resolved);
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
    // (never left stopped), and the result is signal-cut PARTIAL
    // with the SIGKILL status and disposition preserved.
    let h = Harness::fresh("setup-cancel");
    h.cancelled.set(true);
    let (out, post) = h.run();
    let c = out.unwrap();
    assert!(matches!(c.outcome, Outcome::Partial));
    assert!(has_reason(&c, "interrupted"), "{:?}", c.reasons);
    assert!(has_reason(&c, "startup-gap"), "{:?}", c.reasons);
    assert_eq!(c.child_exit, Some(137));
    assert!(matches!(
        c.disposition,
        Some(target::TargetDisposition::Exited { code: 137 })
    ));
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
            bytes: h.bytes.clone(),
            dev: prov2.device,
            ino: prov2.ino,
        },
    );
    h.files.insert(
        newso.path.clone(),
        plan::FileBytes {
            bytes: h.bytes.clone(),
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
    h.polls.push_back(DiscoveryDelta::default());
    h.polls.push_back(DiscoveryDelta {
        candidates: vec![cand_a],
        tables: vec![terminated(1, 0)],
        trigger_observed: true,
        ..DiscoveryDelta::default()
    });
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
    let (out, _) = h.run();
    let err = out.unwrap_err();
    assert!(
        err.to_string()
            .contains("requested window elapsed before window open"),
        "{err:?}"
    );
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
            bytes: h.bytes.clone(),
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
                bytes: bytes_a,
                dev: sa.device,
                ino: sa.ino,
            },
        ),
        (
            sb.path.clone(),
            plan::FileBytes {
                bytes: bytes_b,
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
            bytes: bytes_new.clone(),
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
            bytes: bytes_v2.clone(),
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
            bytes: bytes.clone(),
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
            bytes: bytes_a.clone(),
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
            baseline: false,
        },
    );
    assert_eq!(first.delta.discovered.len(), 1);
    let fp_a = first.delta.discovered[0].site.object.0.clone();
    assert!(fp_a.starts_with("build:"), "{fp_a}");
    let files_b: HashMap<String, plan::FileBytes> = HashMap::from([(
        staged.path.clone(),
        plan::FileBytes {
            bytes: bytes_b.clone(),
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
                bytes,
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
use osslscope::target::OwnedTarget;

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
) -> (anyhow::Result<Capture>, u32) {
    let stage = Stage::fresh(test);
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let owned = OwnedTarget::spawn_stopped(&argv).unwrap();
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
    };
    let count = CountSession::new(pid, SharedBackend(shared));
    let lifecycle = FakeLifecycle {
        polls: VecDeque::new(),
        fallback: false,
    };
    let mut files = HashMap::new();
    files.insert(
        staged.path.clone(),
        plan::FileBytes {
            bytes,
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
        maps_err_at: HashSet::new(),
        maps_delay_ns: 0,
        file_delay_ns: 0,
        maps_calls: 0,
        comm: None,
        comm_settle_at_ns: None,
        comm_settled: None,
        proc_log: Rc::new(RefCell::new(ProcLog::default())),
        stat_seq: VecDeque::new(),
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
        provider: Some(PathBuf::from("/p/provider.so")),
        builtin: false,
        table: None,
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration,
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
        &*clock,
        &mut proc,
        &|| false,
    );
    (out, pid)
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
    let (out, pid) = live_observe(
        "live-exit-recycle",
        &["/bin/sh", "-c", "exit 7"],
        Duration::from_secs(30),
        true,
    );
    let c = out.unwrap();
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
fn live_short_children_are_detected() {
    // Back-to-back 20ms grandchildren across ~1.2s: ten 100ms ppid
    // scans catch at least one (polling is best-effort — the
    // fallback stays explicitly PARTIAL either way).
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "i=0; while [ $i -lt 60 ]; do sleep 0.02; i=$((i+1)); done".to_string(),
    ];
    let mut owned = OwnedTarget::spawn_stopped(&argv).unwrap();
    let pid = owned.pid();
    owned.release().unwrap();
    let mut lc = PollingLifecycle::new(pid);
    assert!(lc.fallback_partial());
    let mut forks = 0u64;
    for _ in 0..10 {
        let delta = lc.poll();
        forks += delta
            .events
            .iter()
            .filter(|e| e.kind == LifecycleKind::Fork)
            .count() as u64;
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        forks >= 1,
        "ten scans across ~1.2s of 20ms children saw nothing"
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
    let mut owned = OwnedTarget::spawn_stopped(&argv).unwrap();
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
    let mut owned = OwnedTarget::spawn_stopped(&argv).unwrap();
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
    let mut owned = OwnedTarget::spawn_stopped(&argv).unwrap();
    let pid = owned.pid();
    owned.release().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut lc = PollingLifecycle::new(pid);
    let before = lc.poll();
    assert!(
        before.events.iter().all(|e| e.kind != LifecycleKind::Exec),
        "no exec before the exec point: {before:?}"
    );
    std::thread::sleep(Duration::from_millis(600));
    let after = lc.poll();
    assert_eq!(after.events.len(), 1, "{after:?}");
    assert_eq!(after.events[0].kind, LifecycleKind::Exec);
    assert_eq!(after.events[0].pid, pid);
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
    let mut owned = OwnedTarget::spawn_stopped(&argv).unwrap();
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
            bytes: h.bytes.clone(),
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
    h.stat_seq = VecDeque::from([None, None, Some((dev, ino + 1000))]);
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
