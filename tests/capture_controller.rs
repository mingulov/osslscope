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
    ClockPort, Config, DiscoveryPort, LifecycleDelta, LifecycleKind, LifecyclePort, ProcPort,
    SessionSet, TargetInfo, TargetPort, observe,
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
    polls: VecDeque<DiscoveryDelta>,
    plans: HashMap<usize, FirePlan>,
    poll_err_at: HashSet<usize>,
    snapshot: DiscoverySnapshot,
    finish_err: bool,
    finish_recycled: bool,
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
            // recycle over discarded state (no pre-wipe final: the
            // fake stages no close-time joins).
            return Err(anyhow::Error::new(Recycled {
                snapshot: DiscoverySnapshot::default(),
                final_snapshot: None,
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
    files: HashMap<String, Vec<u8>>,
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
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no such staged file {path}"))
    }

    fn read_exe(&mut self, _pid: u32) -> Option<PathBuf> {
        self.exe.clone()
    }

    fn file_len(&mut self, path: &str) -> Option<u64> {
        self.files.get(path).map(|b| b.len() as u64)
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
}

struct Harness {
    stage: Stage,
    staged: Staged,
    bytes: Vec<u8>,
    off: u64,
    clock: Rc<FakeClock>,
    shared: Rc<RefCell<SharedState>>,
    target_log: Rc<RefCell<TargetLog>>,
    cfg: Config,
    owned: bool,
    acquired_ns: u64,
    polls: VecDeque<DiscoveryDelta>,
    plans: HashMap<usize, FirePlan>,
    poll_err_at: HashSet<usize>,
    snapshot: DiscoverySnapshot,
    finish_err: bool,
    finish_recycled: bool,
    release_err: bool,
    exit_at_ns: Option<u64>,
    exit_code: i32,
    poll_err: bool,
    verify_err_after: Option<usize>,
    lifecycle_polls: VecDeque<LifecycleDelta>,
    lifecycle_fallback: bool,
    maps: Vec<Mapping>,
    maps_seq: VecDeque<Vec<Mapping>>,
    files: HashMap<String, Vec<u8>>,
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
        files.insert(staged.path.clone(), bytes.clone());
        Self {
            stage,
            staged,
            bytes,
            off,
            clock: clock.clone(),
            shared: Rc::new(RefCell::new(SharedState::default())),
            target_log: Rc::new(RefCell::new(TargetLog::default())),
            cfg: Config {
                harvest_object: Some(PathBuf::new()),
                count_object: Some(PathBuf::new()),
                provider: Some(PathBuf::from("/p/provider.so")),
                builtin: false,
                table: None,
                force_offset: None,
                provider_enrollment: None,
                resolved_provider_class: None,
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
            poll_err_at: HashSet::new(),
            snapshot: DiscoverySnapshot::default(),
            finish_err: false,
            finish_recycled: false,
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
            polls: self.polls,
            plans: self.plans,
            poll_err_at: self.poll_err_at,
            snapshot: self.snapshot,
            finish_err: self.finish_err,
            finish_recycled: self.finish_recycled,
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
    h.files.insert(prov2.path.clone(), h.bytes.clone());
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
    h.files.insert(prov2.path.clone(), h.bytes.clone());
    h.files.insert(newso.path.clone(), h.bytes.clone());
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
    };
    h.snapshot.legacy.set = Some(set);
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
        c.legacy["legacy_provider"]["executed_calls"],
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
    };
    h.snapshot.legacy.set = Some(set);
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
        c.legacy["legacy_provider"]["executed_calls"],
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
    // ~1650ms the sleep has not crossed, the file reads do): the
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
    h.file_delay_ns = 300_000_000;
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
    };
    h.snapshot.legacy.set = Some(set);
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
        c.legacy["legacy_provider"]["executed_calls"],
        serde_json::json!(0)
    );
    assert_eq!(
        c.legacy["engine"]["calls_by_entrypoint"]["ENGINE_by_id"],
        serde_json::json!(0)
    );
    assert_eq!(c.counters.over_budget, 1);
}

#[test]
fn setup_slice_reports_exact_tail_gap() {
    // The kernel window opens pre-setup while the requested window
    // starts at release: the 300ms setup slice is uncounted time
    // inside the requested window, so it reports as an exact 300ms
    // tail gap — never hidden, never inflated by drain time.
    let mut h = Harness::fresh("setup-tail");
    h.snapshot_attached();
    h.file_delay_ns = 300_000_000;
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
    h.file_delay_ns = 600_000_000;
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
    h.files.insert(newso.path.clone(), h.bytes.clone());
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

use osslscope::capture::{AdaptedDelta, AdapterCtx, AdapterState, adapt_delta};

#[test]
fn advertising_fallback_binds_mapping_not_path() {
    // No build-id bytes: the opaque fallback binds the resolving
    // mapping's (dev, ino). A same-path replacement (new inode)
    // changes identity instead of conflating two objects.
    let stage = Stage::fresh("adv-map");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let dev = plan::render_device(staged.device);
    let live1 = vec![mapping(&staged)];
    let mut live2 = live1.clone();
    live2[0].ino += 1;
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let files: HashMap<String, Vec<u8>> = HashMap::new();
    let run = |live: &[Mapping], ino: u64| {
        let mut state = AdapterState::default();
        let delta = DiscoveryDelta {
            candidates: vec![cand(
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
            )],
            ..DiscoveryDelta::default()
        };
        let adapted = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live,
                files: &files,
                builtin_default: false,
                enrolled_class: None,
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
    assert_eq!(
        first,
        format!("unverified-advertising:{dev}:{}", staged.ino)
    );
    assert_eq!(
        second,
        format!("unverified-advertising:{dev}:{}", staged.ino + 1)
    );
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
    let files: HashMap<String, Vec<u8>> = HashMap::new();
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
            builtin_default: false,
            enrolled_class: None,
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
    let files_a: HashMap<String, Vec<u8>> = HashMap::from([(staged.path.clone(), bytes_a.clone())]);
    let first = adapt_delta(
        &mut state,
        &delta(),
        &AdapterCtx {
            live: &live,
            files: &files_a,
            builtin_default: false,
            enrolled_class: None,
            fresh: &fresh,
            post_settle: false,
            baseline: false,
        },
    );
    assert_eq!(first.delta.discovered.len(), 1);
    let fp_a = first.delta.discovered[0].site.object.0.clone();
    assert!(fp_a.starts_with("build:"), "{fp_a}");
    let files_b: HashMap<String, Vec<u8>> = HashMap::from([(staged.path.clone(), bytes_b.clone())]);
    let second = adapt_delta(
        &mut state,
        &delta(),
        &AdapterCtx {
            live: &live,
            files: &files_b,
            builtin_default: false,
            enrolled_class: None,
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
    files: HashMap<String, Vec<u8>>,
    fresh: HashSet<(String, u64)>,
    state: AdapterState,
}

impl AdaptHarness {
    fn fresh(test: &str) -> Self {
        let stage = Stage::fresh(test);
        let bytes = self_bytes();
        let staged = stage.write("prov.so", &bytes);
        let live = vec![mapping(&staged)];
        let files = HashMap::from([(staged.path.clone(), bytes)]);
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
                builtin_default: false,
                enrolled_class: None,
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
        polls: VecDeque::new(),
        plans: HashMap::new(),
        poll_err_at: HashSet::new(),
        snapshot,
        finish_err: false,
        finish_recycled,
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
    files.insert(staged.path.clone(), bytes);
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
        resolved_provider_class: None,
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
