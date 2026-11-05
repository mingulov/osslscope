//! SPDX-License-Identifier: GPL-3.0-or-later
//! L5 signal witness + §9 signal/disposition evidence (harness-side).
//!
//! Mechanism (T7.4's): an INDEPENDENT kernel-mediated observer — a
//! separate observer process traces the workload cgroup via
//! `PTRACE_SEIZE` (clones/f forks auto-traced, cgroup newcomers
//! re-seized on the 60 s /proc cadence) and the kernel reports
//! every signal-delivery stop plus `PTRACE_GETSIGINFO`
//! (`si_pid` — the kernel-reported sender, never inferred). The
//! observer self-reports its OWN sends (generation attempts,
//! independent of delivery — a blocked/ignored/dead-target send has
//! no delivery stop but the attempt is real). No BPF, no loader
//! changes, no workload modification (no handlers/wrappers installed
//! in workload processes; dispositions snapshotted before/after).
//!
//! Log: `signal-witness.jsonl`, one entry per observed delivery
//! (`{ at_ns, signo, sender_pid, target_pid }`, D-record shape) plus
//! T7.4 `kind` (delivery/attempt/death/exit) and `uncertain`.
//! Most-recent-delivery attribution is REMOVED (L5): coalesced
//! standard-signal repeats are honest-uncertain (the oracle's frozen
//! rule below), never attributed to the most recent generate.
//!
//! Privileges: sibling attach needs `CAP_SYS_PTRACE` under Yama 1
//! (the qual runs privileged); parent→child tracing works
//! unprivileged (unit/integration legs).

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Witness entry kinds (T7.4): observed deliveries, self-reported
/// observer sends (attempts), signal-deaths, and plain exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    Delivery,
    Attempt,
    Death,
    Exit,
}

/// One `signal-witness.jsonl` entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessEntry {
    pub at_ns: u64,
    pub signo: i32,
    /// Kernel-reported `si_pid` (delivery), the observer pid
    /// (self-reported attempts), the fatal-stop sender (death), or
    /// null when unobserved (missed delivery — observer failure).
    pub sender_pid: Option<i32>,
    pub target_pid: i32,
    /// Honest-uncertain (L5): set by the ORACLE's frozen rule
    /// (standard signo + ≥2 sends while pending); the observer logs
    /// raw (`false`) and never attributes coalesced repeats.
    #[serde(default)]
    pub uncertain: bool,
    pub kind: WitnessKind,
}

/// One harness-logged send (the harness logs every signal IT sends:
/// target pid + signo; sender = the harness pid).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HarnessSend {
    pub at_ns: u64,
    pub signo: i32,
    pub target_pid: i32,
    pub sender_pid: i32,
}

/// `/proc` snapshot row (60 s cadence + before/after): pid,
/// starttime, state, pending/blocked/ignored/caught sets.
/// Disposition = (ignored, caught, blocked); pending is transient
/// state, compared finally (T7.4: unexplained pending at end FAILs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnap {
    pub pid: i32,
    pub starttime: u64,
    pub state: char,
    pub sigpnd: u64,
    pub sigblk: u64,
    pub sigign: u64,
    pub sigcgt: u64,
}

/// Snapshot one pid from `/proc` (`None` when gone/unreadable).
pub fn snapshot_proc(pid: i32) -> Option<ProcSnap> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    let mut it = after.split_whitespace();
    let state = it.next()?.chars().next()?;
    let starttime = it.nth(19)?.parse::<u64>().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut sigpnd = 0u64;
    let mut sigblk = 0u64;
    let mut sigign = 0u64;
    let mut sigcgt = 0u64;
    for line in status.lines() {
        let (k, v) = line.split_once(':')?;
        let v = v.trim();
        match k {
            "SigPnd" => sigpnd = u64::from_str_radix(v, 16).ok()?,
            "SigBlk" => sigblk = u64::from_str_radix(v, 16).ok()?,
            "SigIgn" => sigign = u64::from_str_radix(v, 16).ok()?,
            "SigCgt" => sigcgt = u64::from_str_radix(v, 16).ok()?,
            _ => {}
        }
    }
    Some(ProcSnap {
        pid,
        starttime,
        state,
        sigpnd,
        sigblk,
        sigign,
        sigcgt,
    })
}

/// Oracle verdict over the signal evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalVerdict {
    /// Untouched (strict §9 conjunction) — acceptance holds.
    Pass,
    /// Observer/service misbehavior or unexplained signal — FAIL.
    Fail(String),
    /// Positive evidence of an external signaler, or unproven
    /// observer (missed canary / phantom) — VOID, rerun required.
    Void(String),
}

/// Oracle inputs (§9 disposition + L5).
pub struct OracleInput<'a> {
    pub witness: &'a [WitnessEntry],
    pub harness_sends: &'a [HarnessSend],
    pub harness_pid: i32,
    pub observer_pid: i32,
    /// Every service-lifetime pid (restarts/upgrade add members —
    /// ANY service-originated signal from ANY lifetime FAILs).
    pub service_pids: &'a HashSet<i32>,
    /// Workload pids under test (witness-targeted entries break
    /// Untouched; survival checked separately from /proc).
    pub workload: &'a HashSet<i32>,
    /// Canary pids (positive + null controls).
    pub canary: &'a HashSet<i32>,
    /// Quiet-canary window `[start_ns, end_ns]` (null control: MUST
    /// log nothing for the canary).
    pub quiet_window: (u64, u64),
    /// External timeline events (positive external evidence for
    /// VOID — time-correlated to the entry, never blanket).
    pub external_events: &'a [ExternalEvent],
}

/// Harness-timeline external event (OOM-killer note, operator kill,
/// container eviction): positive evidence of an external signaler
/// for VOID — but ONLY when it time-correlates (±60 s) with the
/// unexplained entry's target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalEvent {
    pub at_ns: u64,
    pub pid: Option<i32>,
    pub note: String,
}

/// The §9 disposition oracle with L5 honest-uncertain coalescing.
///
/// Frozen uncertainty rule (T7.4): a standard-signo delivery is
/// UNCERTAIN iff ≥2 sends to the same (target, signo) occurred
/// since the target's last observed delivery (sends = harness log ∪
/// observer attempts; deliveries resolve). RT signals never
/// coalesce (queued) — always exact. Deaths are uncertain iff no
/// prior delivery entry names (target, signo) — a missed delivery.
/// Attempts are never uncertain (self-known). `si_pid` is reported
/// as observed; uncertainty flags the possibly-masked sender — the
/// oracle NEVER attributes a coalesced repeat to the most recent
/// generate.
pub fn adjudicate(input: &OracleInput) -> (SignalVerdict, Vec<WitnessEntry>) {
    // Annotate uncertainty first (oracle-owned; the log stays raw).
    let mut entries = input.witness.to_vec();
    // Sends per (target, signo) strictly after the last delivery.
    let mut last_delivery: HashMap<(i32, i32), u64> = HashMap::new();
    for e in entries.iter() {
        if e.kind == WitnessKind::Delivery {
            last_delivery.insert((e.target_pid, e.signo), e.at_ns);
        }
    }
    for e in entries.iter_mut() {
        e.uncertain = match e.kind {
            WitnessKind::Attempt | WitnessKind::Exit => false,
            WitnessKind::Death => {
                // Certain iff a delivery for (target, signo) was
                // observed (the fatal stop precedes the death).
                !input.witness.iter().any(|d| {
                    d.kind == WitnessKind::Delivery
                        && d.target_pid == e.target_pid
                        && d.signo == e.signo
                        && d.at_ns <= e.at_ns
                })
            }
            WitnessKind::Delivery => {
                if e.signo >= libc::SIGRTMIN() {
                    false
                } else {
                    let floor = last_delivery_before(input.witness, e.target_pid, e.signo, e.at_ns);
                    let sends = input
                        .harness_sends
                        .iter()
                        .filter(|s| {
                            s.target_pid == e.target_pid
                                && s.signo == e.signo
                                && s.at_ns > floor
                                && s.at_ns <= e.at_ns
                        })
                        .count()
                        + input
                            .witness
                            .iter()
                            .filter(|a| {
                                a.kind == WitnessKind::Attempt
                                    && a.target_pid == e.target_pid
                                    && a.signo == e.signo
                                    && a.at_ns > floor
                                    && a.at_ns <= e.at_ns
                            })
                            .count();
                    sends >= 2
                }
            }
        };
    }

    // 1. Observer proof (an unproven observer proves nothing):
    // every harness-sent CANARY signal appears with the harness
    // sender_pid (target + signo + time window); the quiet hour
    // logs nothing for the canary. Missed ⟹ VOID, phantom ⟹ VOID.
    for send in input
        .harness_sends
        .iter()
        .filter(|s| input.canary.contains(&s.target_pid))
    {
        let seen = entries.iter().any(|e| {
            e.kind == WitnessKind::Delivery
                && e.target_pid == send.target_pid
                && e.signo == send.signo
                && e.sender_pid == Some(input.harness_pid)
                && e.at_ns >= send.at_ns
        });
        if !seen {
            return (
                SignalVerdict::Void(format!(
                    "missed canary signal {}→{} (observer unproven)",
                    send.signo, send.target_pid
                )),
                entries,
            );
        }
    }
    for e in entries
        .iter()
        .filter(|e| input.canary.contains(&e.target_pid))
    {
        if e.kind == WitnessKind::Delivery
            && e.at_ns >= input.quiet_window.0
            && e.at_ns <= input.quiet_window.1
        {
            return (
                SignalVerdict::Void(format!("phantom canary entry in quiet window: {e:?}")),
                entries,
            );
        }
    }

    // 2. The observer/service is a suspect, never background: ANY
    // entry with sender == observer/service pid is FAIL (L5 positive
    // controls prove this fires).
    for e in &entries {
        if e.sender_pid == Some(input.observer_pid)
            || e.sender_pid
                .is_some_and(|p| input.service_pids.contains(&p))
        {
            return (
                SignalVerdict::Fail(format!("observer/service-originated signal: {e:?}")),
                entries,
            );
        }
    }

    // 3. Harness-sender entries MUST match the harness-sent log.
    for e in entries
        .iter()
        .filter(|e| e.sender_pid == Some(input.harness_pid))
    {
        let matched = input
            .harness_sends
            .iter()
            .any(|s| s.target_pid == e.target_pid && s.signo == e.signo && s.at_ns <= e.at_ns);
        if !matched {
            return (
                SignalVerdict::Fail(format!(
                    "harness-attributed entry without a send record: {e:?}"
                )),
                entries,
            );
        }
    }

    // 4. Workload deliveries/deaths: explained (harness-recorded or
    // third-party-witnessed incl. workload-internal) vs unexplained
    // (FAIL) vs external-positive (VOID).
    for e in entries.iter().filter(|e| {
        input.workload.contains(&e.target_pid)
            && matches!(e.kind, WitnessKind::Delivery | WitnessKind::Death)
    }) {
        let harness_recorded = input
            .harness_sends
            .iter()
            .any(|s| s.target_pid == e.target_pid && s.signo == e.signo && s.at_ns <= e.at_ns);
        if harness_recorded {
            continue;
        }
        match e.sender_pid {
            Some(pid)
                if pid != input.harness_pid
                    && pid != input.observer_pid
                    && !input.service_pids.contains(&pid) =>
            {
                // Third-party sender (workload-internal, kernel 0,
                // or a stranger): explained — the run stands, but
                // strict-Untouched below still decides acceptance.
                continue;
            }
            _ => {
                // No harness record and no third-party witness:
                // unexplained ⟹ observer misbehavior until proven
                // otherwise — FAIL, never void, unless a
                // time-correlated external event proves an external
                // signaler (±60 s, same target or untargeted).
                let correlated = input.external_events.iter().any(|ev| {
                    ev.at_ns.abs_diff(e.at_ns) <= 60_000_000_000
                        && ev.pid.is_none_or(|p| p == e.target_pid)
                });
                if correlated {
                    return (
                        SignalVerdict::Void(format!(
                            "unexplained {e:?} but a correlated external event exists"
                        )),
                        entries,
                    );
                }
                return (
                    SignalVerdict::Fail(format!("unexplained workload signal: {e:?}")),
                    entries,
                );
            }
        }
    }

    // 5. Strict Untouched (§9): ZERO harness workload sends AND an
    // empty-of-workload-targeted witness log AND (survival checked
    // by the harness from /proc) AND canary controls (proven
    // above). Workload-internal activity (sender ∈ workload) voids
    // rather than fails (positive non-harness non-observer sender —
    // rerun may be clean); anything else targeted breaks to FAIL.
    let workload_targeted: Vec<&WitnessEntry> = entries
        .iter()
        .filter(|e| {
            input.workload.contains(&e.target_pid)
                && matches!(e.kind, WitnessKind::Delivery | WitnessKind::Death)
        })
        .collect();
    let harness_to_workload = input
        .harness_sends
        .iter()
        .any(|s| input.workload.contains(&s.target_pid));
    if !harness_to_workload && workload_targeted.is_empty() {
        return (SignalVerdict::Pass, entries);
    }
    if !harness_to_workload
        && workload_targeted.iter().all(|e| {
            e.sender_pid
                .is_some_and(|p| input.workload.contains(&p) && !input.service_pids.contains(&p))
        })
    {
        return (
            SignalVerdict::Void(
                "workload-internal signals only (not untouched; rerun)".to_string(),
            ),
            entries,
        );
    }
    (
        SignalVerdict::Fail(format!(
            "touched: harness_to_workload={harness_to_workload} entries={workload_targeted:?}"
        )),
        entries,
    )
}

fn last_delivery_before(witness: &[WitnessEntry], target: i32, signo: i32, before_ns: u64) -> u64 {
    witness
        .iter()
        .filter(|d| {
            d.kind == WitnessKind::Delivery
                && d.target_pid == target
                && d.signo == signo
                && d.at_ns < before_ns
        })
        .map(|d| d.at_ns)
        .max()
        .unwrap_or(0)
}

/// Observer configuration (harness-side; env-marshalled for the
/// hidden-test observer child — see `tests/six_b_witness.rs`).
#[derive(Debug, Clone)]
pub struct ObserverConfig {
    /// Explicit pids to seize (tests / parent→child legs).
    pub pids: Vec<i32>,
    /// Cgroup whose `cgroup.procs` is enumerated at start and
    /// re-enumerated every 60 s (newcomers seized; fork/exec
    /// inherit tracing via `TRACECLONE`, so no task escapes).
    pub cgroup_procs: Option<std::path::PathBuf>,
    /// `signal-witness.jsonl` append path.
    pub log_path: std::path::PathBuf,
    /// Positive-control hook: send `signo` to `pid` once after
    /// seizing and self-report the attempt (a signaling observer
    /// MUST fail the run — L5 proof leg).
    pub signal_test: Option<(i32, i32)>,
}

/// Run the observer loop (diverges; the harness kills the observer
/// at teardown — killing the tracer auto-detaches + resumes all
/// tracees, so the workload always survives observer death).
/// Exits nonzero (fail-loud) when an explicit pid cannot be seized,
/// an enumerated member fails for a non-ESRCH errno, or a clone
/// child cannot be optioned — the harness voids on observer death
/// (an unproven observer proves nothing). ESRCH on enumerated
/// members is a transient death race (noted, tolerated).
pub fn run_observer(cfg: &ObserverConfig) -> ! {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log_path)
        .unwrap_or_else(|e| {
            eprintln!("witness: cannot open log: {e}");
            std::process::exit(2);
        });
    let mut obs = Observer {
        log,
        traced: HashSet::new(),
        pending_initial: HashSet::new(),
        pending_options: HashSet::new(),
        last_sender: HashMap::new(),
    };
    let explicit: HashSet<i32> = cfg.pids.iter().copied().collect();
    let mut initial = cfg.pids.clone();
    if let Some(cg) = cfg.cgroup_procs.as_ref() {
        initial.extend(read_cgroup_procs(cg));
    }
    initial.sort();
    initial.dedup();
    for pid in initial {
        match obs.seize_or_adopt(pid, explicit.contains(&pid)) {
            SeizeOutcome::Seized => {}
            SeizeOutcome::AdoptedOurs => {
                eprintln!("witness: enumerated {pid} already ours (adoption)");
            }
            SeizeOutcome::GoneEsrch => {
                eprintln!("witness: enumerated {pid} already gone (ESRCH)");
            }
            SeizeOutcome::GoneZombie => {
                eprintln!("witness: enumerated {pid} dead-or-zombie, tolerated");
            }
            SeizeOutcome::Fatal => {
                eprintln!("witness: cannot seize {pid}: lost containment");
                std::process::exit(2);
            }
        }
    }
    if let Some((pid, signo)) = cfg.signal_test {
        // SAFETY: trivially safe libc call.
        let rc = unsafe { libc::kill(pid, signo) };
        if rc == 0 {
            // Self-reported generation attempt (independent of
            // delivery — a blocked/ignored send has no stop).
            obs.append(
                WitnessKind::Attempt,
                signo,
                Some(unsafe { libc::getpid() }),
                pid,
            );
        }
    }
    let mut last_enum = std::time::Instant::now();
    loop {
        if let Some(cg) = cfg.cgroup_procs.as_ref() {
            if last_enum.elapsed() >= std::time::Duration::from_secs(60) {
                last_enum = std::time::Instant::now();
                for pid in read_cgroup_procs(cg) {
                    if obs.traced.contains(&pid) {
                        continue;
                    }
                    match obs.seize_or_adopt(pid, false) {
                        SeizeOutcome::Seized => {}
                        SeizeOutcome::AdoptedOurs => {
                            eprintln!("witness: newcomer {pid} already ours (adoption)");
                        }
                        SeizeOutcome::GoneEsrch => {
                            eprintln!("witness: newcomer {pid} already gone (ESRCH)");
                        }
                        SeizeOutcome::GoneZombie => {
                            eprintln!("witness: newcomer {pid} dead-or-zombie, tolerated");
                        }
                        SeizeOutcome::Fatal => {
                            eprintln!("witness: newcomer {pid} escaped (lost containment)");
                            std::process::exit(3);
                        }
                    }
                }
            }
        }
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
        if got < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD: no tracees right now — persist (newcomers may
            // arrive; the harness owns observer lifetime).
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        if got == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        obs.handle_wait(got, status);
    }
}

fn read_cgroup_procs(path: &Path) -> Vec<i32> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|w| w.parse::<i32>().ok())
        .collect()
}

/// Outcome of a seize-or-adopt attempt.
#[derive(Debug, PartialEq, Eq)]
enum SeizeOutcome {
    /// Attached now.
    Seized,
    /// Already our tracee (unhandled birth); adopted.
    AdoptedOurs,
    /// Died mid-race (ESRCH); tolerated iff enumerated.
    GoneEsrch,
    /// Dead-or-zombie; tolerated iff enumerated.
    GoneZombie,
    /// Explicit-pid failure, another tracer, or persistent
    /// unseizability: fail loud.
    Fatal,
}

struct Observer {
    log: std::fs::File,
    traced: HashSet<i32>,
    /// Clone children awaiting their auto-attach SIGSTOP (an
    /// artifact, never logged — a REAL SIGSTOP to these pids
    /// queues behind it and is handled next).
    pending_initial: HashSet<i32>,
    /// Clone children whose options are deferred to their first
    /// stop: a vfork child mid-flight (spawn uses vfork+exec)
    /// refuses SETOPTIONS with ESRCH until it execs, so the
    /// fork-event arm options immediately when it can (normal
    /// fork/clone children are stopped at birth) and defers on
    /// ANY failure; the SIGSTOP arm then options fail-loud (a
    /// child in a stop is alive and optionable). The deferral
    /// window admits no escape in this workload: only curl
    /// children (which never fork) traverse it.
    pending_options: HashSet<i32>,
    /// Last observed delivery sender per (tid, signo) (death
    /// attribution for fatal stops).
    last_sender: HashMap<(i32, i32), Option<i32>>,
}

impl Observer {
    /// True when `pid` is gone or a zombie (no signals receivable).
    fn target_dead_or_zombie(pid: i32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return true;
        };
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_none_or(|state| state == "Z")
    }

    /// The pid tracing `pid` per kernel truth (`TracerPid`), or
    /// `None` when unreadable (died mid-race).
    fn tracer_pid_of(pid: i32) -> Option<i32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                return rest.trim().parse::<i32>().ok();
            }
        }
        None
    }

    /// Drain all queued tracee stops (birth events adopt their
    /// children here — a drain may explain a pid).
    fn drain_waits(&mut self) {
        loop {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return; // ECHILD: nothing to drain.
            }
            if got == 0 {
                return;
            }
            self.handle_wait(got, status);
        }
    }

    /// Seize with kernel-truth disambiguation (dry-run root cause
    /// #3: a re-enum pass races the unhandled event queue — a birth
    /// whose event-stop hasn't been handled yet is already
    /// auto-attached (ours!) but untracked, so a naive re-seize
    /// dies EPERM on our own tracee every re-enum). EPERM (or any
    /// non-ESRCH failure) against an enumerated pid therefore
    /// consults `TracerPid` instead of guessing: ours → adopt (the
    /// queued event completes bookkeeping); another tracer →
    /// fail loud (containment failure); untraced → transient
    /// kernel state (mid-exec) → bounded retry. ESRCH on an
    /// enumerated pid is a death race (tolerated); anything on an
    /// EXPLICIT pid fails loud (preserved strictness).
    fn seize_or_adopt(&mut self, pid: i32, explicit: bool) -> SeizeOutcome {
        match self.seize(pid) {
            Ok(()) => return SeizeOutcome::Seized,
            Err(e) => {
                // ESRCH is raw errno 3 — NOT `NotFound` (ENOENT).
                if e.raw_os_error() == Some(libc::ESRCH) {
                    if explicit {
                        return SeizeOutcome::Fatal;
                    }
                    return SeizeOutcome::GoneEsrch;
                }
                if explicit {
                    return SeizeOutcome::Fatal;
                }
                if Self::target_dead_or_zombie(pid) {
                    return SeizeOutcome::GoneZombie;
                }
            }
        }
        // Slow path: live, untraced-or-ours, unseizable — resolve
        // by kernel truth with bounded retries (mid-exec and
        // unhandled-birth races resolve in ms).
        for _ in 0..10 {
            self.drain_waits();
            if self.traced.contains(&pid) {
                return SeizeOutcome::AdoptedOurs;
            }
            if Self::target_dead_or_zombie(pid) {
                return SeizeOutcome::GoneZombie;
            }
            match Self::tracer_pid_of(pid) {
                None => return SeizeOutcome::GoneEsrch,
                Some(t) if t as u32 == std::process::id() => {
                    self.traced.insert(pid);
                    self.pending_initial.insert(pid);
                    if self.set_options(pid).is_err() {
                        self.pending_options.insert(pid);
                    }
                    return SeizeOutcome::AdoptedOurs;
                }
                Some(0) => {
                    if self.seize(pid).is_ok() {
                        return SeizeOutcome::Seized;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Some(_) => return SeizeOutcome::Fatal,
            }
        }
        self.drain_waits();
        if self.traced.contains(&pid) {
            return SeizeOutcome::AdoptedOurs;
        }
        if Self::target_dead_or_zombie(pid) {
            return SeizeOutcome::GoneZombie;
        }
        SeizeOutcome::Fatal
    }

    fn seize(&mut self, pid: i32) -> std::io::Result<()> {
        // SEIZE attaches WITHOUT stopping the target, and SETOPTIONS
        // on a running tracee fails ESRCH — so options ride the
        // SEIZE `data` word (atomic attach+options, no stop-dance,
        // no fork-event escape window). A post-SEIZE SETOPTIONS
        // call here would self-inflict ESRCH on every live target
        // (dry-run root cause: startup "already gone" on live
        // workload, then EPERM re-seize at re-enumeration).
        let opts = (libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK) as libc::c_ulong;
        // SAFETY: seize+options on a target pid; `data` carries
        // SETOPTIONS bits.
        let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, opts as *mut libc::c_void) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.traced.insert(pid);
        Ok(())
    }

    fn set_options(&self, pid: i32) -> std::io::Result<()> {
        // SAFETY: option flags are plain bits.
        let opts = (libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK) as libc::c_ulong;
        let rc =
            unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, opts as *mut libc::c_void) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn cont(&self, pid: i32, signo: i32) {
        // SAFETY: cont with an optional re-injected signal.
        unsafe {
            libc::ptrace(libc::PTRACE_CONT, pid, 0, signo as *mut libc::c_void);
        }
    }

    fn siginfo_pid(&self, pid: i32) -> Option<i32> {
        // SAFETY: getsiginfo into a valid buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                pid,
                0,
                &mut info as *mut libc::siginfo_t as *mut libc::c_void,
            )
        };
        if rc != 0 {
            return None;
        }
        // SAFETY: si_pid reads the sender field (0 = kernel/fault).
        Some(unsafe { info.si_pid() })
    }

    fn event_msg(&self, pid: i32) -> u64 {
        // SAFETY: geteventmsg into a valid word.
        let mut msg: libc::c_ulong = 0;
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETEVENTMSG,
                pid,
                0,
                &mut msg as *mut libc::c_ulong as *mut libc::c_void,
            )
        };
        if rc != 0 { 0 } else { msg as u64 }
    }

    fn append(&mut self, kind: WitnessKind, signo: i32, sender_pid: Option<i32>, target_pid: i32) {
        use std::io::Write as _;
        let entry = WitnessEntry {
            at_ns: crate::service::state::monotonic_ns(),
            signo,
            sender_pid,
            target_pid,
            uncertain: false,
            kind,
        };
        if let Ok(mut bytes) = serde_json::to_vec(&entry) {
            bytes.push(b'\n');
            let _ = self.log.write_all(&bytes);
            let _ = self.log.sync_all();
        }
    }

    fn handle_wait(&mut self, pid: i32, status: i32) {
        if !self.traced.contains(&pid) {
            // Unknown pid from waitpid(-1): only our children and
            // auto-attached births surface here, so this is an
            // unprocessed birth whose fork-event still queues
            // (waitpid returns newest first — the child's
            // artifact SIGSTOP routinely precedes the parent's
            // event). Adopt it and handle normally: a first stop
            // is always the artifact stop (kernel: the auto-stop
            // precedes any signal delivery), never a delivery.
            self.traced.insert(pid);
            self.pending_initial.insert(pid);
            if self.set_options(pid).is_err() {
                self.pending_options.insert(pid);
            }
        }
        if libc::WIFEXITED(status) {
            self.traced.remove(&pid);
            self.pending_initial.remove(&pid);
            self.pending_options.remove(&pid);
            self.append(WitnessKind::Exit, 0, None, pid);
            return;
        }
        if libc::WIFSIGNALED(status) {
            self.traced.remove(&pid);
            self.pending_initial.remove(&pid);
            self.pending_options.remove(&pid);
            let signo = libc::WTERMSIG(status);
            let sender = self.last_sender.get(&(pid, signo)).copied().flatten();
            self.append(WitnessKind::Death, signo, sender, pid);
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        let stopsig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xffff;
        if event != 0 {
            if event == libc::PTRACE_EVENT_VFORK_DONE as i32 {
                // Vfork completion: the birth was already handled
                // at the VFORK event; nothing to option.
                self.cont(pid, 0);
                return;
            }
            // Clone/fork/vfork event on the parent: the child is
            // auto-attached — option it now when possible, else
            // defer to its first stop (a vfork child mid-flight
            // refuses ptrace until it execs; the SIGSTOP arm
            // options fail-loud, so no task escapes silently).
            // (Re)tried unconditionally: the child may have been
            // adopted early (first stop beat this event), in which
            // case this is a free second chance.
            let child = self.event_msg(pid) as i32;
            if child != 0 && !Self::target_dead_or_zombie(child) {
                if self.traced.insert(child) {
                    // Fresh birth: expect the artifact stop.
                    // (Adopted-early children keep their possibly
                    // already-consumed artifact state.)
                    self.pending_initial.insert(child);
                }
                if self.set_options(child).is_ok() {
                    self.pending_options.remove(&child);
                } else {
                    self.pending_options.insert(child);
                }
            }
            self.cont(pid, 0);
            return;
        }
        match stopsig {
            libc::SIGTRAP => {
                // Exec trap / stray trap: not a delivery.
                self.cont(pid, 0);
            }
            libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {
                if stopsig == libc::SIGSTOP && self.pending_initial.remove(&pid) {
                    // Auto-attach artifact: arm deferred options
                    // (fail-loud — a child in a stop is alive and
                    // optionable), then resume silently.
                    if self.pending_options.remove(&pid)
                        && let Err(e) = self.set_options(pid)
                    {
                        eprintln!("witness: clone child {pid} escaped (options failed: {e})");
                        std::process::exit(3);
                    }
                    self.cont(pid, 0);
                    return;
                }
                let sender = self.siginfo_pid(pid);
                self.last_sender.insert((pid, stopsig), sender);
                self.append(WitnessKind::Delivery, stopsig, sender, pid);
                // Preserve stop semantics (never inject stops).
                self.cont(pid, 0);
            }
            other => {
                let sender = self.siginfo_pid(pid);
                self.last_sender.insert((pid, other), sender);
                self.append(WitnessKind::Delivery, other, sender, pid);
                // Re-inject: the workload observes the signal
                // exactly as untraced (handlers run, dispositions
                // unchanged by the observer).
                self.cont(pid, other);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        kind: WitnessKind,
        signo: i32,
        sender: Option<i32>,
        target: i32,
        at: u64,
    ) -> WitnessEntry {
        WitnessEntry {
            at_ns: at,
            signo,
            sender_pid: sender,
            target_pid: target,
            uncertain: false,
            kind,
        }
    }

    fn service() -> HashSet<i32> {
        [300].into_iter().collect()
    }

    fn base<'a>(
        witness: &'a [WitnessEntry],
        sends: &'a [HarnessSend],
        workload: &'a HashSet<i32>,
        canary: &'a HashSet<i32>,
        service: &'a HashSet<i32>,
    ) -> OracleInput<'a> {
        OracleInput {
            witness,
            harness_sends: sends,
            harness_pid: 100,
            observer_pid: 200,
            service_pids: service,
            workload,
            canary,
            quiet_window: (1_000_000, 2_000_000),
            external_events: &[],
        }
    }

    /// True when this environment permits parent→child ptrace (a
    /// probe fork+seize+detach). Sandboxes with ptrace-blocking
    /// seccomp fail the probe, and the live tests return early
    /// instead of failing on environmental denial.
    fn ptrace_available() -> bool {
        // SAFETY: fork; the child only sleeps and exits.
        let probe = unsafe { libc::fork() };
        if probe < 0 {
            return false;
        }
        if probe == 0 {
            unsafe {
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        // SAFETY: seize/detach/kill on our own child (detach of a
        // non-tracee fails harmlessly when the seize was denied).
        let ok = unsafe { libc::ptrace(libc::PTRACE_SEIZE, probe, 0, 0) == 0 };
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, probe, 0, 0);
            libc::kill(probe, libc::SIGKILL);
        }
        drain_reap();
        ok
    }

    /// Fork a sleeper child (returns its pid). The child touches no
    /// Rust state.
    fn spawn_sleeper() -> i32 {
        // SAFETY: fork; the child only sleeps and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        pid
    }

    /// seize_or_adopt outcome pins (dry-run root cause #3): the
    /// second seize of our own tracee adopts via TracerPid (not
    /// fail-loud); the dead are Gone (fast, no retry); explicit
    /// failures stay Fatal; self-seize (EPERM + TracerPid 0, never
    /// resolving) retries ~1 s then fails loud; a victim held by
    /// ANOTHER tracer fails loud fast (the containment property).
    #[test]
    fn seize_or_adopt_disambiguates_by_tracer_pid() {
        if !ptrace_available() {
            eprintln!("seize_or_adopt test: ptrace denied, skipping live pin");
            return;
        }
        let log = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let mut obs = Observer {
            log,
            traced: HashSet::new(),
            pending_initial: HashSet::new(),
            pending_options: HashSet::new(),
            last_sender: HashMap::new(),
        };
        // Live own child → Seized, then AdoptedOurs on re-seize
        // (EPERM + TracerPid == us — the re-enum race shape).
        let child = spawn_sleeper();
        assert_eq!(obs.seize_or_adopt(child, false), SeizeOutcome::Seized);
        assert_eq!(obs.seize_or_adopt(child, false), SeizeOutcome::AdoptedOurs);
        // Dead pid → GoneEsrch, fast (ESRCH fast path, no retry).
        let t0 = std::time::Instant::now();
        assert_eq!(
            obs.seize_or_adopt(i32::MAX - 7, false),
            SeizeOutcome::GoneEsrch
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        // Dead pid, explicit → Fatal (preserved strictness).
        assert_eq!(obs.seize_or_adopt(i32::MAX - 7, true), SeizeOutcome::Fatal);
        // Self → Fatal. When untraced ourselves this exercises the
        // retry loop (~1 s: EPERM + TracerPid 0 persists); when the
        // test itself runs traced (debugger/strace) it resolves
        // fast as other-tracer — the outcome is Fatal either way.
        let me_traced = Observer::tracer_pid_of(std::process::id() as i32) != Some(0);
        let t0 = std::time::Instant::now();
        assert_eq!(
            obs.seize_or_adopt(std::process::id() as i32, false),
            SeizeOutcome::Fatal
        );
        let dt = t0.elapsed();
        if !me_traced {
            assert!(
                dt >= std::time::Duration::from_millis(900),
                "no retry: {dt:?}"
            );
        }
        assert!(
            dt < std::time::Duration::from_secs(30),
            "retry ran away: {dt:?}"
        );
        // Victim held by ANOTHER tracer → Fatal, fast. The holder
        // announces the victim pid only AFTER seizing it, so the
        // read returning proves the hold is established.
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe into a valid array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let holder = unsafe { libc::fork() };
        assert!(holder >= 0, "fork failed");
        if holder == 0 {
            unsafe {
                libc::close(fds[0]);
                let victim = libc::fork();
                if victim == 0 {
                    libc::sleep(30);
                    libc::_exit(0);
                }
                libc::ptrace(libc::PTRACE_SEIZE, victim, 0, 0);
                let pid_bytes = victim.to_ne_bytes();
                libc::write(
                    fds[1],
                    pid_bytes.as_ptr() as *const libc::c_void,
                    pid_bytes.len(),
                );
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        // SAFETY: close our write end (EOF-on-death, no hangs).
        unsafe {
            libc::close(fds[1]);
        }
        let mut victim: i32 = 0;
        let mut got = 0usize;
        while got < 4 {
            // SAFETY: read into a valid buffer.
            let n = unsafe {
                libc::read(
                    fds[0],
                    (std::ptr::addr_of_mut!(victim) as *mut u8).add(got) as *mut libc::c_void,
                    4 - got,
                )
            };
            assert!(n > 0, "holder died before announcing victim");
            got += n as usize;
        }
        // SAFETY: done with the read end.
        unsafe {
            libc::close(fds[0]);
        }
        let t0 = std::time::Instant::now();
        assert_eq!(obs.seize_or_adopt(victim, false), SeizeOutcome::Fatal);
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(5),
            "other-tracer case retried?!"
        );
        // Cleanup either way.
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, child, 0, 0);
            libc::kill(child, libc::SIGKILL);
            libc::kill(holder, libc::SIGKILL);
            libc::kill(victim, libc::SIGKILL);
        }
        drain_reap();
    }

    /// Live-seize pin (dry-run regression): SEIZE must attach AND
    /// arm fork-following atomically. The first cut called
    /// SETOPTIONS after SEIZE on a still-running target, which
    /// fails ESRCH — startup then "tolerated" a live attach and
    /// re-enumeration died EPERM. The child also vfork+execs once
    /// (the dry curl shape); mid-flight vfork children refuse
    /// ptrace, which the fork-event arm answers by deferring (not
    /// dying) — the deferral branch itself is pinned by the qual,
    /// which traverses it ~172k times (any fail-loud there VOIDs
    /// the run); forcing the 1–5 ms window deterministically
    /// in-unit would need pipe-synced handling and is not worth
    /// its flake risk. Parent→child ptrace needs no privilege
    /// (Yama parent exemption); when the sandbox denies ptrace
    /// outright (seccomp), this pins nothing and returns.
    #[test]
    fn seize_live_child_attaches_with_fork_events() {
        // SAFETY: fork; the child touches no Rust state — sleeps,
        // forks once, vforks once, sleeps, exits.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                libc::sleep(2);
                if libc::fork() == 0 {
                    libc::_exit(0);
                }
                libc::sleep(2);
                // SAFETY: vfork+exec of /bin/sleep — the dry curl
                // shape. The parent's vfork returns at exec, so
                // the tracer's event handling lands while the
                // exec'd child RUNS (vfork-exec children take no
                // auto-stop) and unoptionable — the fork-event arm
                // must defer, not die. (A bare vfork+_exit would
                // be zombie by handling time and prove nothing.)
                if libc::vfork() == 0 {
                    libc::execl(
                        c"/bin/sleep".as_ptr(),
                        c"sleep".as_ptr(),
                        c"2".as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                    );
                    libc::_exit(127);
                }
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        let log_path =
            std::env::temp_dir().join(format!("witness-seize-{}.log", std::process::id()));
        let log = std::fs::File::create(&log_path).unwrap();
        let mut obs = Observer {
            log,
            traced: HashSet::new(),
            pending_initial: HashSet::new(),
            pending_options: HashSet::new(),
            last_sender: HashMap::new(),
        };
        match obs.seize(child) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                // Sandbox without ptrace: a first-seize EPERM on
                // our own live child can only be environmental.
                eprintln!("seize test: ptrace denied, skipping live pin");
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                }
                drain_reap();
                return;
            }
            Err(e) => panic!("seize of live child must succeed: {e}"),
        }
        assert!(obs.traced.contains(&child));
        // Kernel rule both witness bugs violated: SETOPTIONS on a
        // RUNNING (never-stopped) tracee fails — options need a
        // stop, which SEIZE deliberately never sends.
        assert!(obs.set_options(child).is_err());
        // A second seize proves kernel-level attach (already traced).
        let err = obs.seize(child).expect_err("re-seize must fail EPERM");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        // Drain stops until the child's FORK event lands (options
        // live from the attach instant — no escape window) AND the
        // later vfork birth/death is processed (survival past it
        // pins the deferral — the old code exit(3)d here).
        let mut saw_fork = false;
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_secs(15);
        while (!saw_fork || start.elapsed() < std::time::Duration::from_secs(8))
            && std::time::Instant::now() < deadline
        {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            if got == child && libc::WIFSTOPPED(status) {
                let event = (status >> 16) & 0xffff;
                if event == libc::PTRACE_EVENT_FORK as i32 {
                    saw_fork = true;
                }
            }
            obs.handle_wait(got, status);
        }
        // Cleanup either way: detach, kill, reap to ECHILD.
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, child, 0, 0);
            libc::kill(child, libc::SIGKILL);
        }
        drain_reap();
        assert!(saw_fork, "no FORK event within 15 s — options not armed");
        // End-to-end following: at least one grandchild lifecycle
        // (birth → tracked → exit observed) must be in the log, and
        // no birth bookkeeping may leak (both grandchildren reaped
        // through the Death/Exit arms during the drain).
        assert!(
            obs.pending_initial.is_empty() && obs.pending_options.is_empty(),
            "birth bookkeeping leaked: {:?} {:?}",
            obs.pending_initial,
            obs.pending_options
        );
        assert_eq!(obs.traced.len(), 1);
        assert!(obs.traced.contains(&child));
        drop(obs);
        let bytes = std::fs::read(&log_path).unwrap_or_default();
        let _ = std::fs::remove_file(&log_path);
        let text = String::from_utf8_lossy(&bytes);
        let child_mark = format!("\"target_pid\":{child}");
        let followed = text.lines().any(|l| {
            (l.contains("\"kind\":\"exit\"") || l.contains("\"kind\":\"death\""))
                && !l.contains(&child_mark)
        });
        assert!(followed, "no grandchild exit in log:\n{text}");
    }

    /// Reap until no children/tracees remain (or 10 s pass).
    /// Stopped tracees are detached (detach resumes them) so their
    /// exits become reapable — otherwise ECHILD never arrives.
    fn drain_reap() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got < 0 {
                return; // ECHILD: nothing left.
            }
            if got == 0 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            if libc::WIFSTOPPED(status) {
                // SAFETY: detach a stopped tracee, resuming it.
                unsafe {
                    libc::ptrace(libc::PTRACE_DETACH, got, 0, 0);
                }
            }
        }
    }

    fn strict_untouched_passes() {
        let workload: HashSet<i32> = [11, 12].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        // One canary signal, observed with the harness sender.
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(100), 21, 500)];
        let sends = vec![HarnessSend {
            at_ns: 400,
            signo: 10,
            target_pid: 21,
            sender_pid: 100,
        }];
        let (verdict, _) = adjudicate(&base(&witness, &sends, &workload, &canary, &service()));
        assert_eq!(verdict, SignalVerdict::Pass);
    }

    /// L5 positive control: a signaling observer MUST fail the run.
    #[test]
    fn signaling_observer_fails() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(200), 11, 500)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    /// L5 positive control, attempt edition: the observer's own
    /// self-reported send fails even without a delivery.
    #[test]
    fn observer_attempt_fails_without_delivery() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Attempt, 10, Some(200), 11, 500)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    #[test]
    fn missed_canary_voids() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let sends = vec![HarnessSend {
            at_ns: 400,
            signo: 10,
            target_pid: 21,
            sender_pid: 100,
        }];
        let (verdict, _) = adjudicate(&base(&[], &sends, &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
    }

    #[test]
    fn phantom_canary_voids() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(999), 21, 1_500_000)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
    }

    #[test]
    fn unexplained_workload_delivery_fails() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        // Delivery with no sender (missed) and no harness record.
        let witness = vec![entry(WitnessKind::Delivery, 10, None, 11, 500)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    /// L5 honest-uncertain: two standard sends while pending ⟹ the
    /// delivery is uncertain (never attributed to most-recent).
    #[test]
    fn coalesced_repeat_is_uncertain_not_attributed() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(100), 11, 900)];
        let sends = vec![
            HarnessSend {
                at_ns: 400,
                signo: 10,
                target_pid: 11,
                sender_pid: 100,
            },
            HarnessSend {
                at_ns: 500,
                signo: 10,
                target_pid: 11,
                sender_pid: 100,
            },
        ];
        let (verdict, annotated) =
            adjudicate(&base(&witness, &sends, &workload, &canary, &service()));
        assert!(annotated[0].uncertain, "coalesced repeat must be uncertain");
        // Harness-recorded ⟹ explained at step 4, but strict
        // Untouched still fails (harness touched the workload).
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    #[test]
    fn workload_internal_voids_not_fails() {
        let workload: HashSet<i32> = [11, 12].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        // Master 11 signals worker 12 (workload-internal business).
        let witness = vec![entry(WitnessKind::Delivery, 1, Some(11), 12, 500)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
    }

    #[test]
    fn correlated_external_event_voids() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Death, 9, None, 11, 500_000)];
        let external = vec![ExternalEvent {
            at_ns: 490_000,
            pid: Some(11),
            note: "oom-killer".to_string(),
        }];
        let svc = service();
        let mut input = base(&witness, &[], &workload, &canary, &svc);
        input.external_events = &external;
        let (verdict, annotated) = adjudicate(&input);
        assert!(annotated[0].uncertain, "missed-delivery death is uncertain");
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
        // Uncorrelated: FAIL.
        let mut input2 = base(&witness, &[], &workload, &canary, &svc);
        let far = vec![ExternalEvent {
            at_ns: 999_999_999_999,
            pid: Some(11),
            note: "x".to_string(),
        }];
        input2.external_events = &far;
        let (verdict2, _) = adjudicate(&input2);
        assert!(matches!(verdict2, SignalVerdict::Fail(_)), "{verdict2:?}");
    }
}
