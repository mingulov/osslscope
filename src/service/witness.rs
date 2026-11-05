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
        if let Err(e) = obs.seize(pid) {
            // ESRCH on an enumerated member = a transient that died
            // between enumeration and seize (short-lived workload
            // children churn constantly) — noted, tolerated. ESRCH
            // on an EXPLICIT pid, or any other errno (EPERM =
            // lost containment), fails loud.
            let transient_gone = Observer::tolerate_seize_error(&e, explicit.contains(&pid));
            if transient_gone {
                eprintln!("witness: enumerated {pid} already gone (ESRCH)");
            } else {
                eprintln!("witness: cannot seize {pid}: {e}");
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
                    if let Err(e) = obs.seize(pid) {
                        // Same transient rule as startup: ESRCH on an
                        // enumerated newcomer is a death race, noted;
                        // anything else is a containment failure.
                        if Observer::tolerate_seize_error(&e, false) {
                            eprintln!("witness: newcomer {pid} already gone (ESRCH)");
                        } else {
                            eprintln!("witness: newcomer {pid} escaped (seize failed: {e})");
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

struct Observer {
    log: std::fs::File,
    traced: HashSet<i32>,
    /// Clone children awaiting their auto-attach SIGSTOP (an
    /// artifact, never logged — a REAL SIGSTOP to these pids
    /// queues behind it and is handled next).
    pending_initial: HashSet<i32>,
    /// Last observed delivery sender per (tid, signo) (death
    /// attribution for fatal stops).
    last_sender: HashMap<(i32, i32), Option<i32>>,
}

impl Observer {
    /// Seize-failure triage: ESRCH (raw errno 3 — NOT `NotFound`,
    /// which is ENOENT) on an enumerated member is a transient death
    /// race and tolerated; ESRCH on an explicit pid, or any other
    /// errno, fails loud.
    fn tolerate_seize_error(e: &std::io::Error, explicit: bool) -> bool {
        !explicit && e.raw_os_error() == Some(libc::ESRCH)
    }

    fn seize(&mut self, pid: i32) -> std::io::Result<()> {
        // SAFETY: seize + setoptions on a target pid.
        let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.set_options(pid)?;
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
        if libc::WIFEXITED(status) {
            self.traced.remove(&pid);
            self.append(WitnessKind::Exit, 0, None, pid);
            return;
        }
        if libc::WIFSIGNALED(status) {
            self.traced.remove(&pid);
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
            // Clone/fork/vfork event on the parent: the child is
            // auto-attached — option it (fail-loud: no task
            // escapes), then resume the parent.
            let child = self.event_msg(pid) as i32;
            if child != 0 {
                if self.set_options(child).is_err() {
                    eprintln!("witness: clone child {child} escaped (options failed)");
                    std::process::exit(3);
                }
                self.traced.insert(child);
                self.pending_initial.insert(child);
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
                    // Auto-attach artifact: resume silently.
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

    #[test]
    /// ESRCH triage pin (regression: ESRCH is raw errno 3, NOT
    /// `ErrorKind::NotFound`, which is ENOENT — the first cut
    /// compared kinds and failed loud on every transient).
    #[test]
    fn seize_triage_esrch_enumerated_only() {
        let esrch = std::io::Error::from_raw_os_error(libc::ESRCH);
        assert!(Observer::tolerate_seize_error(&esrch, false));
        assert!(!Observer::tolerate_seize_error(&esrch, true));
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(!Observer::tolerate_seize_error(&eperm, false));
        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(!Observer::tolerate_seize_error(&enoent, false));
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
