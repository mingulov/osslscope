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
//! independent of delivery — a blocked-forever or dead-target send
//! has no delivery stop but the attempt is real; ignored signals DO
//! stop under ptrace, pinned below). F8c: self-report
//! alone is INSUFFICIENT evidence (R1) — a second, independent
//! channel, the attempt tracer, supervises each suspect process
//! under a seccomp `RET_TRACE` filter on the kill family, so the
//! KERNEL stops the suspect at every signal-generation syscall and
//! reports (sender, target, signo, result) to the tracer. The
//! oracle corroborates self-reports against the attempt log and
//! FAILs on kernel-proven suspect sends even when the witness log
//! is empty. No BPF, no loader changes, no workload modification
//! (no handlers/wrappers installed in workload processes;
//! dispositions snapshotted before/after).
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

/// One `attempt-witness.jsonl` entry (F8c): a kernel-traced
/// signal-generation syscall by a suspect process. Written by the
/// attempt tracer — a process that is neither the suspect nor the
/// delivery observer — at the kernel's `PTRACE_EVENT_SECCOMP` stop,
/// with the result captured at the syscall-exit stop. The suspect
/// runs no userspace code between the syscall and the stop, so it
/// can neither suppress nor forge the entry (it can only avoid
/// sending).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttemptRecord {
    /// Tracer `CLOCK_MONOTONIC` at the seccomp-entry stop.
    pub at_ns: u64,
    /// Sending thread (waitpid-reported tid of the suspect task).
    pub sender_pid: i32,
    /// Sending process (tgid at the stop — distinguishes TID from
    /// process identity, R2 Gate 5; `None` in pre-fix logs).
    #[serde(default)]
    pub sender_tgid: Option<i32>,
    /// Traced-tree ownership (the suspect root pid supervised by the
    /// tracer that logged this — every task in that tree carries its
    /// root, R2 Gate 5; `None` in pre-fix logs, which the oracle
    /// judges by pid/tgid alone).
    #[serde(default)]
    pub suspect_root: Option<i32>,
    /// `/proc/<tid>/comm` at the stop (`?` when unreadable).
    pub sender_comm: String,
    /// Decoded syscall name (`kill`, `tkill`, `tgkill`,
    /// `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal`).
    pub syscall: String,
    /// Raw `__NR` (the filter already gates to x86-64).
    pub syscall_nr: i64,
    /// Decoded target: pid/tid, or `None` for pidfd sends the
    /// tracer could not resolve and out-of-range garbage.
    pub target_pid: Option<i32>,
    /// Requested signo (0 = existence probe — generates nothing).
    pub signo: i32,
    /// Raw syscall return (negative errno), or `None` when the
    /// sender died mid-syscall before the exit stop.
    pub result: Option<i64>,
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
    // Post-comm tokens index from field 3 (state): field 22
    // (starttime) is token 19. Parse positionally (a consumed
    // `state` + `nth(19)` re-derives the field-23 vsize trap).
    let toks: Vec<&str> = after.split_whitespace().collect();
    let state = toks.first()?.chars().next()?;
    let starttime = toks.get(19)?.parse::<u64>().ok()?;
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
    /// Kernel-traced generation attempts (F8c independent
    /// channel; empty when the run did not attempt-trace).
    pub attempts: &'a [AttemptRecord],
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
///
/// F8c: traced attempts join the send count (proven sends —
/// successful or unknown result only; a negative result proves the
/// kernel queued nothing, so failed sends are not pending), and
/// kernel-traced suspect sends FAIL even with an empty witness log
/// (rule 1b), while self-reported attempts require traced
/// corroboration (rule 2b — uncorroborated self-report VOIDs).
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
                            .count()
                        + input
                            .attempts
                            .iter()
                            .filter(|a| {
                                // F8c: proven traced sends join the
                                // count (failed sends queued nothing
                                // and are not pending; signo 0
                                // generates nothing).
                                a.target_pid == Some(e.target_pid)
                                    && a.signo == e.signo
                                    && a.signo != 0
                                    && a.result.is_none_or(|r| r >= 0)
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

    // 1b. F8c independent attempt evidence: kernel-traced suspect
    // sends FAIL even with an EMPTY witness log (a blocked-forever
    // or dead-target send has no delivery stop — this rule is the
    // L5 no-stop detector). The result is diagnostic, never
    // exculpatory: a
    // correct observer/service never calls kill on workload pids
    // (even ESRCH attempts FAIL). Signo 0 generates nothing
    // (existence probes — the observer heartbeat) and is ignored.
    for a in input.attempts.iter().filter(|a| a.signo != 0) {
        // R2 Gate 5: every traced suspect task stays suspect —
        // TID (`sender_pid`), process (`sender_tgid`), or tree
        // ownership (`suspect_root`) matching a suspect root proves
        // suspect origin (pre-fix logs carry tid only; the tid check
        // preserves their leader/stranger behavior exactly).
        let suspect = a.sender_pid == input.observer_pid
            || input.service_pids.contains(&a.sender_pid)
            || a.sender_tgid
                .is_some_and(|t| t == input.observer_pid || input.service_pids.contains(&t))
            || a.suspect_root
                .is_some_and(|r| r == input.observer_pid || input.service_pids.contains(&r));
        if suspect {
            match a.target_pid {
                Some(t) if input.workload.contains(&t) => {
                    return (
                        SignalVerdict::Fail(format!(
                            "traced observer/service-originated signal attempt: {a:?}"
                        )),
                        entries,
                    );
                }
                None => {
                    return (
                        SignalVerdict::Fail(format!(
                            "traced observer/service-originated signal attempt with \
                             indeterminate target (cannot prove the workload missed): {a:?}"
                        )),
                        entries,
                    );
                }
                Some(t) if t <= 0 => {
                    return (
                        SignalVerdict::Fail(format!(
                            "traced observer/service-originated broadcast signal attempt \
                             (cannot prove the workload missed): {a:?}"
                        )),
                        entries,
                    );
                }
                Some(t) if input.canary.contains(&t) => {
                    // The canary catches everything: a missing
                    // delivery means the delivery observer is
                    // unproven — VOID, never a pass. (A matching
                    // delivery FAILs below at rule 2a.)
                    let seen = entries.iter().any(|e| {
                        e.kind == WitnessKind::Delivery
                            && e.target_pid == t
                            && e.signo == a.signo
                            && e.at_ns >= a.at_ns
                    });
                    if !seen {
                        return (
                            SignalVerdict::Void(format!(
                                "suspect→canary attempt without observed delivery \
                                 (observer unproven): {a:?}"
                            )),
                            entries,
                        );
                    }
                }
                _ => {} // Suspect send elsewhere (self-probes, own tree) — ignored.
            }
        } else if a.sender_pid == input.harness_pid
            || a.sender_tgid.is_some_and(|t| t == input.harness_pid)
            || a.suspect_root.is_some_and(|r| r == input.harness_pid)
        {
            // Traced harness sends must match the harness-sent log
            // (the attempt-channel mirror of rule 3).
            let matched = match a.target_pid {
                Some(t) => input
                    .harness_sends
                    .iter()
                    .any(|s| s.target_pid == t && s.signo == a.signo && s.at_ns <= a.at_ns),
                None => false,
            };
            if !matched {
                return (
                    SignalVerdict::Fail(format!(
                        "traced harness send without a send record: {a:?}"
                    )),
                    entries,
                );
            }
        }
        // Stranger/workload-internal attempts without deliveries are
        // kernel-dropped (ignored) sends — unobservable, ignored.
    }

    // 2a. The observer/service is a suspect, never background: ANY
    // delivery/death/exit entry with sender == observer/service pid
    // is FAIL (delivery-channel evidence — independent of
    // self-report; L5 positive controls prove this fires).
    for e in &entries {
        if !matches!(
            e.kind,
            WitnessKind::Delivery | WitnessKind::Death | WitnessKind::Exit
        ) {
            continue;
        }
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

    // 2b. F8c: self-reported attempts need INDEPENDENT corroboration
    // (R1: self-report alone is insufficient — a matching traced
    // attempt within ±60 s proves the claim). Corroborated ⟹ FAIL
    // (proven misbehavior wins); otherwise VOID (an unproven
    // observer proves nothing — rerun under the attempt tracer).
    let self_reports: Vec<&WitnessEntry> = entries
        .iter()
        .filter(|e| {
            e.kind == WitnessKind::Attempt
                && (e.sender_pid == Some(input.observer_pid)
                    || e.sender_pid
                        .is_some_and(|p| input.service_pids.contains(&p)))
        })
        .collect();
    if let Some(proven) = self_reports.iter().find(|e| {
        input.attempts.iter().any(|a| {
            // R2 Gate 5: a worker-task traced send corroborates its
            // process/root self-report (tid, tgid, or tree ownership
            // matching the self-reported sender).
            (Some(a.sender_pid) == e.sender_pid
                || a.sender_tgid.is_some_and(|t| Some(t) == e.sender_pid)
                || a.suspect_root.is_some_and(|r| Some(r) == e.sender_pid))
                && a.target_pid == Some(e.target_pid)
                && a.signo == e.signo
                && a.at_ns.abs_diff(e.at_ns) <= 60_000_000_000
        })
    }) {
        return (
            SignalVerdict::Fail(format!(
                "corroborated observer/service-originated signal attempt: {proven:?}"
            )),
            entries,
        );
    }
    if let Some(unproven) = self_reports.first() {
        return (
            SignalVerdict::Void(format!(
                "uncorroborated self-reported observer/service attempt \
                 (no attempt-trace evidence — rerun under the tracer): {unproven:?}"
            )),
            entries,
        );
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
            // delivery — a blocked-forever send has no stop).
            obs.append(
                WitnessKind::Attempt,
                signo,
                Some(unsafe { libc::getpid() }),
                pid,
            );
        }
    }
    // F8c: startup heartbeat (the attempt-tracer positive
    // control starts here — every 60 s below keeps it live).
    Observer::heartbeat();
    let mut last_enum = std::time::Instant::now();
    let mut last_beat = std::time::Instant::now();
    loop {
        if last_beat.elapsed() >= std::time::Duration::from_secs(60) {
            last_beat = std::time::Instant::now();
            Observer::heartbeat();
        }
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

    /// Zero-effect liveness probe (F8c): `kill(self, 0)` checks
    /// existence and generates nothing. The observer emits one at
    /// startup and every 60 s; under the attempt tracer each probe
    /// lands in the attempt log as a signo-0 record — the
    /// attempt-tracer positive control (a broken tracer logs no
    /// heartbeat). Returns the raw `kill` return (0 = alive).
    pub fn heartbeat() -> i32 {
        // SAFETY: kill(self, 0) is an existence check with no effect.
        unsafe { libc::kill(libc::getpid(), 0) }
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
            if event == libc::PTRACE_EVENT_VFORK_DONE {
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

// ---------------------------------------------------------------------------
// F8c attempt tracer: independent kernel-mediated generation-attempt evidence.
//
// The delivery observer above sees signal DELIVERIES (ptrace stops at
// the target). L5 additionally requires generation ATTEMPTS
// independent of delivery: a blocked-forever or dead-target send
// has no delivery stop (ignored signals DO stop under ptrace —
// default and explicit alike, pinned by
// `delivery_observer_sees_default_ignored_signal`), and the T7.4
// self-report (the suspect logging its own sends) is insufficient
// evidence (R1 F8c). The attempt tracer supervises
// each SUSPECT process (the delivery observer; the service in a
// later round) under a seccomp `RET_TRACE` filter covering the six
// kill-family syscalls: the KERNEL stops the suspect at every
// signal-generation syscall and reports (nr, args) to the tracer,
// which decodes (sender, target, signo) and captures the result at
// the syscall-exit stop. One `attempt-witness.jsonl` entry per
// traced syscall. The suspect runs no userspace code between the
// syscall and the stop — it can avoid sending, never suppress or
// forge the record.
//
// Launcher semantics (like strace): spawn the suspect, supervise its
// whole tree (clone/fork/vfork inherit both the filter and the
// tracing) to completion, return 0. Nonzero is fail-loud (a hole in
// supervision voids the run's attempt evidence, never a silent gap).
// The suspect's own exit status is NOT propagated — the oracle
// judges the log, not the code.

/// `ptrace_syscall_info` (linux/ptrace.h): `op u8, reserved u8,
/// flags u16, arch u32, ip u64, sp u64`, then the variant payload
/// (entry/seccomp: nr + args[6]; exit: rval + is_error).
#[repr(C)]
pub struct SyscallInfo {
    pub op: u8,
    pub reserved: u8,
    pub flags: u16,
    pub arch: u32,
    pub ip: u64,
    pub sp: u64,
    pub data: [u64; 8],
}

const SYSCALL_INFO_ENTRY: u8 = 1;
const SYSCALL_INFO_EXIT: u8 = 2;
const SYSCALL_INFO_SECCOMP: u8 = 3;

/// A decoded signal-generation syscall: name, target
/// (pid for kill/tkill/rt_sigqueueinfo, tid for tgkill family,
/// `None` for pidfd sends — resolved separately), and signo.
pub struct DecodedSignalSyscall {
    pub name: &'static str,
    pub target: Option<i32>,
    pub signo: i32,
}

/// Decode a kill-family syscall (pure — unit-tested). `None` for
/// anything else. Pids outside i32 range decode to indeterminate
/// (the kernel rejects them; the oracle fails suspect sends with
/// indeterminate targets — it cannot prove the workload missed).
pub fn decode_signal_syscall(nr: i64, args: &[u64; 6]) -> Option<DecodedSignalSyscall> {
    fn pid(v: u64) -> Option<i32> {
        let raw = v as i64;
        if raw < i32::MIN as i64 || raw > i32::MAX as i64 {
            None
        } else {
            Some(raw as i32)
        }
    }
    let (name, target, signo) = if nr == libc::SYS_kill {
        ("kill", pid(args[0]), args[1] as i32)
    } else if nr == libc::SYS_tkill {
        ("tkill", pid(args[0]), args[1] as i32)
    } else if nr == libc::SYS_tgkill {
        ("tgkill", pid(args[1]), args[2] as i32)
    } else if nr == libc::SYS_rt_sigqueueinfo {
        ("rt_sigqueueinfo", pid(args[0]), args[1] as i32)
    } else if nr == libc::SYS_rt_tgsigqueueinfo {
        ("rt_tgsigqueueinfo", pid(args[1]), args[2] as i32)
    } else if nr == libc::SYS_pidfd_send_signal {
        ("pidfd_send_signal", None, args[1] as i32)
    } else {
        return None;
    };
    Some(DecodedSignalSyscall {
        name,
        target,
        signo,
    })
}

/// Classic-BPF opcodes from linux/filter.h (the `BPF_STMT` macros
/// are C-only, so the program is hand-encoded; the filter test pins
/// the literal values, not these constants).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
/// `AUDIT_ARCH_X86_64` (linux/audit.h: `EM_X86_64 | __AUDIT_ARCH_64BIT`).
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// The suspect's seccomp program: arch-gated, `RET_TRACE` on
/// exactly the six kill-family nrs, `RET_ALLOW` everywhere else
/// (near-zero overhead — the filter is a handful of insns per
/// syscall and stops only signal-generation syscalls).
pub fn attempt_filter() -> Vec<libc::sock_filter> {
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    let nrs = [
        libc::SYS_kill as u32,
        libc::SYS_tkill as u32,
        libc::SYS_tgkill as u32,
        libc::SYS_rt_sigqueueinfo as u32,
        libc::SYS_rt_tgsigqueueinfo as u32,
        libc::SYS_pidfd_send_signal as u32,
    ];
    // [LD arch][JEQ arch → LD nr][RET ALLOW][LD nr]
    // [JEQ nr → TRACE × 6][RET TRACE][RET ALLOW]
    let mut prog = vec![
        stmt(BPF_LD_W_ABS, 4), // struct seccomp_data.arch
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_LD_W_ABS, 0), // struct seccomp_data.nr
    ];
    let trace_at = 4 + nrs.len();
    for (i, nr) in nrs.iter().enumerate() {
        let jt = (trace_at - (4 + i) - 1) as u8;
        // The LAST compare must skip the TRACE ret on mismatch
        // (jf=1 → ALLOW tail); jf=0 would fall through INTO the
        // TRACE ret and trace every syscall on the box.
        let jf = if i + 1 == nrs.len() { 1 } else { 0 };
        prog.push(jump(BPF_JMP_JEQ_K, *nr, jt, jf));
    }
    prog.push(stmt(BPF_RET_K, libc::SECCOMP_RET_TRACE));
    prog.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    prog
}

fn get_syscall_info(tid: i32) -> std::io::Result<SyscallInfo> {
    let mut info: SyscallInfo = unsafe { std::mem::zeroed() };
    // SAFETY: GET_SYSCALL_INFO into a valid buffer (returns bytes written).
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            std::mem::size_of::<SyscallInfo>() as *mut libc::c_void,
            &mut info as *mut SyscallInfo as *mut libc::c_void,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

/// Resolve a pidfd held by `tid` to its target pid via
/// `/proc/<tid>/fdinfo/<fd>` (`Pid:` line). `None` when unreadable
/// (the oracle treats indeterminate suspect targets as FAIL — it
/// cannot prove the workload missed).
pub fn resolve_pidfd(tid: i32, fd: i32) -> Option<i32> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Pid:") {
            return rest.trim().parse::<i32>().ok();
        }
    }
    None
}

fn read_comm(tid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{tid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

/// Read a task's thread-group id (`Tgid:` from
/// `/proc/<tid>/status` — the process identity for R2 Gate 5).
/// `None` when unreadable (the task died mid-stop — the record
/// still carries tid + ownership; the oracle judges by those).
fn read_tgid(tid: i32) -> Option<i32> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse::<i32>().ok();
        }
    }
    None
}

/// Attempt-tracer configuration (launcher; see `run_attempt_tracer`).
pub struct AttemptTracerConfig {
    /// `attempt-witness.jsonl` append path.
    pub log_path: std::path::PathBuf,
    /// Optional path the tracer writes the suspect root pid to
    /// (the harness kills the suspect first at teardown, then reaps
    /// the tracer — suspect-first leaves no untraced gap).
    pub suspect_pid_file: Option<std::path::PathBuf>,
    /// Suspect command (`execvp` — `PATH` lookup).
    pub argv: Vec<String>,
}

/// An in-flight traced syscall (entry stop seen, exit stop pending).
struct PendingAttempt {
    at_ns: u64,
    comm: String,
    tgid: Option<i32>,
    name: &'static str,
    nr: i64,
    target: Option<i32>,
    signo: i32,
}

struct AttemptTracer {
    log: std::fs::File,
    traced: HashSet<i32>,
    pending: HashMap<i32, PendingAttempt>,
    /// Suspect root pid (the initial supervised child — every
    /// record from this tree carries it as ownership, R2 Gate 5).
    root: i32,
}

impl AttemptTracer {
    fn set_options(&self, pid: i32) -> std::io::Result<()> {
        // SAFETY: option flags are plain bits.
        let opts = (libc::PTRACE_O_TRACESECCOMP
            | libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK) as libc::c_ulong;
        // SAFETY: setoptions on a stopped tracee.
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

    fn syscall(&self, pid: i32) {
        // SAFETY: run to the next syscall-entry/exit stop.
        unsafe {
            libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0);
        }
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

    fn emit(&mut self, tid: i32, p: PendingAttempt, result: Option<i64>) {
        use std::io::Write as _;
        let rec = AttemptRecord {
            at_ns: p.at_ns,
            sender_pid: tid,
            sender_tgid: p.tgid,
            suspect_root: Some(self.root),
            sender_comm: p.comm,
            syscall: p.name.to_string(),
            syscall_nr: p.nr,
            target_pid: p.target,
            signo: p.signo,
            result,
        };
        if let Ok(mut bytes) = serde_json::to_vec(&rec) {
            bytes.push(b'\n');
            let _ = self.log.write_all(&bytes);
            let _ = self.log.sync_all();
        }
    }

    /// Handle one wait status. Returns 0 to continue, nonzero to
    /// abort the run with that exit code (fail-loud supervision
    /// holes — a missed attempt voids the evidence, never a gap).
    fn handle_wait(&mut self, pid: i32, status: i32) -> i32 {
        if !self.traced.contains(&pid) {
            // Not ours (a co-located observer's tracee in unit
            // tests — in qual the tracer supervises exactly its
            // suspect tree, so this never fires there).
            if libc::WIFSTOPPED(status) {
                self.cont(pid, 0);
            }
            return 0;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            // A tid that died mid-syscall: the send may or may not
            // have queued — emit with an unknown result (the oracle
            // counts unknown results as pending — conservative).
            if let Some(p) = self.pending.remove(&pid) {
                self.emit(pid, p, None);
            }
            self.traced.remove(&pid);
            return 0;
        }
        if !libc::WIFSTOPPED(status) {
            return 0;
        }
        let stopsig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xffff;
        if event == libc::PTRACE_EVENT_SECCOMP {
            match get_syscall_info(pid) {
                Ok(info) if info.op == SYSCALL_INFO_SECCOMP => {
                    let nr = info.data[0] as i64;
                    let mut args = [0u64; 6];
                    args.copy_from_slice(&info.data[1..7]);
                    match decode_signal_syscall(nr, &args) {
                        Some(d) => {
                            let target = match d.target {
                                Some(t) => Some(t),
                                None if nr == libc::SYS_pidfd_send_signal => {
                                    resolve_pidfd(pid, args[0] as i32)
                                }
                                None => None,
                            };
                            self.pending.insert(
                                pid,
                                PendingAttempt {
                                    at_ns: crate::service::state::monotonic_ns(),
                                    comm: read_comm(pid),
                                    tgid: read_tgid(pid),
                                    name: d.name,
                                    nr,
                                    target,
                                    signo: d.signo,
                                },
                            );
                            // Run to the syscall-exit stop for the result.
                            self.syscall(pid);
                        }
                        None => {
                            // Impossible by construction (the filter
                            // traces exactly the decoder's nr set) —
                            // a disagreement is a broken filter, so
                            // fail loud rather than skip silently.
                            eprintln!(
                                "attempt-tracer: filter/decoder disagree on nr {nr} from {pid}"
                            );
                            return 3;
                        }
                    }
                }
                _ => {
                    eprintln!("attempt-tracer: cannot read seccomp stop of {pid} (missed attempt)");
                    return 3;
                }
            }
            return 0;
        }
        if event != 0 {
            if event == libc::PTRACE_EVENT_VFORK_DONE {
                self.cont(pid, 0);
                return 0;
            }
            // Clone/fork/vfork birth: the child inherits the filter
            // AND auto-attach — option it (fail-loud: an unoptioned
            // suspect task is a supervision hole).
            let child = self.event_msg(pid) as i32;
            if child != 0 && !Observer::target_dead_or_zombie(child) {
                self.traced.insert(child);
                if self.set_options(child).is_err() {
                    eprintln!("attempt-tracer: suspect task {child} escaped (lost containment)");
                    return 3;
                }
            }
            self.cont(pid, 0);
            return 0;
        }
        if stopsig == libc::SIGTRAP | 0x80 {
            match self.pending.remove(&pid) {
                Some(p) => match get_syscall_info(pid) {
                    Ok(info) if info.op == SYSCALL_INFO_EXIT => {
                        self.emit(pid, p, Some(info.data[0] as i64));
                        self.cont(pid, 0);
                    }
                    Ok(info) if info.op == SYSCALL_INFO_ENTRY => {
                        // Re-entered (a signal raced the exit path):
                        // keep waiting for the exit.
                        self.pending.insert(pid, p);
                        self.syscall(pid);
                    }
                    _ => {
                        eprintln!("attempt-tracer: cannot read exit stop of {pid} (missed result)");
                        return 3;
                    }
                },
                None => self.cont(pid, 0), // Stray syscall stop — resume.
            }
            return 0;
        }
        match stopsig {
            // Exec trap / stray trap: not a delivery — never inject.
            libc::SIGTRAP => self.cont(pid, 0),
            libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {
                // Preserve stop semantics (never inject stops).
                self.cont(pid, 0);
            }
            other => {
                // Re-inject: the suspect observes signals exactly
                // as untraced (handlers run, dispositions unchanged).
                self.cont(pid, other);
            }
        }
        0
    }

    /// Blocking reap of one pid (teardown paths only).
    fn reap_quiet(&self, pid: i32) {
        loop {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
            if got < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return;
            }
            // A stop on the way out (e.g. the initial SIGSTOP when
            // options failed): detach, resuming it toward the exit.
            // SAFETY: detach a stopped tracee.
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            }
        }
    }
}

/// Supervise a suspect command under the kill-family seccomp filter
/// to completion (launcher semantics — returns, unlike the
/// diverging delivery observer).
///
/// Returns 0 when the whole suspect tree was supervised to
/// completion (the log is complete — possibly empty); 2 on
/// usage/spawn/setup failure; 3 on a supervision hole (a suspect
/// task escaped optioning, or a stop became unreadable — the
/// attempt evidence is void, never silently gapped).
///
/// Fork-safety: the child only `TRACEME`s, stops for options,
/// installs the pre-built filter, and execs — no allocation before
/// exec (the test suite runs `RUST_TEST_THREADS=1`).
pub fn run_attempt_tracer(cfg: &AttemptTracerConfig) -> i32 {
    if cfg.argv.is_empty() {
        eprintln!("attempt-tracer: no suspect command");
        return 2;
    }
    let log = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("attempt-tracer: cannot open log: {e}");
            return 2;
        }
    };
    // Pre-fork: argv CStrings + the filter program (the child must
    // not allocate before exec).
    let mut cstrs = Vec::with_capacity(cfg.argv.len());
    for a in &cfg.argv {
        match std::ffi::CString::new(a.as_str()) {
            Ok(c) => cstrs.push(c),
            Err(_) => {
                eprintln!("attempt-tracer: NUL byte in suspect argv");
                return 2;
            }
        }
    }
    let mut ptrs: Vec<*const libc::c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let mut filter = attempt_filter();
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: fork; the child only traces itself, stops, installs
    // the filter, and execs (see above).
    let child = unsafe { libc::fork() };
    if child < 0 {
        eprintln!("attempt-tracer: fork failed");
        return 2;
    }
    if child == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                libc::_exit(9);
            }
            libc::raise(libc::SIGSTOP);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) != 0 {
                libc::_exit(9);
            }
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const libc::sock_fprog,
                0,
                0,
            ) != 0
            {
                libc::_exit(9);
            }
            libc::execvp(ptrs[0], ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    // The initial stop (the child's SIGSTOP): option the suspect
    // before it runs a single filtered syscall.
    let status = loop {
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let got = unsafe { libc::waitpid(child, &mut status, libc::__WALL) };
        if got < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("attempt-tracer: waitpid for suspect stop failed");
            return 2;
        }
        break status;
    };
    let mut tracer = AttemptTracer {
        log,
        traced: HashSet::from([child]),
        pending: HashMap::new(),
        root: child,
    };
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        eprintln!("attempt-tracer: suspect {child} refused supervision (TRACEME/filter denied?)");
        if libc::WIFSTOPPED(status) {
            tracer.cont(child, 0);
        }
        tracer.reap_quiet(child);
        return 2;
    }
    if tracer.set_options(child).is_err() {
        eprintln!("attempt-tracer: cannot option suspect {child}");
        // SAFETY: kill our own suspect.
        unsafe {
            libc::kill(child, libc::SIGKILL);
        }
        tracer.reap_quiet(child);
        return 2;
    }
    if let Some(p) = cfg.suspect_pid_file.as_ref() {
        if std::fs::write(p, format!("{child}\n")).is_err() {
            eprintln!("attempt-tracer: cannot write suspect pid file");
            // SAFETY: kill our own suspect.
            unsafe {
                libc::kill(child, libc::SIGKILL);
            }
            tracer.reap_quiet(child);
            return 2;
        }
    }
    tracer.cont(child, 0);
    loop {
        if tracer.traced.is_empty() {
            break;
        }
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if got < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD with live tracees = lost supervision — fail loud.
            eprintln!(
                "attempt-tracer: waitpid failed with {} suspect tasks live",
                tracer.traced.len()
            );
            return 3;
        }
        let rc = tracer.handle_wait(got, status);
        if rc != 0 {
            return rc;
        }
    }
    0
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
            attempts: &[],
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

    fn attempt(sender: i32, target: Option<i32>, signo: i32, at: u64) -> AttemptRecord {
        AttemptRecord {
            at_ns: at,
            sender_pid: sender,
            sender_tgid: None,
            suspect_root: None,
            sender_comm: "sh".to_string(),
            syscall: "kill".to_string(),
            syscall_nr: 62,
            target_pid: target,
            signo,
            result: Some(0),
        }
    }

    fn base_a<'a>(
        witness: &'a [WitnessEntry],
        sends: &'a [HarnessSend],
        workload: &'a HashSet<i32>,
        canary: &'a HashSet<i32>,
        service: &'a HashSet<i32>,
        attempts: &'a [AttemptRecord],
    ) -> OracleInput<'a> {
        OracleInput {
            attempts,
            ..base(witness, sends, workload, canary, service)
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

    /// F8c: a SELF-REPORTED observer send with no independent
    /// attempt-trace corroboration VOIDs (an unproven observer
    /// proves nothing — self-report alone is insufficient).
    #[test]
    fn uncorroborated_self_report_voids() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Attempt, 10, Some(200), 11, 500)];
        let (verdict, _) = adjudicate(&base(&witness, &[], &workload, &canary, &service()));
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
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

    /// F8c L5 core: a kernel-traced suspect→workload send FAILs
    /// even with an EMPTY witness log (a blocked-forever or
    /// dead-target send has no delivery stop — the attempt channel
    /// is the only evidence).
    #[test]
    fn traced_suspect_attempt_fails_without_delivery() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let attempts = vec![attempt(200, Some(11), libc::SIGURG, 500)];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(
            matches!(verdict, SignalVerdict::Fail(ref d) if d.contains("traced")),
            "{verdict:?}"
        );
    }

    /// F8c: a suspect attempt on a dead workload pid (ESRCH) still
    /// FAILs — a correct observer/service never calls kill on
    /// workload pids; the result is diagnostic, not exculpatory.
    #[test]
    fn traced_suspect_esrch_attempt_still_fails() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let attempts = vec![AttemptRecord {
            result: Some(-(libc::ESRCH as i64)),
            ..attempt(200, Some(11), 10, 500)
        }];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    /// F8c: a self-report WITH a matching traced attempt FAILs
    /// (the independent channel corroborates the claim).
    #[test]
    fn corroborated_self_report_fails() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Attempt, 10, Some(200), 11, 500)];
        let attempts = vec![attempt(200, Some(11), 10, 490)];
        let (verdict, _) = adjudicate(&base_a(
            &witness,
            &[],
            &workload,
            &canary,
            &service(),
            &attempts,
        ));
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    /// F8c: signo 0 generates nothing (existence probe — the
    /// observer heartbeat) and never breaks Untouched.
    #[test]
    fn traced_signo_zero_ignored() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let attempts = vec![attempt(200, Some(11), 0, 500)];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(matches!(verdict, SignalVerdict::Pass), "{verdict:?}");
    }

    /// F8c: a suspect→canary attempt with no observed delivery VOIDs
    /// (the canary catches everything — a missing delivery means the
    /// delivery observer is unproven, never a pass).
    #[test]
    fn suspect_canary_attempt_without_delivery_voids() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let attempts = vec![attempt(200, Some(21), 10, 500)];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(matches!(verdict, SignalVerdict::Void(_)), "{verdict:?}");
    }

    /// F8c: a stranger's never-delivered send (traced attempt, no
    /// delivery — blocked-forever or dead-target) is unobservable
    /// by the workload and does not break Untouched.
    #[test]
    fn stranger_ignored_attempt_ignored() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let attempts = vec![attempt(999, Some(11), 10, 500)];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(matches!(verdict, SignalVerdict::Pass), "{verdict:?}");
    }

    /// F8c: proven traced sends join the L5 coalescing count — one
    /// harness send + one traced stranger send while pending ⟹ the
    /// delivery is uncertain (never most-recent attributed).
    #[test]
    fn traced_attempt_counts_for_coalescing() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(100), 11, 900)];
        let sends = vec![HarnessSend {
            at_ns: 400,
            signo: 10,
            target_pid: 11,
            sender_pid: 100,
        }];
        let attempts = vec![attempt(999, Some(11), 10, 500)];
        let (verdict, annotated) = adjudicate(&base_a(
            &witness,
            &sends,
            &workload,
            &canary,
            &service(),
            &attempts,
        ));
        assert!(
            annotated[0].uncertain,
            "traced + harness sends must be uncertain"
        );
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
    }

    /// F8c: a FAILED send (negative result — the kernel queued
    /// nothing) is not a pending send and does not coalesce.
    #[test]
    fn failed_send_does_not_coalesce() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let witness = vec![entry(WitnessKind::Delivery, 10, Some(100), 11, 900)];
        let sends = vec![HarnessSend {
            at_ns: 400,
            signo: 10,
            target_pid: 11,
            sender_pid: 100,
        }];
        let attempts = vec![AttemptRecord {
            result: Some(-(libc::ESRCH as i64)),
            ..attempt(999, Some(11), 10, 500)
        }];
        let (_, annotated) = adjudicate(&base_a(
            &witness,
            &sends,
            &workload,
            &canary,
            &service(),
            &attempts,
        ));
        assert!(!annotated[0].uncertain, "a failed send is not pending");
    }

    /// F8c: a traced HARNESS send must match the harness-sent log
    /// (mirrors the rule-3 delivery check on the attempt channel).
    #[test]
    fn traced_harness_attempt_must_match_log() {
        let workload: HashSet<i32> = [11].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        // Negative: traced but undeclared ⟹ FAIL naming the log gap.
        let attempts = vec![attempt(100, Some(11), 10, 500)];
        let (verdict, _) = adjudicate(&base_a(&[], &[], &workload, &canary, &service(), &attempts));
        assert!(
            matches!(verdict, SignalVerdict::Fail(ref d) if d.contains("without a send record")),
            "{verdict:?}"
        );
        // Positive: declared ⟹ the ordinary touched-FAIL (the
        // harness sent the workload — the attempt channel agrees).
        let sends = vec![HarnessSend {
            at_ns: 400,
            signo: 10,
            target_pid: 11,
            sender_pid: 100,
        }];
        let (verdict2, _) = adjudicate(&base_a(
            &[],
            &sends,
            &workload,
            &canary,
            &service(),
            &attempts,
        ));
        assert!(
            matches!(verdict2, SignalVerdict::Fail(ref d) if d.contains("touched")),
            "{verdict2:?}"
        );
    }

    /// F8c decoder pins: every kill-family nr decodes to
    /// (name, target, signo); pidfd targets resolve separately
    /// (None here); anything else is not a signal send.
    #[test]
    fn decode_kill_family() {
        let args = |a0: u64, a1: u64, a2: u64| [a0, a1, a2, 0, 0, 0];
        let d = decode_signal_syscall(libc::SYS_kill as i64, &args(11, 10, 0)).unwrap();
        assert_eq!((d.name, d.target, d.signo), ("kill", Some(11), 10));
        let d = decode_signal_syscall(libc::SYS_tkill as i64, &args(12, 9, 0)).unwrap();
        assert_eq!((d.name, d.target, d.signo), ("tkill", Some(12), 9));
        let d = decode_signal_syscall(libc::SYS_tgkill as i64, &args(13, 14, 15)).unwrap();
        assert_eq!((d.name, d.target, d.signo), ("tgkill", Some(14), 15));
        let d = decode_signal_syscall(libc::SYS_rt_sigqueueinfo as i64, &args(11, 10, 0)).unwrap();
        assert_eq!(
            (d.name, d.target, d.signo),
            ("rt_sigqueueinfo", Some(11), 10)
        );
        let d =
            decode_signal_syscall(libc::SYS_rt_tgsigqueueinfo as i64, &args(13, 14, 10)).unwrap();
        assert_eq!(
            (d.name, d.target, d.signo),
            ("rt_tgsigqueueinfo", Some(14), 10)
        );
        let d = decode_signal_syscall(libc::SYS_pidfd_send_signal as i64, &args(7, 10, 0)).unwrap();
        assert_eq!((d.name, d.target, d.signo), ("pidfd_send_signal", None, 10));
        // Literal-ABI leg (not via libc's own numbers): 62 is kill.
        let d = decode_signal_syscall(62, &args(11, 10, 0)).unwrap();
        assert_eq!((d.name, d.target, d.signo), ("kill", Some(11), 10));
        assert!(decode_signal_syscall(libc::SYS_getpid as i64, &args(0, 0, 0)).is_none());
        assert!(decode_signal_syscall(9999, &args(0, 0, 0)).is_none());
    }

    /// F8c filter pins (literal kernel ABI from linux/filter.h +
    /// linux/seccomp.h — NOT the implementation's own constants):
    /// arch-gated, TRACE on exactly the six kill-family nrs,
    /// ALLOW everywhere else.
    #[test]
    fn filter_traces_kill_family_allows_rest() {
        let prog = attempt_filter();
        // LD W ABS arch.
        assert_eq!(prog[0].code, 0x20);
        assert_eq!(prog[0].k, 4);
        // JEQ AUDIT_ARCH_X86_64.
        assert_eq!(prog[1].code, 0x15);
        assert_eq!(prog[1].k, 0xC000_003E);
        // One TRACE ret, six nr comparisons, default ALLOW tail.
        let traces = prog
            .iter()
            .filter(|i| i.code == 0x06 && i.k == 0x7FF0_0000)
            .count();
        assert_eq!(traces, 1);
        let compares = prog
            .iter()
            .filter(|i| i.code == 0x15 && i.k != 0xC000_003E)
            .count();
        assert_eq!(compares, 6);
        // The six compared nrs are exactly the x86-64 kill family
        // (literal kernel ABI: kill 62, rt_sigqueueinfo 129, tkill
        // 200, tgkill 234, rt_tgsigqueueinfo 297, pidfd_send_signal
        // 424).
        let mut nrs: Vec<u32> = prog
            .iter()
            .filter(|i| i.code == 0x15 && i.k != 0xC000_003E)
            .map(|i| i.k)
            .collect();
        nrs.sort_unstable();
        assert_eq!(nrs, vec![62, 129, 200, 234, 297, 424]);
        // The LAST compare skips the TRACE ret on mismatch (a
        // fall-through jf=0 would trace every syscall on the box —
        // that exact bug is what this pin guards).
        assert_eq!(prog[4 + 6 - 1].jf, 1);
        for i in 0..5 {
            assert_eq!(prog[4 + i].jf, 0);
        }
        let last = prog.last().unwrap();
        assert_eq!((last.code, last.k), (0x06, 0x7FFF_0000));
    }

    /// F8c: `SyscallInfo` matches the kernel's
    /// `ptrace_syscall_info` (`op u8, reserved u8, flags u16, arch
    /// u32, ip u64, sp u64`, variant payload at 24, 88 bytes).
    #[test]
    fn syscall_info_layout() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(SyscallInfo, op), 0);
        assert_eq!(offset_of!(SyscallInfo, arch), 4);
        assert_eq!(offset_of!(SyscallInfo, ip), 8);
        assert_eq!(offset_of!(SyscallInfo, sp), 16);
        assert_eq!(offset_of!(SyscallInfo, data), 24);
        assert_eq!(std::mem::size_of::<SyscallInfo>(), 88);
    }

    /// F8c: pidfd→pid resolution round-trips on our own pidfd.
    #[test]
    fn resolve_pidfd_roundtrip() {
        // SAFETY: pidfd_open/close on our own pid.
        let me = unsafe { libc::getpid() };
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, me, 0) };
        assert!(fd >= 0, "pidfd_open failed");
        assert_eq!(resolve_pidfd(me, fd as i32), Some(me));
        assert_eq!(resolve_pidfd(me, 999_999), None);
        unsafe {
            libc::close(fd as i32);
        }
    }

    /// F8c: the observer heartbeat is a zero-effect self-probe
    /// (kill(self, 0) — traced, oracle-ignored, proves the attempt
    /// channel is live).
    #[test]
    fn observer_heartbeat_is_noop_probe() {
        assert_eq!(Observer::heartbeat(), 0);
    }

    /// F8c L5 live leg, blocked edition: a SIGURG that is BLOCKED
    /// in the target never dequeues, so the attached delivery
    /// observer provably sees nothing (the drain runs with NO
    /// tracer active — no waitpid sharing can eat a stop, so an
    /// empty log is an airtight no-stop proof), while the attempt
    /// tracer kernel-catches the same send and the oracle FAILs on
    /// the pair. Blocked windows model real daemons (workers block
    /// signals around critical sections).
    #[test]
    fn l5_attempt_tracer_catches_blocked_send() {
        if !ptrace_available() {
            eprintln!("l5: ptrace denied, skipping live leg");
            return;
        }
        let dir = std::env::temp_dir().join(format!("osslscope-l5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let attempt_log = dir.join("attempt-witness.jsonl");
        let witness_log = dir.join("signal-witness.jsonl");
        // Target: SIGURG blocked forever (a python fixture — the
        // block models a daemon's masked window, not a handler).
        let mut target = std::process::Command::new("python3")
            .arg("-c")
            .arg("import signal,time;signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGURG});time.sleep(30)")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn python3 fixture");
        let fixture = target.id() as i32;
        // Wait (<= 5 s) for the mask: SigBlk bit (SIGURG - 1) set.
        // No blind sleep — the test proceeds only when the kernel
        // confirms the block.
        let mask_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let status =
                std::fs::read_to_string(format!("/proc/{fixture}/status")).unwrap_or_default();
            let blocked = status
                .lines()
                .find(|l| l.starts_with("SigBlk:"))
                .is_some_and(|l| {
                    u64::from_str_radix(l["SigBlk:".len()..].trim(), 16)
                        .is_ok_and(|m| m & (1 << (libc::SIGURG - 1)) != 0)
                });
            if blocked {
                break;
            }
            assert!(
                std::time::Instant::now() < mask_deadline,
                "fixture never blocked SIGURG"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // Delivery observer over the fixture (parent→child).
        let wlog = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&witness_log)
            .unwrap();
        let mut obs = Observer {
            log: wlog,
            traced: HashSet::new(),
            pending_initial: HashSet::new(),
            pending_options: HashSet::new(),
            last_sender: HashMap::new(),
        };
        assert!(matches!(
            obs.seize_or_adopt(fixture, true),
            SeizeOutcome::Seized
        ));
        // A plain (untraced) send + drain FIRST: with no tracer
        // running, the observer is the only stop consumer — an
        // empty log proves the blocked send never stopped.
        // SAFETY: kill our own fixture.
        assert_eq!(unsafe { libc::kill(fixture, libc::SIGURG) }, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got == fixture {
                obs.handle_wait(got, status);
            } else if got <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        let wtext = std::fs::read_to_string(&witness_log).unwrap();
        assert!(
            wtext.trim().is_empty(),
            "blocked send must not stop: {wtext}"
        );
        // The SAME send under the attempt tracer: kernel-caught.
        let cfg = AttemptTracerConfig {
            log_path: attempt_log.clone(),
            suspect_pid_file: None,
            argv: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("kill -s URG {fixture}"),
            ],
        };
        assert_eq!(run_attempt_tracer(&cfg), 0);
        // The fixture cannot have stopped (still blocked), so the
        // tracer can have eaten nothing — re-drain to be sure.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got == fixture {
                obs.handle_wait(got, status);
            } else if got <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        drop(obs);
        let text = std::fs::read_to_string(&attempt_log).unwrap();
        let attempts: Vec<AttemptRecord> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(attempts.len(), 1, "attempt log:\n{text}");
        assert_eq!(attempts[0].syscall, "kill");
        assert_eq!(attempts[0].target_pid, Some(fixture));
        assert_eq!(attempts[0].signo, libc::SIGURG);
        assert_eq!(attempts[0].result, Some(0));
        assert!(!attempts[0].sender_comm.is_empty());
        // Delivery channel: proven empty (both drains).
        let wtext = std::fs::read_to_string(&witness_log).unwrap();
        assert!(wtext.trim().is_empty(), "witness log:\n{wtext}");
        // Oracle: traced attempt + proven-empty witness ⟹ FAIL.
        let workload: HashSet<i32> = [fixture].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let svc = service();
        let mut input = base_a(&[], &[], &workload, &canary, &svc, &attempts);
        input.observer_pid = attempts[0].sender_pid;
        let (verdict, _) = adjudicate(&input);
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
        // SIGKILL is unblockable; reap everything.
        target.kill().unwrap();
        target.wait().unwrap();
        drain_reap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// F8c L5 live leg, dead-target edition: a send to a dead
    /// workload pid cannot stop anything (no task exists — silence
    /// BY CONSTRUCTION, no observer needed), the attempt tracer
    /// kernel-catches it with an ESRCH result, and the oracle FAILs.
    /// (Pid-reuse safety: Linux allocates pids sequentially, so the
    /// sender forked after the reap cannot take the dead pid short
    /// of a full pid-space wraparound — and the target!=sender
    /// assert would catch that visibly.)
    #[test]
    fn l5_attempt_tracer_catches_dead_target_send() {
        if !ptrace_available() {
            eprintln!("l5: ptrace denied, skipping live leg");
            return;
        }
        let dir = std::env::temp_dir().join(format!("osslscope-l5d-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let attempt_log = dir.join("attempt-witness.jsonl");
        // A reaped workload pid (spawn + wait — fully dead).
        let mut dead = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn true");
        let gone = dead.id() as i32;
        dead.wait().unwrap();
        let cfg = AttemptTracerConfig {
            log_path: attempt_log.clone(),
            suspect_pid_file: None,
            argv: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("kill -s URG {gone} 2>/dev/null"),
            ],
        };
        assert_eq!(run_attempt_tracer(&cfg), 0);
        let text = std::fs::read_to_string(&attempt_log).unwrap();
        let attempts: Vec<AttemptRecord> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(attempts.len(), 1, "attempt log:\n{text}");
        assert_eq!(attempts[0].syscall, "kill");
        assert_eq!(attempts[0].target_pid, Some(gone));
        assert_eq!(attempts[0].signo, libc::SIGURG);
        assert_eq!(attempts[0].result, Some(-(libc::ESRCH as i64)));
        assert_ne!(attempts[0].sender_pid, gone, "pid reuse collision");
        // Oracle: traced dead-target attempt, empty witness ⟹ FAIL.
        let workload: HashSet<i32> = [gone].into_iter().collect();
        let canary: HashSet<i32> = [21].into_iter().collect();
        let svc = service();
        let mut input = base_a(&[], &[], &workload, &canary, &svc, &attempts);
        input.observer_pid = attempts[0].sender_pid;
        let (verdict, _) = adjudicate(&input);
        assert!(matches!(verdict, SignalVerdict::Fail(_)), "{verdict:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Kernel-truth pin (guards the L5 design against a plausible
    /// wrong model): a DEFAULT-ignored signal DOES stop a seized
    /// tracee — the delivery observer logs it with the kernel
    /// sender. (Explicitly-ignored signals stop too — verified with
    /// a C probe during F8c, since the ptrace hook runs before the
    /// ignore check.) Only blocked-forever and dead-target sends
    /// are stop-free — those are the cases the attempt channel
    /// exists for.
    #[test]
    fn delivery_observer_sees_default_ignored_signal() {
        if !ptrace_available() {
            eprintln!("delivery pin: ptrace denied, skipping live leg");
            return;
        }
        let dir = std::env::temp_dir().join(format!("osslscope-l5e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let witness_log = dir.join("signal-witness.jsonl");
        let sleeper = spawn_sleeper();
        let wlog = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&witness_log)
            .unwrap();
        let mut obs = Observer {
            log: wlog,
            traced: HashSet::new(),
            pending_initial: HashSet::new(),
            pending_options: HashSet::new(),
            last_sender: HashMap::new(),
        };
        assert!(matches!(
            obs.seize_or_adopt(sleeper, true),
            SeizeOutcome::Seized
        ));
        // SAFETY: kill our own sleeper (SIGURG default-ignored).
        assert_eq!(unsafe { libc::kill(sleeper, libc::SIGURG) }, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut status = 0;
            // SAFETY: waitpid with a valid status pointer.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if got == sleeper {
                obs.handle_wait(got, status);
            } else if got <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        drop(obs);
        let text = std::fs::read_to_string(&witness_log).unwrap();
        let entries: Vec<WitnessEntry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(entries.len(), 1, "witness log:\n{text}");
        assert_eq!(entries[0].kind, WitnessKind::Delivery);
        assert_eq!(entries[0].target_pid, sleeper);
        assert_eq!(entries[0].signo, libc::SIGURG);
        // SAFETY: getpid for the expected si_pid.
        assert_eq!(entries[0].sender_pid, Some(unsafe { libc::getpid() }));
        // SAFETY: kill our own sleeper; reap everything.
        unsafe {
            libc::kill(sleeper, libc::SIGKILL);
        }
        drain_reap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// F8c launcher semantics: a clean suspect exits the tracer 0
    /// with an empty log, and the suspect-pid file names the
    /// (reaped) suspect pid honestly.
    #[test]
    fn attempt_tracer_clean_suspect_empty_log() {
        if !ptrace_available() {
            eprintln!("attempt-tracer: ptrace denied, skipping live leg");
            return;
        }
        let dir = std::env::temp_dir().join(format!("osslscope-l5b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("attempt.jsonl");
        let pidfile = dir.join("suspect.pid");
        let cfg = AttemptTracerConfig {
            log_path: log.clone(),
            suspect_pid_file: Some(pidfile.clone()),
            argv: vec!["true".to_string()],
        };
        assert_eq!(run_attempt_tracer(&cfg), 0);
        assert!(std::fs::read_to_string(&log).unwrap().is_empty());
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(pid > 0);
        // SAFETY: existence probe on the reaped suspect.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
