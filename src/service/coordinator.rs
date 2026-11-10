//! SPDX-License-Identifier: GPL-3.0-or-later
//! §2 coordinator: windows, boundaries, the run loop.
//!
//! Phases (frozen order): pre-start admission (exit 2, no side
//! effects) → lock → quota latch → recovery (§4.4) → engine open
//! (W4: ONE engine per run) → window tiling (§2) → close (§7) →
//! summary + the §7.3 fold. Every blocking op runs on a §7.2
//! control worker (startup under `--timeout`, close under
//! `--grace` sub-deadlines, in-run boundaries under `--timeout`
//! with the shared cancel flag — the D-record binds startup and
//! close explicitly; the in-run bound is T7.4's, reported).
//!
//! Stderr discipline: pre-start exit-2 usage errors print
//! synchronously (the run — and its diagnostics worker — never
//! started); every run-lifetime line goes through the §7.2
//! diagnostics worker.

use crate::crypto_watch::ServiceEngine;
use crate::service::cli::{Format, ServiceConfig};
use crate::service::envelope::{
    AccumExceeded, CloseOp, OpOutcome, RunSummary, Spilled, TapRecovered, TickSpan, WindowEnvelope,
    WindowSpan, split_envelope_at_array,
};
use crate::service::exit::{RunFold, RunToolFailure};
use crate::service::publish::{AttemptKey, PublishStep, StreamedPublish};
use crate::service::queue::{StreamQueue, stream_record_identity};
use crate::service::recovery::{Recovery, Refusal, recover};
use crate::service::retain::{
    enforce_retention, rotate_file, rotation_due, unlatched_defense_blocks, write_latch,
};
use crate::service::signals::{Signal, SignalFd};
use crate::service::snapshot::{Snapshot, WindowCtx, produce, sealed_map};
use crate::service::staging::{
    AssembledCounts, Carry, Staging, TickDecision, TickPiece, assemble_inner_into,
};
use crate::service::state::{
    AbandonReason, DirLock, PolicyIdentity, PolicyRejection, PolicyStatus, Reservation,
    ReservationState, RunId, SCHEMA_POLICY, SequenceState, clean_tmps, is_reserved_sink_name,
    monotonic_ns, rotated_name, scan_highest_seq, sync_dir, wall_ns, write_state,
};
use crate::service::stream::{Tap, TapOpenError, resolve_stream};
use crate::service::worker::{
    Control, DestClass, Destination, Diagnostics, Gate, WaitPoll, WorkerOut, outcome_of, peek_slot,
    push_accounting, run_under_control, view_slot,
};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// `osslscope service` entry: parse, admit, run, exit per §7.3.
pub fn run(args: &[String]) -> ExitCode {
    match crate::service::cli::parse(args) {
        Err(help) if help == "__help__" => {
            print!("{}", crate::service::cli::USAGE);
            ExitCode::SUCCESS
        }
        Err(reason) => {
            crate::report::err_line(&format!("osslscope service: {reason}"));
            ExitCode::from(2)
        }
        Ok(cfg) => run_service(cfg),
    }
}

/// Engine duration: the service runs until canceled — the engine's
/// own deadline only bounds its sample waits, so park it a decade
/// out (well inside `Instant` range; cancel always wins first).
const ENGINE_DURATION: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// The 6A engine-state cap (mirrors the private
/// `crypto_watch::GLOBAL_BYTES` 256 MiB — the service pool is the
/// same budget the 6A path uses).
const POOL_BYTES: usize = 256 << 20;

/// Pump cadence quanta (mirrors the 6A 25 ms loop sleep; here the
/// quantum is a signalfd wait so signals stay synchronous).
const PUMP_QUANTUM: Duration = Duration::from_millis(25);

/// Pre-start refusal (exit 2, decided before any window opens —
/// synchronous CLI usage error, pre-worker by construction).
fn refuse2(msg: &str) -> ExitCode {
    crate::report::err_line(&format!("osslscope service: {msg}"));
    ExitCode::from(2)
}

/// One diagnostic event through the §7.2 diagnostics worker
/// (§1.5 shape per `--format`).
fn diag_line(diag: &Diagnostics, format: &Format, level: &str, msg: &str) {
    let bounded = crate::report::bound_line(msg);
    let line = match format {
        Format::Json => {
            let at = wall_ns().unwrap_or(0);
            format!(
                "{{\"at_wall_ns\":{at},\"level\":\"{level}\",\"msg\":{}}}",
                serde_json::to_string(&bounded).unwrap_or_default()
            )
        }
        Format::Human => format!("osslscope: {bounded}"),
    };
    diag.emit(line.as_bytes());
}

/// (device, inode) identity of a path (follows the §4.1 alias rule
/// — hard links share identity).
fn dev_ino_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Pre-start sink admission (§4.1) on the RESOLVED active file.
/// Returns the resolved tap path. Refusals are exit 2.
fn admit_sink(out: &Path, stream: Option<&Path>) -> Result<Option<PathBuf>, String> {
    let Some(given) = stream else {
        return Ok(None);
    };
    let resolved = resolve_stream(given).map_err(|e| format!("--stream: {e}"))?;
    // The resolved file itself must not be a directory/socket/device
    // (only a regular file or FIFO opens; a missing path is created
    // at open — its parent must exist).
    if let Ok(meta) = std::fs::symlink_metadata(&resolved) {
        use std::os::unix::fs::FileTypeExt;
        let ft = meta.file_type();
        if ft.is_dir() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            return Err("--stream must resolve to a regular file or FIFO".to_string());
        }
        if ft.is_symlink() {
            return Err("--stream must not be a symlink".to_string());
        }
        // Alias check (§4.1): the resolved existing file must not
        // share identity with a RESERVED out-DIR entry
        // (window/state/latch/lock — hard links included). A
        // resident non-reserved tap (the canonical
        // `out-DIR/stream.jsonl`) is the tap's own file and admits.
        if let Some(id) = dev_ino_of(&resolved) {
            let entries = std::fs::read_dir(out).map_err(|e| format!("--out unreadable: {e}"))?;
            for entry in entries.flatten() {
                let reserved = entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_reserved_sink_name);
                if reserved && dev_ino_of(&entry.path()) == Some(id) {
                    return Err("--stream aliases out-DIR evidence or state".to_string());
                }
            }
        }
    } else if let Some(parent) = resolved.parent() {
        if !parent.is_dir() {
            return Err("--stream parent directory does not exist".to_string());
        }
    }
    if let Some(name) = resolved.file_name().and_then(|n| n.to_str()) {
        if is_reserved_sink_name(name) {
            return Err("--stream filename is reserved".to_string());
        }
    }
    Ok(Some(resolved))
}

/// Test-only scripted engine (S4 close-staging regressions):
/// canned close-drain bytes + a canned snapshot, served through
/// the same four methods the coordinator calls on
/// `ServiceEngine`. The close path under test (staging, spill
/// sink, seal reads, assemble, publish, judge, sinks, seal,
/// summary, the §7.3 fold) is 100% production; only the engine
/// I/O is scripted (an unprivileged test process cannot observe
/// real members). Zero production impact (`cfg(test)` only; the
/// startup path never runs under `cfg(test)` — no lib unit test
/// calls it — so its substitution below is compile-only
/// scaffolding).
#[cfg(test)]
struct FakeCloseEngine {
    drain_bytes: Vec<u8>,
    snap: Snapshot,
}

#[cfg(test)]
impl FakeCloseEngine {
    fn for_test() -> Self {
        Self {
            drain_bytes: Vec::new(),
            snap: Snapshot {
                at_ns: 0,
                stable: true,
                members: Vec::new(),
                run: crate::service::snapshot::RunTallies::default(),
                polling: false,
            },
        }
    }

    fn pump_iteration(
        &mut self,
        _cancel: &AtomicBool,
    ) -> std::io::Result<crate::crypto_watch::IterationOut> {
        unreachable!("test engine never pumps (close-path tests only)");
    }

    fn snapshot(&self, _flip_to: Option<u64>) -> Snapshot {
        self.snap.clone()
    }

    fn snapshot_sealed(&self, _sealed_gen: u64) -> Snapshot {
        self.snap.clone()
    }

    fn close_drain_capped(
        &mut self,
        _cancel: &AtomicBool,
        _deadline: Option<Instant>,
    ) -> std::io::Result<crate::crypto_watch::CloseOut> {
        Ok(crate::crypto_watch::CloseOut {
            bytes: self.drain_bytes.clone(),
            code: 3,
        })
    }
}

/// Live run state (owned by the coordinator; destructured at exit
/// into the summary + the §7.3 fold).
struct Run {
    cfg: ServiceConfig,
    run_id: RunId,
    tag: String,
    generation: u64,
    out: PathBuf,
    diag: Diagnostics,
    _lock: DirLock,
    signals: SignalFd,
    cancel: AtomicBool,
    #[cfg(test)]
    engine: FakeCloseEngine,
    #[cfg(not(test))]
    engine: ServiceEngine,
    /// Pool-budget guards (companion bytes; sessions lease from the
    /// engine's clone of the same pool).
    _leases: Vec<crate::observation_memory::MemoryLease>,
    /// Signal state: first cancel latched, double-signal latched.
    /// Atomic: worker-wait polls consume signalfd concurrently with
    /// the coordinator path (R1 finding 3 — shared refs only).
    cancel_latched: AtomicBool,
    double_signal: AtomicBool,
    /// SIGHUP reload pending (consumed at the next boundary, §3).
    /// Atomic: set by wait polls (R1 finding 3).
    reload_pending: AtomicBool,
    /// The ONE shutdown deadline (R1 finding 3): minted at
    /// run-final close entry (before the drain), or when a mid-run
    /// close diverts to a run-ending tail — every later close stage
    /// draws its budget from the REMAINDER, so `--grace` bounds the
    /// complete close. `None` in-run and mid-close (per-stage
    /// boundary budgets there, as before).
    close_deadline: Option<Instant>,
    /// Policy state (§3).
    policy: PolicyState,
    /// Stream state (§5.2/§5.3/§6.1 — `None` without `--stream`).
    stream: Option<StreamState>,
    /// Window-cycle state (§2/§4.3/§5.1) — `None` before the first
    /// open and after the final seal (no such instant mid-run).
    cycle: Option<Cycle>,
    /// Summary accumulators (§7.3).
    summary: SummaryAccum,
    /// Finalized windows' fold inputs (§7.3).
    /// §7.3 exit inputs (O(1) accumulator — per-window bits, never
    /// documents; R1 finding 2a).
    fold: RunFold,
    /// First finalized seq (summary `first_seq`).
    first_seq: Option<u64>,
    /// Run-level tool failure (the §7.3 priority-4 1-group).
    tool_failure: Option<RunToolFailure>,
    /// Window origin: the 6A `Start.run_origin_ns` tick anchor +
    /// requested-start[run-first] (T00 rule, §2).
    origin_ns: u64,
    /// Engine tick length (ns).
    tick_ns: u64,
    /// Coordinator admission-tick index (u64 per run, §5.1).
    tick_id: u64,
    /// Least (pid, starttime) over the RUN's observed members (the
    /// empty-window target fallback, §11.1).
    run_member_floor: Option<(u32, u64)>,
    /// Leaked spill tmps awaiting absorb-retry (consumed at the
    /// next boundary — consumed identities only, deduplicated,
    /// capped at [`MAX_PENDING_SPILL_UNLINKS`]).
    pending_spill_unlinks: Vec<PathBuf>,
    /// Output-format alias (diagnostics shape).
    format: Format,
}

/// Active/pending policy (§3: at most one pending candidate).
struct PolicyState {
    active: Option<PolicyIdentity>,
    active_rules: Option<crate::policy_config::RuleSet>,
    pending: Option<PendingPolicy>,
    displaced: u64,
    adopted: u64,
    rejected: u64,
    last_rejection: Option<PolicyRejection>,
}

/// One pending candidate (snapshot bytes already admitted —
/// adoption at the next window open needs no re-read).
struct PendingPolicy {
    ident: PolicyIdentity,
    rules: crate::policy_config::RuleSet,
}

/// Stream tap + queue + ledger (§§5.2–5.3, 6.1, 7.2).
struct StreamState {
    tap_path: PathBuf,
    tap: Tap,
    queue: StreamQueue,
    /// Rotation clock: the file's first ASSIGNED record instant.
    first_record_wall: Option<std::time::Instant>,
    /// Assigned seq span of the ACTIVE file (window-ref seqs +
    /// drop-marker at_seqs; extended by reconciled tails, §6.1).
    active_first: Option<u64>,
    active_last: Option<u64>,
    /// Records assigned (for the span extension audit).
    active_records: u64,
    /// In-flight tap ops (cutoff-frozen dispatch records, §7.2).
    inflight: Vec<crate::service::stream::InflightRecord>,
    next_op_id: u64,
    /// Awaiting rotation-tail reconcile (last boundary's rename).
    pending_reconcile: Option<PendingRotation>,
}

/// Per-window cycle state (§§2, 4.3, 5.1).
struct Cycle {
    /// The window currently open.
    seq: u64,
    requested_start_ns: u64,
    requested_end_ns: u64,
    effective_start_ns: u64,
    /// Open baseline (the chained close snapshot, §5.1).
    open: Snapshot,
    /// Staging account (carried tick preloaded at open).
    staging: Staging,
    /// Current tick piece (admission in progress).
    piece: TickPiece,
    /// Carry into the NEXT window (set by the budget decision).
    carry_out: Option<Carry>,
    /// Carried INTO this window: `(from_seq, tick_id)` — the valid
    /// carried records count at assemble time (never predicted).
    carried_in: Option<(u64, u64)>,
    /// Admission-tick id at window open (the empty-window
    /// `tick_span` fallback — the ticks that elapsed, honestly).
    open_tick_id: u64,
    /// Coordinator-recorded FIRST fatal this window (event order).
    fatal: Option<crate::evidence::FatalKind>,
    /// Single-tick exceed note (§5.1).
    accum_exceeded: Option<AccumExceeded>,
    /// Whether this window cut on accumulation (carries into the
    /// close decision + the `windows_cut_accum` count).
    accum_cut: bool,
}

/// Run-summary accumulators (§7.3 — everything the fold + the
/// summary file need).
struct SummaryAccum {
    abandoned: Vec<crate::service::envelope::AbandonedNote>,
    abandoned_overflow: u64,
    commit_recovered: Option<crate::service::envelope::CommitRecovered>,
    orphan_cut_tail: Option<crate::service::envelope::OrphanCutTail>,
    durability_uncertain: Option<crate::service::envelope::DurabilityUncertain>,
    final_close_completed_ns: Option<u64>,
    close_unmeasured: Vec<u64>,
    windows_cut_accum: u64,
    quota_exceeded: Option<crate::service::envelope::QuotaExceeded>,
    tap_recovered: TapRecovered,
    tap_uncertain: Vec<crate::service::envelope::TapUncertain>,
    tap_uncertain_overflow: crate::service::envelope::UncertainOverflow,
    rotation_tail: Vec<crate::service::envelope::RotationTail>,
    rotation_tail_overflow: u64,
    close_accounting: Vec<CloseOp>,
    close_accounting_overflow: u64,
    /// Pending sealed close instant (the §4.3 1b seal value —
    /// the first monotonic read after the last commit fsync).
    pending_close_completed: Option<u64>,
    /// Last step-5 commit instant this run (never consumed — the
    /// summary's `final_close_completed_ns` fallback for ends
    /// without a seal: "the first read after the last commit
    /// fsync", §4.3).
    last_commit_ts: Option<u64>,
    /// Retained reservation/evidence for the exit path.
    last_seq: Option<u64>,
}

impl SummaryAccum {
    fn new() -> Self {
        Self {
            abandoned: Vec::new(),
            abandoned_overflow: 0,
            commit_recovered: None,
            orphan_cut_tail: None,
            durability_uncertain: None,
            final_close_completed_ns: None,
            close_unmeasured: Vec::new(),
            windows_cut_accum: 0,
            quota_exceeded: None,
            tap_recovered: TapRecovered::default(),
            tap_uncertain: Vec::new(),
            tap_uncertain_overflow: crate::service::envelope::UncertainOverflow::default(),
            rotation_tail: Vec::new(),
            rotation_tail_overflow: 0,
            close_accounting: Vec::new(),
            close_accounting_overflow: 0,
            pending_close_completed: None,
            last_commit_ts: None,
            last_seq: None,
        }
    }

    /// Cap `abandoned[]` at the most recent 4096 + overflow (§6.2).
    fn push_abandoned(&mut self, note: crate::service::envelope::AbandonedNote) {
        self.abandoned.push(note);
        while self.abandoned.len() > 4096 {
            self.abandoned.remove(0);
            self.abandoned_overflow += 1;
        }
    }
}

/// Hoist one wait poll for a `&mut Run` scope: the standard
/// run-cancel form (`wait_poll_for` with the run's own refs).
/// Kept as a macro: a `fn` taking `&Run` would borrow the whole
/// run and conflict with the caller's `&mut` field borrows.
macro_rules! run_wait_poll {
    ($run:expr) => {
        wait_poll_for(
            &$run.signals,
            &$run.cancel,
            &$run.cancel_latched,
            &$run.double_signal,
            &$run.reload_pending,
        )
    };
}

/// One §7.2 worker op: run under `budget` + `cancel`, record the
/// coordinator-observed outcome in `close_accounting`, and emit
/// one bounded diagnostic on anything but `Done`. `wait_poll`
/// (when present) consumes signalfd during the wait (R1 finding
/// 3); pre-`Run` startup ops pass `None` (signals pend for the
/// loop-top drain, as before).
#[allow(clippy::too_many_arguments)]
fn run_op<T, F>(
    diag: &Diagnostics,
    format: &Format,
    accum: &mut SummaryAccum,
    cancel: &AtomicBool,
    op_name: &str,
    dest: Destination,
    budget: Duration,
    wait_poll: Option<&WaitPoll>,
    op: F,
) -> Control<T>
where
    T: Send + 'static,
    F: FnOnce(Gate) -> WorkerOut<T> + Send + 'static,
{
    let control = run_under_control(dest, budget, cancel, op, wait_poll);
    let outcome = outcome_of(&control);
    if outcome != OpOutcome::Done {
        diag_line(
            diag,
            format,
            "warn",
            &format!("op {op_name} ended {outcome:?}"),
        );
    }
    push_accounting(
        &mut accum.close_accounting,
        &mut accum.close_accounting_overflow,
        op_name.to_string(),
        outcome,
    );
    control
}

/// Spill-sink control failure (R3 adjudication d): the spill op
/// never ran to judgment (expiry/cancel/worker-unavailable) —
/// distinct from errno failures (ENOSPC/EIO) so callers
/// disambiguate expiry from disk-full by TYPE (downcast), never
/// by message string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpillControlFail {
    Cancelled,
    Expired,
    SpawnFailed,
}

impl std::fmt::Display for SpillControlFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpillControlFail::Cancelled => write!(f, "spill cancelled"),
            SpillControlFail::Expired => write!(f, "spill expired"),
            SpillControlFail::SpawnFailed => write!(f, "spill worker unavailable"),
        }
    }
}

impl std::error::Error for SpillControlFail {}

/// Map a spill-sink failure to its abandonment reason (R3
/// adjudication d): control failures are NOT disk-full (spawn
/// failure → `worker_unavailable`, other control failures →
/// `io_error` — mirroring the assemble map); errno failures map
/// ENOSPC → `disk_full`, anything else → `io_error` (mirroring
/// the publish stage map). Exit-neutral (§7.3 folds from windows,
/// never from the reason).
fn spill_abandon_reason(e: &std::io::Error) -> AbandonReason {
    if let Some(fail) = e
        .get_ref()
        .and_then(|r| r.downcast_ref::<SpillControlFail>())
    {
        return match fail {
            SpillControlFail::SpawnFailed => AbandonReason::WorkerUnavailable,
            SpillControlFail::Cancelled | SpillControlFail::Expired => AbandonReason::IoError,
        };
    }
    match e.raw_os_error() {
        Some(errno) if errno == libc::ENOSPC => AbandonReason::DiskFull,
        _ => AbandonReason::IoError,
    }
}

/// Abandon after a spill-sink failure (R3 adjudication d):
/// control failures need no extra stderr (the op outcome in
/// `close_accounting` + `run_op`'s line already say which);
/// errno failures print (the op returned `Done(Err)` — silent
/// otherwise).
fn abandon_on_spill_failure(run: Run, e: std::io::Error) -> ExitCode {
    if e.get_ref()
        .and_then(|r| r.downcast_ref::<SpillControlFail>())
        .is_none()
    {
        diag_line(
            &run.diag,
            &run.format,
            "error",
            &format!("spill failed: {e}"),
        );
    }
    abandon_window(run, spill_abandon_reason(&e), None)
}

/// Worker-backed spill sink for staging (R1 finding 3): each spill
/// file write + fsync runs on an OwnTmp control worker under
/// `budget` + `cancel` — never coordinator-direct. Registry keys
/// derive from the spill tmp name (run tag + tick + index — unique
/// per record, so a lingering detached slot never collides).
/// `poll` consumes signalfd during the wait.
fn spill_sink_for<'a>(
    diag: &'a Diagnostics,
    format: &'a Format,
    accum: &'a mut SummaryAccum,
    cancel: &'a AtomicBool,
    poll: Option<&'a WaitPoll<'a>>,
    budget: Duration,
) -> impl FnMut(&Path, &[u8]) -> std::io::Result<()> + 'a {
    // R2 Gate 2 (F3): the sink mints ONE absolute deadline at
    // creation (`now + budget` — the close/startup remainder then,
    // so exactly the shared deadline) and every operation draws
    // the REMAINDER, never a fresh full budget.
    let deadline = Instant::now() + budget;
    move |tmp: &Path, line: &[u8]| {
        let key = tmp
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("spill")
            .to_string();
        let op_budget = deadline.saturating_duration_since(Instant::now());
        let wrote: Control<std::io::Result<()>> = run_op(
            diag,
            format,
            accum,
            cancel,
            "spill_write",
            Destination {
                class: DestClass::OwnTmp,
                key: format!("spill-{key}"),
            },
            op_budget,
            poll,
            {
                let (tmp, line) = (tmp.to_path_buf(), line.to_vec());
                move |_gate| {
                    WorkerOut::value(crate::service::staging::spill_write_direct(&tmp, &line))
                }
            },
        );
        match wrote {
            Control::Done(result) => {
                // R4 finding 3: the spill op executed and returned
                // an errno ⟹ `Failed`, never `Done` (frozen failure
                // accounting: `failed` = executed + errored). The
                // sink owns no fenced refusal, so `Done(Err)` is
                // unambiguously an executed error (ENOSPC/EIO/…).
                // `run_op` recorded `Done` (it cannot see inside the
                // value); reclassify the entry it just pushed (same
                // thread, synchronous — exactly one entry). The errno
                // diagnostic + the R3 adj-d abandonment reason ride
                // the existing `abandon_on_spill_failure` path,
                // untouched.
                if result.is_err() {
                    if let Some(last) = accum.close_accounting.last_mut() {
                        debug_assert!(last.op == "spill_write");
                        debug_assert!(last.outcome == OpOutcome::Done);
                        last.outcome = OpOutcome::Failed;
                    }
                }
                result
            }
            Control::Cancelled => Err(std::io::Error::other(SpillControlFail::Cancelled)),
            Control::Expired => Err(std::io::Error::other(SpillControlFail::Expired)),
            Control::SpawnFailed => Err(std::io::Error::other(SpillControlFail::SpawnFailed)),
        }
    }
}

/// State-file destination key (per-destination registry, §7.2).
fn state_dest(name: &str) -> Destination {
    Destination {
        class: DestClass::StateMut,
        key: format!("state:{name}"),
    }
}

/// Mutable-state write (§4.2 discipline: tmp+rename+fsync+dirsync)
/// as a worker-op closure body. Returns the IO result for the
/// coordinator to judge (a `Failed` op outcome is recorded by the
/// caller from the returned `Err`).
fn write_state_body(
    dir: PathBuf,
    name: String,
    tag: String,
    bytes: Vec<u8>,
) -> std::io::Result<()> {
    write_state(&dir, &name, &tag, &bytes)
}

/// Timestamped state write: the worker takes the FIRST monotonic
/// read immediately after its commit fsync returns (the §4.3
/// close-completion numerator — coordinator-side reads would add
/// join-poll latency; the oracle measures sub-second closes).
fn write_state_ts(
    dir: &Path,
    name: &str,
    tag: &str,
    bytes: &[u8],
) -> (std::io::Result<()>, Option<u64>) {
    match write_state(dir, name, tag, bytes) {
        Ok(()) => (Ok(()), Some(monotonic_ns())),
        Err(e) => (Err(e), None),
    }
}

/// Reconciled state write (§7.2 STATE rule): attempt on a fenced
/// worker; on abandonment, poll for unregister, re-read the file,
/// and re-apply once when the transition is not reflected.
/// Returns `(Ok(true), ts)` when the file reflects the transition
/// (written or converged), `(Ok(false), _)` when it verifiably
/// does not (caller judges the tool failure), `Err` for IO errors
/// on the deciding attempt.
fn state_write_reconciled(
    run: &mut Run,
    op_name: &str,
    file: &str,
    bytes: Vec<u8>,
    budget: Duration,
) -> (Result<bool, std::io::Error>, Option<u64>) {
    let dest = state_dest(file);
    // Attempt 1 (fenced worker with the pre-mutation re-check).
    // Every wait re-caps by the shutdown remainder (R1 finding 3 —
    // attempt 1 may consume the whole budget, leaving the
    // reconcile waits to fail fast instead of stacking more).
    let first = {
        let (out, tag) = (run.out.clone(), run.tag.clone());
        let file = file.to_string();
        let bytes = bytes.clone();
        let attempt_budget = cap_by_deadline(run, budget);
        let poll = run_wait_poll!(run);
        run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            op_name,
            dest.clone(),
            attempt_budget,
            Some(&poll),
            move |gate| {
                if gate.abandoned() {
                    return WorkerOut::value((Err(std::io::Error::other("abandoned")), None));
                }
                WorkerOut::value(write_state_ts(&out, &file, &tag, &bytes))
            },
        )
    };
    match first {
        Control::Done((Ok(()), ts)) => return (Ok(true), ts),
        Control::Done((Err(e), _)) => {
            // Verifiable non-reflection can only be claimed after a
            // re-read (a post-check completion may still land) —
            // fall through to reconcile like an abandonment, but
            // remember the IO error for the final judgment.
            let _ = e;
        }
        _ => {}
    }
    // Abandonment/error: poll for unregister, then re-read (the
    // re-read is itself a worker op — §7.2 lists reads; a distinct
    // slot so a still-registered writer never refuses it). A
    // reflected transition converges (the detached worker's
    // post-check completion won the race, §7.2). The poll is capped
    // by the shutdown remainder and breaks on the double (R1
    // finding 3 — reconciliation adds no fresh wait past grace).
    let poll_cap = cap_by_deadline(run, Duration::from_secs(1));
    let unreg_poll = run_wait_poll!(run);
    if !poll_unregister(&dest, poll_cap, Some(&unreg_poll)) {
        diag_line(
            &run.diag,
            &run.format,
            "warn",
            &format!("{op_name}: worker still registered"),
        );
    }
    let reread = {
        let (out, file) = (run.out.clone(), file.to_string());
        let reread_budget = cap_by_deadline(run, budget);
        let poll = run_wait_poll!(run);
        run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            op_name,
            Destination {
                class: DestClass::StateMut,
                key: format!("reread-{file}"),
            },
            reread_budget,
            Some(&poll),
            move |_gate| WorkerOut::value(std::fs::read(out.join(&file)).ok()),
        )
    };
    // A failed re-read re-applies blind: the transition is an
    // idempotent set-operation (identical bytes ⟹ identical result),
    // so a redundant re-application converges harmlessly.
    if matches!(reread, Control::Done(Some(ref b)) if *b == bytes) {
        return (Ok(true), None);
    }
    // Re-apply once via a fresh worker (the slot is consumed, so a
    // successor registers — reconcile-before-next-use, §7.2).
    let second = {
        let (out, tag) = (run.out.clone(), run.tag.clone());
        let file = file.to_string();
        let retry_budget = cap_by_deadline(run, budget);
        let poll = run_wait_poll!(run);
        run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            op_name,
            dest.clone(),
            retry_budget,
            Some(&poll),
            move |gate| {
                if gate.abandoned() {
                    return WorkerOut::value((Err(std::io::Error::other("abandoned")), None));
                }
                WorkerOut::value(write_state_ts(&out, &file, &tag, &bytes))
            },
        )
    };
    match second {
        Control::Done((Ok(()), ts)) => (Ok(true), ts),
        Control::Done((Err(e), _)) => (Err(e), None),
        _ => (Ok(false), None),
    }
}

/// Run the service (parsed config → pre-start → run → exit).
fn run_service(cfg: ServiceConfig) -> ExitCode {
    // Signals first: block TERM/INT/HUP process-wide so every later
    // thread (workers, engine) inherits the mask; all handling is
    // synchronous through the signalfd (§§3, 7.1).
    let signals = match SignalFd::install() {
        Ok(s) => s,
        Err(e) => return refuse2(&format!("signals unavailable: {e}")),
    };
    // Startup deadline (RANK-1/WS-A): minted BEFORE any admission
    // I/O (lockfile reads included) so every later startup worker
    // draws from a deadline that already exists; signals arriving
    // mid-startup queue in the mask (none lost) and are consumed
    // at the first run-loop poll. The lock take itself is
    // non-blocking admission (type gate + capped prior read), so
    // no lock path can stall startup past signal response.
    let startup_deadline = Instant::now() + cfg.timeout;
    let startup_budget = || startup_deadline.saturating_duration_since(Instant::now());
    // The out-DIR is the unit of durability (§4) — create it when
    // missing (T7.4's: a service that cannot create its workspace
    // cannot run; refusal here would strand fresh deploys).
    if let Err(e) = std::fs::create_dir_all(&cfg.out) {
        return refuse2(&format!("--out not creatable: {e}"));
    }
    // Sink admission (§4.1) — usage check before the lock.
    let stream_path = match admit_sink(&cfg.out, cfg.stream.as_deref()) {
        Ok(p) => p,
        Err(reason) => return refuse2(&reason),
    };
    // `--reset-sequence` refuses when windows exist (exit 2); the
    // state rewrite itself runs under the lock below.
    if cfg.reset_sequence {
        match scan_highest_seq(&cfg.out) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return refuse2("--reset-sequence refuses: out-DIR holds windows");
            }
            Err(e) => return refuse2(&format!("out-DIR unreadable: {e}")),
        }
    }
    let run_id = match RunId::current() {
        Ok(id) => id,
        Err(e) => return refuse2(&format!("run identity unreadable: {e}")),
    };
    let tag = run_id.tag();
    let started_wall_ns = wall_ns().unwrap_or(0);
    let lock = match DirLock::take(&cfg.out, &run_id, started_wall_ns) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return refuse2("out-DIR locked");
        }
        Err(e) => return refuse2(&format!("lock failed: {e}")),
    };
    let diag = Diagnostics::spawn();
    let format = cfg.format;
    let mut accum = SummaryAccum::new();
    let cancel = AtomicBool::new(false);
    // `--reset-sequence`: fresh state, generation+1, reserved null,
    // policy-status untouched (§4.3).
    if cfg.reset_sequence {
        let dir = cfg.out.clone();
        let control: Control<std::io::Result<()>> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "reset_sequence_write",
            state_dest("sequence.json"),
            startup_budget(),
            None,
            move |gate| {
                let old_gen = std::fs::read(dir.join("sequence.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<SequenceState>(&b).ok())
                    .map(|s| s.generation)
                    .unwrap_or(0);
                // Fenced re-check before the ONE state mutation.
                if gate.abandoned() {
                    return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                }
                let mut fresh = SequenceState::fresh(
                    RunId {
                        pid: 0,
                        starttime: 0,
                        boot_id: String::new(),
                    },
                    wall_ns().unwrap_or(0),
                );
                fresh.generation = old_gen.saturating_add(1);
                fresh.next_seq = 0;
                fresh.reserved = None;
                let bytes = serde_json::to_vec(&fresh).map_err(std::io::Error::other);
                let out = match bytes {
                    Ok(b) => {
                        let _ = crate::service::state::check_state_cap(&b);
                        write_state_body(dir, "sequence.json".to_string(), "reset".to_string(), b)
                    }
                    Err(e) => Err(e),
                };
                WorkerOut::value(out)
            },
        );
        match control {
            Control::Done(Ok(())) => {}
            Control::Done(Err(e)) => {
                let _ = diag.abandon(Duration::from_millis(200));
                crate::report::err_line(&format!("osslscope service: reset failed: {e}"));
                return ExitCode::from(4);
            }
            _ => {
                let _ = diag.abandon(Duration::from_millis(200));
                crate::report::err_line("osslscope service: reset timed out");
                return ExitCode::from(4);
            }
        }
    }
    startup_recovery(
        cfg,
        stream_path,
        run_id,
        tag,
        lock,
        diag,
        accum,
        cancel,
        signals,
        startup_deadline,
    )
}

/// Pre-run exit-4 (synchronous stderr — the run never opened, so no
/// worker could drain; the diagnostics worker is abandoned).
fn prestart_exit4(diag: Diagnostics, lock: DirLock, msg: &str) -> ExitCode {
    lock.restore();
    let _ = diag.abandon(Duration::from_millis(200));
    crate::report::err_line(&format!("osslscope service: {msg}"));
    ExitCode::from(4)
}

/// Startup recovery (§4.4 frozen order): quota latch → clean tmps →
/// read state → scan → read summary → unlatched defense → recover.
/// Refusals exit here; clean recovery proceeds to engine open.
#[allow(clippy::too_many_arguments)]
fn startup_recovery(
    cfg: ServiceConfig,
    stream_path: Option<PathBuf>,
    run_id: RunId,
    tag: String,
    lock: DirLock,
    diag: Diagnostics,
    mut accum: SummaryAccum,
    cancel: AtomicBool,
    signals: SignalFd,
    startup_deadline: Instant,
) -> ExitCode {
    let format = cfg.format;
    let out = cfg.out.clone();
    let startup_budget = || startup_deadline.saturating_duration_since(Instant::now());
    // Quota-stop latch (§6.2): present → re-evaluate from live disk
    // truth (NON-deleting — a latch-hold exits 4 byte-identical).
    let latch: Control<Option<Vec<u8>>> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "startup_latch_probe",
        state_dest("quota-stop.json"),
        startup_budget(),
        None,
        {
            let out = out.clone();
            move |_gate| WorkerOut::value(std::fs::read(out.join("quota-stop.json")).ok())
        },
    );
    let Control::Done(latch_bytes) = latch else {
        return prestart_exit4(diag, lock, "startup timed out");
    };
    if latch_bytes.is_some() {
        let probe: Control<(bool, bool)> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "startup_quota_probe",
            state_dest("quota-probe"),
            startup_budget(),
            None,
            {
                let out = out.clone();
                let (rw, rb) = (cfg.retain_windows, cfg.retain_bytes);
                move |_gate| WorkerOut::value(crate::service::retain::quota_state(&out, rw, rb))
            },
        );
        let Control::Done((over, deletable)) = probe else {
            return prestart_exit4(diag, lock, "startup timed out");
        };
        if over && !deletable {
            return prestart_exit4(diag, lock, "quota stop latched");
        }
        // Quota clears (or deletion can proceed at the first
        // boundary — the latch's un-deletable premise is moot):
        // unlink the latch (+dirsync) and start normally.
        let clear: Control<std::io::Result<()>> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "startup_latch_clear",
            state_dest("quota-stop.json"),
            startup_budget(),
            None,
            {
                let out = out.clone();
                move |gate| {
                    if gate.abandoned() {
                        return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                    }
                    let r = crate::service::retain::clear_latch(&out).and_then(|_| sync_dir(&out));
                    WorkerOut::value(r)
                }
            },
        );
        match clear {
            Control::Done(Ok(())) => {}
            Control::Done(Err(e)) => {
                diag_line(&diag, &format, "warn", &format!("latch clear failed: {e}"));
            }
            _ => return prestart_exit4(diag, lock, "startup timed out"),
        }
    }
    // Stale tmp cleanup (§4.2 — under the §4.1 lock, no live run
    // races this).
    let cleaned: Control<std::io::Result<u64>> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "startup_clean_tmps",
        Destination {
            class: DestClass::Delete,
            key: "startup-tmps".to_string(),
        },
        startup_budget(),
        None,
        {
            let out = out.clone();
            move |_gate| WorkerOut::value(clean_tmps(&out))
        },
    );
    let Control::Done(Ok(_)) = cleaned else {
        return prestart_exit4(diag, lock, "startup timed out");
    };
    // State reads (one worker op, three reads; parsing is
    // in-memory and non-blocking).
    type StartupReads = (Option<Vec<u8>>, Option<u64>, Option<Vec<u8>>);
    let reads: Control<StartupReads> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "startup_state_reads",
        state_dest("startup-reads"),
        startup_budget(),
        None,
        {
            let out = out.clone();
            move |_gate| {
                let seq = std::fs::read(out.join("sequence.json")).ok();
                let highest = scan_highest_seq(&out).unwrap_or(None);
                let summary = std::fs::read(out.join("run-summary.json")).ok();
                WorkerOut::value((seq, highest, summary))
            }
        },
    );
    let Control::Done((seq_bytes, highest, summary_bytes)) = reads else {
        return prestart_exit4(diag, lock, "startup timed out");
    };
    let (state, state_missing) = match seq_bytes {
        Some(b) => match serde_json::from_slice::<SequenceState>(&b) {
            Ok(s) => (Some(s), false),
            Err(_) => return prestart_exit4(diag, lock, "sequence state missing"),
        },
        None => (None, highest.is_some()),
    };
    let prev_summary: Option<RunSummary> =
        summary_bytes.and_then(|b| serde_json::from_slice::<RunSummary>(&b).ok());
    // Unlatched-stop defense (§6.2 — after state+summary are read,
    // before any reserve, before any window; zero bytes on refusal).
    if latch_bytes.is_none() {
        let probe: Control<(bool, bool)> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "startup_quota_probe",
            state_dest("quota-probe"),
            startup_budget(),
            None,
            {
                let out = out.clone();
                let (rw, rb) = (cfg.retain_windows, cfg.retain_bytes);
                move |_gate| WorkerOut::value(crate::service::retain::quota_state(&out, rw, rb))
            },
        );
        let Control::Done((over, deletable)) = probe else {
            return prestart_exit4(diag, lock, "startup timed out");
        };
        if over && !deletable {
            let expected_gen = state.as_ref().map(|s| s.generation).unwrap_or(0);
            // The recovered state's run_id names the dead run (the
            // identity binding needs the state; without state the
            // summary cannot verify — clause (b)).
            let blocks = match state.as_ref() {
                Some(s) => {
                    unlatched_defense_blocks(prev_summary.as_ref(), &s.run_id, expected_gen, true)
                }
                None => true,
            };
            if blocks {
                return prestart_exit4(diag, lock, "quota stop defense (unlatched)");
            }
        }
    }
    // Recovery proper (§4.4 — pure over the reads above).
    let recovery = recover(
        &out,
        state.as_ref(),
        state_missing,
        highest,
        prev_summary.as_ref(),
    );
    match recovery.refuse {
        Some(Refusal::SequenceStateMissing) => {
            return prestart_exit4(diag, lock, "sequence state missing");
        }
        Some(Refusal::Integrity(reason)) => {
            let _ = diag.abandon(Duration::from_millis(200));
            crate::report::err_line(&format!("osslscope service: integrity refusal: {reason}"));
            return ExitCode::from(1);
        }
        Some(Refusal::Exhausted) => {
            // TERMINAL row: the abandoned note is history-preserved
            // in THIS run's summary, then refuse (exit 1).
            return terminal_refusal(cfg, run_id, tag, diag, accum, recovery);
        }
        None => {}
    }
    // Adopt the recovery notes into this run's summary accumulators.
    if let Some(note) = recovery.abandoned {
        accum.push_abandoned(note);
    }
    accum.commit_recovered = recovery.commit_recovered;
    accum.orphan_cut_tail = recovery.orphan_cut_tail;
    accum.close_unmeasured.extend(recovery.close_unmeasured);
    let generation = state.as_ref().map(|s| s.generation).unwrap_or(0);
    let carried_close_completed = state.as_ref().and_then(|s| s.close_completed_ns);
    open_engine(
        cfg,
        stream_path,
        run_id,
        tag,
        lock,
        diag,
        accum,
        cancel,
        signals,
        startup_deadline,
        generation,
        recovery.next_seq,
        carried_close_completed,
    )
}

/// TERMINAL refusal (§4.4 row): the `abandoned` note is
/// history-preserved in this run's summary, then exit 1 with the
/// "sequence exhausted" diagnostic + summary note.
fn terminal_refusal(
    cfg: ServiceConfig,
    run_id: RunId,
    tag: String,
    diag: Diagnostics,
    mut accum: SummaryAccum,
    recovery: Recovery,
) -> ExitCode {
    let format = cfg.format;
    let out = cfg.out.clone();
    let generation = recovery
        .abandoned
        .as_ref()
        .map(|n| n.generation)
        .or_else(|| recovery.reconciled.as_ref().map(|r| r.generation))
        .unwrap_or(0);
    if let Some(note) = recovery.abandoned {
        accum.push_abandoned(note);
    }
    accum.orphan_cut_tail.clone_from(&recovery.orphan_cut_tail);
    accum.close_unmeasured.extend(recovery.close_unmeasured);
    let mut summary = RunSummary::blank(run_id, generation, 0);
    summary.abandoned = std::mem::take(&mut accum.abandoned);
    summary.abandoned_overflow = accum.abandoned_overflow;
    summary.orphan_cut_tail = accum.orphan_cut_tail.clone();
    summary.close_unmeasured = std::mem::take(&mut accum.close_unmeasured);
    summary.close_accounting = std::mem::take(&mut accum.close_accounting);
    summary.close_accounting_overflow = accum.close_accounting_overflow;
    summary.exit = 1;
    let bytes = serde_json::to_vec(&summary).unwrap_or_default();
    let cancel = AtomicBool::new(false);
    let control: Control<std::io::Result<()>> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "terminal_summary_write",
        state_dest("run-summary.json"),
        Duration::from_secs(10),
        None,
        {
            move |gate| {
                if gate.abandoned() {
                    return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                }
                WorkerOut::value(write_state_body(
                    out,
                    "run-summary.json".to_string(),
                    tag,
                    bytes,
                ))
            }
        },
    );
    if !matches!(control, Control::Done(Ok(()))) {
        diag_line(&diag, &format, "warn", "terminal summary write failed");
    }
    let _ = diag.abandon(Duration::from_millis(200));
    crate::report::err_line("osslscope service: sequence exhausted");
    ExitCode::from(1)
}

/// Read one policy-file snapshot with the exact §3 open discipline
/// (`O_NONBLOCK | O_CLOEXEC`, regular file only, 64 KiB + 1 probe
/// byte). Returns the immutable bytes (identity derives from THESE
/// bytes only — the file is never reopened).
fn read_policy_snapshot(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open policy file".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect policy file".to_string())?;
    if !metadata.is_file() {
        return Err("policy file must be a regular file".to_string());
    }
    let mut bytes = Vec::with_capacity(65_537);
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read policy file".to_string())?;
    Ok(bytes)
}

/// Zero counts + ledgers of the run-open acquisition snapshot (§11.1
/// fresh-run rule: membership + gauges from the read, counts/ledgers
/// from true zero — `[attach, acq]` hits are run-observed evidence
/// attributed to the first window, never subtracted away).
fn zero_acquisition_baseline(snap: &mut Snapshot) {
    use crate::service::snapshot::LossView;
    for m in &mut snap.members {
        for s in &mut m.sites {
            s.calls = 0;
        }
        m.loss = LossView {
            loss: 0,
            deferred_ticks: 0,
            deferred_first: 0,
            deferred_last: 0,
            lost: Vec::new(),
            coalesced: 0,
        };
        m.ring = [0; 8];
        m.gaps.clear();
        m.engine.clear();
    }
    snap.run = crate::service::snapshot::RunTallies::default();
}

/// Requested span for window `seq` (tiling from the run origin —
/// saturating at `u64::MAX`, §4.2; unreachable in practice).
fn requested_span(origin_ns: u64, first_seq: u64, seq: u64, window_ns: u64) -> (u64, u64) {
    let steps = seq.saturating_sub(first_seq);
    let start = origin_ns.saturating_add(steps.saturating_mul(window_ns));
    let end = start.saturating_add(window_ns);
    (start, end)
}

/// Engine open (W4: ONE engine per run) + the initial policy +
/// first reserve/open + run assembly. Hands the live `Run` to the
/// window loop.
#[allow(clippy::too_many_arguments)]
fn open_engine(
    cfg: ServiceConfig,
    stream_path: Option<PathBuf>,
    run_id: RunId,
    tag: String,
    lock: DirLock,
    diag: Diagnostics,
    mut accum: SummaryAccum,
    cancel: AtomicBool,
    signals: SignalFd,
    startup_deadline: Instant,
    generation: u64,
    first_seq: u64,
    carried_close_completed: Option<u64>,
) -> ExitCode {
    let format = cfg.format;
    let out = cfg.out.clone();
    let startup_budget = || startup_deadline.saturating_duration_since(Instant::now());
    // Initial `--policy` (§3 — the identical snapshot path: read
    // once, admit, adopt at the first window open; invalid ⟹
    // observe-only + the full rejection recording, never a start
    // refusal — the §3 invalid rule with no old policy).
    let mut policy = PolicyState {
        active: None,
        active_rules: None,
        pending: None,
        displaced: 0,
        adopted: 0,
        rejected: 0,
        last_rejection: None,
    };
    if let Some(path) = cfg.policy.clone() {
        let path_for_worker = path.clone();
        let read: Control<Result<Vec<u8>, String>> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "startup_policy_read",
            state_dest("policy-read"),
            startup_budget(),
            None,
            move |_gate| WorkerOut::value(read_policy_snapshot(&path_for_worker)),
        );
        match read {
            Control::Done(Ok(bytes)) => match crate::policy_config::admit_snapshot(&bytes) {
                Ok(admission) => {
                    policy.active = Some(PolicyIdentity {
                        path: path.to_string_lossy().into_owned(),
                        sha256: admission.sha256,
                        version: admission.version,
                        rule_count: admission.rule_count,
                        adopted_seq: Some(first_seq),
                    });
                    policy.active_rules = Some(admission.ruleset);
                    policy.adopted += 1;
                }
                Err(reason) => {
                    policy.rejected += 1;
                    policy.last_rejection = Some(PolicyRejection {
                        at_wall_ns: wall_ns().unwrap_or(0),
                        reason: crate::report::bound_line(&reason),
                        attempted_path: path.to_string_lossy().into_owned(),
                        attempted_sha256: Some(crate::kinds::prov_hash(&bytes)),
                    });
                    diag_line(
                        &diag,
                        &format,
                        "warn",
                        &format!("osslscope: policy reload rejected: {reason}"),
                    );
                }
            },
            Control::Done(Err(reason)) => {
                policy.rejected += 1;
                policy.last_rejection = Some(PolicyRejection {
                    at_wall_ns: wall_ns().unwrap_or(0),
                    reason: crate::report::bound_line(&reason),
                    attempted_path: path.to_string_lossy().into_owned(),
                    attempted_sha256: None,
                });
                diag_line(
                    &diag,
                    &format,
                    "warn",
                    &format!("osslscope: policy reload rejected: {reason}"),
                );
            }
            _ => return prestart_exit4(diag, lock, "startup timed out"),
        }
        // Initial `policy-status.json` (mutable-state discipline).
        let status = PolicyStatus {
            schema: SCHEMA_POLICY.to_string(),
            active: policy.active.clone(),
            pending_valid: None,
            pending_displaced: 0,
            last_rejection: policy.last_rejection.clone(),
        };
        let bytes = serde_json::to_vec(&status).unwrap_or_default();
        let put: Control<std::io::Result<()>> = run_op(
            &diag,
            &format,
            &mut accum,
            &cancel,
            "startup_policy_status_write",
            state_dest("policy-status.json"),
            startup_budget(),
            None,
            {
                let (out, tag) = (out.clone(), tag.clone());
                move |gate| {
                    if gate.abandoned() {
                        return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                    }
                    WorkerOut::value(write_state_body(
                        out,
                        "policy-status.json".to_string(),
                        tag,
                        bytes,
                    ))
                }
            },
        );
        match put {
            Control::Done(Ok(())) => {}
            Control::Done(Err(e)) => {
                diag_line(
                    &diag,
                    &format,
                    "warn",
                    &format!("policy status write failed: {e}"),
                );
            }
            _ => return prestart_exit4(diag, lock, "startup timed out"),
        }
    }
    // Engine pool + companions (mirrors the 6A `run` setup: resolve
    // or degrade to passive inventory — an unprivileged run with no
    // companions observes membership without tracing, never fails).
    let pool = crate::observation_memory::MemoryPool::new(POOL_BYTES);
    let resolving = pool.reserve(64 << 20);
    let objects = match crate::package::commands::resolve_focused_objects(None, None) {
        Ok(o) => o,
        Err(_) => {
            use sha2::{Digest, Sha256};
            crate::focused_capture::FocusedObjects {
                observation: std::sync::Arc::from([]),
                count: std::sync::Arc::from([]),
                count_sha256: Sha256::digest([]).into(),
            }
        }
    };
    drop(resolving);
    let object_bytes = objects.observation.len() + objects.count.len();
    let mut leases = Vec::new();
    match pool.reserve(object_bytes) {
        Some(lease) => leases.push(lease),
        None => return prestart_exit4(diag, lock, "engine pool exhausted"),
    }
    let engine_config = crate::crypto_watch::CryptoWatchConfig {
        selection: crate::inventory::scope::Selection {
            pids: cfg.pids.clone(),
            cgroup: cfg.cgroup.clone(),
            modules: cfg.modules.clone(),
            resolve_paths: false,
        },
        max_active: crate::crypto_watch::CryptoWatchConfig::default().max_active,
        max_state_bytes: POOL_BYTES,
        duration: ENGINE_DURATION,
        interval: cfg.interval,
        resolve_paths: false,
        terminal: false,
    };
    // Engine open (coordinator-direct: `ServiceEngine` holds the
    // `!Send` pool — the §7.2 worker list governs the service's
    // FILE IO; engine calls inherit 6A's synchronous discipline,
    // bounded by their own timeouts + the shared cancel flag).
    let opened = match ServiceEngine::open(&engine_config, objects, &pool, true, None) {
        Ok(o) => o,
        Err(e) => {
            let _ = diag.abandon(Duration::from_millis(200));
            crate::report::err_line(&format!("osslscope service: engine open failed: {e}"));
            return ExitCode::from(4);
        }
    };
    let engine = match opened.engine {
        Some(engine) => engine,
        None => {
            // Scope unavailable pre-loop (mirrors the 6A exit-4):
            // the setup bytes ride the diagnostics worker (the
            // stderr log keeps them — no window exists to carry
            // them), then exit 4 with a summary.
            for line in opened
                .setup_bytes
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
            {
                diag.emit(line);
            }
            return prestart_exit4(diag, lock, "scope unavailable");
        }
    };
    let origin_ns = engine.run_origin_ns();
    let tick_ns = engine.tick_ns();
    open_first_window(
        cfg,
        stream_path,
        run_id,
        tag,
        lock,
        diag,
        accum,
        cancel,
        signals,
        startup_deadline,
        generation,
        first_seq,
        carried_close_completed,
        policy,
        leases,
        engine,
        opened.setup_bytes,
        origin_ns,
        tick_ns,
    )
}

/// First-window open: the acquisition snapshot (§11.1 fresh-run
/// rule — flip to the opening seq when nonzero, then zero
/// counts/ledgers), the step-1a reservation, the step-1b open flip,
/// setup-bytes staging (tick 0 opens the first window, §11), and
/// `Run` assembly. Hands the live run to the window loop.
#[allow(clippy::too_many_arguments)]
fn open_first_window(
    cfg: ServiceConfig,
    stream_path: Option<PathBuf>,
    run_id: RunId,
    tag: String,
    lock: DirLock,
    diag: Diagnostics,
    mut accum: SummaryAccum,
    cancel: AtomicBool,
    signals: SignalFd,
    startup_deadline: Instant,
    generation: u64,
    first_seq: u64,
    carried_close_completed: Option<u64>,
    policy: PolicyState,
    leases: Vec<crate::observation_memory::MemoryLease>,
    engine: ServiceEngine,
    setup_bytes: Vec<u8>,
    origin_ns: u64,
    tick_ns: u64,
) -> ExitCode {
    let format = cfg.format;
    let out = cfg.out.clone();
    let window_ns = cfg.window.as_nanos().min(u128::from(u64::MAX)) as u64;
    let (req_start, req_end) = requested_span(origin_ns, first_seq, first_seq, window_ns);
    // Acquisition snapshot: flip the bound epoch to the opening
    // seq (no-op when zero — fresh maps already read 0), then zero
    // counts/ledgers per the fresh-run rule. The sealed read of
    // this call is open-side garbage by construction — `produce`
    // only consumes close-side sealed bounds.
    let mut acquisition = if first_seq == 0 {
        engine.snapshot(None)
    } else {
        engine.snapshot(Some(first_seq))
    };
    zero_acquisition_baseline(&mut acquisition);
    // Step 1a (first window): reserve BEFORE the window opens,
    // carrying `close_completed_ns` forward unchanged.
    let reservation = Reservation {
        seq: first_seq,
        run_id: run_id.clone(),
        generation,
        requested_start_ns: req_start,
        requested_end_ns: req_end,
        state: ReservationState::Open,
        reason: None,
        started: false,
    };
    let state = SequenceState {
        schema: crate::service::state::SCHEMA_SEQ.to_string(),
        generation,
        next_seq: first_seq,
        updated_wall_ns: wall_ns().unwrap_or(0),
        close_completed_ns: carried_close_completed,
        exhausted: false,
        run_id: run_id.clone(),
        reserved: Some(reservation),
    };
    let bytes = serde_json::to_vec(&state).unwrap_or_default();
    let startup_budget = || startup_deadline.saturating_duration_since(Instant::now());
    let put: Control<std::io::Result<()>> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "reserve_first_window",
        state_dest("sequence.json"),
        startup_budget(),
        None,
        {
            let (out, tag) = (out.clone(), tag.clone());
            move |gate| {
                if gate.abandoned() {
                    return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                }
                WorkerOut::value(write_state_body(
                    out,
                    "sequence.json".to_string(),
                    tag,
                    bytes,
                ))
            }
        },
    );
    match put {
        Control::Done(Ok(())) => {}
        Control::Done(Err(e)) => {
            let msg = format!("first reserve failed: {e}");
            return write_abandoned_summary_and_exit(
                cfg, run_id, tag, diag, accum, generation, origin_ns, &msg, 4,
            );
        }
        _ => return prestart_exit4(diag, lock, "startup timed out"),
    }
    // Step 1b (first window): flip `started` (no previous close to
    // seal — the field stays as recovery left it).
    let state = SequenceState {
        reserved: Some(Reservation {
            seq: first_seq,
            run_id: run_id.clone(),
            generation,
            requested_start_ns: req_start,
            requested_end_ns: req_end,
            state: ReservationState::Open,
            reason: None,
            started: true,
        }),
        updated_wall_ns: wall_ns().unwrap_or(0),
        ..state
    };
    let bytes = serde_json::to_vec(&state).unwrap_or_default();
    let put: Control<std::io::Result<()>> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "open_first_window",
        state_dest("sequence.json"),
        startup_budget(),
        None,
        {
            let (out, tag) = (out.clone(), tag.clone());
            move |gate| {
                if gate.abandoned() {
                    return WorkerOut::value(Err(std::io::Error::other("abandoned")));
                }
                WorkerOut::value(write_state_body(
                    out,
                    "sequence.json".to_string(),
                    tag,
                    bytes,
                ))
            }
        },
    );
    match put {
        Control::Done(Ok(())) => {}
        Control::Done(Err(e)) => {
            let msg = format!("first open failed: {e}");
            return write_abandoned_summary_and_exit(
                cfg, run_id, tag, diag, accum, generation, origin_ns, &msg, 4,
            );
        }
        _ => return prestart_exit4(diag, lock, "startup timed out"),
    }
    // Setup bytes open the first window's tick 0 (§11: `Start`
    // opens the run's first window). Spill-capable from the first
    // byte (the same admission path as every tick) — spills run on
    // workers (no signal poll pre-`Run`; signals pend for the
    // loop-top drain, as before — R1 finding 3).
    let mut staging = Staging::new();
    let mut piece = TickPiece::open(0);
    let mut setup_sink =
        spill_sink_for(&diag, &format, &mut accum, &cancel, None, startup_budget());
    for line in setup_bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if staging
            .admit_record(&mut piece, &out, &tag, line, 0, &mut setup_sink)
            .is_err()
        {
            drop(setup_sink);
            return prestart_exit4(diag, lock, "staging setup records failed");
        }
    }
    drop(setup_sink);
    // Tick 0 admits unconditionally (a Carry with empty staging
    // would fabricate an empty window — the first tick is always
    // consumed; §5.1 admitted-first accounting).
    staging.admit_piece(piece);
    let piece = TickPiece::open(1);
    let stream = stream_path.clone().map(|tap_path| StreamState {
        tap_path,
        tap: Tap::pending(),
        queue: StreamQueue::new(cfg.queue_bytes, cfg.queue_events),
        first_record_wall: None,
        active_first: None,
        active_last: None,
        active_records: 0,
        inflight: Vec::new(),
        next_op_id: 1,
        pending_reconcile: None,
    });
    let cycle = Cycle {
        seq: first_seq,
        requested_start_ns: req_start,
        requested_end_ns: req_end,
        effective_start_ns: req_start,
        open: acquisition,
        staging,
        piece,
        carry_out: None,
        carried_in: None,
        open_tick_id: 0,
        fatal: None,
        accum_exceeded: None,
        accum_cut: false,
    };
    // Test-build engine substitution (compile-only scaffolding —
    // no lib unit test reaches this path; see `FakeCloseEngine`).
    #[cfg(test)]
    let engine = FakeCloseEngine::for_test();
    let run = Run {
        cfg,
        run_id,
        tag,
        generation,
        out,
        diag,
        _lock: lock,
        signals,
        cancel,
        engine,
        _leases: leases,
        cancel_latched: AtomicBool::new(false),
        double_signal: AtomicBool::new(false),
        reload_pending: AtomicBool::new(false),
        close_deadline: None,
        policy,
        stream,
        cycle: Some(cycle),
        summary: accum,
        fold: RunFold::new(),
        first_seq: None,
        tool_failure: None,
        origin_ns,
        tick_ns,
        tick_id: 1,
        run_member_floor: None,
        pending_spill_unlinks: Vec::new(),
        format,
    };
    run_loop(run)
}

/// Consume synchronously-polled signals (§§3, 7.1): TERM is the
/// cancel edge (second TERM mid-close is the double-signal
/// abandon); HUP is the reload flag (consumed at the next
/// boundary, never mid-window).
fn consume_signals(run: &mut Run, sigs: Vec<Signal>) {
    for sig in sigs {
        match sig {
            Signal::Term => {
                if run.cancel_latched.load(Ordering::SeqCst) {
                    run.double_signal.store(true, Ordering::SeqCst);
                }
                run.cancel_latched.store(true, Ordering::SeqCst);
                run.cancel.store(true, Ordering::Release);
            }
            Signal::Hup => {
                run.reload_pending.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// True once the second stop is observed (wait polls + loop drains
/// both latch — the divert checks read this, never `cancel`, which
/// `close_gate` resets at close entry).
fn double_observed(run: &Run) -> bool {
    run.double_signal.load(Ordering::SeqCst)
}

/// Mint the ONE shutdown deadline (R1 finding 3) when no close has
/// one yet: now + `--grace`.
fn mint_close_deadline(run: &mut Run) {
    if run.close_deadline.is_none() {
        run.close_deadline = Some(Instant::now() + run.cfg.grace);
    }
}

/// Close-stage worker budget (R1 finding 3): the shutdown
/// deadline's REMAINDER once minted (every close stage shares the
/// one `--grace`), else the in-run boundary budget. Saturates at
/// zero past the deadline (the wait fails fast — Expired — instead
/// of stacking another full budget).
fn close_budget(run: &Run) -> Duration {
    match run.close_deadline {
        Some(deadline) => deadline.saturating_duration_since(Instant::now()),
        None => boundary_budget(run.cfg.timeout),
    }
}

/// Cap an explicit multi-wait budget by the shutdown remainder
/// (R1 finding 3): `state_write_reconciled` passes attempt/reread/
/// retry/poll waits through here so reconciliation never outlives
/// the one deadline.
fn cap_by_deadline(run: &Run, budget: Duration) -> Duration {
    match run.close_deadline {
        Some(deadline) => budget.min(deadline.saturating_duration_since(Instant::now())),
        None => budget,
    }
}

/// This wait's signal poll (R1 finding 3): drain signalfd every
/// quantum into the run latches + `cancel`. Dissected refs (never
/// `&Run` — the caller also borrows `&mut summary`).
fn wait_poll_for<'a>(
    signals: &'a SignalFd,
    cancel: &'a AtomicBool,
    latched: &'a AtomicBool,
    double: &'a AtomicBool,
    reload: &'a AtomicBool,
) -> WaitPoll<'a> {
    WaitPoll::new(signals, cancel, latched, double, reload)
}

/// Enter the close (§7.1): the latched run cancel stops the
/// ENGINE (admission + drain promptness), never the close
/// mechanics — close worker ops run under the one shutdown
/// deadline on a fresh gate, or a signal-cut close would cancel
/// its own publish + summary. `cancel_latched` keeps the
/// interruption fact for the §7.3 fold. A second signal observed
/// DURING the close re-stores cancel via the wait polls (R1
/// finding 3) — the divert checks read `double_signal`, which no
/// gate ever resets. No-op in-run (the latch is only set on the
/// signal/pump-failure paths, which always close next).
fn close_gate(run: &mut Run) {
    run.cancel.store(false, Ordering::Release);
}

/// In-run boundary worker budget (T7.4's: the D-record binds
/// startup (`--timeout`) and close (`--grace`) explicitly; in-run
/// boundaries share the startup bound but never block signal
/// polling past one slice — Expired reconciles + retries at the
/// next boundary, DIR publish/commit excepted per their rules).
/// Takes the timeout by value (a field copy — no whole-`Run`
/// borrow inside worker-op argument lists).
fn boundary_budget(timeout: Duration) -> Duration {
    timeout.min(Duration::from_secs(5))
}

/// Boundary outcome: continue the loop with the run, or exit.
enum BoundaryOut {
    Continue(Box<Run>),
    Exit(ExitCode),
}

/// The window loop: pump the engine (§7.2 quanta with sync signal
/// polls), stage records per tick (§5.1), and close windows at
/// requested ends, budget cuts, or cancel (signal cut, §7.1).
fn run_loop(mut run: Run) -> ExitCode {
    loop {
        let sigs = run.signals.drain();
        consume_signals(&mut run, sigs);
        if double_observed(&run) {
            return double_signal_exit(run);
        }
        // One engine pump (coordinator-direct per the §7.2
        // implementability boundary — engine calls inherit 6A's
        // synchronous discipline; the shared cancel flag stops
        // admission promptly).
        let it = match run.engine.pump_iteration(&run.cancel) {
            Ok(it) => it,
            Err(e) => {
                // Pump failure (unreachable in practice — the pump
                // writes into a `Vec`): record the FIRST fatal and
                // stop after this window (cut + close + summary).
                diag_line(
                    &run.diag,
                    &run.format,
                    "error",
                    &format!("engine pump failed: {e}"),
                );
                if let Some(cycle) = run.cycle.as_mut() {
                    if cycle.fatal.is_none() {
                        cycle.fatal = Some(crate::evidence::FatalKind::Runtime(
                            "engine pump failed".into(),
                        ));
                    }
                }
                run.cancel_latched.store(true, Ordering::SeqCst);
                run.cancel.store(true, Ordering::Release);
                return close_final_window(run);
            }
        };
        // Stage this pump's records into the current tick piece
        // (the record pull discipline: ONE unrendered record held
        // at a time — split lines borrow from `it.bytes`, each
        // rendered + staging/spill-decided + dropped before the
        // next pull).
        let tick = run.tick_id;
        let mut spill_fail: Option<std::io::Error> = None;
        // In-run spills run on workers but survive the first stop
        // (fresh cancel — a first-Term iteration still signal-cuts
        // instead of abandoning; only the double cancels, via the
        // poll, and then the abandon funnel diverts — R1 finding 3).
        let spill_cancel = AtomicBool::new(false);
        let spill_poll = wait_poll_for(
            &run.signals,
            &spill_cancel,
            &run.cancel_latched,
            &run.double_signal,
            &run.reload_pending,
        );
        let spill_budget = close_budget(&run);
        let mut spill_sink = spill_sink_for(
            &run.diag,
            &run.format,
            &mut run.summary,
            &spill_cancel,
            Some(&spill_poll),
            spill_budget,
        );
        if let Some(cycle) = run.cycle.as_mut() {
            for line in it.bytes.split(|b| *b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Err(e) = cycle.staging.admit_record(
                    &mut cycle.piece,
                    &run.out,
                    &run.tag,
                    line,
                    tick,
                    &mut spill_sink,
                ) {
                    spill_fail = Some(e);
                    break;
                }
            }
        }
        // End the sink's borrows (its `impl FnMut` type would
        // otherwise hold them to scope end, blocking the moves
        // below).
        drop(spill_sink);
        if let Some(e) = spill_fail {
            // Spill-write failure (the record can neither stage nor
            // spill): Control-2 pre-publish disposition — abandon
            // with the disambiguated reason (R3 adjudication d —
            // expiry is not disk-full) + persisted bounds, resume
            // N+1 at the next start.
            return abandon_on_spill_failure(run, e);
        }
        // Sample edge = tick end: run the §5.1 budget decision.
        if it.sample_fired {
            let decision = {
                let cycle = run.cycle.as_ref().expect("window open in run loop");
                let d = cycle.staging.decide_tick(&cycle.piece, cycle.seq);
                // A Carry with EMPTY staging would fabricate an
                // empty window — the first tick is always consumed
                // (§5.1 admitted-first accounting).
                match d {
                    TickDecision::Carry
                        if cycle.staging.staged.is_empty() && cycle.staging.spilled.is_empty() =>
                    {
                        TickDecision::Admit
                    }
                    other => other,
                }
            };
            match decision {
                TickDecision::Admit => {
                    let cycle = run.cycle.as_mut().expect("window open in run loop");
                    let piece = std::mem::replace(&mut cycle.piece, TickPiece::open(tick + 1));
                    cycle.staging.admit_piece(piece);
                    run.tick_id += 1;
                }
                TickDecision::Carry => {
                    let cycle = run.cycle.as_mut().expect("window open in run loop");
                    let piece = std::mem::replace(&mut cycle.piece, TickPiece::open(tick + 1));
                    let from_seq = cycle.seq;
                    cycle.carry_out = Some(Staging::carry_piece(piece, from_seq));
                    cycle.accum_cut = true;
                    run.summary.windows_cut_accum += 1;
                    run.tick_id += 1;
                    match close_mid_window(run) {
                        BoundaryOut::Continue(r) => run = *r,
                        BoundaryOut::Exit(code) => return code,
                    }
                    continue;
                }
                TickDecision::AdmitWholeExceed { bytes_over } => {
                    let cycle = run.cycle.as_mut().expect("window open in run loop");
                    let piece = std::mem::replace(&mut cycle.piece, TickPiece::open(tick + 1));
                    cycle.staging.admit_piece(piece);
                    cycle.accum_exceeded = Some(AccumExceeded { bytes: bytes_over });
                    cycle.accum_cut = true;
                    run.summary.windows_cut_accum += 1;
                    run.tick_id += 1;
                    match close_mid_window(run) {
                        BoundaryOut::Continue(r) => run = *r,
                        BoundaryOut::Exit(code) => return code,
                    }
                    continue;
                }
            }
        }
        // Requested end reached → normal boundary close.
        let close_at_end = match run.cycle.as_ref() {
            Some(cycle) => monotonic_ns() >= cycle.requested_end_ns,
            None => false,
        };
        if close_at_end {
            match close_mid_window(run) {
                BoundaryOut::Continue(r) => run = *r,
                BoundaryOut::Exit(code) => return code,
            }
            continue;
        }
        // Cancel latched → the in-flight window finalizes NOW with
        // `signal_cut` (stop after the current window, §7.1).
        if run.cancel_latched.load(Ordering::SeqCst) {
            return close_final_window(run);
        }
        // Quantum sleep that doubles as the synchronous signal poll.
        let sigs = run.signals.wait(PUMP_QUANTUM);
        consume_signals(&mut run, sigs);
    }
}

/// Effective-ns → tick via the `Start.run_origin_ns` anchor (6A §7;
/// both domains `CLOCK_MONOTONIC`). Saturates at 0 below the origin.
fn tick_of(ns: u64, origin_ns: u64, tick_ns: u64) -> u64 {
    if tick_ns == 0 || ns <= origin_ns {
        return 0;
    }
    ns.saturating_sub(origin_ns) / tick_ns
}

/// Close mode: mid-run (commit + next window) vs run-final
/// (seal + end) vs terminal (MAX seal + end, `exhausted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseMode {
    Mid,
    Final,
    Terminal,
}

/// Mid-run boundary close (§§2, 4.3, 5.1, 6, 11.1): close snapshot
/// (the flip IS the cut) → produce → envelope → publish → sinks →
/// step-5 commit+reserve → adoption → next 1a-verify/1b open.
/// `N == u64::MAX` diverts to the terminal seal (no window after
/// MAX is representable, §4.2).
fn close_mid_window(run: Run) -> BoundaryOut {
    let seq = run.cycle.as_ref().expect("window open at close").seq;
    if seq == u64::MAX {
        return close_terminal_window(run);
    }
    // Close snapshot: flip every member's bound-epoch to N+1 (the
    // flip IS the cut — §11.1 close order: flip-all → record the
    // effective edge → guarded read pass).
    let close = run.engine.snapshot(Some(seq.saturating_add(1)));
    close_common_body(run, close, false, CloseMode::Mid)
}

/// Run-final close (§7.1 — cancel latched): drain FIRST (the `End`
/// plus retirement seals ride the final window's `crypto_watch[]`,
/// and Control-7 exact-Σ needs sealed totals, not
/// snapshot-then-retire micro-gaps), stage the drain bytes into
/// the current piece (admitted whole — the final window consumes
/// its tail undecided), then the common close with `signal_cut`.
fn close_final_window(mut run: Run) -> ExitCode {
    // Mint the ONE shutdown deadline BEFORE the drain (R1 finding
    // 3): drain, assembly, publication, sinks, seal, and summary
    // all draw from this single `--grace`.
    run.close_deadline = Some(Instant::now() + run.cfg.grace);
    let seq = run.cycle.as_ref().expect("window open at final close").seq;
    // Drain (the engine retires sessions without readmit; cancel
    // stops admission, never the drain mechanics — mirrors 6A).
    // The minted shutdown deadline caps the drain itself (S3/WS-A —
    // a bare assignment would not bound it); seal/cleanup/summary
    // below draw from the same deadline's remainder.
    let drain_deadline = run.close_deadline.expect("minted above");
    let drain = run
        .engine
        .close_drain_capped(&run.cancel, Some(drain_deadline));
    match drain {
        Ok(out) => {
            // Stage the drain bytes (spill-capable — a spill failure
            // here abandons pre-close, like the run loop's; spills
            // run on workers under the shutdown remainder — R1
            // finding 3). Close-critical staging survives the first
            // stop (fresh cancel — shutdown preemption is EXPECTED
            // at close, not a failure; only the double cancels, via
            // the poll, and then the divert below expedites —
            // mirroring the in-run spills).
            let mut spill_fail: Option<std::io::Error> = None;
            let tick = run.tick_id;
            let spill_budget = close_budget(&run);
            let spill_cancel = AtomicBool::new(false);
            let spill_poll = wait_poll_for(
                &run.signals,
                &spill_cancel,
                &run.cancel_latched,
                &run.double_signal,
                &run.reload_pending,
            );
            let mut spill_sink = spill_sink_for(
                &run.diag,
                &run.format,
                &mut run.summary,
                &spill_cancel,
                Some(&spill_poll),
                spill_budget,
            );
            if let Some(cycle) = run.cycle.as_mut() {
                for line in out.bytes.split(|b| *b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    if let Err(e) = cycle.staging.admit_record(
                        &mut cycle.piece,
                        &run.out,
                        &run.tag,
                        line,
                        tick,
                        &mut spill_sink,
                    ) {
                        spill_fail = Some(e);
                        break;
                    }
                }
                // Admit the tail piece whole (no tick-end decision —
                // the final window consumes its tail undecided; the
                // staging RAM ceiling still bounds via spill).
                let piece = std::mem::replace(&mut cycle.piece, TickPiece::open(tick + 1));
                cycle.staging.admit_piece(piece);
            }
            drop(spill_sink);
            if let Some(e) = spill_fail {
                // A double observed during close staging expedites
                // (R1 finding 3): immediate stop, never the
                // abandonment mapping (the funnel backstops this,
                // but the explicit divert keeps errno noise out of
                // the double exit).
                if double_observed(&run) {
                    return double_signal_exit(run);
                }
                // Spill-write failure: abandon pre-close with the
                // disambiguated reason (R3 adjudication d — expiry
                // is not disk-full), like the run loop's.
                return abandon_on_spill_failure(run, e);
            }
        }
        Err(e) => {
            // Drain failure (mirrors the 6A close-failure salvage):
            // record the FIRST fatal and continue with the close
            // snapshot (still-open members read exact-at-snapshot).
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("close drain failed: {e}"),
            );
            if let Some(cycle) = run.cycle.as_mut() {
                if cycle.fatal.is_none() {
                    cycle.fatal = Some(crate::evidence::FatalKind::Runtime(
                        "close drain failed".into(),
                    ));
                }
            }
        }
    }
    // MAX under cancel still seals terminally (no N+1 exists) with
    // the cut flag set (cancel cut it).
    if seq == u64::MAX {
        let close = run.engine.snapshot_sealed(u64::MAX);
        return close_common_body(run, close, true, CloseMode::Terminal).into_exit_code();
    }
    let close = run.engine.snapshot(Some(seq.saturating_add(1)));
    close_common_body(run, close, true, CloseMode::Final).into_exit_code()
}

/// Terminal close (`N == u64::MAX`, §4.2): drain (the `End` rides
/// the MAX window like any final close), then the sealed-without-
/// flip snapshot (MAX+1 is unrepresentable) and the common close
/// with the TERMINAL seal (`exhausted`, no next window ever).
fn close_terminal_window(mut run: Run) -> BoundaryOut {
    // The ONE shutdown deadline (R1 finding 3 — before the drain,
    // like the final close), capping the drain itself (S3/WS-A).
    run.close_deadline = Some(Instant::now() + run.cfg.grace);
    let drain_deadline = run.close_deadline.expect("minted above");
    let drain = run
        .engine
        .close_drain_capped(&run.cancel, Some(drain_deadline));
    match drain {
        Ok(out) => {
            // Close-drain staging (worker-backed spills under the
            // shutdown remainder — R1 finding 3, like the final).
            // Close-critical staging survives the first stop (fresh
            // cancel — shutdown preemption is EXPECTED at close,
            // not a failure; only the double cancels, via the poll,
            // and then the divert below expedites — mirroring the
            // in-run spills).
            let mut spill_fail: Option<std::io::Error> = None;
            let tick = run.tick_id;
            let spill_budget = close_budget(&run);
            let spill_cancel = AtomicBool::new(false);
            let spill_poll = wait_poll_for(
                &run.signals,
                &spill_cancel,
                &run.cancel_latched,
                &run.double_signal,
                &run.reload_pending,
            );
            let mut spill_sink = spill_sink_for(
                &run.diag,
                &run.format,
                &mut run.summary,
                &spill_cancel,
                Some(&spill_poll),
                spill_budget,
            );
            if let Some(cycle) = run.cycle.as_mut() {
                for line in out.bytes.split(|b| *b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    if let Err(e) = cycle.staging.admit_record(
                        &mut cycle.piece,
                        &run.out,
                        &run.tag,
                        line,
                        tick,
                        &mut spill_sink,
                    ) {
                        spill_fail = Some(e);
                        break;
                    }
                }
                let piece = std::mem::replace(&mut cycle.piece, TickPiece::open(tick + 1));
                cycle.staging.admit_piece(piece);
            }
            drop(spill_sink);
            if let Some(e) = spill_fail {
                // A double observed during close staging expedites
                // (R1 finding 3): immediate stop, never the
                // abandonment mapping (the funnel backstops this,
                // but the explicit divert keeps errno noise out of
                // the double exit).
                if double_observed(&run) {
                    return BoundaryOut::Exit(double_signal_exit(run));
                }
                // Spill-write failure (the record can neither stage
                // nor spill): Control-2 pre-publish disposition —
                // abandon with the disambiguated reason (R3
                // adjudication d — expiry is not disk-full).
                return BoundaryOut::Exit(abandon_on_spill_failure(run, e));
            }
        }
        Err(e) => {
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("close drain failed: {e}"),
            );
            if let Some(cycle) = run.cycle.as_mut() {
                if cycle.fatal.is_none() {
                    cycle.fatal = Some(crate::evidence::FatalKind::Runtime(
                        "close drain failed".into(),
                    ));
                }
            }
        }
    }
    let close = run.engine.snapshot_sealed(u64::MAX);
    close_common_body(run, close, false, CloseMode::Terminal)
}

impl BoundaryOut {
    fn into_exit_code(self) -> ExitCode {
        match self {
            BoundaryOut::Exit(code) => code,
            // The final/terminal tail always ends the run (commit
            // is unreachable — mode diverts to seal first).
            BoundaryOut::Continue(_) => ExitCode::from(1),
        }
    }
}

/// Shared close body (all modes): floor + sealed map + produce →
/// publish → judge → sinks → commit-or-seal.
fn close_common_body(
    mut run: Run,
    close: Snapshot,
    signal_cut: bool,
    mode: CloseMode,
) -> BoundaryOut {
    close_gate(&mut run);
    let effective_end_ns = close.at_ns;
    // Run-member floor (the empty-window target fallback, §11.1).
    for m in &close.members {
        let id = (m.pid, m.starttime);
        run.run_member_floor = Some(match run.run_member_floor {
            Some(f) => f.min(id),
            None => id,
        });
    }
    let close_segments: std::collections::BTreeSet<u64> =
        close.members.iter().map(|m| m.segment).collect();
    // Sealed map (R2 Gate 3): spilled seals read on workers under
    // the ONE close deadline with WaitPoll signal consumption —
    // never coordinator-direct. Staged values never touch the FS.
    let (sealed, seal_outcomes) = {
        let cycle = run.cycle.as_ref().expect("window open at close");
        let deadline = run.close_deadline;
        let fallback = boundary_budget(run.cfg.timeout);
        let poll = run_wait_poll!(run);
        sealed_map(
            &cycle.staging.staged,
            &cycle.staging.spilled,
            &close_segments,
            deadline,
            fallback,
            &run.cancel,
            Some(&poll),
        )
    };
    // Record every spilled seal-read outcome (R3 Gate 4 F2 — the
    // frozen rule: every Expired/Cancelled/Lost/Failed op lands in
    // `close_accounting` + one bounded stderr line, `failed` with
    // its errno). A seal that cannot be consumed gaps
    // `snapshot.member_unsealed` in `produce` (fail-closed — the
    // retirement record still rides `crypto_watch[]` verbatim; the
    // seal only sharpens the exact-Σ).
    for o in &seal_outcomes {
        let op = format!("seal_read_{}", o.seg_hint);
        if o.outcome != OpOutcome::Done {
            let mut msg = format!("op {op} ended {:?}", o.outcome);
            if let Some(errno) = o.errno {
                msg.push_str(&format!(" (errno {errno})"));
            }
            diag_line(&run.diag, &run.format, "warn", &msg);
        }
        push_accounting(
            &mut run.summary.close_accounting,
            &mut run.summary.close_accounting_overflow,
            op,
            o.outcome,
        );
    }
    let cycle = run.cycle.as_ref().expect("window open at close");
    let open_tick = tick_of(cycle.effective_start_ns, run.origin_ns, run.tick_ns);
    let close_tick = tick_of(effective_end_ns, run.origin_ns, run.tick_ns);
    let policy_rules = match run.policy.active_rules.as_ref() {
        Some(ruleset) => crate::check::policy_rules(ruleset),
        None => Vec::new(),
    };
    let ctx = WindowCtx {
        seq: cycle.seq,
        generation: run.generation,
        run_id: run.run_id.clone(),
        span: WindowSpan {
            requested_start_ns: cycle.requested_start_ns,
            requested_end_ns: cycle.requested_end_ns,
            effective_start_ns: cycle.effective_start_ns,
            effective_end_ns,
            signal_cut,
            accum_cut: cycle.accum_cut,
        },
        open_tick,
        close_tick,
        policy_rules,
        active_policy: run.policy.active.clone(),
        fatal: cycle.fatal.clone(),
        run_member_floor: run.run_member_floor,
        selection_pid: run.cfg.pids.first().copied().unwrap_or(0),
    };
    let produced = produce(&cycle.open, &close, &sealed, &ctx);
    mid_window_publish(run, close, produced, effective_end_ns, signal_cut, mode)
}

/// Poll a destination's slot until the worker unregisters (a
/// detached worker mutates at most once, then exits — §7.2), so a
/// successor may register. Returns true when the slot is gone
/// (consumed) or free. Bounded — reconciliation never waits past
/// its sub-deadline — and double-aware (R1 finding 3): the poll
/// consumes signals and breaks early on the second stop (false —
/// the caller judges, and the funnel diverts to the double exit).
fn poll_unregister(dest: &Destination, budget: Duration, wait_poll: Option<&WaitPoll>) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        match view_slot(dest) {
            None => return true,
            Some(view) if !view.live => return true,
            Some(_) => {}
        }
        if let Some(poll) = wait_poll {
            poll.poll();
            if poll.doubled() {
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Evidence destination key (per-destination registry, §7.2 — one
/// live publisher per window file).
fn evidence_dest(seq: u64) -> Destination {
    Destination {
        class: DestClass::EvidenceLink,
        key: format!("window-{seq}"),
    }
}

/// Publish one rendered window (TWO-phase assemble + link, §7.2):
/// assemble (read-only, spill tmps intact — abandonment-safe),
/// render + link on an evidence worker, then absorb the consumed
/// spills. Returns the publish judgment for the caller.
struct PublishJudgment {
    step: PublishStep,
    stage_errno: Option<(crate::service::publish::PublishStage, i32)>,
    sha256: String,
    /// `true` when the publish worker never ran to judgment
    /// (Expired/Cancelled/SpawnFailed — the window cannot publish
    /// this boundary; the late P1 may still land, §4.4).
    worker_gone: bool,
    /// `true` iff the worker was never spawned (F-015).
    spawn_failed: bool,
}

fn mid_window_publish(
    mut run: Run,
    close: Snapshot,
    produced: crate::service::snapshot::Produced,
    effective_end_ns: u64,
    signal_cut: bool,
    mode: CloseMode,
) -> BoundaryOut {
    let seq = run.cycle.as_ref().expect("window open at publish").seq;
    // Assemble (worker, OwnTmp — streams the array-inner into an
    // array tmp through bounded buffers, R1 finding 2b). Staged
    // MOVES worker-side (no clone — abandonment-safe: any non-Done
    // assemble abandons the run, so moved bytes are never needed
    // after; a detached worker owns its inputs outright). Spill
    // metas clone (paths + flags only — bytes stay on disk), and
    // spill tmps stay intact for the post-publish absorb (§7.2
    // lossless two-phase).
    let (staged, spilled, carried_tick, carried_from, staging_peak, open_tick_id) = {
        let cycle = run.cycle.as_mut().expect("window open at publish");
        (
            std::mem::take(&mut cycle.staging.staged),
            cycle.staging.spilled.clone(),
            cycle.carried_in.map(|(_, tick)| tick),
            cycle.carried_in.map(|(from, _)| from),
            cycle.staging.meter.staging_peak(),
            cycle.open_tick_id,
        )
    };
    let array_tmp = run.out.join(format!(
        ".window-{seq:010}.tmp.{}.{}.array",
        run.tag,
        crate::service::state::next_op_nonce()
    ));
    // The shutdown remainder once a close minted the deadline
    // (run-final — R1 finding 3), else the in-run boundary budget
    // (mid-close, unchanged).
    let budget = close_budget(&run);
    let dest = Destination {
        class: DestClass::OwnTmp,
        key: format!("assemble-{seq}"),
    };
    let asm_poll = run_wait_poll!(run);
    let asm: Control<std::io::Result<AssembledCounts>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("assemble_window_{seq}"),
        dest.clone(),
        budget,
        Some(&asm_poll),
        {
            let array_tmp = array_tmp.clone();
            move |_gate| {
                // The worker owns the array tmp lifecycle (unlinked
                // on every error path — a detached worker's tmp, if
                // any, is §4.4-cleaned next start).
                let result = (|| -> std::io::Result<AssembledCounts> {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&array_tmp)?;
                    let counts = assemble_inner_into(
                        &staged,
                        &spilled,
                        carried_tick,
                        carried_from,
                        false,
                        &mut f,
                    )?;
                    drop(f);
                    Ok(counts)
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&array_tmp);
                }
                WorkerOut::value(result)
            }
        },
    );
    let assembled = match asm {
        Control::Done(Ok(a)) => a,
        Control::Done(Err(e)) => {
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("assemble failed: {e}"),
            );
            return BoundaryOut::Exit(abandon_window(
                run,
                AbandonReason::IoError,
                Some(effective_end_ns),
            ));
        }
        _ => {
            // Assemble never ran to judgment (slow FS or signal):
            // the window cannot publish this boundary — abandon
            // (the run ends; the next start resumes at N+1, §4.4).
            // Spawn failure names `worker_unavailable` (F-015).
            // (The moved staged vec is owned by the detached
            // worker, if any — abandonment-safe by construction;
            // its array tmp, if any, is §4.4-cleaned.)
            let reason = match asm {
                Control::SpawnFailed => AbandonReason::WorkerUnavailable,
                _ => AbandonReason::IoError,
            };
            return BoundaryOut::Exit(abandon_window(run, reason, Some(effective_end_ns)));
        }
    };
    if assembled.skipped_invalid > 0 {
        diag_line(
            &run.diag,
            &run.format,
            "warn",
            &format!(
                "window {seq}: {} non-JSON records skipped",
                assembled.skipped_invalid
            ),
        );
    }
    // Render (coordinator CPU — the envelope WITHOUT the array
    // is held; the array streams from the array tmp at publish):
    // split at the byte-verbatim `crypto_watch[]` site (serde
    // renders the empty vec deterministically as
    // `"crypto_watch":[]` — the search pattern is provably
    // structural: string values render with ESCAPED quotes, so no
    // value can match the unescaped pattern).
    let cycle = run.cycle.as_ref().expect("window open at publish");
    let (first_tick, last_tick) = match (assembled.first_tick, assembled.last_tick) {
        (Some(f), Some(l)) => (f, l),
        // Empty array: the ticks that elapsed (honest — these ticks
        // were admitted, zero records).
        _ => (open_tick_id, run.tick_id),
    };
    let tick_span = TickSpan {
        first_tick,
        last_tick,
        carried_records: assembled.carried_records,
        carried_from_seq: assembled.carried_from_seq,
    };
    let spilled_note = Spilled {
        records: assembled.spilled_records,
        bytes: assembled.spilled_bytes,
    };
    let envelope = WindowEnvelope {
        schema: crate::service::envelope::SCHEMA_WINDOW.to_string(),
        seq,
        generation: run.generation,
        run_id: run.run_id.clone(),
        window: WindowSpan {
            requested_start_ns: cycle.requested_start_ns,
            requested_end_ns: cycle.requested_end_ns,
            effective_start_ns: cycle.effective_start_ns,
            effective_end_ns,
            signal_cut,
            accum_cut: cycle.accum_cut,
        },
        accum_exceeded: cycle.accum_exceeded.clone(),
        spilled: spilled_note.clone(),
        staging_peak_bytes: staging_peak,
        tick_span: tick_span.clone(),
        policy: run.policy.active.clone(),
        members: produced.members.clone(),
        site_sources: produced.site_sources.clone(),
        crypto_watch: Vec::new(),
        document: produced.document.clone(),
    };
    let envelope_value = serde_json::to_value(&envelope).unwrap_or(serde_json::Value::Null);
    let rendered = serde_json::to_vec(&envelope_value).unwrap_or_default();
    let Some((head, tail)) = split_envelope_at_array(&rendered) else {
        // Unreachable (the envelope always carries the empty vec) —
        // fail closed, never a corrupt file. (The orphaned array
        // tmp, if any, is §4.4-cleaned next start.)
        return BoundaryOut::Exit(abandon_window(
            run,
            AbandonReason::IoError,
            Some(effective_end_ns),
        ));
    };
    // Publish (evidence worker — single attempt; a successor is
    // refused while the worker is registered, §7.2 — so non-Done
    // abandons the window and the late P1 adopts at recovery). The
    // worker streams head + array + tail into the window tmp
    // (bounded buffers, incremental hash — R1 finding 2b) and owns
    // the array tmp lifecycle (consumed on every settled path; a
    // detached worker's tmp, if any, is §4.4-cleaned).
    let attempt = AttemptKey {
        seq,
        pid: run.run_id.pid,
        starttime: run.run_id.starttime,
        boot_id: run.run_id.boot_id.clone(),
    };
    let pub_dest = evidence_dest(seq);
    let pub_budget = close_budget(&run);
    let pub_poll = run_wait_poll!(run);
    let published: Control<StreamedPublish> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("publish_window_{seq}"),
        pub_dest,
        pub_budget,
        Some(&pub_poll),
        {
            let (out, tag) = (run.out.clone(), run.tag.clone());
            move |_gate| {
                // EvidenceLink is P-class (no fenced re-check — the
                // link is no-overwrite; EEXIST converges per the ONE
                // rule inside the publish call).
                let out = crate::service::publish::publish_window_streaming(
                    &out, seq, &tag, &head, &tail, &array_tmp, &attempt,
                );
                let _ = std::fs::remove_file(&array_tmp);
                WorkerOut::value(out)
            }
        },
    );
    let judgment = match published {
        Control::Done((step, stage_errno, sha256)) => PublishJudgment {
            step,
            stage_errno,
            sha256,
            worker_gone: false,
            spawn_failed: false,
        },
        // The worker never reported a hash (no bytes were linked by
        // THIS attempt — sha is judgment-only on the durable arms,
        // so empty here is unreachable downstream).
        Control::SpawnFailed => PublishJudgment {
            step: PublishStep::NotPublished,
            stage_errno: None,
            sha256: String::new(),
            worker_gone: true,
            spawn_failed: true,
        },
        _ => PublishJudgment {
            step: PublishStep::NotPublished,
            stage_errno: None,
            sha256: String::new(),
            worker_gone: true,
            spawn_failed: false,
        },
    };
    mid_window_judge(run, close, produced, effective_end_ns, judgment, mode)
}

/// Judge the publish step (§4.2): durable/converged proceed to
/// sinks; uncertain/not-published/worker-gone/integrity end the
/// run through their frozen dispositions.
fn mid_window_judge(
    mut run: Run,
    close: Snapshot,
    produced: crate::service::snapshot::Produced,
    effective_end_ns: u64,
    judgment: PublishJudgment,
    mode: CloseMode,
) -> BoundaryOut {
    use crate::service::publish::PublishStep;
    // A double observed during assemble/publish expedites (R1
    // finding 3): immediate stop, never the abandonment mapping.
    if double_observed(&run) {
        return BoundaryOut::Exit(double_signal_exit(run));
    }
    let seq = run.cycle.as_ref().expect("window open at judge").seq;
    if judgment.worker_gone {
        let reason = if judgment.spawn_failed {
            AbandonReason::WorkerUnavailable
        } else {
            AbandonReason::IoError
        };
        return BoundaryOut::Exit(abandon_window(run, reason, Some(effective_end_ns)));
    }
    match judgment.step {
        PublishStep::Durable | PublishStep::Converged => {}
        PublishStep::Uncertain => {
            // Neither durable nor abandoned: the reservation stays
            // open-attempted (recovery adopts-or-gaps via the §4.4
            // matrix + the identity-bound summary flag) — the run
            // ends as a run-level tool failure WITHOUT sealing (a
            // seal would claim committed — false).
            run.summary.durability_uncertain =
                Some(crate::service::envelope::DurabilityUncertain { seq });
            run.tool_failure = Some(RunToolFailure::DurabilityUncertain);
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("window {seq}: publish uncertain"),
            );
            return BoundaryOut::Exit(close_run_end(run));
        }
        PublishStep::NotPublished => {
            // ENOSPC at any stage ⟹ `disk_full`, any other IO error
            // ⟹ `io_error` (T7.4's stage→reason map, reported).
            let reason = match judgment.stage_errno {
                Some((_, errno)) if errno == libc::ENOSPC => AbandonReason::DiskFull,
                _ => AbandonReason::IoError,
            };
            if let Some((stage, errno)) = judgment.stage_errno {
                diag_line(
                    &run.diag,
                    &run.format,
                    "error",
                    &format!("window {seq}: publish failed at {stage:?} (errno {errno})"),
                );
            }
            return BoundaryOut::Exit(abandon_window(run, reason, Some(effective_end_ns)));
        }
        PublishStep::IntegrityRefusal => {
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("window {seq}: duplicate-seq attempt"),
            );
            return BoundaryOut::Exit(integrity_exit(run, "duplicate-seq attempt"));
        }
    }
    // Durable (or converged): absorb the consumed spills (OwnTmp —
    // the bytes are coordinator-held, so a leak reconciles via
    // retry + §4.4 cleanup, never a loss) AND retry previously
    // queued consumed identities (RANK-4: the queue has a consumer
    // at every boundary — consumed identities only, live excluded,
    // deduplicated; retention accounting untouched).
    let spill_tmps: Vec<PathBuf> = run
        .cycle
        .as_ref()
        .expect("window open at judge")
        .staging
        .spilled
        .iter()
        .map(|r| r.tmp.clone())
        .collect();
    let live = {
        let cycle = run.cycle.as_ref().expect("window open at judge");
        live_spill_set(&cycle.staging, &cycle.piece, cycle.carry_out.as_ref())
    };
    let queued = std::mem::take(&mut run.pending_spill_unlinks);
    let attempt = spill_retry_plan(spill_tmps, queued, &live);
    if !attempt.is_empty() {
        let absorb_budget = close_budget(&run);
        let absorb_poll = run_wait_poll!(run);
        let absorb: Control<usize> = run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            &format!("absorb_spills_{seq}"),
            Destination {
                class: DestClass::OwnTmp,
                key: format!("absorb-{seq}"),
            },
            absorb_budget,
            Some(&absorb_poll),
            {
                let attempt = attempt.clone();
                move |_gate| {
                    let mut unlinked = 0usize;
                    for tmp in &attempt {
                        if std::fs::remove_file(tmp).is_ok() {
                            unlinked += 1;
                        }
                    }
                    WorkerOut::value(unlinked)
                }
            },
        );
        // A non-Done absorb leaks (retried at the next boundary;
        // §4.4 cleanup backstops at the next start). Partial
        // absorbs re-list below — the op reports its count; the
        // LEAKED remainder is unknown without a re-list, so re-list
        // the spill tmps (read-only) and queue survivors.
        let unlinked = matches!(absorb, Control::Done(_));
        if !unlinked {
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                &format!("window {seq}: spill absorb deferred"),
            );
        }
    }
    // Re-list survivors EVERY boundary (leak detection requires the
    // listing — queued or not, spilled or not): live-filtered
    // (minus the just-consumed attempt), deduplicated, capped.
    let consumed: std::collections::BTreeSet<PathBuf> = attempt.into_iter().collect();
    queue_leaked_spills(&mut run, seq, &consumed);
    // Release the staging RAM (the envelope holds the bytes now).
    if let Some(cycle) = run.cycle.as_mut() {
        cycle.staging.release();
    }
    // The finalized window enters the §7.3 fold (O(1) bits —
    // the document is never cloned in, R1 finding 2a). Delivery
    // here always succeeded (this arm runs only on
    // Durable/Converged).
    run.fold.add(
        produced.outcome,
        &produced.document.status,
        produced.document.has_usable_evidence(),
        false,
    );
    if run.first_seq.is_none() {
        run.first_seq = Some(seq);
    }
    run.summary.last_seq = Some(seq);
    let (run, sinks) = mid_window_sinks(run, judgment.sha256);
    mid_window_commit(run, close, effective_end_ns, sinks, mode)
}

/// Bound on queued spill-unlink retries (RANK-4): the retry
/// queue holds paths only (no bytes); past the cap, further leaks
/// shed with a diagnostic — the next start's §4.4 `clean_tmps`
/// backstops (leak, never loss; queue metadata bounded either way).
const MAX_PENDING_SPILL_UNLINKS: usize = 1024;

/// Live spill identities (RANK-4 deletion authority): the current
/// window's staging + open piece + carried tick. A re-listed path
/// in this set is still in use and MUST NOT be unlinked — a
/// run-prefix re-list alone is NOT deletion authority.
fn live_spill_set(
    staging: &Staging,
    piece: &TickPiece,
    carry_out: Option<&Carry>,
) -> std::collections::BTreeSet<PathBuf> {
    let mut live = std::collections::BTreeSet::new();
    for r in &staging.spilled {
        live.insert(r.tmp.clone());
    }
    for tmp in staging.spill_files.keys() {
        live.insert(tmp.clone());
    }
    for r in &piece.spilled {
        live.insert(r.tmp.clone());
    }
    if let Some(carry) = carry_out {
        for r in &carry.spilled {
            live.insert(r.tmp.clone());
        }
    }
    live
}

/// This boundary's unlink plan (RANK-4): the window's consumed
/// spills PLUS queued retries for consumed identities only —
/// queued paths still live are excluded (they ride their own
/// window's consume step instead), and the plan deduplicates.
fn spill_retry_plan(
    spill_tmps: Vec<PathBuf>,
    queued: Vec<PathBuf>,
    live: &std::collections::BTreeSet<PathBuf>,
) -> Vec<PathBuf> {
    let mut attempt = spill_tmps;
    for q in queued {
        if !live.contains(&q) && !attempt.contains(&q) {
            attempt.push(q);
        }
    }
    attempt
}

/// Retry-queue merge outcome (diagnosed on shed, never silent
/// about pressure; live-skips are routine — carried ticks re-list
/// while live — and stay quiet).
struct PendingMerge {
    added: usize,
    skipped_live: usize,
    shed_cap: usize,
}

/// Dedup-merge re-listed survivors into the retry queue (RANK-4):
/// live identities are excluded — minus the just-consumed attempt,
/// whose survivors are consumed-pending-retry, not live — and the
/// queue is deduplicated and capped at
/// [`MAX_PENDING_SPILL_UNLINKS`].
fn merge_pending_spills(
    pending: &mut Vec<PathBuf>,
    relisted: Vec<PathBuf>,
    live: &std::collections::BTreeSet<PathBuf>,
    consumed: &std::collections::BTreeSet<PathBuf>,
) -> PendingMerge {
    let mut out = PendingMerge {
        added: 0,
        skipped_live: 0,
        shed_cap: 0,
    };
    for p in relisted {
        if live.contains(&p) && !consumed.contains(&p) {
            out.skipped_live += 1;
            continue;
        }
        if pending.contains(&p) {
            continue;
        }
        if pending.len() >= MAX_PENDING_SPILL_UNLINKS {
            out.shed_cap += 1;
            continue;
        }
        pending.push(p);
        out.added += 1;
    }
    out
}

/// Re-list this run's spill tmps (worker — read-only) and queue
/// survivors for the next boundary's absorb retry (leak, never
/// loss — §4.4 cleanup backstops at the next start). Consumed
/// identities only (live minus the just-consumed attempt is
/// excluded); deduplicated + capped. Retention quota (windows +
/// rotated) is untouched — spill tmps are transient, diagnosed
/// here, never counted as managed.
fn queue_leaked_spills(run: &mut Run, seq: u64, consumed: &std::collections::BTreeSet<PathBuf>) {
    let prefix = format!(".{}.tmp.spill.", run.tag);
    let relist_budget = close_budget(run);
    let relist_poll = run_wait_poll!(run);
    let relist: Control<Vec<PathBuf>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("relist_spills_{seq}"),
        Destination {
            class: DestClass::OwnTmp,
            key: format!("relist-{seq}"),
        },
        relist_budget,
        Some(&relist_poll),
        {
            let out = run.out.clone();
            move |_gate| {
                let leaked: Vec<PathBuf> = std::fs::read_dir(&out)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with(&prefix))
                    })
                    .collect();
                WorkerOut::value(leaked)
            }
        },
    );
    if let Control::Done(leaked) = relist {
        let live = {
            let cycle = run.cycle.as_ref().expect("window open at relist");
            live_spill_set(&cycle.staging, &cycle.piece, cycle.carry_out.as_ref())
        };
        let merged = merge_pending_spills(&mut run.pending_spill_unlinks, leaked, &live, consumed);
        if merged.shed_cap > 0 {
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                &format!(
                    "window {seq}: spill retry queue +{} live-skipped={} shed={} at cap {}",
                    merged.added, merged.skipped_live, merged.shed_cap, MAX_PENDING_SPILL_UNLINKS
                ),
            );
        }
    }
}

/// Awaiting rotation-tail reconcile (the rotated file + the
/// pre-rename size + the declared span at rename).
struct PendingRotation {
    rotated: PathBuf,
    dev: u64,
    ino: u64,
    first: u64,
    last: u64,
}

/// Boundary sinks outcome: continue to commit, or stop with the
/// quota latch written (the window is published — lossless DIR
/// path — and the run ends as a run-level tool failure, §6.2).
enum SinksOut {
    Continue,
    QuotaStop,
}

/// Boundary sinks (§4.3 step 4): pending-rotation reconcile →
/// rotation decision → stream marker+ref enqueue → stale-op
/// recheck → tap drive → retention + quota. No `--stream` ⟹
/// retention only.
/// Rotation-tail reconcile (L6 over the ROTATED file): content-match
/// the rotated tail against the in-flight records abandoned at
/// rotation (§7.2 rotation mode — those records were folded
/// `epipe`), strike what landed (`tap_recovered`), and file the
/// `rotation_tail` note (matched seqs beyond the declared span
/// extend it — normally zero, honestly computed, never assumed).
fn reconcile_rotation(run: &mut Run) {
    let pending = run.stream.as_mut().and_then(|s| s.pending_reconcile.take());
    let Some(rot) = pending else {
        return;
    };
    // Bounded tail read (worker): the last 8 MiB + the identity
    // gate (reconcile only the file the rename produced — a
    // replaced path reconciles nothing).
    let tail_budget = close_budget(run);
    let tail_poll = run_wait_poll!(run);
    let tail: Control<(std::io::Result<Vec<Vec<u8>>>, bool)> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        "rotation_tail_read",
        Destination {
            class: DestClass::TapWrite,
            key: format!("tail-{}-{}", rot.first, rot.last),
        },
        tail_budget,
        Some(&tail_poll),
        {
            let (path, dev, ino) = (rot.rotated.clone(), rot.dev, rot.ino);
            move |_gate| {
                let lines = crate::service::stream::read_tail_lines(&path, 8 << 20);
                let same = {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata(&path)
                        .map(|m| (m.dev(), m.ino()) == (dev, ino))
                        .unwrap_or(false)
                };
                WorkerOut::value((lines, same))
            }
        },
    );
    let Control::Done((Ok(lines), true)) = tail else {
        // Tail unreadable or identity replaced: reconciling nothing
        // is the honest outcome (a replaced file's bytes are not
        // this run's evidence). Still file the note (zero extras —
        // the reconcile RAN, it matched nothing).
        run.summary
            .rotation_tail
            .push(crate::service::envelope::RotationTail {
                file: rot.rotated.to_string_lossy().into_owned(),
                extra_records: 0,
                extra_bytes: 0,
            });
        truncate_rotation_tail(&mut run.summary);
        return;
    };
    let matched_op_ids = {
        let s = match run.stream.as_ref() {
            Some(s) => s,
            None => return,
        };
        crate::service::stream::reconcile_tail(&lines, &s.inflight)
    };
    let mut extra_records = 0u64;
    let mut extra_bytes = 0u64;
    {
        let s = run.stream.as_mut().expect("stream state vanished");
        for op_id in &matched_op_ids {
            if let Some(rec) = s.inflight.iter().find(|r| r.op_id == *op_id) {
                // Struck from the (epipe-folded) ledger + counted
                // recovered (delivered-exactly-once: the fold
                // claimed the drop, the tail proves the landing —
                // NET corrects, gross stands; a proof post-delivery
                // still credits — R4 finding 1, same rule as the
                // receipt/tail rungs).
                let seq = rec.seq.unwrap_or(rot.last);
                let full = rec.full_bytes();
                let struck = s.queue.strike(
                    seq,
                    full,
                    crate::service::envelope::DropReason::Epipe,
                    rec.fold_token,
                );
                let (r, b) = credit_proven_landing(struck, full, rec.fold_token);
                // Rotation content-match proves the landing (same
                // proof as the active tail) — a landed marker is
                // delivered (R3 Gate 4 F4 — mirrors the regular
                // tail path).
                if rec.kind == "drop-marker" {
                    s.queue.clear_marker(seq);
                }
                run.summary.tap_recovered.records += r;
                run.summary.tap_recovered.bytes += b;
                if seq < rot.first || seq > rot.last {
                    extra_records += r;
                    extra_bytes += b;
                }
            }
        }
        s.inflight.retain(|r| !matched_op_ids.contains(&r.op_id));
    }
    run.summary
        .rotation_tail
        .push(crate::service::envelope::RotationTail {
            file: rot.rotated.to_string_lossy().into_owned(),
            extra_records,
            extra_bytes,
        });
    truncate_rotation_tail(&mut run.summary);
}

/// Cap `rotation_tail[]` at the most recent 4096 + overflow (§6.2).
fn truncate_rotation_tail(accum: &mut SummaryAccum) {
    while accum.rotation_tail.len() > 4096 {
        accum.rotation_tail.remove(0);
        accum.rotation_tail_overflow += 1;
    }
}

/// Rotation decision (regular-file taps only, ≥1 record assigned):
/// EITHER threshold fires at the boundary. The active size is a
/// true file length (worker stat — pre-existing bytes count).
fn rotation_fires(run: &mut Run) -> bool {
    let Some(s) = run.stream.as_ref() else {
        return false;
    };
    if s.active_records == 0 {
        return false;
    }
    let is_fifo = matches!(s.tap, Tap::Open(ref t) if t.ident.is_fifo);
    if is_fifo {
        return false;
    }
    // Zero-record files never rotate (age clock restarts below).
    let Some(first_wall) = s.first_record_wall else {
        return false;
    };
    let size_budget = close_budget(run);
    let size_poll = run_wait_poll!(run);
    let size: Control<Option<u64>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        "tap_size_check",
        Destination {
            class: DestClass::TapWrite,
            key: "tap-size".to_string(),
        },
        size_budget,
        Some(&size_poll),
        {
            let path = s.tap_path.clone();
            move |_gate| WorkerOut::value(std::fs::metadata(&path).map(|m| m.len()).ok())
        },
    );
    let Control::Done(Some(len)) = size else {
        return false;
    };
    let age = first_wall.elapsed().as_secs();
    rotation_due(
        len,
        age,
        run.cfg.rotate_bytes,
        run.cfg.rotate_interval.as_secs(),
    )
}

/// Rotation outcome: renamed, deferred (retry next boundary), or
/// held-name fatal (exit 1, never a skip).
enum RotationOut {
    Rotated,
    Deferred,
    Held,
}

/// Rename the active tap aside (fenced Rotate worker — the rename
/// is the ONE destination mutation). On success the tap returns to
/// pending (fresh fd next drive — the old fd names the rotated
/// file now) and the reconcile pends for the next boundary.
fn rotate_active(run: &mut Run, seq: u64) -> RotationOut {
    let (active, first, last) = match run.stream.as_ref() {
        Some(s) => match (s.active_first, s.active_last) {
            (Some(f), Some(l)) => (s.tap_path.clone(), f, l),
            _ => return RotationOut::Deferred,
        },
        None => return RotationOut::Deferred,
    };
    let rotated = active.with_file_name(rotated_name(first, last));
    let rename_budget = close_budget(run);
    let rename_poll = run_wait_poll!(run);
    let renamed: Control<Result<(), String>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("rotate_stream_{seq}"),
        Destination {
            class: DestClass::Rotate,
            key: "tap-rotate".to_string(),
        },
        rename_budget,
        Some(&rename_poll),
        {
            let (active, rotated) = (active.clone(), rotated.clone());
            move |gate| {
                // Fenced re-check before the ONE rename (F3: never
                // initiate past abandonment).
                if gate.abandoned() {
                    return WorkerOut::value(Err("abandoned".to_string()));
                }
                WorkerOut::value(rotate_file(&active, &rotated))
            }
        },
    );
    match renamed {
        Control::Done(Ok(())) => {}
        Control::Done(Err(e)) if e.starts_with("rotated stream name held") => {
            diag_line(&run.diag, &run.format, "error", &e);
            return RotationOut::Held;
        }
        _ => {
            // Rename abandoned/failed/transient: DEFER to the next
            // boundary (the active file keeps receiving — the ONLY
            // fatal rename is the held name).
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                "rotation deferred to next boundary",
            );
            return RotationOut::Deferred;
        }
    }
    // Rename won: snapshot the rotated file's (len, dev, ino) for
    // the tail window + identity gate (worker stat — the rename
    // preserves identity, so this names the produced file).
    let stat_budget = close_budget(run);
    let stat_poll = run_wait_poll!(run);
    let stat: Control<Option<(u64, u64, u64)>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        "rotated_size_check",
        Destination {
            class: DestClass::TapWrite,
            key: "rotated-size".to_string(),
        },
        stat_budget,
        Some(&stat_poll),
        {
            let rotated = rotated.clone();
            move |_gate| {
                use std::os::unix::fs::MetadataExt;
                WorkerOut::value(
                    std::fs::metadata(&rotated)
                        .map(|m| (m.len(), m.dev(), m.ino()))
                        .ok(),
                )
            }
        },
    );
    let Control::Done(stat) = stat else {
        // Identity unknown: reconcile from 0 with a wildcard gate
        // (dev/ino 0 — the gate compares against the stat the
        // reconcile worker takes; 0 never matches a real file, so
        // the reconcile honestly matches nothing).
        if let Some(s) = run.stream.as_mut() {
            s.pending_reconcile = Some(PendingRotation {
                rotated,
                dev: 0,
                ino: 0,
                first,
                last,
            });
            reset_active_file(s);
        }
        return RotationOut::Rotated;
    };
    if let Some(s) = run.stream.as_mut() {
        let (_, dev, ino) = stat.unwrap_or((0, 0, 0));
        s.pending_reconcile = Some(PendingRotation {
            rotated,
            dev,
            ino,
            first,
            last,
        });
        reset_active_file(s);
    }
    RotationOut::Rotated
}

/// Reset the active-file assignment after a rotation (fresh fd next
/// drive — the old fd names the rotated file).
fn reset_active_file(s: &mut StreamState) {
    s.tap = Tap::pending();
    s.first_record_wall = None;
    s.active_first = None;
    s.active_last = None;
    s.active_records = 0;
}

/// Enqueue this boundary's marker (covering all uncleared spans) +
/// window-ref (§§5.2, 10 — marker first: evictions predate the ref,
/// chronological). Both assign to the CURRENT active file. One
/// marker per boundary max (none since → no marker).
fn enqueue_boundary_records(run: &mut Run, seq: u64, sha256: &str) {
    use crate::service::envelope::StreamRecord;
    use crate::service::queue::QueuedRecord;
    let Some(s) = run.stream.as_mut() else {
        return;
    };
    if s.queue.has_pending_spans() {
        let marker = StreamRecord::DropMarker {
            schema: crate::service::envelope::SCHEMA_WINDOW.to_string(),
            at_seq: seq,
            generation: run.generation,
            stream_gaps: s.queue.spans(),
        };
        // Cover BEFORE enqueue: the marker's own eviction (if any)
        // folds into the same span as uncovered growth → the next
        // boundary's marker re-covers it (marker-specific deltas;
        // the delayed marker covers old + new, §5.2). Marker
        // identity = the window seq (unique per run: seqs
        // increase, ≤1 marker/boundary).
        s.queue.mark_all(seq);
        if let Ok(line) = serde_json::to_vec(&marker) {
            s.queue.enqueue(QueuedRecord { seq, bytes: line });
            assign_active(s, seq);
        }
    }
    let reference = StreamRecord::WindowRef {
        schema: crate::service::envelope::SCHEMA_WINDOW.to_string(),
        generation: run.generation,
        seq,
        sha256: sha256.to_string(),
    };
    if let Ok(line) = serde_json::to_vec(&reference) {
        s.queue.enqueue(QueuedRecord { seq, bytes: line });
        assign_active(s, seq);
    }
}

/// Assign one record's seq to the active file's declared span (the
/// rotation age clock starts on the file's first ASSIGNED record).
fn assign_active(s: &mut StreamState, seq: u64) {
    s.active_first = Some(s.active_first.map(|f| f.min(seq)).unwrap_or(seq));
    s.active_last = Some(s.active_last.map(|l| l.max(seq)).unwrap_or(seq));
    s.active_records += 1;
    if s.first_record_wall.is_none() {
        s.first_record_wall = Some(Instant::now());
    }
}

/// Tap destination key (TapWrite — one live writer per tap).
fn tap_dest(run: &Run) -> Destination {
    Destination {
        class: DestClass::TapWrite,
        key: format!(
            "tap-{}",
            run.stream
                .as_ref()
                .map(|s| s.tap_path.display().to_string())
                .unwrap_or_default()
        ),
    }
}

/// Tap-slot readiness (R4 finding 1): a finished prior receipt
/// reconciles BEFORE tap reuse/marker delivery — never
/// consumed-and-dropped by an availability probe. Returns false
/// when a live worker owns the slot (retry next boundary); true
/// when the slot is free (a finished receipt reconciled, or an
/// empty/settled slot consumed).
fn tap_slot_ready(run: &mut Run, abandon_cause: crate::service::envelope::DropReason) -> bool {
    let dest = tap_dest(run);
    match peek_slot(&dest) {
        None => true,
        Some(v) if v.live => false,
        Some(v) => {
            if let Some(receipt) = v.receipt {
                let owned = run
                    .stream
                    .as_ref()
                    .is_some_and(|s| s.inflight.iter().any(|r| r.op_id == receipt.op_id));
                if owned {
                    reconcile_tap_write(run, receipt.op_id, abandon_cause);
                    // The reconcile consumed the slot; re-peek
                    // defensively (anything but free retries next
                    // boundary — never proceed while occupied).
                    return peek_slot(&tap_dest(run)).is_none();
                }
            }
            // Receiptless, or an already-settled owner's redundant
            // receipt (rotation/prior recheck credited it): consume
            // and proceed.
            view_slot(&dest);
            true
        }
    }
}

/// Drive the tap (§§5.2–5.3, 7.2): open while pending (every
/// boundary), then pop+write while open and queued
/// (MAX_OUTSTANDING_TAP = 1 — a registered prior refuses the
/// successor; in-run abandonment folds `epipe`, shutdown folds
/// `stream_abandoned`).
/// Drive the tap; returns true iff the tap failed CLOSED on a
/// post-open reserved identity (the run must end as a tool
/// failure — `run.tool_failure` is already set).
fn drive_tap(run: &mut Run) -> bool {
    // Shutdown cutoff is handled by the close path (this drive is
    // the in-run form — `epipe` folds, no deadline).
    drive_tap_inner(run, crate::service::envelope::DropReason::Epipe, None)
}

fn drive_tap_inner(
    run: &mut Run,
    abandon_cause: crate::service::envelope::DropReason,
    cutoff: Option<Instant>,
) -> bool {
    use crate::service::stream::WriteOutcome;
    if run.stream.is_none() {
        return false;
    }
    // Open while pending (every boundary; ENXIO-class failures stay
    // pending — records accumulate + evict oldest as queue_full).
    if !run.stream.as_ref().expect("stream state").tap.is_open() {
        let dest = tap_dest(run);
        // A finished prior receipt reconciles before tap reuse (R4
        // finding 1); a live prior refuses the successor
        // (fail-closed — retry next boundary, never concurrent).
        if !tap_slot_ready(run, abandon_cause) {
            return false;
        }
        let open_budget = close_budget(run);
        let open_poll = run_wait_poll!(run);
        let opened: Control<Result<Tap, TapOpenError>> = run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            "tap_open",
            dest,
            open_budget,
            Some(&open_poll),
            {
                let path = run.stream.as_ref().expect("stream state").tap_path.clone();
                let out = run.out.clone();
                move |_gate| WorkerOut::value(Tap::open_checked(&path, &out))
            },
        );
        match opened {
            Control::Done(Ok(tap)) => {
                if let Some(s) = run.stream.as_mut() {
                    s.tap = tap;
                }
            }
            Control::Done(Err(TapOpenError::Identity)) => {
                // Post-open reserved match (§4.1): the fd closed
                // pre-write; the run fails as a run-level tool
                // failure (the §7.3 fold resolves 1/4).
                run.tool_failure = Some(RunToolFailure::SinkIdentity);
                diag_line(
                    &run.diag,
                    &run.format,
                    "error",
                    "stream tap aliases out-DIR evidence or state (post-open identity)",
                );
                return true;
            }
            _ => return false,
        }
    }
    // Pop + write while open and queued (one op per record — the
    // tap ping-pongs through the worker and back).
    loop {
        // Shutdown cutoff: double-signal or grace expiry stops the
        // flush between records (leftovers fold `stream_abandoned`
        // at the close path). Signals drain between records so a
        // mid-flush double is observed promptly.
        if cutoff.is_some() {
            let sigs = run.signals.drain();
            consume_signals(run, sigs);
            if double_observed(run) || cutoff.is_some_and(|d| Instant::now() >= d) {
                return false;
            }
        }
        let dest = tap_dest(run);
        // A finished prior receipt (this drive's or an earlier
        // boundary's) reconciles before the next dispatch (R4
        // finding 1); a live prior stops the drive here.
        if !tap_slot_ready(run, abandon_cause) {
            return false;
        }
        let popped = run.stream.as_mut().and_then(|s| s.queue.pop());
        let Some(record) = popped else {
            return false;
        };
        // Records are identified from their rendered bytes (kind +
        // seq/at_seq — exact, no parallel bookkeeping to desync).
        let (kind, at_seq) = stream_record_identity(&record.bytes);
        let is_marker = kind == "drop-marker";
        let tap = match run
            .stream
            .as_mut()
            .map(|s| std::mem::replace(&mut s.tap, Tap::pending()))
        {
            Some(Tap::Open(t)) => t,
            _ => {
                // Tap closed under us (rotation raced? — no: rotation
                // runs before the drive at each boundary; this is
                // Long-Term-Cutoff (shutdown) — requeue + stop.
                if let Some(s) = run.stream.as_mut() {
                    s.queue.enqueue(record);
                }
                return false;
            }
        };
        let op_id = run.stream.as_ref().expect("stream state").next_op_id;
        let tap_is_fifo = tap.ident.is_fifo;
        if let Some(s) = run.stream.as_mut() {
            s.next_op_id += 1;
            s.inflight.push(crate::service::stream::InflightRecord {
                op_id,
                content: record.bytes.clone(),
                kind: kind.clone(),
                seq: Some(at_seq),
                span: None,
                fifo: tap_is_fifo,
                fold_token: 0,
            });
        }
        let seq_for_fold = at_seq;
        let bytes_for_fold = record.bytes.len() as u64 + 1;
        let write_budget = close_budget(run);
        let write_poll = run_wait_poll!(run);
        let written: Control<(crate::service::stream::OpenTap, WriteOutcome)> = run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            &format!("tap_write_{op_id}"),
            dest.clone(),
            write_budget,
            Some(&write_poll),
            move |_gate| {
                // P-class: no fenced re-check (the write is never
                // revoked — abandoned writes reconcile). EINTR
                // without a byte retries INSIDE the worker (before
                // ANY other state change, §5.3).
                let mut tap = tap;
                let outcome = loop {
                    match tap.write_record(&record.bytes) {
                        WriteOutcome::Failed { errno } if errno == libc::EINTR => continue,
                        other => break other,
                    }
                };
                let receipt_state = match outcome {
                    WriteOutcome::Complete { bytes } => {
                        crate::service::worker::TapReceiptState::Complete { bytes }
                    }
                    WriteOutcome::Partial { written, .. } => {
                        crate::service::worker::TapReceiptState::Partial { bytes: written }
                    }
                    WriteOutcome::Failed { errno } => {
                        crate::service::worker::TapReceiptState::Failed { errno }
                    }
                };
                let receipt = crate::service::worker::TapReceipt {
                    op_id,
                    state: receipt_state,
                    kind,
                    seq: Some(at_seq),
                    span: None,
                    record_bytes: bytes_for_fold,
                    dest_path: tap.ident.path.display().to_string(),
                    dest_dev: tap.ident.dev,
                    dest_ino: tap.ident.ino,
                };
                WorkerOut {
                    value: (tap, outcome),
                    receipt: Some(receipt),
                }
            },
        );
        match written {
            Control::Done((tap, outcome)) => {
                // The tap returns (its clean/written state updated
                // by the write) — store it back, then judge.
                let is_fifo = tap.ident.is_fifo;
                if let Some(s) = run.stream.as_mut() {
                    s.tap = Tap::Open(tap);
                    s.inflight.retain(|r| r.op_id != op_id);
                }
                match outcome {
                    WriteOutcome::Complete { .. } => {
                        if is_marker {
                            if let Some(s) = run.stream.as_mut() {
                                s.queue.clear_marker(at_seq);
                            }
                        }
                    }
                    WriteOutcome::Partial { .. } | WriteOutcome::Failed { .. } => {
                        let errno = match outcome {
                            WriteOutcome::Failed { errno } => errno,
                            _ => -1,
                        };
                        if let Some(s) = run.stream.as_mut() {
                            s.queue.fold(seq_for_fold, bytes_for_fold, abandon_cause);
                            // A failed/partial marker never proves
                            // delivery (R3 Gate 4 F4 — the record
                            // leaves in-flight; no reconcile will
                            // ever prove it, so it retires).
                            if is_marker {
                                s.queue.retire_marker(at_seq);
                            }
                        }
                        diag_line(
                            &run.diag,
                            &run.format,
                            "warn",
                            &format!("tap write failed (errno {errno})"),
                        );
                        if errno == libc::EPIPE {
                            // Disconnect: close the fd, return to
                            // pending (boundary-retry), stop driving.
                            if let Some(s) = run.stream.as_mut() {
                                s.tap = Tap::pending();
                            }
                            return false;
                        }
                        if is_fifo {
                            // FIFO non-EPIPE errors fail closed to
                            // pending (same disposition as ENXIO).
                            if let Some(s) = run.stream.as_mut() {
                                s.tap = Tap::pending();
                            }
                            return false;
                        }
                        // Regular-file non-EPIPE (ENOSPC family):
                        // the tap stays open for the next record.
                    }
                }
            }
            _ => {
                // Worker gone (expired/cancelled/never-spawned): the
                // tap fd went with it (P3 late bytes permitted) —
                // fold the FULL record bytes (whole-record rule) and
                // reconcile (receipt → strike; no-receipt regular →
                // tail re-read; FIFO → uncertain). Stop driving:
                // the successor is refused while registered.
                if let Some(s) = run.stream.as_mut() {
                    let token = s.queue.fold(seq_for_fold, bytes_for_fold, abandon_cause);
                    if let Some(inflight) = s.inflight.iter_mut().find(|r| r.op_id == op_id) {
                        inflight.fold_token = token;
                    }
                    s.tap = Tap::pending();
                }
                reconcile_tap_write(run, op_id, abandon_cause);
                return false;
            }
        }
    }
}

/// Retire a dead marker's coverage delta (R3 Gate 4 F4): the
/// marker will never deliver (failed dispatch / failed receipt /
/// uncertain / never-landing), so its claim merges away.
/// Evictions retire queue-internally; every other death reports
/// here. Non-markers no-op.
fn retire_if_marker(queue: &mut StreamQueue, kind: &str, seq: u64) {
    if kind == "drop-marker" {
        queue.retire_marker(seq);
    }
}

/// Proven-landing credit (R4 finding 1): `strike` guards the
/// pending spans (post-delivery ⟹ no-op, never a
/// double-subtract); the GROSS credit is independent — a proven
/// landing credits its full bytes even when the spans no-op (gross
/// retains them; Control 1 subtracts recovery ONCE from gross).
/// Folded ops only (an unfolded op has no gross bytes to recover).
fn credit_proven_landing(struck: (u64, u64), full_bytes: u64, fold_token: u64) -> (u64, u64) {
    if struck == (0, 0) && fold_token != 0 {
        (1, full_bytes)
    } else {
        struck
    }
}

/// Settle one in-flight tap op from its worker receipt (the §7.2
/// outcome ladder's receipt rung): Complete → strike + credit (a
/// landed marker is delivered); Failed → the marker retires, the
/// record stays folded; Partial → stays in-flight for the tail
/// recheck.
fn settle_tap_receipt(
    run: &mut Run,
    rec: &crate::service::stream::InflightRecord,
    seq: u64,
    state: crate::service::worker::TapReceiptState,
    abandon_cause: crate::service::envelope::DropReason,
) {
    match state {
        crate::service::worker::TapReceiptState::Complete { .. } => {
            let full = rec.full_bytes();
            let struck = run.stream.as_mut().expect("stream state").queue.strike(
                seq,
                full,
                abandon_cause,
                rec.fold_token,
            );
            let (r, b) = credit_proven_landing(struck, full, rec.fold_token);
            run.summary.tap_recovered.records += r;
            run.summary.tap_recovered.bytes += b;
            if rec.kind == "drop-marker" {
                if let Some(s) = run.stream.as_mut() {
                    s.queue.clear_marker(seq);
                }
            }
            // Settles exactly once (no future recheck re-credits).
            if let Some(s) = run.stream.as_mut() {
                s.inflight.retain(|r| r.op_id != rec.op_id);
            }
        }
        crate::service::worker::TapReceiptState::Failed { .. } => {
            // Failed: the bytes never land (the worker is gone) —
            // a Failed marker retires (it never delivers). The
            // record stays in-flight until the next recheck drops
            // it as never-landing.
            if let Some(s) = run.stream.as_mut() {
                retire_if_marker(&mut s.queue, &rec.kind, seq);
            }
        }
        _ => {}
    }
}

/// Settle a consumed receipt's owner (R4 finding 1 — the tap slot
/// is shared, so a recheck can consume another op's receipt): the
/// owner settles from its own dispatch record; an already-settled
/// owner (rotation content-match, prior recheck) makes the receipt
/// redundant — never a second credit.
fn settle_receipt_owner(
    run: &mut Run,
    receipt: &crate::service::worker::TapReceipt,
    abandon_cause: crate::service::envelope::DropReason,
) {
    let owner = run.stream.as_ref().and_then(|s| {
        s.inflight
            .iter()
            .find(|r| r.op_id == receipt.op_id)
            .cloned()
    });
    let Some(rec) = owner else {
        return;
    };
    let seq = rec.seq.unwrap_or(0);
    settle_tap_receipt(run, &rec, seq, receipt.state, abandon_cause);
}

/// Receiptless reconcile (no worker receipt for this op): regular
/// files tail-re-read (bounded content-match — the L6 resync rule
/// covers resync-completed partials); FIFOs go uncertain (the bytes
/// may yet land, unprovable — no tail exists).
fn reconcile_receiptless(
    run: &mut Run,
    rec: &crate::service::stream::InflightRecord,
    seq: u64,
    abandon_cause: crate::service::envelope::DropReason,
    worker_live: bool,
) {
    if !rec.fifo {
        tail_reconcile_regular(run, rec, seq, abandon_cause, worker_live);
    } else {
        push_tap_uncertain(run, rec, seq);
    }
}

/// Reconcile one detached tap write (§7.2 outcome ladder):
/// receipt Complete → strike + `tap_recovered`; Partial/Failed →
/// stays folded (a Failed marker retires — its bytes never land);
/// no receipt + regular file → bounded tail re-read
/// (content-match → strike + recovered; absent + worker gone →
/// settle — never landing); no receipt + FIFO (or still
/// registered at cutoff) → `tap_uncertain` entry.
fn reconcile_tap_write(
    run: &mut Run,
    op_id: u64,
    abandon_cause: crate::service::envelope::DropReason,
) {
    let dest = tap_dest(run);
    let slot = view_slot(&dest);
    // The in-flight dispatch record (frozen at dispatch — the ONLY
    // source for what this op attempted).
    let inflight = run
        .stream
        .as_ref()
        .and_then(|s| s.inflight.iter().find(|r| r.op_id == op_id).cloned());
    let Some(rec) = inflight else {
        return;
    };
    let seq = rec.seq.unwrap_or(0);
    // Worker still live ⟺ the slot view says so (None ⟺ the worker
    // exited — consumed — or never spawned: nothing left to land).
    let worker_live = slot.as_ref().is_some_and(|v| v.live);
    match slot.and_then(|v| v.receipt) {
        Some(receipt) if receipt.op_id == op_id => {
            // The worker exited with its receipt: settle now.
            settle_tap_receipt(run, &rec, seq, receipt.state, abandon_cause);
        }
        Some(receipt) => {
            // Another op's receipt (the tap slot is shared): its
            // owner settles from it FIRST (R4 finding 1 — a
            // consumed receipt is never dropped); then this op
            // proceeds receiptless + worker-gone (it never owned
            // this slot, so no worker of its can still be live).
            settle_receipt_owner(run, &receipt, abandon_cause);
            reconcile_receiptless(run, &rec, seq, abandon_cause, false);
        }
        _ => {
            reconcile_receiptless(run, &rec, seq, abandon_cause, worker_live);
        }
    }
}

/// Bounded tail re-read for a no-receipt regular-file write (L6
/// content-match over the ACTIVE file — the detached worker's fd
/// still names it; rotation renames first, so a rotated-away file
/// reconciles under `reconcile_rotation` instead — the identity
/// gate keeps the two disjoint).
/// `worker_live` settles the tail-absent branch (R3 Gate 4 F4):
/// a live worker may yet land (stays in-flight for the next
/// boundary's recheck); a gone worker never lands (settle — the
/// fold stands, the entry drops). Callers run rotation first, so
/// this never drops a rotated match.
fn tail_reconcile_regular(
    run: &mut Run,
    rec: &crate::service::stream::InflightRecord,
    seq: u64,
    abandon_cause: crate::service::envelope::DropReason,
    worker_live: bool,
) {
    let tail_budget = close_budget(run);
    let tail_poll = run_wait_poll!(run);
    let tail: Control<std::io::Result<crate::service::stream::TailSplit>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("tail_reconcile_{}", rec.op_id),
        Destination {
            class: DestClass::TapWrite,
            key: format!("tail-active-{}", rec.op_id),
        },
        tail_budget,
        Some(&tail_poll),
        {
            let path = run.stream.as_ref().expect("stream state").tap_path.clone();
            move |_gate| WorkerOut::value(crate::service::stream::read_tail_split(&path, 8 << 20))
        },
    );
    let Control::Done(Ok((lines, held, truncated))) = tail else {
        // Tail unreadable: the bytes are unprovable → uncertain
        // (regular-file no-receipt with an unreadable tail is the
        // honest uncertain — not a silent fold).
        push_tap_uncertain(run, rec, seq);
        return;
    };
    let matched = crate::service::stream::reconcile_tail(&lines, std::slice::from_ref(rec));
    if matched.contains(&rec.op_id) {
        let full = rec.full_bytes();
        let struck = run.stream.as_mut().expect("stream state").queue.strike(
            seq,
            full,
            abandon_cause,
            rec.fold_token,
        );
        // A content-proven landing credits even post-delivery (R4
        // finding 1 — same rule as the receipt rung; exactly once:
        // the op leaves in-flight below).
        let (r, b) = credit_proven_landing(struck, full, rec.fold_token);
        run.summary.tap_recovered.records += r;
        run.summary.tap_recovered.bytes += b;
        if rec.kind == "drop-marker" {
            if let Some(s) = run.stream.as_mut() {
                s.queue.clear_marker(seq);
            }
        }
        if let Some(s) = run.stream.as_mut() {
            s.inflight.retain(|r| r.op_id != rec.op_id);
        }
    } else if worker_live {
        // Content absent with the worker still live: NOT proven
        // (the detached worker may land bytes after this read) —
        // the record stays in-flight for the next boundary's
        // recheck.
    } else if !truncated && !rec.content.is_empty() && held == rec.content {
        // Resync-completable (R5 finding 1): the worker is gone and
        // no complete line matches, but the record's FULL content
        // is the held unterminated suffix — the drive-phase resync
        // `\n` completes exactly this record reader-visible, so the
        // "never landing" removal must NOT fire here. The record
        // stays in-flight through the drive; the post-drive recheck
        // credits it through the match arm above exactly once (or
        // retains it again if the drive wrote nothing). A short
        // prefix (partial content) still settles below — resync
        // terminates it into a line that never matches.
    } else {
        // Content absent with the worker gone: never landing (no
        // worker to land it, no bytes to match — rotation already
        // ran, so no rotated match is pending either) — settle:
        // the fold stands (honestly pending) and the in-flight
        // entry drops (no future change possible). A marker that
        // never lands never delivers — retire it.
        if let Some(s) = run.stream.as_mut() {
            retire_if_marker(&mut s.queue, &rec.kind, seq);
            s.inflight.retain(|r| r.op_id != rec.op_id);
        }
    }
}

/// File one `tap_uncertain` entry (4096 cap + overflow, §6.2 —
/// the destination identity is the ACTIVE path's live truth...
/// — no: the uncertain destination is the DISPATCH-time identity.
/// The dispatch fd is gone with the worker; the receipt-less
/// reconcile cannot name (dev, ino) honestly → dev/ino 0 with the
/// path (unknown-identity marking, reported — never a fabricated
/// identity).
fn push_tap_uncertain(run: &mut Run, rec: &crate::service::stream::InflightRecord, seq: u64) {
    use crate::service::envelope::{TapUncertain, UncertainDest, UncertainRecord};
    let path = run
        .stream
        .as_ref()
        .map(|s| s.tap_path.display().to_string())
        .unwrap_or_default();
    run.summary.tap_uncertain.push(TapUncertain {
        op: format!("tap_write_{}", rec.op_id),
        record: UncertainRecord {
            kind: rec.kind.clone(),
            seq: Some(seq),
            span: None,
            bytes: rec.full_bytes(),
        },
        dest: UncertainDest {
            path,
            dev: 0,
            ino: 0,
        },
    });
    while run.summary.tap_uncertain.len() > 4096 {
        run.summary.tap_uncertain.remove(0);
        run.summary.tap_uncertain_overflow.ops += 1;
        run.summary.tap_uncertain_overflow.bytes += rec.full_bytes();
    }
    if let Some(s) = run.stream.as_mut() {
        // Uncertain records never prove — an uncertain marker
        // never delivers (R3 Gate 4 F4).
        retire_if_marker(&mut s.queue, &rec.kind, seq);
        s.inflight.retain(|r| r.op_id != rec.op_id);
    }
}

/// Step-5 commit + reserve (§4.3): commit this window AND reserve
/// the next in ONE write (mid-run there is no instant where N is
/// committed but N+1 is unreserved). Quota-stop diverts to the
/// seal-and-end path instead.
fn mid_window_commit(
    mut run: Run,
    close: Snapshot,
    effective_end_ns: u64,
    sinks: SinksOut,
    mode: CloseMode,
) -> BoundaryOut {
    // A double observed during the sinks expedites (R1 finding 3):
    // immediate stop, never commit-then-exit.
    if double_observed(&run) {
        return BoundaryOut::Exit(double_signal_exit(run));
    }
    let seq = run.cycle.as_ref().expect("window open at commit").seq;
    let next = seq.saturating_add(1);
    let terminal = mode == CloseMode::Terminal;
    if matches!(sinks, SinksOut::QuotaStop) {
        // Quota-stop (held rotation name / sink-identity tool
        // failure alike): the published window stands; seal the
        // reservation and end the run (the fold resolves exit 1 —
        // finalized windows exist).
        return BoundaryOut::Exit(seal_and_end(run, seq, terminal));
    }
    if mode != CloseMode::Mid {
        // Run-final (cancel cut or terminal): no next window — seal
        // the reservation and end the run.
        return BoundaryOut::Exit(seal_and_end(run, seq, terminal));
    }
    // Reload consumption (§3 — the SIGHUP flag becomes a pending
    // candidate or a recorded rejection at THIS boundary; adoption
    // at the next open below).
    consume_reload(&mut run);
    // Step 5 proper: next_seq = N+1, reserved = {N+1 fresh},
    // close_completed_ns = null (the sealed value carries to 1b).
    let window_ns = run.cfg.window.as_nanos().min(u128::from(u64::MAX)) as u64;
    let first_seq = run.first_seq.unwrap_or(seq);
    let (next_start, next_end) = requested_span(run.origin_ns, first_seq, next, window_ns);
    let bytes = serde_json::to_vec(&SequenceState {
        schema: crate::service::state::SCHEMA_SEQ.to_string(),
        generation: run.generation,
        next_seq: next,
        updated_wall_ns: wall_ns().unwrap_or(0),
        close_completed_ns: None,
        exhausted: false,
        run_id: run.run_id.clone(),
        reserved: Some(Reservation {
            seq: next,
            run_id: run.run_id.clone(),
            generation: run.generation,
            requested_start_ns: next_start,
            requested_end_ns: next_end,
            state: ReservationState::Open,
            reason: None,
            started: false,
        }),
    })
    .unwrap_or_default();
    let commit_budget = close_budget(&run);
    let (reflected, ts) = state_write_reconciled(
        &mut run,
        &format!("commit_window_{seq}"),
        "sequence.json",
        bytes,
        commit_budget,
    );
    match reflected {
        Ok(true) => {
            run.summary.pending_close_completed = ts;
            run.summary.last_commit_ts = ts.or(run.summary.last_commit_ts);
        }
        _ => {
            // State-commit failure after publish (§4.3 step 5): a
            // run-level tool failure (priority 4) — the published
            // window stands (recovery adopts it); try the seal once
            // (a commit-shaped write — success commits N durably),
            // then end through the table.
            run.tool_failure = Some(RunToolFailure::StateCommit);
            diag_line(
                &run.diag,
                &run.format,
                "error",
                &format!("window {seq}: step-5 commit failed"),
            );
            return BoundaryOut::Exit(seal_and_end(run, seq, terminal));
        }
    }
    open_next_window(run, next, next_start, next_end, close, effective_end_ns)
}

/// Reload consumption (§3 — at the boundary, never mid-window):
/// the SIGHUP flag becomes a pending candidate (displacing any
/// older pending, counted) or a recorded rejection (three ways:
/// status file at open below, stderr line, summary count). At most
/// one pending candidate ever exists.
fn consume_reload(run: &mut Run) {
    if !run.reload_pending.load(Ordering::SeqCst) {
        return;
    }
    run.reload_pending.store(false, Ordering::SeqCst);
    let Some(path) = run.cfg.policy.clone() else {
        // No policy file configured: the HUP names no candidate —
        // ignore (a diagnostic, never a fabricated rejection).
        diag_line(
            &run.diag,
            &run.format,
            "info",
            "SIGHUP with no --policy: ignored",
        );
        return;
    };
    let reload_budget = close_budget(run);
    let reload_poll = run_wait_poll!(run);
    let read: Control<Result<Vec<u8>, String>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        "reload_policy_read",
        state_dest("policy-read"),
        reload_budget,
        Some(&reload_poll),
        {
            let path = path.clone();
            move |_gate| WorkerOut::value(read_policy_snapshot(&path))
        },
    );
    let bytes = match read {
        Control::Done(Ok(b)) => b,
        Control::Done(Err(reason)) => {
            run.policy.rejected += 1;
            run.policy.last_rejection = Some(PolicyRejection {
                at_wall_ns: wall_ns().unwrap_or(0),
                reason: crate::report::bound_line(&reason),
                attempted_path: path.to_string_lossy().into_owned(),
                attempted_sha256: None,
            });
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                &format!("policy reload rejected: {reason}"),
            );
            return;
        }
        _ => {
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                "policy reload read abandoned",
            );
            return;
        }
    };
    match crate::policy_config::admit_snapshot(&bytes) {
        Ok(admission) => {
            if run.policy.pending.is_some() {
                run.policy.displaced += 1;
            }
            run.policy.pending = Some(PendingPolicy {
                ident: PolicyIdentity {
                    path: path.to_string_lossy().into_owned(),
                    sha256: admission.sha256,
                    version: admission.version,
                    rule_count: admission.rule_count,
                    adopted_seq: None,
                },
                rules: admission.ruleset,
            });
        }
        Err(reason) => {
            run.policy.rejected += 1;
            run.policy.last_rejection = Some(PolicyRejection {
                at_wall_ns: wall_ns().unwrap_or(0),
                reason: crate::report::bound_line(&reason),
                attempted_path: path.to_string_lossy().into_owned(),
                attempted_sha256: Some(crate::kinds::prov_hash(&bytes)),
            });
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                &format!("policy reload rejected: {reason}"),
            );
        }
    }
}

/// Next-window open (§§2, 3, 4.3): 1a-VERIFY the step-5
/// reservation (fatal integrity refusal on mismatch, exit 1) →
/// adopt any pending policy → 1b flip + seal → chained `Cycle`
/// (open IS the previous close; effective_start IS the previous
/// effective end; the carried tick preloaded).
fn open_next_window(
    mut run: Run,
    next: u64,
    next_start: u64,
    next_end: u64,
    close: Snapshot,
    effective_end_ns: u64,
) -> BoundaryOut {
    // A double observed during the commit expedites (R1 finding 3):
    // immediate stop, never verify-then-exit (a Cancelled verify
    // would otherwise misread as an integrity refusal).
    if double_observed(&run) {
        return BoundaryOut::Exit(double_signal_exit(run));
    }
    // 1a-VERIFY: re-read + check the reservation names N+1 fresh
    // (step 5 wrote it; anything else is a fatal integrity
    // refusal — exit 1, never a skip).
    let verify_budget = close_budget(&run);
    let verify_poll = run_wait_poll!(run);
    let reread: Control<Option<Vec<u8>>> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("verify_reserve_{next}"),
        Destination {
            class: DestClass::StateMut,
            key: format!("reread-sequence-{next}"),
        },
        verify_budget,
        Some(&verify_poll),
        {
            let out = run.out.clone();
            move |_gate| WorkerOut::value(std::fs::read(out.join("sequence.json")).ok())
        },
    );
    let verified = match reread {
        Control::Done(Some(bytes)) => serde_json::from_slice::<SequenceState>(&bytes)
            .ok()
            .and_then(|s| s.reserved)
            .is_some_and(|r| {
                r.seq == next
                    && r.run_id == run.run_id
                    && r.generation == run.generation
                    && r.state == ReservationState::Open
                    && !r.started
                    && r.requested_start_ns == next_start
                    && r.requested_end_ns == next_end
            }),
        _ => false,
    };
    if !verified {
        diag_line(
            &run.diag,
            &run.format,
            "error",
            "reservation mismatch at next-window verify",
        );
        return BoundaryOut::Exit(integrity_exit(run, "reservation mismatch"));
    }
    // Adoption (W2: the pending candidate becomes active AT the
    // next window open — one atomic step with the open below).
    if let Some(pending) = run.policy.pending.take() {
        let mut ident = pending.ident;
        ident.adopted_seq = Some(next);
        run.policy.active = Some(ident);
        run.policy.active_rules = Some(pending.rules);
        run.policy.adopted += 1;
    }
    // Single policy-status write per boundary (covers admit + adopt
    // + rejection atomically — observability, never run-fatal).
    let status = PolicyStatus {
        schema: SCHEMA_POLICY.to_string(),
        active: run.policy.active.clone(),
        pending_valid: run.policy.pending.as_ref().map(|p| p.ident.clone()),
        pending_displaced: run.policy.displaced,
        last_rejection: run.policy.last_rejection.clone(),
    };
    let status_bytes = serde_json::to_vec(&status).unwrap_or_default();
    let status_budget = close_budget(&run);
    let (written, _) = state_write_reconciled(
        &mut run,
        "policy_status_write",
        "policy-status.json",
        status_bytes,
        status_budget,
    );
    if !matches!(written, Ok(true)) {
        diag_line(&run.diag, &run.format, "warn", "policy status write failed");
    }
    // 1b: flip `started` + seal the carried close instant (the
    // pending value from step 5 — the pairing rule, §4.3).
    let seal = run.summary.pending_close_completed.take();
    let state_bytes = serde_json::to_vec(&SequenceState {
        schema: crate::service::state::SCHEMA_SEQ.to_string(),
        generation: run.generation,
        next_seq: next,
        updated_wall_ns: wall_ns().unwrap_or(0),
        close_completed_ns: seal,
        exhausted: false,
        run_id: run.run_id.clone(),
        reserved: Some(Reservation {
            seq: next,
            run_id: run.run_id.clone(),
            generation: run.generation,
            requested_start_ns: next_start,
            requested_end_ns: next_end,
            state: ReservationState::Open,
            reason: None,
            started: true,
        }),
    })
    .unwrap_or_default();
    // The 1b seal value escapes into the summary when the flip
    // fails (the carried sealed value — the summary still pairs
    // the last finalized window honestly, §4.3).
    let open_budget = close_budget(&run);
    let (reflected, _) = state_write_reconciled(
        &mut run,
        &format!("open_window_{next}"),
        "sequence.json",
        state_bytes,
        open_budget,
    );
    if !matches!(reflected, Ok(true)) {
        run.summary.pending_close_completed = seal;
        run.tool_failure = Some(RunToolFailure::StateCommit);
        diag_line(
            &run.diag,
            &run.format,
            "error",
            &format!("window {next}: 1b open flip failed"),
        );
        // The previous window stands committed (step 5 won); the
        // seal converts the un-openable N+1 reservation into the
        // honest committed seal, then the run ends via the table.
        let seq = next.saturating_sub(1);
        return BoundaryOut::Exit(seal_and_end(run, seq, false));
    }
    // Chained cycle: open IS the previous close (same object),
    // effective_start IS the previous effective end, the carried
    // tick preloaded (admitted-first — every window consumes at
    // least its carried tick).
    let old = run.cycle.take().expect("window open at next-open");
    let (staging, carried_in) = match old.carry_out {
        Some(carry) => {
            let tick = carry
                .staged
                .first()
                .map(|r| r.tick)
                .or_else(|| carry.spilled.first().map(|r| r.tick));
            let from = carry.from_seq;
            (Staging::with_carry(carry), tick.map(|t| (from, t)))
        }
        None => (Staging::new(), None),
    };
    run.cycle = Some(Cycle {
        seq: next,
        requested_start_ns: next_start,
        requested_end_ns: next_end,
        effective_start_ns: effective_end_ns,
        open: close,
        staging,
        piece: TickPiece::open(run.tick_id),
        carry_out: None,
        carried_in,
        open_tick_id: run.tick_id,
        fatal: None,
        accum_exceeded: None,
        accum_cut: false,
    });
    BoundaryOut::Continue(Box::new(run))
}

/// Seal the run's final window and end (§4.3 seal path):
/// `next_seq` = N+1, reserved = {N, committed}, `exhausted` for the
/// terminal seal. `final_close_completed_ns` = the carried sealed
/// value when one pends (the 1b-failure path — N's first durable
/// commit was its step-5), else the seal's own commit instant.
fn seal_and_end(mut run: Run, seq: u64, terminal: bool) -> ExitCode {
    // A double observed upstream expedites (R1 finding 3).
    if double_observed(&run) {
        return double_signal_exit(run);
    }
    // Run-ending tail: mint the shutdown deadline when no close
    // has one yet (mid-close diversion — R1 finding 3).
    mint_close_deadline(&mut run);
    let (req_start, req_end) = match run.cycle.as_ref() {
        Some(cycle) => (cycle.requested_start_ns, cycle.requested_end_ns),
        None => (0, 0),
    };
    let bytes = serde_json::to_vec(&SequenceState {
        schema: crate::service::state::SCHEMA_SEQ.to_string(),
        generation: run.generation,
        next_seq: seq.saturating_add(1),
        updated_wall_ns: wall_ns().unwrap_or(0),
        close_completed_ns: None,
        exhausted: terminal,
        run_id: run.run_id.clone(),
        reserved: Some(Reservation {
            seq,
            run_id: run.run_id.clone(),
            generation: run.generation,
            requested_start_ns: req_start,
            requested_end_ns: req_end,
            state: ReservationState::Committed,
            reason: None,
            started: true,
        }),
    })
    .unwrap_or_default();
    let seal_budget = close_budget(&run);
    let (reflected, ts) = state_write_reconciled(
        &mut run,
        &format!("seal_window_{seq}"),
        "sequence.json",
        bytes,
        seal_budget,
    );
    run.summary.final_close_completed_ns = run.summary.pending_close_completed.take().or(ts);
    if !matches!(reflected, Ok(true)) {
        // Seal failure: the published window stands (recovery
        // adopts it); first failure wins (a set tool_failure is
        // never overwritten — the seal is the terminal commit, so
        // a bare seal failure is `StateCommit`).
        if run.tool_failure.is_none() {
            run.tool_failure = Some(RunToolFailure::StateCommit);
        }
        diag_line(
            &run.diag,
            &run.format,
            "error",
            &format!("window {seq}: seal write failed"),
        );
    }
    run.cycle = None;
    close_run_end(run)
}

/// Abandon the open window and end the run (§4.2 abandonment: the
/// seq is permanently gapped, never reused; the next start resumes
/// at N+1 via the §4.4 gap row). `close_at_ns` = the observation
/// end for post-close abandonments (publish/assemble stage — the
/// coverage is `[effective_start, close]`); pre-close abandonments
/// (spill failure — the window never closed) cut at the mark
/// instant.
fn abandon_window(mut run: Run, reason: AbandonReason, close_at_ns: Option<u64>) -> ExitCode {
    // A double observed upstream expedites with the DoubleSignal
    // disposition (R1 finding 3) — never the caller's mapping.
    if double_observed(&run) {
        return double_signal_exit(run);
    }
    // Run-ending tail: mint the shutdown deadline when no close
    // has one yet (R1 finding 3).
    mint_close_deadline(&mut run);
    close_gate(&mut run);
    let cycle = run.cycle.take().expect("window open at abandon");
    let mark = serde_json::to_vec(&SequenceState {
        schema: crate::service::state::SCHEMA_SEQ.to_string(),
        generation: run.generation,
        next_seq: cycle.seq.saturating_add(1),
        updated_wall_ns: wall_ns().unwrap_or(0),
        close_completed_ns: None,
        exhausted: false,
        run_id: run.run_id.clone(),
        reserved: Some(Reservation {
            seq: cycle.seq,
            run_id: run.run_id.clone(),
            generation: run.generation,
            requested_start_ns: cycle.requested_start_ns,
            requested_end_ns: cycle.requested_end_ns,
            state: ReservationState::Abandoned,
            reason: Some(reason),
            started: true,
        }),
    })
    .unwrap_or_default();
    let abandon_budget = close_budget(&run);
    let (reflected, ts) = state_write_reconciled(
        &mut run,
        &format!("abandon_window_{}", cycle.seq),
        "sequence.json",
        mark,
        abandon_budget,
    );
    if !matches!(reflected, Ok(true)) {
        diag_line(
            &run.diag,
            &run.format,
            "error",
            "abandonment mark failed (best-effort)",
        );
    }
    // The cut instant is the FIRST monotonic read after the
    // abandonment is marked (the mark write's own timestamp, else a
    // coordinator read — the state write already returned).
    let cut_ns = close_at_ns.or(ts).unwrap_or_else(monotonic_ns);
    run.summary
        .push_abandoned(crate::service::envelope::AbandonedNote {
            seq: cycle.seq,
            run_id: run.run_id.clone(),
            generation: run.generation,
            requested_start_ns: cycle.requested_start_ns,
            requested_end_ns: cycle.requested_end_ns,
            reason,
            cut_tail_ns: Some(crate::service::envelope::CutTail {
                effective_end_ns: cut_ns,
                requested_end_ns: cycle.requested_end_ns,
            }),
        });
    diag_line(
        &run.diag,
        &run.format,
        "warn",
        &format!("window {} abandoned ({reason:?})", cycle.seq),
    );
    close_run_end(run)
}

/// Swap the diagnostics worker at shutdown: abandon the run's
/// worker (its drop count enters the summary) and install a fresh
/// one for the summary write's own accounting. The fresh worker
/// carries only routine lines (`run_op` stays silent on `Done`;
/// failures also print synchronously), so its own uncounted drops
/// are zero in practice.
fn swap_diag(run: &mut Run) -> u64 {
    let old = std::mem::replace(&mut run.diag, Diagnostics::spawn());
    // Capped by the shutdown remainder (R1 finding 3 — the swap is
    // a close stage too; the worker only drains stderr, so the cap
    // binds only pathologically).
    old.abandon(cap_by_deadline(run, Duration::from_millis(200)))
}

/// Fatal integrity refusal (explicit exit 1, never a skip): the
/// message prints synchronously (fatal-integrity visibility — the
/// run is dying, the worker may be implicated) and the summary is
/// best-effort. No drain, no flush — immediate.
fn integrity_exit(mut run: Run, msg: &str) -> ExitCode {
    close_gate(&mut run);
    run.cycle = None;
    let dropped = swap_diag(&mut run);
    let mut summary = RunSummary::blank(run.run_id.clone(), run.generation, run.origin_ns);
    fill_summary(&mut run, &mut summary, dropped);
    summary.exit = 1;
    let bytes = serde_json::to_vec(&summary).unwrap_or_default();
    // Capped by the shutdown remainder when a close minted one (R1
    // finding 3 — the integrity exit is still a close stage).
    let integ_budget = cap_by_deadline(&run, Duration::from_secs(2));
    let wrote = state_write_reconciled(
        &mut run,
        "integrity_summary_write",
        "run-summary.json",
        bytes,
        integ_budget,
    );
    if !matches!(wrote.0, Ok(true)) {
        crate::report::err_line("osslscope service: integrity summary write failed");
    }
    let tail_cap = cap_by_deadline(&run, Duration::from_millis(200));
    let _ = run.diag.abandon(tail_cap);
    crate::report::err_line(&format!("osslscope service: integrity refusal: {msg}"));
    ExitCode::from(1)
}

/// Run end (§7): the stream flushes within `--grace` (single-signal
/// and tool-failure ends — the double-signal path cuts with no
/// flush), shutdown reconciliation settles every in-flight write,
/// the summary writes, and the §7.3 fold decides the exit. The
/// engine is never drained here (the final/terminal path drains
/// before its close; every other end leaves published windows +
/// the summary with no `End` — there is no open window for drain
/// bytes to ride).
fn close_run_end(mut run: Run) -> ExitCode {
    close_gate(&mut run);
    run.cycle = None;
    // The ONE shutdown deadline (R1 finding 3): minted at close
    // entry upstream — minted here only when no close ran (the
    // double-signal and uncertain paths). The flush cutoff and the
    // summary write share its remainder.
    mint_close_deadline(&mut run);
    let deadline = run.close_deadline.expect("minted above");
    // Shutdown flush (no flush on the double-signal cutoff — §7.1):
    // drive the tap within grace (delivery errors fold `epipe` —
    // the cause names the mechanism, not the phase), then fold
    // never-attempted leftovers as `stream_abandoned`.
    if !double_observed(&run) && run.stream.is_some() {
        // Identity failure (if any) already set `tool_failure`;
        // leftovers fold below and the fold resolves the exit.
        let _ = drive_tap_inner(
            &mut run,
            crate::service::envelope::DropReason::Epipe,
            Some(deadline),
        );
    }
    if let Some(s) = run.stream.as_mut() {
        while let Some(record) = s.queue.pop() {
            let bytes = record.bytes.len() as u64 + 1;
            s.queue.fold(
                record.seq,
                bytes,
                crate::service::envelope::DropReason::StreamAbandoned,
            );
            // Leftover markers never deliver (R3 Gate 4 F4).
            let (kind, at_seq) = stream_record_identity(&record.bytes);
            retire_if_marker(&mut s.queue, &kind, at_seq);
        }
    }
    // Last rotation-tail reconcile FIRST (the final boundary's
    // rename — content-matches settle before the per-op pass, so
    // the exited-never-landing rule below never drops a rotated
    // match).
    reconcile_rotation(&mut run);
    // Shutdown reconciliation: every in-flight write settles —
    // receipt/tail when the worker exited, `tap_uncertain` when it
    // is still registered at the cutoff (unprovable, never silent).
    let op_ids: Vec<u64> = run
        .stream
        .as_ref()
        .map(|s| s.inflight.iter().map(|r| r.op_id).collect())
        .unwrap_or_default();
    for op_id in op_ids {
        // Peek (non-consuming — R4 finding 1): the reconcile below
        // must see a finished receipt.
        let live = matches!(peek_slot(&tap_dest(&run)), Some(v) if v.live);
        if live {
            let rec = run
                .stream
                .as_ref()
                .and_then(|s| s.inflight.iter().find(|r| r.op_id == op_id).cloned());
            if let Some(rec) = rec {
                let seq = rec.seq.unwrap_or(0);
                push_tap_uncertain(&mut run, &rec, seq);
            }
        } else {
            reconcile_tap_write(&mut run, op_id, crate::service::envelope::DropReason::Epipe);
        }
    }
    // Diagnostics swap (the run worker's drop count enters the
    // summary; the fresh worker serves the summary write).
    let dropped = swap_diag(&mut run);
    let mut summary = RunSummary::blank(run.run_id.clone(), run.generation, run.origin_ns);
    fill_summary(&mut run, &mut summary, dropped);
    // The §7.3 fold (interrupted = cancel OR double-signal stop).
    let interrupted = run.cancel_latched.load(Ordering::SeqCst) || double_observed(&run);
    let code = run.fold.fold(run.tool_failure, interrupted);
    summary.exit = code;
    let bytes = serde_json::to_vec(&summary).unwrap_or_default();
    let wrote = state_write_reconciled(
        &mut run,
        "run_summary_write",
        "run-summary.json",
        bytes,
        deadline.saturating_duration_since(Instant::now()),
    );
    if !matches!(wrote.0, Ok(true)) {
        // Post-abandon last resort (the summary is evidence, not
        // gating — the exit proceeds regardless).
        crate::report::err_line("osslscope service: run summary write failed");
    }
    let tail_cap = cap_by_deadline(&run, Duration::from_millis(200));
    let _ = run.diag.abandon(tail_cap);
    ExitCode::from(code)
}

/// Fill a run summary from the accumulators (§7.3 — every field
/// the fold's callers and the §9 oracles read).
fn fill_summary(run: &mut Run, summary: &mut RunSummary, diagnostics_dropped: u64) {
    use crate::service::envelope::{ByReason, ReasonTotals};
    summary.first_seq = run.first_seq;
    summary.last_seq = run.summary.last_seq;
    summary.abandoned = std::mem::take(&mut run.summary.abandoned);
    summary.abandoned_overflow = run.summary.abandoned_overflow;
    summary.commit_recovered = run.summary.commit_recovered.clone();
    summary.orphan_cut_tail = run.summary.orphan_cut_tail.clone();
    summary.durability_uncertain = run.summary.durability_uncertain.clone();
    // `final_close_completed_ns`: the seal path's value first,
    // else the last commit instant ("the first read after the last
    // commit fsync", §4.3).
    summary.final_close_completed_ns = run
        .summary
        .final_close_completed_ns
        .or(run.summary.last_commit_ts);
    summary.close_unmeasured = std::mem::take(&mut run.summary.close_unmeasured);
    summary.reloads_adopted = run.policy.adopted;
    summary.reloads_rejected = run.policy.rejected;
    summary.windows_cut_accum = run.summary.windows_cut_accum;
    summary.quota_exceeded = run.summary.quota_exceeded.clone();
    if let Some(s) = run.stream.as_ref() {
        let (records, bytes) = s.queue.gross();
        let (qf_r, qf_b) = s
            .queue
            .gross_by_reason(crate::service::envelope::DropReason::QueueFull);
        let (ep_r, ep_b) = s
            .queue
            .gross_by_reason(crate::service::envelope::DropReason::Epipe);
        let (sa_r, sa_b) = s
            .queue
            .gross_by_reason(crate::service::envelope::DropReason::StreamAbandoned);
        summary.stream_drops = crate::service::envelope::StreamDrops {
            records,
            bytes,
            by_reason: ByReason {
                queue_full: ReasonTotals {
                    records: qf_r,
                    bytes: qf_b,
                },
                epipe: ReasonTotals {
                    records: ep_r,
                    bytes: ep_b,
                },
                stream_abandoned: ReasonTotals {
                    records: sa_r,
                    bytes: sa_b,
                },
            },
        };
        summary.stream_pending = s.queue.spans();
    }
    summary.tap_recovered = run.summary.tap_recovered.clone();
    summary.tap_uncertain = std::mem::take(&mut run.summary.tap_uncertain);
    summary.tap_uncertain_overflow = run.summary.tap_uncertain_overflow.clone();
    summary.rotation_tail = std::mem::take(&mut run.summary.rotation_tail);
    summary.rotation_tail_overflow = run.summary.rotation_tail_overflow;
    summary.close_accounting = std::mem::take(&mut run.summary.close_accounting);
    summary.close_accounting_overflow = run.summary.close_accounting_overflow;
    summary.diagnostics_dropped = diagnostics_dropped;
}

/// Pre-first-window failure exit (1a/1b reserve/open failed): a
/// minimal summary (the attempt's accumulators + `close_accounting`
/// showing the failed op) writes best-effort, the cause prints
/// synchronously (pre-run — no worker could drain), and the run
/// exits 4 (zero finalized).
#[allow(clippy::too_many_arguments)]
fn write_abandoned_summary_and_exit(
    cfg: ServiceConfig,
    run_id: RunId,
    tag: String,
    diag: Diagnostics,
    mut accum: SummaryAccum,
    generation: u64,
    origin_ns: u64,
    msg: &str,
    code: u8,
) -> ExitCode {
    let mut summary = RunSummary::blank(run_id, generation, origin_ns);
    summary.abandoned = std::mem::take(&mut accum.abandoned);
    summary.abandoned_overflow = accum.abandoned_overflow;
    summary.commit_recovered = accum.commit_recovered.clone();
    summary.orphan_cut_tail = accum.orphan_cut_tail.clone();
    summary.close_unmeasured = std::mem::take(&mut accum.close_unmeasured);
    summary.close_accounting = std::mem::take(&mut accum.close_accounting);
    summary.close_accounting_overflow = accum.close_accounting_overflow;
    summary.exit = code;
    let bytes = serde_json::to_vec(&summary).unwrap_or_default();
    let cancel = AtomicBool::new(false);
    let format = cfg.format;
    let out = cfg.out.clone();
    let wrote: Control<(std::io::Result<()>, Option<u64>)> = run_op(
        &diag,
        &format,
        &mut accum,
        &cancel,
        "abandoned_summary_write",
        state_dest("run-summary.json"),
        Duration::from_secs(5),
        None,
        move |gate| {
            if gate.abandoned() {
                return WorkerOut::value((Err(std::io::Error::other("abandoned")), None));
            }
            WorkerOut::value(write_state_ts(&out, "run-summary.json", &tag, &bytes))
        },
    );
    let _ = diag.abandon(Duration::from_millis(200));
    if !matches!(wrote, Control::Done((Ok(()), _))) {
        crate::report::err_line("osslscope service: summary write failed");
    }
    crate::report::err_line(&format!("osslscope service: {msg}"));
    ExitCode::from(code)
}

/// Double-signal exit (§7.1): immediate stop — the in-flight
/// window is abandoned best-effort (single attempt, no reconcile —
/// immediacy beats certainty; recovery re-derives from the open
/// reservation when the mark lands nowhere), the stream is cut
/// (no flush — cutoff, leftovers fold `stream_abandoned`), and the
/// run exits via the table.
fn double_signal_exit(mut run: Run) -> ExitCode {
    close_gate(&mut run);
    diag_line(
        &run.diag,
        &run.format,
        "warn",
        "second signal: immediate stop",
    );
    if let Some(cycle) = run.cycle.take() {
        let mark = serde_json::to_vec(&SequenceState {
            schema: crate::service::state::SCHEMA_SEQ.to_string(),
            generation: run.generation,
            next_seq: cycle.seq.saturating_add(1),
            updated_wall_ns: wall_ns().unwrap_or(0),
            close_completed_ns: None,
            exhausted: false,
            run_id: run.run_id.clone(),
            reserved: Some(Reservation {
                seq: cycle.seq,
                run_id: run.run_id.clone(),
                generation: run.generation,
                requested_start_ns: cycle.requested_start_ns,
                requested_end_ns: cycle.requested_end_ns,
                state: ReservationState::Abandoned,
                reason: Some(AbandonReason::DoubleSignal),
                started: true,
            }),
        })
        .unwrap_or_default();
        // Best-effort single attempt (no poll, no re-apply — the
        // double-signal path never waits): 500 ms, capped by the
        // shutdown remainder when a close minted one (R1 finding 3).
        let mark_budget = cap_by_deadline(&run, Duration::from_millis(500));
        let mark_poll = run_wait_poll!(run);
        let marked: Control<(std::io::Result<()>, Option<u64>)> = run_op(
            &run.diag,
            &run.format,
            &mut run.summary,
            &run.cancel,
            "double_signal_mark",
            state_dest("sequence.json"),
            mark_budget,
            Some(&mark_poll),
            {
                let (out, tag) = (run.out.clone(), run.tag.clone());
                move |gate| {
                    if gate.abandoned() {
                        return WorkerOut::value((Err(std::io::Error::other("abandoned")), None));
                    }
                    WorkerOut::value(write_state_ts(&out, "sequence.json", &tag, &mark))
                }
            },
        );
        let cut_ns = match marked {
            Control::Done((_, ts)) => ts.unwrap_or_else(monotonic_ns),
            _ => monotonic_ns(),
        };
        run.summary
            .push_abandoned(crate::service::envelope::AbandonedNote {
                seq: cycle.seq,
                run_id: run.run_id.clone(),
                generation: run.generation,
                requested_start_ns: cycle.requested_start_ns,
                requested_end_ns: cycle.requested_end_ns,
                reason: AbandonReason::DoubleSignal,
                cut_tail_ns: Some(crate::service::envelope::CutTail {
                    effective_end_ns: cut_ns,
                    requested_end_ns: cycle.requested_end_ns,
                }),
            });
    }
    close_run_end(run)
}

fn mid_window_sinks(mut run: Run, sha256: String) -> (Run, SinksOut) {
    let seq = run.cycle.as_ref().expect("window open at sinks").seq;
    // Pending rotation-tail reconcile (last boundary's rename —
    // the L6 tail content-match over the ROTATED file).
    reconcile_rotation(&mut run);
    // Rotation decision (regular-file taps only, records assigned).
    if rotation_fires(&mut run) {
        match rotate_active(&mut run, seq) {
            RotationOut::Rotated | RotationOut::Deferred => {}
            RotationOut::Held => {
                // Held rotated name: fatal (never a skip) — the
                // published window stands; the run ends and the
                // fold resolves exit 1 (finalized windows exist).
                run.tool_failure = Some(RunToolFailure::RotatedNameHeld);
                return (run, SinksOut::QuotaStop);
            }
        }
    }
    // Stream marker + ref enqueue (assign to the CURRENT active
    // file — post-rotation, so queued records land in the new
    // file, §6.1).
    enqueue_boundary_records(&mut run, seq, &sha256);
    // Stale ops (below this boundary's first op id) recheck BEFORE
    // the tap drive (R4 finding 1 — prior receipts reconcile before
    // tap reuse/marker delivery; rotation already ran above, so
    // rotated landings matched first). Receipts landing mid-drive
    // reconcile at the drive's own availability checks
    // (`tap_slot_ready`) or at the next boundary.
    let recheck_below = run.stream.as_ref().map(|s| s.next_op_id).unwrap_or(0);
    let stale: Vec<u64> = run
        .stream
        .as_ref()
        .map(|s| {
            s.inflight
                .iter()
                .filter(|r| r.op_id < recheck_below)
                .map(|r| r.op_id)
                .collect()
        })
        .unwrap_or_default();
    for op_id in stale {
        reconcile_tap_write(&mut run, op_id, crate::service::envelope::DropReason::Epipe);
    }
    // Tap drive (open attempts + writes, MAX_OUTSTANDING_TAP = 1).
    // A post-open reserved identity ends the run as a tool failure
    // (the published window stands; the fold resolves exit 1).
    if drive_tap(&mut run) {
        return (run, SinksOut::QuotaStop);
    }
    // Post-drive recheck (R5 finding 1): the drive's resync `\n`
    // may have completed a retained partial into a reader-visible
    // record — it re-resolves through the SAME ladder (a completed
    // record credits exactly once via the match arm + in-flight
    // removal; a still-unterminated one retains again; a proven
    // unlandable one settles ≤1 boundary early with identical
    // terminal accounting — its tail-proved absence from the
    // active file means no later rotation match could credit it
    // either). Receipt-before-reuse is untouched (the pre-drive
    // pass above still runs first). Regular files only: FIFO
    // survivors keep their exact prior timing (no tail exists, no
    // resync completes them — they resolve at the next boundary).
    let survivors: Vec<u64> = run
        .stream
        .as_ref()
        .map(|s| {
            s.inflight
                .iter()
                .filter(|r| r.op_id < recheck_below && !r.fifo)
                .map(|r| r.op_id)
                .collect()
        })
        .unwrap_or_default();
    for op_id in survivors {
        reconcile_tap_write(&mut run, op_id, crate::service::envelope::DropReason::Epipe);
    }
    // Retention + quota (§6.2 — enforced at this boundary).
    let retain_budget = close_budget(&run);
    let retain_poll = run_wait_poll!(run);
    let retention: Control<crate::service::retain::RetentionOut> = run_op(
        &run.diag,
        &run.format,
        &mut run.summary,
        &run.cancel,
        &format!("retain_boundary_{seq}"),
        Destination {
            class: DestClass::Delete,
            key: format!("retain-{seq}"),
        },
        retain_budget,
        Some(&retain_poll),
        {
            let (out, rw, rb) = (
                run.out.clone(),
                run.cfg.retain_windows,
                run.cfg.retain_bytes,
            );
            move |gate| {
                // Fenced pre-check (F2: never initiate deletes past
                // abandonment — a retry at the next boundary covers
                // the skipped pass).
                if gate.abandoned() {
                    return WorkerOut::value(crate::service::retain::RetentionOut {
                        deleted_files: 0,
                        deleted_bytes: 0,
                        delete_errors: vec!["abandoned".to_string()],
                        quota_exceeded: None,
                        window_count: 0,
                        managed_bytes: 0,
                    });
                }
                WorkerOut::value(enforce_retention(&out, rw, rb))
            }
        },
    );
    match retention {
        Control::Done(out) => {
            for err in &out.delete_errors {
                diag_line(&run.diag, &run.format, "warn", &format!("retention: {err}"));
            }
            if let Some(qe) = out.quota_exceeded {
                use crate::service::envelope::QuotaCause;
                match qe.cause {
                    QuotaCause::ProtectedEvidence => {
                        run.summary.quota_exceeded = Some(qe);
                        diag_line(
                            &run.diag,
                            &run.format,
                            "warn",
                            "quota exceeded (protected evidence)",
                        );
                    }
                    QuotaCause::DeletionFailure => {
                        // Quota-stop: the in-flight window is
                        // PUBLISHED (lossless — never discarded);
                        // write the latch, then end the run as a
                        // run-level tool failure.
                        run.summary.quota_exceeded = Some(qe);
                        let (generation, qbytes, qcap) = (
                            run.generation,
                            run.summary
                                .quota_exceeded
                                .as_ref()
                                .map(|q| q.bytes)
                                .unwrap_or(0),
                            run.summary
                                .quota_exceeded
                                .as_ref()
                                .map(|q| q.cap)
                                .unwrap_or(0),
                        );
                        let latch_budget = close_budget(&run);
                        let latch_poll = run_wait_poll!(run);
                        let latched: Control<std::io::Result<()>> = run_op(
                            &run.diag,
                            &run.format,
                            &mut run.summary,
                            &run.cancel,
                            &format!("quota_latch_{seq}"),
                            state_dest("quota-stop.json"),
                            latch_budget,
                            Some(&latch_poll),
                            {
                                let (out, tag) = (run.out.clone(), run.tag.clone());
                                let (generation, bytes, cap) = (generation, qbytes, qcap);
                                move |gate| {
                                    if gate.abandoned() {
                                        return WorkerOut::value(Err(std::io::Error::other(
                                            "abandoned",
                                        )));
                                    }
                                    WorkerOut::value(write_latch(
                                        &out, &tag, generation, seq, bytes, cap,
                                    ))
                                }
                            },
                        );
                        match latched {
                            Control::Done(Ok(())) => {}
                            Control::Done(Err(e)) => {
                                diag_line(
                                    &run.diag,
                                    &run.format,
                                    "error",
                                    &format!("quota latch write failed: {e}"),
                                );
                            }
                            _ => {
                                diag_line(
                                    &run.diag,
                                    &run.format,
                                    "warn",
                                    "quota latch write abandoned",
                                );
                            }
                        }
                        run.tool_failure = Some(RunToolFailure::QuotaDeletionFailure);
                        return (run, SinksOut::QuotaStop);
                    }
                }
            }
        }
        _ => {
            // Retention abandoned/expired: retried at the next
            // boundary (§6.2) — never fatal in-run.
            diag_line(
                &run.diag,
                &run.format,
                "warn",
                "retention deferred to next boundary",
            );
        }
    }
    (run, SinksOut::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2 Gate 2 (F3): spill waits share ONE absolute deadline —
    /// ops past the deadline expire instead of renewing the budget.
    /// Adopted from the R2 spill-deadline probe (inverted +
    /// deterministic): after sleeping past the 12 ms sink budget,
    /// further ops must expire. The pre-fix sink renews the full
    /// budget per op, so the post-sleep op completes (RED); the
    /// fixed sink draws the remainder, so it expires (GREEN).
    #[test]
    fn spill_sink_shares_one_absolute_deadline() {
        let dir = std::env::temp_dir().join(format!(
            "t74-gate2-spill-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let diag = Diagnostics::spawn();
        let format = Format::Json;
        let mut accum = SummaryAccum::new();
        let cancel = AtomicBool::new(false);
        let budget = Duration::from_millis(12);
        let mut sink = spill_sink_for(&diag, &format, &mut accum, &cancel, None, budget);
        // Sleep past the sink's absolute deadline (12 ms + margin).
        std::thread::sleep(Duration::from_millis(30));
        let mut expired = 0u32;
        for n in 0..5 {
            match sink(&dir.join(format!("spill-{n}")), b"{}") {
                Ok(()) => {}
                Err(_) => expired += 1,
            }
        }
        drop(sink);
        diag.abandon(Duration::from_millis(50));
        eprintln!("spill-deadline post-sleep: expired={expired}/5");
        assert_eq!(
            expired, 5,
            "all ops past the sink deadline must expire (none may renew)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R3 adjudication (d): spill control failures (expiry / cancel
    /// / worker-unavailable) are NOT disk-full — only ENOSPC is
    /// (other errno failures are `io_error`, mirroring the publish
    /// stage map; spawn failure is `worker_unavailable`, mirroring
    /// the assemble map).
    #[test]
    fn spill_failures_disambiguate_control_from_disk_full() {
        use std::io::Error;
        assert_eq!(
            spill_abandon_reason(&Error::other(SpillControlFail::Expired)),
            AbandonReason::IoError
        );
        assert_eq!(
            spill_abandon_reason(&Error::other(SpillControlFail::Cancelled)),
            AbandonReason::IoError
        );
        assert_eq!(
            spill_abandon_reason(&Error::other(SpillControlFail::SpawnFailed)),
            AbandonReason::WorkerUnavailable
        );
        assert_eq!(
            spill_abandon_reason(&Error::from_raw_os_error(libc::ENOSPC)),
            AbandonReason::DiskFull
        );
        assert_eq!(
            spill_abandon_reason(&Error::from_raw_os_error(libc::EIO)),
            AbandonReason::IoError
        );
        assert_eq!(
            spill_abandon_reason(&Error::other("mystery")),
            AbandonReason::IoError
        );
    }

    /// RANK-4: the live set covers staging + open piece + carried
    /// tick — every still-in-use identity is deletion-excluded.
    #[test]
    fn spill_retry_live_set_covers_staging_piece_and_carry() {
        use crate::service::staging::SpilledRecord;
        fn spilled(name: &str) -> SpilledRecord {
            SpilledRecord {
                tmp: PathBuf::from(name),
                bytes: 8,
                tick: 1,
                valid: true,
                seal_segment: None,
                content_sha: [0u8; 32],
            }
        }
        let mut staging = Staging::new();
        staging.spilled.push(spilled("/o/.t.tmp.spill.1.0"));
        staging
            .spill_files
            .insert(PathBuf::from("/o/.t.tmp.spill.1.0"), 8);
        let mut piece = TickPiece::open(2);
        piece.spilled.push(spilled("/o/.t.tmp.spill.2.0"));
        let carry = Carry {
            staged: Vec::new(),
            spilled: vec![spilled("/o/.t.tmp.spill.0.7")],
            staged_bytes: 0,
            from_seq: 9,
        };
        let live = live_spill_set(&staging, &piece, Some(&carry));
        assert!(live.contains(&PathBuf::from("/o/.t.tmp.spill.1.0")));
        assert!(live.contains(&PathBuf::from("/o/.t.tmp.spill.2.0")));
        assert!(live.contains(&PathBuf::from("/o/.t.tmp.spill.0.7")));
        assert_eq!(live.len(), 3, "registry duplicates collapse");
        assert!(!live.contains(&PathBuf::from("/o/.t.tmp.spill.9.9")));
    }

    /// RANK-4: the unlink plan retries queued consumed identities
    /// alongside the window's consumed spills — queued paths still
    /// live are excluded, and the plan deduplicates.
    #[test]
    fn spill_retry_plan_excludes_live_and_dedups() {
        use std::collections::BTreeSet;
        let live: BTreeSet<PathBuf> = ["/o/live"].into_iter().map(PathBuf::from).collect();
        let plan = spill_retry_plan(
            vec![PathBuf::from("/o/cur")],
            vec![
                PathBuf::from("/o/old"),
                PathBuf::from("/o/live"),
                PathBuf::from("/o/cur"),
                PathBuf::from("/o/old"),
            ],
            &live,
        );
        assert_eq!(plan, vec![PathBuf::from("/o/cur"), PathBuf::from("/o/old")]);
    }

    /// RANK-4: the re-list merge excludes live identities (minus
    /// the just-consumed attempt, whose survivors are
    /// consumed-pending-retry), deduplicates, and caps — overflow
    /// sheds with a count, never unbounded growth.
    #[test]
    fn spill_retry_merge_filters_live_dedups_and_caps() {
        use std::collections::BTreeSet;
        let live: BTreeSet<PathBuf> = ["/o/live", "/o/attempted"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let consumed: BTreeSet<PathBuf> = ["/o/attempted"].into_iter().map(PathBuf::from).collect();
        let mut pending = vec![PathBuf::from("/o/queued")];
        let m = merge_pending_spills(
            &mut pending,
            vec![
                PathBuf::from("/o/live"),
                PathBuf::from("/o/attempted"),
                PathBuf::from("/o/queued"),
                PathBuf::from("/o/new"),
            ],
            &live,
            &consumed,
        );
        assert_eq!(m.added, 2);
        assert_eq!(m.skipped_live, 1);
        assert_eq!(m.shed_cap, 0);
        assert!(pending.contains(&PathBuf::from("/o/attempted")));
        assert!(pending.contains(&PathBuf::from("/o/new")));
        assert!(!pending.contains(&PathBuf::from("/o/live")));
        // Cap: a full queue sheds with a count.
        pending.clear();
        for n in 0..MAX_PENDING_SPILL_UNLINKS {
            pending.push(PathBuf::from(format!("/o/p{n}")));
        }
        let m = merge_pending_spills(
            &mut pending,
            vec![PathBuf::from("/o/overflow")],
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(m.shed_cap, 1);
        assert_eq!(pending.len(), MAX_PENDING_SPILL_UNLINKS);
    }

    /// R3 adjudication (d): the spill sink reports control
    /// failures typed (downcastable — not stringly), so callers
    /// disambiguate expiry from disk-full.
    #[test]
    fn spill_sink_reports_control_failures_typed() {
        let dir = std::env::temp_dir().join(format!(
            "t74-spilltyped-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let diag = Diagnostics::spawn();
        let format = Format::Json;
        let mut accum = SummaryAccum::new();
        let cancel = AtomicBool::new(false);
        let mut sink = spill_sink_for(
            &diag,
            &format,
            &mut accum,
            &cancel,
            None,
            Duration::from_millis(12),
        );
        std::thread::sleep(Duration::from_millis(30));
        let err = sink(&dir.join("spill-typed"), b"{}").expect_err("past-deadline op must fail");
        drop(sink);
        diag.abandon(Duration::from_millis(50));
        let fail = err
            .get_ref()
            .and_then(|r| r.downcast_ref::<SpillControlFail>())
            .expect("control failure must be typed");
        assert_eq!(*fail, SpillControlFail::Expired);
        assert_eq!(spill_abandon_reason(&err), AbandonReason::IoError);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R4 finding 3: a spill op that executes and returns an errno
    /// (EEXIST through the real spill write — the leaked-tmp shape
    /// production already tolerates) records `Failed` in
    /// `close_accounting`, never `Done` (frozen failure accounting:
    /// `failed` = the op executed and returned an error). RED
    /// pre-fix (records `done`); GREEN post-fix. The S4 twin
    /// (`s4_close_final_spill_errno_abandons_honestly`) pins the
    /// same rule at the close path.
    #[test]
    fn spill_sink_errno_records_failed() {
        let name = format!(
            "spill-errno-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!(
            "t74-spillerrno-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&name), b"{\"blocker\":true}\n").unwrap();
        let diag = Diagnostics::spawn();
        let format = Format::Json;
        let mut accum = SummaryAccum::new();
        let cancel = AtomicBool::new(false);
        let mut sink = spill_sink_for(
            &diag,
            &format,
            &mut accum,
            &cancel,
            None,
            Duration::from_secs(5),
        );
        let err = sink(&dir.join(&name), b"{}").expect_err("EEXIST spill must error");
        drop(sink);
        diag.abandon(Duration::from_millis(50));
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EEXIST),
            "the op executed and errored with a real errno"
        );
        assert!(
            accum
                .close_accounting
                .iter()
                .any(|o| o.op == "spill_write" && o.outcome == OpOutcome::Failed),
            "executed-and-errored spill must record failed: {:?}",
            accum.close_accounting
        );
        assert!(
            !accum
                .close_accounting
                .iter()
                .any(|o| o.op == "spill_write" && o.outcome == OpOutcome::Done),
            "an errno spill must never record done: {:?}",
            accum.close_accounting
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- S4 close-staging regressions (shut fix) ---
    //
    // The close path under test is 100% production
    // (`close_final_window` / `close_mid_window` → staging, spill
    // sink, seal reads, assemble, publish, judge, sinks, seal,
    // summary, the §7.3 fold); only the engine I/O is scripted
    // (`FakeCloseEngine` — an unprivileged test process cannot
    // observe real members). Signals are REAL (raised through the
    // installed signalfd, consumed via the loop-top edge), so the
    // sticky-cancel state is production-shaped, not hand-set.
    // Serial suite (process-wide signal mask — see signals.rs).
    use crate::evidence::{
        CandidateCoverage, CandidateIdentity, CaptureWindow, FinalizeInput, LegacyCallPartition,
        ObjectId, OpensslVersion, SiteExecution, SiteKey, TargetRecord, finalize,
    };

    fn s4_site(seg: u64, i: u32) -> SiteKey {
        SiteKey {
            object: ObjectId(format!("libt74s4-{seg}-{i}")),
            device: 7,
            inode: 8,
            offset: u64::from(i),
        }
    }

    fn s4_target(pid: u32) -> TargetRecord {
        TargetRecord::new(pid, "t".to_string(), String::new(), String::new())
    }

    /// Proving-shape retirement seal document: 9000 sites × 211
    /// calls with candidates — multi-MB JSON, thousands of sites,
    /// ~1.9M calls per seal (≈5.7M across the three-seal drain,
    /// mirroring the proving dry's 20,725 sites / 5.7M calls at
    /// the same order of magnitude).
    fn s4_seal_doc(seg: u64, pid: u32) -> crate::evidence::CaptureDocument {
        let sites: Vec<SiteExecution> = (0..9000u32)
            .map(|i| SiteExecution {
                site: s4_site(seg, i),
                generation: 1,
                candidates: (0..3u32)
                    .map(|c| {
                        CandidateIdentity::new(
                            ObjectId(format!("libt74s4-c{c}")),
                            "prov".to_string(),
                            c,
                            c + 1,
                            vec!["AES-GCM".to_string(), "SHA-512".to_string()],
                            false,
                        )
                    })
                    .collect(),
                candidates_coverage: CandidateCoverage::Complete,
                calls: 211,
                first_ns: 1,
                last_ns: 90,
                installed_at: None,
            })
            .collect();
        finalize(FinalizeInput {
            corpse_wait: None,
            window: CaptureWindow {
                requested_start_ns: 0,
                requested_end_ns: 100,
                effective_start_ns: 0,
                effective_end_ns: 100,
                signal_cut: false,
                count_admission: None,
            },
            sites,
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: s4_target(pid),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        })
    }

    fn s4_seal_line(seg: u64, pid: u32) -> Vec<u8> {
        let doc = s4_seal_doc(seg, pid);
        let rec = serde_json::json!({
            "kind": "process_observation",
            "incarnation": {"pid": pid, "starttime": 100u64},
            "segment": seg,
            "document": serde_json::to_value(&doc).unwrap(),
            "image_epoch": 3u64,
        });
        serde_json::to_vec(&rec).unwrap()
    }

    /// Three-seal close drain (~15 MB): the first seal stages, the
    /// rest spill (the tick staged cap is 8 MiB) — the proving
    /// shape (mixed staged + spilled seals at close).
    fn s4_drain_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        for (seg, pid) in [(101u64, 9001u32), (102, 9002), (103, 9003)] {
            let line = s4_seal_line(seg, pid);
            eprintln!("s4 seal seg={seg}: {} bytes", line.len());
            out.extend_from_slice(&line);
            out.push(b'\n');
        }
        eprintln!("s4 drain total: {} bytes", out.len());
        out
    }

    struct S4MaskGuard;
    impl Drop for S4MaskGuard {
        fn drop(&mut self) {
            crate::service::signals::restore_test_mask();
        }
    }

    fn s4_scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "t74s4-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Assemble a live `Run` with window `seq` open and the
    /// scripted engine serving `drain` (+ empty snapshots): the
    /// state a real run holds just before its run-final close.
    fn s4_run(out: &Path, seq: u64, drain: Vec<u8>) -> (Run, S4MaskGuard) {
        // NOTE: installs the process-wide mask (serial suite).
        let signals = SignalFd::install().expect("signalfd installs");
        let guard = S4MaskGuard;
        let run_id = RunId {
            pid: 4242,
            starttime: 999,
            boot_id: "t74s4boot".to_string(),
        };
        let lock = DirLock::take(out, &run_id, wall_ns().unwrap_or(0)).expect("lock takes");
        let mut cfg = ServiceConfig::default();
        cfg.out = out.to_path_buf();
        cfg.pids = vec![4242];
        let snap = Snapshot {
            at_ns: monotonic_ns(),
            stable: true,
            members: Vec::new(),
            run: crate::service::snapshot::RunTallies::default(),
            polling: false,
        };
        let cycle = Cycle {
            seq,
            requested_start_ns: 0,
            requested_end_ns: 1_000_000_000,
            effective_start_ns: 0,
            open: snap.clone(),
            staging: Staging::new(),
            piece: TickPiece::open(1),
            carry_out: None,
            carried_in: None,
            open_tick_id: 1,
            fatal: None,
            accum_exceeded: None,
            accum_cut: false,
        };
        let run = Run {
            cfg,
            run_id,
            tag: "t74s4".to_string(),
            generation: 1,
            out: out.to_path_buf(),
            diag: Diagnostics::spawn(),
            _lock: lock,
            signals,
            cancel: AtomicBool::new(false),
            engine: FakeCloseEngine {
                drain_bytes: drain,
                snap,
            },
            _leases: Vec::new(),
            cancel_latched: AtomicBool::new(false),
            double_signal: AtomicBool::new(false),
            reload_pending: AtomicBool::new(false),
            close_deadline: None,
            policy: PolicyState {
                active: None,
                active_rules: None,
                pending: None,
                displaced: 0,
                adopted: 0,
                rejected: 0,
                last_rejection: None,
            },
            stream: None,
            cycle: Some(cycle),
            summary: SummaryAccum::new(),
            fold: RunFold::new(),
            first_seq: None,
            tool_failure: None,
            origin_ns: 0,
            tick_ns: 200_000_000,
            tick_id: 1,
            run_member_floor: None,
            pending_spill_unlinks: Vec::new(),
            format: Format::Json,
        };
        (run, guard)
    }

    /// One loop-top signal edge: drain + consume a batch (exactly
    /// `run_loop`'s edge — the production SIGTERM path).
    fn s4_consume_batch(run: &mut Run) {
        let sigs = run.signals.drain();
        consume_signals(run, sigs);
    }

    fn s4_read_json(path: &Path) -> serde_json::Value {
        let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("{path:?} exists"));
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("{path:?} is valid JSON"))
    }

    /// S4 main regression: close with staging-spill under shutdown
    /// cancel PUBLISHES the final window carrying its (large)
    /// retirement seals — shutdown preemption must not cancel
    /// close-critical staging. RED pre-fix (Cancelled spill →
    /// abandoned/IoError + zero seals); GREEN post-fix.
    #[test]
    fn s4_close_final_publishes_large_seals_under_shutdown_cancel() {
        let out = s4_scratch("final-seals");
        let drain = s4_drain_bytes();
        let (mut run, _guard) = s4_run(&out, 0, drain);
        // Load-hardened grace: this test pins CANCEL-survival of
        // close-critical staging (15.8 MB through worker-backed
        // spill + assembly + seal), not deadline arithmetic — the
        // 5 s default expires honestly-but-spuriously on loaded
        // runners (assemble_window Expired → exit 4). Deadline
        // expiry itself is pinned by dedicated unit tests.
        run.cfg.grace = Duration::from_secs(60);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        assert!(
            run.cancel_latched.load(Ordering::SeqCst) && run.cancel.load(Ordering::SeqCst),
            "SIGTERM latched the shutdown cancel"
        );
        let code = close_final_window(run);
        assert_eq!(
            code,
            ExitCode::from(3),
            "signal-cut close with a finalized window exits 3"
        );
        let win = s4_read_json(&out.join(crate::service::state::window_name(0)));
        let seals: Vec<&serde_json::Value> = win["crypto_watch"]
            .as_array()
            .expect("crypto_watch array")
            .iter()
            .filter(|r| r["kind"] == "process_observation")
            .collect();
        assert_eq!(
            seals.len(),
            3,
            "all three seals ride crypto_watch[] verbatim"
        );
        for s in &seals {
            let n = s["document"]["sites"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            assert!(
                n >= 2000,
                "proving-shape seal carries thousands of sites, got {n}"
            );
        }
        let members = win["members"].as_array().expect("members array");
        assert_eq!(members.len(), 3, "absent-open seals project members");
        assert!(
            members.iter().all(|m| m["retired"].as_bool() == Some(true)),
            "sealed members retired"
        );
        let sum = s4_read_json(&out.join("run-summary.json"));
        assert_eq!(
            sum["abandoned"].as_array().map(|a| a.len()),
            Some(0),
            "no abandoned window"
        );
        assert_eq!(sum["exit"], 3);
        let ops = sum["close_accounting"]
            .as_array()
            .expect("close_accounting array");
        assert!(
            ops.iter()
                .any(|o| o["op"] == "spill_write" && o["outcome"] == "done"),
            "close spill ran to judgment: {ops:?}"
        );
        assert!(
            ops.iter().all(|o| o["outcome"] == "done"),
            "no Cancelled/Expired/Failed at close: {ops:?}"
        );
        let seq = s4_read_json(&out.join("sequence.json"));
        assert_eq!(
            seq["reserved"]["state"], "committed",
            "sealed, not merely written"
        );
        assert_eq!(seq["next_seq"], 1);
        let _ = std::fs::remove_dir_all(&out);
    }

    /// S4 terminal twin: the terminal close stages its drain
    /// through the same fixed path (reached here via the MAX-seq
    /// mid-close diversion).
    #[test]
    fn s4_close_terminal_publishes_large_seals_under_shutdown_cancel() {
        let out = s4_scratch("terminal-seals");
        let drain = s4_drain_bytes();
        let (mut run, _guard) = s4_run(&out, u64::MAX, drain);
        // Load-hardened grace (same as the final twin): cancel-
        // survival, not deadline arithmetic, is what's pinned here.
        run.cfg.grace = Duration::from_secs(60);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        let code = match close_mid_window(run) {
            BoundaryOut::Exit(code) => code,
            BoundaryOut::Continue(_) => panic!("terminal close always ends the run"),
        };
        assert_eq!(
            code,
            ExitCode::from(3),
            "signal-cut terminal close with a finalized window exits 3"
        );
        let win = s4_read_json(&out.join(crate::service::state::window_name(u64::MAX)));
        let seals: Vec<&serde_json::Value> = win["crypto_watch"]
            .as_array()
            .expect("crypto_watch array")
            .iter()
            .filter(|r| r["kind"] == "process_observation")
            .collect();
        assert_eq!(
            seals.len(),
            3,
            "all three seals ride crypto_watch[] verbatim"
        );
        let sum = s4_read_json(&out.join("run-summary.json"));
        assert_eq!(
            sum["abandoned"].as_array().map(|a| a.len()),
            Some(0),
            "no abandoned window"
        );
        let seq = s4_read_json(&out.join("sequence.json"));
        assert_eq!(
            seq["reserved"]["state"], "committed",
            "sealed, not merely written"
        );
        assert_eq!(seq["exhausted"], true, "terminal seal exhausts");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// S4 honest-abandon pin: a REAL errno at close staging (EEXIST
    /// through the real spill write — the leaked-tmp shape
    /// production already tolerates) still abandons honestly with
    /// the loud `io_error` disposition (the ENOSPC→`disk_full` /
    /// EIO→`io_error` mapping itself is pinned by
    /// `spill_failures_disambiguate_control_from_disk_full`).
    #[test]
    fn s4_close_final_spill_errno_abandons_honestly() {
        let out = s4_scratch("errno-abandon");
        for idx in 0..3u64 {
            std::fs::write(
                out.join(format!(".t74s4.tmp.spill.1.{idx}")),
                b"{\"blocker\":true}\n",
            )
            .unwrap();
        }
        let drain = s4_drain_bytes();
        let (mut run, _guard) = s4_run(&out, 0, drain);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        let code = close_final_window(run);
        assert_eq!(
            code,
            ExitCode::from(4),
            "zero finalized + interrupted exits 4"
        );
        assert!(
            !out.join(crate::service::state::window_name(0)).exists(),
            "abandoned window never publishes"
        );
        let sum = s4_read_json(&out.join("run-summary.json"));
        let abandoned = sum["abandoned"].as_array().expect("abandoned array");
        assert_eq!(abandoned.len(), 1, "exactly the final window abandoned");
        assert_eq!(
            abandoned[0]["reason"], "io_error",
            "honest errno disposition"
        );
        assert_eq!(sum["exit"], 4);
        let ops = sum["close_accounting"]
            .as_array()
            .expect("close_accounting array");
        assert!(
            ops.iter()
                .any(|o| o["op"] == "spill_write" && o["outcome"] == "failed"),
            "the spill worker ran to judgment (errno is loud): {ops:?}"
        );
        let seq = s4_read_json(&out.join("sequence.json"));
        assert_eq!(seq["reserved"]["state"], "abandoned");
        assert_eq!(seq["reserved"]["reason"], "io_error");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// S4 expedite pin: a second stop during close staging still
    /// expedites with the immediate DoubleSignal disposition —
    /// never the abandonment mapping (both REAL signals through
    /// the real signalfd; the spill itself fails so the divert
    /// arm, not the publish arm, is exercised).
    #[test]
    fn s4_close_final_spill_double_signal_diverts_immediate() {
        let out = s4_scratch("double-divert");
        for idx in 0..3u64 {
            std::fs::write(
                out.join(format!(".t74s4.tmp.spill.1.{idx}")),
                b"{\"blocker\":true}\n",
            )
            .unwrap();
        }
        let drain = s4_drain_bytes();
        let (mut run, _guard) = s4_run(&out, 0, drain);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        assert!(
            run.double_signal.load(Ordering::SeqCst),
            "second SIGTERM latched double"
        );
        let code = close_final_window(run);
        assert_eq!(
            code,
            ExitCode::from(4),
            "double-signal zero-finalized exits 4"
        );
        assert!(
            !out.join(crate::service::state::window_name(0)).exists(),
            "doubled close never publishes"
        );
        let sum = s4_read_json(&out.join("run-summary.json"));
        let abandoned = sum["abandoned"].as_array().expect("abandoned array");
        assert_eq!(abandoned.len(), 1);
        assert_eq!(
            abandoned[0]["reason"], "double_signal",
            "expedite disposition"
        );
        let seq = s4_read_json(&out.join("sequence.json"));
        assert_eq!(seq["reserved"]["state"], "abandoned");
        assert_eq!(seq["reserved"]["reason"], "double_signal");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// S4 expedite-preservation pin: even when close staging
    /// SUCCEEDS (fresh cancel), a doubled close still diverts —
    /// the run ends DoubleSignal, never sealed/committed.
    #[test]
    fn s4_doubled_close_with_healthy_staging_diverts_unsealed() {
        let out = s4_scratch("double-healthy");
        let drain = s4_drain_bytes();
        let (mut run, _guard) = s4_run(&out, 0, drain);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        unsafe { libc::raise(libc::SIGTERM) };
        s4_consume_batch(&mut run);
        assert!(
            run.double_signal.load(Ordering::SeqCst),
            "second SIGTERM latched double"
        );
        let code = close_final_window(run);
        assert_eq!(
            code,
            ExitCode::from(4),
            "double-signal zero-finalized exits 4"
        );
        let sum = s4_read_json(&out.join("run-summary.json"));
        let abandoned = sum["abandoned"].as_array().expect("abandoned array");
        assert_eq!(abandoned.len(), 1);
        assert_eq!(
            abandoned[0]["reason"], "double_signal",
            "expedite disposition"
        );
        let seq = s4_read_json(&out.join("sequence.json"));
        assert_eq!(
            seq["reserved"]["state"], "abandoned",
            "a doubled run never seals"
        );
        assert_eq!(seq["reserved"]["reason"], "double_signal");
        let _ = std::fs::remove_dir_all(&out);
    }

    // --- R4 finding 1 regressions (stale-op/tap reconciliation) ---
    //
    // Reviewer schedule: R expired + folded; initial reconciliation
    // before R lands; R lands fully; the next boundary consumes the
    // receipt during the tap check; the drive delivers R's marker;
    // the stale recheck strikes R. RED = `tap_recovered` misses R's
    // bytes while R is reader-visible and gross retains them (an
    // over-claim beyond the named uncertain bytes); GREEN = credit
    // preserved exactly once.

    /// Live `Run` with window `seq` open and an attached stream
    /// (regular-file tap under the scratch out-DIR).
    fn r41_run(out: &Path, seq: u64) -> (Run, S4MaskGuard) {
        let (mut run, guard) = s4_run(out, seq, Vec::new());
        let tap_path = out.join("stream.jsonl");
        std::fs::write(&tap_path, b"").unwrap();
        run.stream = Some(StreamState {
            tap_path,
            tap: Tap::pending(),
            queue: crate::service::queue::StreamQueue::new(65536, 4096),
            first_record_wall: None,
            active_first: None,
            active_last: None,
            active_records: 0,
            inflight: Vec::new(),
            next_op_id: 0,
            pending_reconcile: None,
        });
        (run, guard)
    }

    fn r41_record(seq: u64) -> Vec<u8> {
        format!("{{\"kind\":\"window-ref\",\"generation\":1,\"seq\":{seq},\"sha256\":\"abc\"}}")
            .into_bytes()
    }

    /// Fold R as an abandoned tap dispatch (op 0): ledger fold +
    /// the in-flight dispatch record carrying the fold token.
    fn r41_fold_abandoned(run: &mut Run, content: Vec<u8>, seq: u64) {
        use crate::service::envelope::DropReason;
        let full = content.len() as u64 + 1;
        let s = run.stream.as_mut().expect("stream attached");
        let token = s.queue.fold(seq, full, DropReason::Epipe);
        s.inflight.push(crate::service::stream::InflightRecord {
            op_id: 0,
            content,
            kind: "window-ref".to_string(),
            seq: Some(seq),
            span: None,
            fifo: false,
            fold_token: token,
        });
        s.next_op_id = 1;
    }

    /// Plant a Complete tap receipt for `op_id` in the tap slot (the
    /// abandoned-worker shape: a zero-budget waiter expires while
    /// the worker is gated; the release lets it exit with its
    /// receipt, which `on_exit` stores because the flag is set).
    fn r41_plant_complete_receipt(run: &Run, op_id: u64, kind: &str, seq: u64, bytes: u64) {
        use crate::service::worker::{TapReceipt, TapReceiptState};
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let cancel = AtomicBool::new(false);
        let receipt = TapReceipt {
            op_id,
            state: TapReceiptState::Complete { bytes },
            kind: kind.to_string(),
            seq: Some(seq),
            span: None,
            record_bytes: bytes,
            dest_path: run
                .stream
                .as_ref()
                .expect("stream attached")
                .tap_path
                .display()
                .to_string(),
            dest_dev: 0,
            dest_ino: 0,
        };
        let ctrl: Control<u64> = run_under_control(
            tap_dest(run),
            Duration::from_millis(0),
            &cancel,
            move |_| {
                let _ = gate_rx.recv();
                WorkerOut {
                    value: 1,
                    receipt: Some(receipt),
                }
            },
            None,
        );
        assert!(matches!(ctrl, Control::Expired));
        gate_tx.send(()).unwrap();
        // Let the detached exit land (the seal-bound precedent).
        std::thread::sleep(Duration::from_millis(500));
    }

    /// Plant a Partial tap receipt for `op_id` in the tap slot
    /// (the abandoned-worker shape, R5 finding 1 twin of
    /// `r41_plant_complete_receipt`: a zero-budget waiter expires
    /// while the worker is gated; the release lets it exit with its
    /// receipt, which `on_exit` stores because the flag is set).
    /// `written` = landed bytes (all content, newline failed);
    /// `full` = the whole record bytes.
    fn r51_plant_partial_receipt(
        run: &Run,
        op_id: u64,
        kind: &str,
        seq: u64,
        written: u64,
        full: u64,
    ) {
        use crate::service::worker::{TapReceipt, TapReceiptState};
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let cancel = AtomicBool::new(false);
        let receipt = TapReceipt {
            op_id,
            state: TapReceiptState::Partial { bytes: written },
            kind: kind.to_string(),
            seq: Some(seq),
            span: None,
            record_bytes: full,
            dest_path: run
                .stream
                .as_ref()
                .expect("stream attached")
                .tap_path
                .display()
                .to_string(),
            dest_dev: 0,
            dest_ino: 0,
        };
        let ctrl: Control<u64> = run_under_control(
            tap_dest(run),
            Duration::from_millis(0),
            &cancel,
            move |_| {
                let _ = gate_rx.recv();
                WorkerOut {
                    value: 1,
                    receipt: Some(receipt),
                }
            },
            None,
        );
        assert!(matches!(ctrl, Control::Expired));
        gate_tx.send(()).unwrap();
        // Let the detached exit land (the seal-bound precedent).
        std::thread::sleep(Duration::from_millis(500));
    }

    fn r41_append_tap(out: &Path, content: &[u8]) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(out.join("stream.jsonl"))
            .unwrap();
        f.write_all(content).unwrap();
        f.write_all(b"\n").unwrap();
    }

    /// R4 finding 1 (credit independence, tail arm): R's marker
    /// delivers BEFORE the tail content-match proves R landed — the
    /// strike no-ops on the delivered span (that protection stays),
    /// but `tap_recovered` still credits R's proven bytes exactly
    /// once. RED pre-fix (recovered 0 while R is reader-visible and
    /// gross retains it); GREEN post-fix.
    #[test]
    fn r41_tail_match_after_delivery_still_recovers() {
        use crate::service::envelope::DropReason;
        let out = s4_scratch("r41-tail");
        let (mut run, _guard) = r41_run(&out, 9);
        let content = r41_record(7);
        let full = content.len() as u64 + 1;
        r41_fold_abandoned(&mut run, content.clone(), 7);
        {
            let s = run.stream.as_mut().expect("stream attached");
            s.queue.mark_all(9);
            s.queue.clear_marker(9);
        }
        // R lands fully (reader-visible).
        r41_append_tap(&out, &content);
        reconcile_tap_write(&mut run, 0, DropReason::Epipe);
        let rec = &run.summary.tap_recovered;
        assert_eq!(
            (rec.records, rec.bytes),
            (1, full),
            "a proven landing credits even post-delivery"
        );
        let s = run.stream.as_ref().expect("stream attached");
        assert!(s.inflight.is_empty(), "R settles exactly once");
        assert!(
            s.queue.spans().is_empty(),
            "the delivered span stays cleared (no double-subtract)"
        );
        assert_eq!(s.queue.gross(), (1, full), "gross retains R");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// R4 finding 1 (credit independence, receipt arm): the receipt
    /// twin of the tail test — R's proof is its worker's Complete
    /// receipt rather than the tail content-match. RED/GREEN as
    /// above.
    #[test]
    fn r41_receipt_after_delivery_still_recovers() {
        use crate::service::envelope::DropReason;
        let out = s4_scratch("r41-receipt");
        let (mut run, _guard) = r41_run(&out, 9);
        let content = r41_record(7);
        let full = content.len() as u64 + 1;
        r41_fold_abandoned(&mut run, content.clone(), 7);
        r41_plant_complete_receipt(&run, 0, "window-ref", 7, full);
        {
            let s = run.stream.as_mut().expect("stream attached");
            s.queue.mark_all(9);
            s.queue.clear_marker(9);
        }
        reconcile_tap_write(&mut run, 0, DropReason::Epipe);
        let rec = &run.summary.tap_recovered;
        assert_eq!(
            (rec.records, rec.bytes),
            (1, full),
            "a proven landing credits even post-delivery"
        );
        let s = run.stream.as_ref().expect("stream attached");
        assert!(s.inflight.is_empty(), "R settles exactly once");
        assert!(
            s.queue.spans().is_empty(),
            "the delivered span stays cleared (no double-subtract)"
        );
        assert_eq!(s.queue.gross(), (1, full), "gross retains R");
        assert!(
            view_slot(&tap_dest(&run)).is_none(),
            "the receipt is consumed"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    /// R4 finding 1 (ordering — the reviewer's schedule through a
    /// real boundary): R expired + folded; the initial reconcile
    /// runs before R lands (worker live — R stays in-flight); R
    /// lands fully (Complete receipt + reader-visible bytes); the
    /// next boundary reconciles the stale receipt BEFORE the drive
    /// delivers R's marker. RED pre-fix (the drive's tap check
    /// consumes the receipt, the marker delivers, the stale strike
    /// no-ops — recovered 0 with zero uncertain); GREEN post-fix.
    #[test]
    fn r41_stale_receipt_reconciled_before_drive_delivery() {
        use crate::service::envelope::DropReason;
        let out = s4_scratch("r41-order");
        let (mut run, _guard) = r41_run(&out, 9);
        let content = r41_record(7);
        let full = content.len() as u64 + 1;
        r41_fold_abandoned(&mut run, content.clone(), 7);
        // Boundary N's worker: abandoned (zero budget) while gated.
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let receipt = crate::service::worker::TapReceipt {
            op_id: 0,
            state: crate::service::worker::TapReceiptState::Complete { bytes: full },
            kind: "window-ref".to_string(),
            seq: Some(7),
            span: None,
            record_bytes: full,
            dest_path: run
                .stream
                .as_ref()
                .expect("stream attached")
                .tap_path
                .display()
                .to_string(),
            dest_dev: 0,
            dest_ino: 0,
        };
        let cancel = AtomicBool::new(false);
        let ctrl: Control<u64> = run_under_control(
            tap_dest(&run),
            Duration::from_millis(0),
            &cancel,
            move |_| {
                let _ = gate_rx.recv();
                WorkerOut {
                    value: 1,
                    receipt: Some(receipt),
                }
            },
            None,
        );
        assert!(matches!(ctrl, Control::Expired), "R expires while gated");
        // Initial reconciliation before R lands: worker live, no
        // receipt, empty tail — R stays in-flight, uncredited.
        reconcile_tap_write(&mut run, 0, DropReason::Epipe);
        assert_eq!(
            run.stream.as_ref().expect("stream attached").inflight.len(),
            1,
            "R stays in-flight while its worker is live"
        );
        assert_eq!(
            (
                run.summary.tap_recovered.records,
                run.summary.tap_recovered.bytes
            ),
            (0, 0),
            "nothing proven yet — nothing credited"
        );
        // R lands fully: the worker exits with its Complete receipt
        // and R's bytes are reader-visible on the tap.
        gate_tx.send(()).unwrap();
        r41_append_tap(&out, &content);
        std::thread::sleep(Duration::from_millis(500));
        // The next boundary: stale recheck, then the drive.
        let (run, sinks) = mid_window_sinks(run, "abc".to_string());
        assert!(matches!(sinks, SinksOut::Continue));
        let rec = &run.summary.tap_recovered;
        assert_eq!(
            (rec.records, rec.bytes),
            (1, full),
            "the stale receipt credits before marker delivery"
        );
        let s = run.stream.as_ref().expect("stream attached");
        assert!(s.inflight.is_empty(), "R settles exactly once");
        assert!(
            s.queue.spans().is_empty(),
            "struck + delivered spans clear exactly"
        );
        assert_eq!(s.queue.gross(), (1, full), "gross retains R");
        assert!(
            run.summary.tap_uncertain.is_empty(),
            "no uncertainty is named"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    /// R5 finding 1 (resync-completable partial retained through the
    /// drive — the reviewer's schedule through a real boundary): R
    /// expired + folded; the worker lands all R content but the
    /// terminating newline fails; the initial reconciliation
    /// consumes the Partial receipt (R stays in-flight); the next
    /// boundary (no rotation) must NOT remove R pre-drive — the
    /// drive's resync `\n` completes R reader-visible, and R
    /// credits exactly once through the proven-landing ladder. RED
    /// pre-fix (R removed pre-drive, then the drive's resync
    /// completes R with recovered=0 — O=B); GREEN post-fix. The
    /// L6 newline test does not cover this ordering (no boundary).
    #[test]
    fn r51_partial_retained_through_drive_resync() {
        use crate::service::envelope::DropReason;
        let out = s4_scratch("r51-resync");
        let (mut run, _guard) = r41_run(&out, 9);
        let content = r41_record(7);
        let full = content.len() as u64 + 1;
        r41_fold_abandoned(&mut run, content.clone(), 7);
        // Boundary N's worker lands all R content (newline fails)
        // and exits with its Partial receipt.
        r51_plant_partial_receipt(&run, 0, "window-ref", 7, content.len() as u64, full);
        std::fs::write(out.join("stream.jsonl"), &content).unwrap();
        // Initial reconciliation consumes the Partial receipt; R
        // stays in-flight, uncredited.
        reconcile_tap_write(&mut run, 0, DropReason::Epipe);
        assert_eq!(
            run.stream.as_ref().expect("stream attached").inflight.len(),
            1,
            "a consumed Partial receipt leaves R in-flight"
        );
        assert_eq!(
            (
                run.summary.tap_recovered.records,
                run.summary.tap_recovered.bytes
            ),
            (0, 0),
            "nothing proven yet — nothing credited"
        );
        assert!(
            view_slot(&tap_dest(&run)).is_none(),
            "the Partial receipt is consumed"
        );
        // The next boundary: stale recheck, then the drive.
        let (run, sinks) = mid_window_sinks(run, "abc".to_string());
        assert!(matches!(sinks, SinksOut::Continue));
        // The schedule holds on both colors: the drive's resync
        // completes R into a reader-visible record.
        let lines =
            crate::service::stream::read_tail_lines(&out.join("stream.jsonl"), 8 << 20).unwrap();
        assert!(
            lines.contains(&content),
            "the drive's resync completes R reader-visible"
        );
        let rec = &run.summary.tap_recovered;
        assert_eq!(
            (rec.records, rec.bytes),
            (1, full),
            "a resync-completed partial credits exactly once (RED: removed pre-drive, O=B)"
        );
        let s = run.stream.as_ref().expect("stream attached");
        assert!(s.inflight.is_empty(), "R settles exactly once");
        assert!(
            s.queue.spans().is_empty(),
            "struck + delivered spans clear exactly"
        );
        assert_eq!(s.queue.gross(), (1, full), "gross retains R");
        assert!(
            run.summary.tap_uncertain.is_empty(),
            "no uncertainty is named"
        );
        let _ = std::fs::remove_dir_all(&out);
    }
}
