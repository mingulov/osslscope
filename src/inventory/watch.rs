// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded sampled inventory, not a lossless event or execution history.
use super::{
    CaptureInterval, GapReason, Limits, ModuleRecord, Snapshot,
    scope::{ScopedScanner, Selection},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct WatchOptions {
    pub selection: Selection,
    pub limits: Limits,
    pub interval: Duration,
    pub duration: Option<Duration>,
    /// T5 `--resolve-paths` RENDER intent (raw flag + JSON veto,
    /// computed by the caller): human change-row fragments render
    /// iff this is on AND the sink is a terminal. Acquisition is
    /// gated separately by `selection.resolve_paths` (effective:
    /// JSON output and flagged runs acquire alike — v0.6.0 D1
    /// rejected the never-in-JSON gate; external F2).
    pub resolve_paths: bool,
}
impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            selection: Selection::default(),
            limits: Limits::default(),
            interval: Duration::from_secs(1),
            duration: None,
            resolve_paths: false,
        }
    }
}
impl WatchOptions {
    pub fn validate(&self) -> io::Result<()> {
        if !(Duration::from_millis(50)..=Duration::from_secs(3600)).contains(&self.interval)
            || self
                .duration
                .is_some_and(|d| d.is_zero() || d > Duration::from_secs(3600))
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Duration,
    Interrupted,
    ScopeUnavailable,
    Output,
}
#[derive(Clone, Debug, Serialize)]
pub struct WatchOutcome {
    pub schema_version: &'static str,
    pub mode: &'static str,
    pub record: &'static str,
    pub sequence: u64,
    pub reason: EndReason,
    pub status: u8,
    pub elapsed: Duration,
    pub limits: Limits,
    pub gap: Option<GapReason>,
    pub sampled_history: &'static str,
    /// Rendered P0-6 privilege hint for this run (serde-skipped, so
    /// machine end bytes are identical): the last tick whose
    /// snapshot carried an errno-proven denial, decided per tick by
    /// `super::cli::privilege_hint` and retained once per run —
    /// never per tick. `None` when no tick was denied (or none ran).
    #[serde(skip)]
    pub privilege_hint: Option<String>,
}
impl WatchOutcome {
    pub fn exit_code(&self) -> u8 {
        self.status
    }
}

/// Stderr reason for watch exits 3/4, derived from the same
/// (reason, status, gap) triple the end record and exit code derive
/// from. `None` on clean (0) and output-failure (1: the caller's Err
/// arm already owns that line) ends.
pub(super) fn exit_reason(outcome: &WatchOutcome) -> Option<String> {
    if outcome.status == 0 || outcome.status == 1 {
        return None;
    }
    let gap = outcome
        .gap
        .map(|g| format!(": {}", g.word()))
        .unwrap_or_default();
    match outcome.reason {
        EndReason::Interrupted => {
            Some("osslscope discovery: watch interrupted (partial; see records above)".into())
        }
        EndReason::ScopeUnavailable => Some(format!(
            "osslscope discovery: watch scope unavailable{gap} (see end record above)"
        )),
        EndReason::Duration if outcome.status == 3 => {
            Some("osslscope discovery: watch inventory partial (see records above)".into())
        }
        EndReason::Duration if outcome.sequence == 0 => Some(
            "osslscope discovery: watch ended before any snapshot (see end record above)".into(),
        ),
        EndReason::Duration => {
            Some("osslscope discovery: watch inventory unavailable (see records above)".into())
        }
        EndReason::Output => None,
    }
}

/// Run-level sample-history uncertainty (F8/H2), shared by the
/// inventory, provider, and crypto-watch routes: a later
/// complete sample never erases earlier uncertainty. `usable`
/// tracks whether ANY sample was usable (exit != 4);
/// `partial`/`unavailable` book the first uncertain sample per
/// track. An exit-4 sample books the unavailable track only —
/// one note per track, never a double note for one sample.
#[derive(Clone, Debug, Default)]
pub(crate) struct Cumulative {
    pub(crate) usable: bool,
    pub(crate) partial: bool,
    pub(crate) unavailable: bool,
    pub(crate) first_partial: Option<u64>,
    pub(crate) first_unavailable: Option<u64>,
}
impl Cumulative {
    pub(crate) fn observe(&mut self, sample: u64, exit: u8) {
        self.usable |= exit != 4;
        match exit {
            4 => {
                self.unavailable = true;
                self.first_unavailable.get_or_insert(sample);
            }
            0 => {}
            // Unknown exits fail closed into partial history:
            // unrecognized status is uncertainty, never clean.
            _ => {
                self.partial = true;
                self.first_partial.get_or_insert(sample);
            }
        }
    }
    /// A degraded observation without an unavailable inventory
    /// sample still books partial history (provider route).
    pub(crate) fn note_partial(&mut self, sample: u64) {
        self.partial = true;
        self.first_partial.get_or_insert(sample);
    }
    /// End status for a Duration end: 4 iff zero usable samples
    /// (all unavailable, or none at all — same rule as the
    /// provider end record), else 3 iff any uncertainty was
    /// seen, else 0.
    pub(crate) fn end_status(&self) -> u8 {
        if !self.usable {
            4
        } else if self.partial || self.unavailable {
            3
        } else {
            0
        }
    }
    pub(crate) fn word(&self) -> &'static str {
        super::cumulative_word(self.partial, self.unavailable)
    }
    pub(crate) fn notes(&self) -> String {
        super::cumulative_notes(self.first_partial, self.first_unavailable)
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ChangeKind {
    ProcessSeen,
    ModuleSeen,
    ProcessNotSeen,
    ModuleNotSeen,
    VisibilityLost,
}
impl ChangeKind {
    /// Human word for change event lines. Mirrors the serde
    /// snake_case label (and the discovery-v1 schema enum)
    /// exactly — see `tests::watch_words_match_json`.
    fn word(&self) -> &'static str {
        match self {
            ChangeKind::ProcessSeen => "process_seen",
            ChangeKind::ModuleSeen => "module_seen",
            ChangeKind::ProcessNotSeen => "process_not_seen",
            ChangeKind::ModuleNotSeen => "module_not_seen",
            ChangeKind::VisibilityLost => "visibility_lost",
        }
    }
}
/// Human word for the end reason. Mirrors the serde snake_case
/// label exactly — see `tests::watch_words_match_json`.
fn reason_word(reason: EndReason) -> &'static str {
    match reason {
        EndReason::Duration => "duration",
        EndReason::Interrupted => "interrupted",
        EndReason::ScopeUnavailable => "scope_unavailable",
        EndReason::Output => "output",
    }
}
#[derive(Serialize)]
struct Change {
    kind: ChangeKind,
    pid: u32,
    starttime: u64,
    module: Option<ModuleRecord>,
}
#[derive(Serialize)]
struct Record<'a> {
    schema_version: &'static str,
    mode: &'static str,
    record: &'static str,
    sequence: u64,
    interval: &'a CaptureInterval,
    poll_interval: Duration,
    snapshot: &'a Snapshot,
    changes: Vec<Change>,
    sampled_history: &'static str,
}
fn same_module(a: &ModuleRecord, b: &ModuleRecord) -> bool {
    // Identity, evidence, and version sameness on top of file
    // identity: a status flip or a changed locator/version hint
    // is a meaningful watch change (W1). `capture_unix_ms` is
    // re-stamped every sample and excluded — comparing it would
    // flap every tick and kill the heartbeat.
    a.info == b.info
        && a.identity_status == b.identity_status
        && same_verified_path(a.verified_path.as_ref(), b.verified_path.as_ref())
        && a.verified_path_unavailable == b.verified_path_unavailable
        && a.maps_spelling == b.maps_spelling
}
fn same_verified_path(a: Option<&super::VerifiedPath>, b: Option<&super::VerifiedPath>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            x.path == y.path
                && x.path_encoding == y.path_encoding
                && x.locator_kind == y.locator_kind
        }
        _ => false,
    }
}
fn visible(snapshot: &Snapshot, pid: u32) -> bool {
    snapshot.gaps.iter().all(|gap| {
        if gap.pid.is_some_and(|value| value != pid) {
            return true;
        }
        // Candidate association is still uncertain, but successful executable
        // mapping enumeration is usable for sampled absence. Ordinary ELF
        // candidates may be filtered from the public module list. Every
        // backing/read/churn/selection failure still forbids absence claims.
        // IdentityUnverified is emitted only after successful candidate
        // acquisition; unresolved/mismatched backing is BackingUnavailable.
        gap.reason == GapReason::IdentityUnverified
    })
}
fn changes(previous: Option<&Snapshot>, current: &Snapshot) -> Vec<Change> {
    let mut result = Vec::new();
    let mut add = |kind, pid, starttime, module| {
        result.push(Change {
            kind,
            pid,
            starttime,
            module,
        })
    };
    for process in &current.processes {
        let old = previous.and_then(|s| {
            s.processes.iter().find(|p| {
                p.pid == process.pid
                    && p.starttime == process.starttime
                    && p.namespaces == process.namespaces
            })
        });
        if old.is_none() {
            add(
                ChangeKind::ProcessSeen,
                process.pid,
                process.starttime,
                None,
            );
        }
        for module in &process.modules {
            if old.is_none_or(|p| !p.modules.iter().any(|m| same_module(m, module))) {
                add(
                    ChangeKind::ModuleSeen,
                    process.pid,
                    process.starttime,
                    Some(module.clone()),
                );
            }
        }
    }
    if let Some(previous) = previous {
        for old in &previous.processes {
            let now = current.processes.iter().find(|p| {
                p.pid == old.pid && p.starttime == old.starttime && p.namespaces == old.namespaces
            });
            if !visible(current, old.pid) {
                // Visibility loss fires on transitions (was usable,
                // now not) and for pids gone from an unusable sample
                // (exit unprovable — never process_not_seen). A pid
                // that stays present across persistently unusable
                // samples is NOT news every tick: steady
                // uncertainty heartbeats (W1); gap churn still
                // breaks the human heartbeat via `gaps_changed`.
                let was_visible = visible(previous, old.pid);
                let gone = !current.processes.iter().any(|p| p.pid == old.pid);
                if was_visible || gone {
                    add(ChangeKind::VisibilityLost, old.pid, old.starttime, None);
                }
            } else if let Some(now) = now {
                for module in &old.modules {
                    if !now.modules.iter().any(|m| same_module(m, module)) {
                        add(
                            ChangeKind::ModuleNotSeen,
                            old.pid,
                            old.starttime,
                            Some(module.clone()),
                        );
                    }
                }
            } else if !current.processes.iter().any(|p| p.pid == old.pid) {
                add(ChangeKind::ProcessNotSeen, old.pid, old.starttime, None);
            } else {
                // Reused PID or changed namespace is a new observation, not
                // evidence of an exit or unload of the previous incarnation.
                add(ChangeKind::VisibilityLost, old.pid, old.starttime, None);
            }
        }
    }
    result
}

/// (pid, starttime) processes re-observed with different names
/// (comm/exe): the same incarnation, so `changes()` — whose
/// vocabulary is schema-pinned — stays silent, but the human
/// tick must not heartbeat over a rename (W1 names).
fn names_changed(previous: &Snapshot, current: &Snapshot) -> Vec<(u32, u64)> {
    let mut renamed = Vec::new();
    for process in &current.processes {
        let old = previous.processes.iter().find(|p| {
            p.pid == process.pid
                && p.starttime == process.starttime
                && p.namespaces == process.namespaces
        });
        let names = (
            process.comm.as_deref(),
            process.comm_status,
            process.exe.as_deref(),
            process.exe_status,
        );
        if old.is_some_and(|old| {
            (
                old.comm.as_deref(),
                old.comm_status,
                old.exe.as_deref(),
                old.exe_status,
            ) != names
        }) {
            renamed.push((process.pid, process.starttime));
        }
    }
    renamed
}

/// True when the gap multiset changed between samples (W1
/// gaps): gap-only churn still breaks the human heartbeat —
/// uncertainty deltas are meaningful changes. Sorted before
/// comparing: sample order never counts, membership does.
fn gaps_changed(previous: &Snapshot, current: &Snapshot) -> bool {
    let mut old = previous.gaps.clone();
    old.sort();
    let mut new = current.gaps.clone();
    new.sort();
    old != new
}
fn emit(value: &impl Serialize, writer: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}
/// Human change event line (typed; the `path=` fragment still
/// reads through the JSON-shaped module because
/// `TerminalPathWriter::change_fragment` takes a `Value`). The
/// hash is the 12-char short label at every level (W2) — a
/// label, never a key; the machine record keeps the full sha256.
fn human_change_line(
    writer: &mut impl Write,
    change: &Change,
    paths: &super::resolve::TerminalPathWriter,
) -> io::Result<()> {
    write!(
        writer,
        "  {} pid={} starttime={}",
        change.kind.word(),
        change.pid,
        change.starttime
    )?;
    if let Some(module) = &change.module {
        write!(
            writer,
            " sha256={}",
            super::resolve::TerminalPathWriter::short_sha(&module.info.sha256)
        )?;
        // T5 `--resolve-paths`: TTY-only fragment from the
        // dedicated writer (never in the machine record). R13:
        // flag-off lines fall back to the acquired snapshot
        // evidence via `human_path` — never omit what was
        // acquired (`change_fragment` returns `None` only when
        // the flag is off, so the fallback's live branch is dead
        // here).
        let value = serde_json::to_value(module).map_err(io::Error::other)?;
        if let Some(fragment) = paths.change_fragment(&value) {
            write!(writer, " path={fragment}")?;
        } else {
            write!(writer, " path={}", paths.human_path(module))?;
        }
    }
    writeln!(writer)
}
/// Human per-sample render (W1): every tick opens with its
/// `tick N:` status line — the per-sample heartbeat with
/// status/counts — and the state beneath depends on what
/// moved. Tick 1 and `-v` ticks render full state; change ticks
/// render event lines plus changed-process blocks; gap-only or
/// name-only churn renders full state or the renamed blocks
/// (gap diffs can be unnamed, so only the names case stays
/// targeted); quiet ticks print the line alone. `previous` is
/// `None` only for tick 1.
fn human_tick(
    writer: &mut impl Write,
    sequence: u64,
    snapshot: &Snapshot,
    deltas: &[Change],
    previous: Option<&Snapshot>,
    paths: &super::resolve::TerminalPathWriter,
    verbosity: u8,
) -> io::Result<()> {
    let (verified, locator) = snapshot.identity_counts();
    let total = verified + locator;
    let status = snapshot.capabilities.inventory.word();
    let procs = snapshot.processes.len();
    let renamed = previous.map_or_else(Vec::new, |old| names_changed(old, snapshot));
    let gaps_moved = previous.is_some_and(|old| gaps_changed(old, snapshot));
    let verbose = verbosity >= 1;
    if previous.is_none() {
        writeln!(
            writer,
            "tick {sequence}: initial state (status {status}, processes {procs}, modules {verified}/{total} verified)"
        )?;
        // First-sighting event lines (starttimes ride here at
        // level 0 — the verdict lines below carry no starttime).
        for delta in deltas {
            human_change_line(writer, delta, paths)?;
        }
        super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, None)?;
    } else if !deltas.is_empty() {
        writeln!(
            writer,
            "tick {sequence}: {} sampled changes (status {status}, processes {procs}, modules {verified}/{total} verified)",
            deltas.len()
        )?;
        for delta in deltas {
            human_change_line(writer, delta, paths)?;
        }
        if verbose || gaps_moved {
            super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, None)?;
        } else {
            let only: std::collections::BTreeSet<(u32, u64)> = deltas
                .iter()
                .map(|delta| (delta.pid, delta.starttime))
                .chain(renamed)
                .collect();
            super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, Some(&only))?;
        }
    } else if !renamed.is_empty() || gaps_moved {
        writeln!(
            writer,
            "tick {sequence}: state changed (status {status}, processes {procs}, modules {verified}/{total} verified)"
        )?;
        if !verbose && !gaps_moved {
            let only: std::collections::BTreeSet<(u32, u64)> = renamed.into_iter().collect();
            super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, Some(&only))?;
        } else {
            super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, None)?;
        }
    } else {
        // Quiet tick: the line always reports reality; `-v`
        // additionally dumps full state beneath it.
        writeln!(
            writer,
            "tick {sequence}: no changes (status {status}, processes {procs}, modules {verified}/{total} verified)"
        )?;
        if verbose {
            super::cli::human_snapshot_body(writer, snapshot, paths, verbosity, None)?;
        }
    }
    writer.flush()
}
/// Human end render (typed): the `Watch ended:` verdict with
/// run-level cumulative history (F8/H2) plus the
/// first-uncertain notes — a later complete sample never
/// erases earlier uncertainty.
fn human_end(writer: &mut impl Write, outcome: &WatchOutcome, seen: &Cumulative) -> io::Result<()> {
    writeln!(
        writer,
        "Watch ended: {} (status {}, snapshots {}, cumulative: {}). Sampled history remains incomplete.",
        reason_word(outcome.reason),
        outcome.status,
        outcome.sequence,
        seen.word()
    )?;
    writer.write_all(seen.notes().as_bytes())?;
    writeln!(
        writer,
        "  elapsed={}s+{}ns; limits: pids={} objects={} charged_bytes={} timeout={}s+{}ns",
        outcome.elapsed.as_secs(),
        outcome.elapsed.subsec_nanos(),
        outcome.limits.max_pids,
        outcome.limits.max_objects,
        outcome.limits.max_read_bytes,
        outcome.limits.timeout.as_secs(),
        outcome.limits.timeout.subsec_nanos()
    )?;
    if let Some(gap) = outcome.gap {
        writeln!(writer, "  scope gap={}", gap.word())?;
    }
    // P0-6: when the run retained a privilege hint, the end record
    // names where it went (stderr) and where the remedy lives.
    if outcome.privilege_hint.is_some() {
        writeln!(
            writer,
            "  privilege: permission-denied gaps this run; remediation hint on stderr (see usage.md#privilege)"
        )?;
    }
    writer.flush()
}
/// Stream bounded NDJSON. This never installs signal handlers or signals a
/// workload. Cancellation/deadlines are cooperative between bounded snapshots.
pub fn run(
    options: &WatchOptions,
    writer: &mut impl Write,
    cancel: &AtomicBool,
) -> Result<WatchOutcome, io::Error> {
    // Machine-only entry (v0.6.0 D1, F7): machine records
    // always acquire path evidence — proven `verified_path` or
    // null plus a finite `verified_path_unavailable` reason —
    // exactly like the CLI `--json` path (`acquire_paths`). Only
    // the human TTY `path=` render fragment stays off here.
    let mut machine = options.clone();
    machine.selection.resolve_paths = true;
    machine.resolve_paths = false;
    run_formatted(&machine, writer, cancel, false, false, 0)
}
pub(super) fn run_formatted(
    options: &WatchOptions,
    writer: &mut impl Write,
    cancel: &AtomicBool,
    human: bool,
    terminal: bool,
    verbosity: u8,
) -> io::Result<WatchOutcome> {
    run_inner(options, writer, cancel, None, human, terminal, verbosity)
}
/// Shutdown-aware entry for the CLI watch route: the loop checks
/// `cancelled_and_acked()` instead of the bare flag, so the first
/// observed cancel writes the ack to stderr promptly (before the end
/// record), then ends `Interrupted` with the usual cumulative history
/// (`human_end`/end record below — H2 intact). The `&AtomicBool`
/// entries stay stderr-silent for library callers.
pub(super) fn run_shutdown(
    options: &WatchOptions,
    writer: &mut impl Write,
    shutdown: &crate::shutdown::Shutdown,
    human: bool,
    terminal: bool,
    verbosity: u8,
) -> io::Result<WatchOutcome> {
    run_inner(
        options,
        writer,
        shutdown.cancel_flag(),
        Some(shutdown),
        human,
        terminal,
        verbosity,
    )
}
fn run_inner(
    options: &WatchOptions,
    writer: &mut impl Write,
    cancel: &AtomicBool,
    shutdown: Option<&crate::shutdown::Shutdown>,
    human: bool,
    terminal: bool,
    verbosity: u8,
) -> io::Result<WatchOutcome> {
    // First-observation ack rides the Shutdown path only; the
    // library path checks the same bit with no stderr side effect.
    let observed = || match shutdown {
        Some(shutdown) => shutdown.cancelled_and_acked(),
        None => cancel.load(Ordering::Relaxed),
    };
    options.validate()?;
    let started = Instant::now();
    if human {
        writer.write_all(b"Passive sampled inventory: mappings do not prove activation or execution.\nProvider activation/interfaces: unknown; execution: not_observed.\n")?;
    }
    let mut sequence = 0;
    let mut previous = None;
    let mut blindness_printed = false;
    // F8/H2: run-level sample history — the Duration end status
    // derives from this, never from the last sample alone.
    let mut seen = Cumulative::default();
    let mut end = WatchOutcome {
        schema_version: "osslscope.discovery.v1",
        mode: "watch",
        record: "end",
        sequence: 0,
        reason: EndReason::Duration,
        status: 4,
        elapsed: Duration::ZERO,
        limits: options.limits.clone(),
        gap: None,
        sampled_history: "incomplete",
        privilege_hint: None,
    };
    if observed() {
        end.reason = EndReason::Interrupted;
        end.status = 3;
        end.elapsed = started.elapsed();
        if human {
            human_end(writer, &end, &seen)?;
        } else {
            emit(&end, writer)?;
        }
        return Ok(end);
    }
    let mut scanner = match ScopedScanner::new(options.selection.clone(), options.limits.clone()) {
        Ok(scanner) => scanner,
        Err(gap) => {
            if observed() {
                end.reason = EndReason::Interrupted;
                end.status = 3;
            } else {
                end.reason = EndReason::ScopeUnavailable;
            }
            end.gap = Some(gap);
            end.elapsed = started.elapsed();
            if human {
                human_end(writer, &end, &seen)?;
            } else {
                emit(&end, writer)?;
            }
            return Ok(end);
        }
    };
    loop {
        if observed() {
            end.reason = EndReason::Interrupted;
            break;
        }
        if options.duration.is_some_and(|d| started.elapsed() >= d) {
            break;
        }
        let poll_started = Instant::now();
        // v0.6.0 signals (Task 2): the run's cancel flag flows
        // into acquisition, so a signal ends the in-flight sample
        // early with a Deadline gap instead of running it out.
        let snapshot = match options.duration {
            Some(duration) => {
                scanner.snapshot_for_with_cancel(duration.saturating_sub(started.elapsed()), cancel)
            }
            None => scanner.snapshot_with_cancel(cancel),
        };
        // The blindness boundary prints once per run, before the first
        // sample that establishes it (a snapshot is the knowledge
        // event: nothing is known at loop entry).
        if human && !blindness_printed && super::snapshot_conclusively_without_openssl(&snapshot) {
            writer.write_all(super::blindness_line().as_bytes())?;
            blindness_printed = true;
        }
        sequence += 1;
        seen.observe(sequence, snapshot.exit_code());
        // P0-6: retain the latest denied tick's hint on the outcome
        // (stderr emission happens once, after the run, in `cli`).
        if let Some(hint) = super::cli::privilege_hint(&snapshot) {
            end.privilege_hint = Some(hint);
        }
        let deltas = changes(previous.as_ref(), &snapshot);
        // T5 `--resolve-paths`: per-snapshot writer over this
        // snapshot's sidecar (render intent + TTY from the caller;
        // acquisition was gated separately by the effective
        // selection flag — human fragments only).
        let paths = super::resolve::TerminalPathWriter::new(
            options.resolve_paths,
            terminal,
            &snapshot.resolve,
        );
        let rendered = if human {
            human_tick(
                writer,
                sequence,
                &snapshot,
                &deltas,
                previous.as_ref(),
                &paths,
                verbosity,
            )
        } else {
            emit(
                &Record {
                    schema_version: "osslscope.discovery.v1",
                    mode: "watch",
                    record: "snapshot",
                    sequence,
                    interval: &snapshot.interval,
                    poll_interval: options.interval,
                    changes: deltas,
                    snapshot: &snapshot,
                    sampled_history: "incomplete",
                },
                writer,
            )
        };
        if let Err(error) = rendered {
            end.reason = EndReason::Output;
            end.status = 1;
            end.sequence = sequence;
            end.elapsed = started.elapsed();
            // A broken sink often cannot accept its end record. Attempt once;
            // preserve the original error and never continue acquiring data.
            if human {
                let _ = human_end(writer, &end, &seen);
            } else {
                let _ = emit(&end, writer);
            }
            return Err(error);
        }
        previous = Some(snapshot);
        let wait_started = poll_started;
        while wait_started.elapsed() < options.interval {
            if observed() || options.duration.is_some_and(|d| started.elapsed() >= d) {
                break;
            }
            let mut wait = options
                .interval
                .saturating_sub(wait_started.elapsed())
                .min(Duration::from_millis(25));
            if let Some(duration) = options.duration {
                wait = wait.min(duration.saturating_sub(started.elapsed()));
            }
            std::thread::sleep(wait);
        }
    }
    end.sequence = sequence;
    // ScopeUnavailable and Output return early above; only
    // Duration (cumulative history, F8) and Interrupted reach here.
    end.status = match end.reason {
        EndReason::Interrupted => 3,
        _ => seen.end_status(),
    };
    end.elapsed = started.elapsed();
    if human {
        human_end(writer, &end, &seen)?;
    } else {
        emit(&end, writer)?;
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            assert!(self.0.wait().unwrap().success());
        }
    }

    // Catches treating duration-skipped live PIDs as absent, while preserving
    // successful sampled scope departure as process_not_seen.
    #[test]
    fn duration_capped_snapshot_loses_visibility_for_all_live_pids() {
        let mut children: Vec<_> = (0..3)
            .map(|_| {
                Owned(
                    Command::new("/bin/cat")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();
        let pids: Vec<_> = children.iter().map(|child| child.0.id()).collect();
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: pids.clone(),
                ..Default::default()
            },
            Limits::default(),
        )
        .unwrap();
        let previous = scanner.snapshot();
        assert_eq!(previous.processes.len(), pids.len());

        // This is the production final-duration snapshot route, with no
        // remaining acquisition budget rather than a host-specific deadline.
        let current = scanner.snapshot_for(Duration::ZERO);
        assert!(current.processes.is_empty());
        let observed = serde_json::to_value(changes(Some(&previous), &current)).unwrap();
        let observed = observed.as_array().unwrap();
        assert_eq!(observed.len(), pids.len());
        for &pid in &pids {
            assert!(
                observed
                    .iter()
                    .any(|change| { change["pid"] == pid && change["kind"] == "visibility_lost" })
            );
        }

        // A successful scan of a smaller selection can still report a sampled
        // departure for the omitted live processes.
        let mut remaining = ScopedScanner::new(
            Selection {
                pids: vec![pids[0]],
                ..Default::default()
            },
            Limits::default(),
        )
        .unwrap();
        let current = remaining.snapshot();
        assert_eq!(current.processes.len(), 1);
        assert!(visible(&current, pids[1]));
        assert!(visible(&current, pids[2]));
        let observed = serde_json::to_value(changes(Some(&previous), &current)).unwrap();
        for &pid in &pids[1..] {
            let matching: Vec<_> = observed
                .as_array()
                .unwrap()
                .iter()
                .filter(|change| change["pid"] == pid)
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["kind"], "process_not_seen");
        }
        for child in &mut children {
            assert!(child.0.try_wait().unwrap().is_none());
        }
    }

    fn outcome(reason: EndReason, status: u8, gap: Option<GapReason>) -> WatchOutcome {
        WatchOutcome {
            schema_version: "osslscope.discovery.v1",
            mode: "watch",
            record: "end",
            sequence: 1,
            reason,
            status,
            elapsed: Duration::ZERO,
            limits: Limits::default(),
            gap,
            sampled_history: "incomplete",
            privilege_hint: None,
        }
    }

    #[test]
    fn watch_reason_covers_every_end_state() {
        assert_eq!(
            super::exit_reason(&outcome(EndReason::Duration, 0, None)),
            None
        );
        let interrupted = super::exit_reason(&outcome(EndReason::Interrupted, 3, None)).unwrap();
        assert!(interrupted.contains("interrupted"), "got: {interrupted}");
        let scope = super::exit_reason(&outcome(
            EndReason::ScopeUnavailable,
            4,
            Some(GapReason::CgroupUnavailable),
        ))
        .unwrap();
        assert!(
            scope.contains("scope unavailable") && scope.contains("cgroup_unavailable"),
            "got: {scope}"
        );
        let partial = super::exit_reason(&outcome(EndReason::Duration, 3, None)).unwrap();
        assert!(partial.contains("partial"), "got: {partial}");
        let mut none_seen = outcome(EndReason::Duration, 4, None);
        none_seen.sequence = 0;
        let empty = super::exit_reason(&none_seen).unwrap();
        assert!(
            empty.contains("before any snapshot"),
            "zero-snapshot end named, got: {empty}"
        );
    }

    #[test]
    fn human_end_mentions_privilege_destination_only_when_fired() {
        // P0-6: a retained hint adds the destination line to the
        // human end record; a clean run stays silent; the machine
        // end record never carries the hint (serde-skipped).
        let mut fired = outcome(EndReason::Duration, 3, None);
        fired.privilege_hint = Some("osslscope discovery: 1 of 1 modules unverified: permission denied (EACCES); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege".into());
        let mut buf = Vec::new();
        super::human_end(&mut buf, &fired, &Cumulative::default()).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("privilege: permission-denied gaps this run; remediation hint on stderr (see usage.md#privilege)"),
            "end must name the hint destination, got: {out}"
        );
        // The Task 3 reason line is unchanged by the retention.
        assert_eq!(
            super::exit_reason(&fired),
            super::exit_reason(&outcome(EndReason::Duration, 3, None))
        );
        let mut clean = Vec::new();
        super::human_end(
            &mut clean,
            &outcome(EndReason::Duration, 0, None),
            &Cumulative::default(),
        )
        .unwrap();
        let clean_out = String::from_utf8(clean).unwrap();
        assert!(
            !clean_out.contains("privilege:"),
            "clean end must stay silent, got: {clean_out}"
        );
        let value = serde_json::to_value(&fired).unwrap();
        assert!(
            value.get("privilege_hint").is_none(),
            "machine end leaked the hint: {value}"
        );
    }

    #[test]
    fn watch_run_retains_privilege_hint_once_per_run() {
        // Lane-independent retention proof: a short PID-1 watch
        // retains a hint iff PID 1 actually denies this observer
        // right now — root keeps None, denied observers keep one
        // single-line hint for the whole run, never one per tick.
        let mut probe = ScopedScanner::new(
            Selection {
                pids: vec![1],
                ..Default::default()
            },
            Limits::default(),
        )
        .unwrap();
        let denied_now = probe.snapshot().gaps.iter().any(|gap| {
            gap.errno
                .is_some_and(|errno| errno == libc::EPERM || errno == libc::EACCES)
        });
        let options = super::WatchOptions {
            selection: Selection {
                pids: vec![1],
                ..Default::default()
            },
            limits: Limits::default(),
            interval: Duration::from_millis(50),
            duration: Some(Duration::from_millis(200)),
            resolve_paths: false,
        };
        let cancel = AtomicBool::new(false);
        let mut sink = Vec::new();
        let outcome = super::run_formatted(&options, &mut sink, &cancel, false, false, 0).unwrap();
        assert!(outcome.sequence >= 1, "the run must tick");
        assert_eq!(
            outcome.privilege_hint.is_some(),
            denied_now,
            "retention must match observed denial"
        );
        if let Some(hint) = outcome.privilege_hint.as_deref() {
            assert!(
                hint.contains("re-run as root") && !hint.contains('\n'),
                "one single-line hint per run, got: {hint}"
            );
        }
    }

    fn tick_process(pid: u32, comm: &str) -> crate::inventory::ProcessRecord {
        crate::inventory::ProcessRecord {
            interval: crate::inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            namespaces: crate::inventory::NamespaceIds::default(),
            pid,
            starttime: 7,
            comm: Some(comm.to_string()),
            comm_status: crate::inventory::IdentityAvailability::Available,
            exe: None,
            exe_status: crate::inventory::IdentityAvailability::Unreadable,
            modules: vec![module_record(crate::inventory::IdentityStatus::Verified)],
            other_objects: crate::inventory::OtherCounts::default(),
            provider_activation: crate::inventory::ObservationState::Unknown,
            provider_interfaces: crate::inventory::ObservationState::Unknown,
            execution: crate::inventory::ObservationState::NotObserved,
        }
    }

    fn tick_snapshot(
        processes: Vec<crate::inventory::ProcessRecord>,
        gaps: Vec<crate::inventory::Gap>,
        state: crate::inventory::InventoryState,
    ) -> crate::inventory::Snapshot {
        crate::inventory::Snapshot {
            interval: crate::inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            scope_record: crate::inventory::ScopeRecord::default(),
            schema_version: "osslscope.discovery.v1".into(),
            mode: crate::inventory::SnapshotMode::Snapshot,
            scope: crate::inventory::Scope::Pids,
            selected_pids: vec![11],
            processes,
            gaps,
            totals: crate::inventory::WorkTotals::default(),
            limits: Limits::default(),
            capabilities: crate::inventory::Capabilities {
                inventory: state,
                provider_activation: crate::inventory::ObservationState::Unknown,
                provider_interfaces: crate::inventory::ObservationState::Unknown,
                execution: crate::inventory::ObservationState::NotObserved,
            },
            resolve: crate::inventory::resolve::ResolveSidecar::default(),
            cgroup_identity: std::collections::BTreeMap::new(),
        }
    }

    fn render_tick(
        sequence: u64,
        snapshot: &Snapshot,
        previous: Option<&Snapshot>,
        verbosity: u8,
    ) -> String {
        let deltas = super::changes(previous, snapshot);
        let mut buf = Vec::new();
        let paths =
            crate::inventory::resolve::TerminalPathWriter::new(false, false, &snapshot.resolve);
        super::human_tick(
            &mut buf, sequence, snapshot, &deltas, previous, &paths, verbosity,
        )
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn human_tick_renders_initial_heartbeat_and_state_changed() {
        // Tick 1 renders full state with identity totals; an
        // identical tick 2 heartbeats; a tick-3 rename renders
        // the renamed block instead of a heartbeat.
        let gap = || crate::inventory::Gap {
            pid: Some(11),
            device: Some(7),
            inode: Some(9),
            reason: crate::inventory::GapReason::IdentityUnverified,
            errno: None,
            actor_euid: None,
        };
        let snap1 = tick_snapshot(
            vec![tick_process(11, "child")],
            vec![gap()],
            crate::inventory::InventoryState::Partial,
        );
        let tick1 = render_tick(1, &snap1, None, 0);
        assert!(
            tick1.contains(
                "tick 1: initial state (status partial, processes 1, modules 1/1 verified)"
            ),
            "got: {tick1}"
        );
        assert!(
            tick1.contains("pid=11 comm=child exe=- modules=1 status=partial"),
            "verdict, got: {tick1}"
        );
        assert!(
            tick1
                .contains("identity: 1 verified, 0 locator-candidate of 1 modules (100% verified)"),
            "totals, got: {tick1}"
        );
        assert!(
            tick1.contains("gaps: 1 (identity_unverified=1;"),
            "counts, got: {tick1}"
        );
        let snap2 = snap1.clone();
        let tick2 = render_tick(2, &snap2, Some(&snap1), 0);
        assert!(
            tick2
                .contains("tick 2: no changes (status partial, processes 1, modules 1/1 verified)"),
            "got: {tick2}"
        );
        assert!(!tick2.contains("pid=11"), "heartbeat re-dumped: {tick2}");
        // Verbose quiet tick: the line still reports reality; the
        // full state dumps beneath it.
        let tick2v = render_tick(2, &snap2, Some(&snap1), 1);
        assert!(
            tick2v
                .contains("tick 2: no changes (status partial, processes 1, modules 1/1 verified)"),
            "got: {tick2v}"
        );
        assert!(
            tick2v.contains("pid=11 comm=child"),
            "verbose dumps state, got: {tick2v}"
        );
        let snap3 = tick_snapshot(
            vec![tick_process(11, "renamed")],
            vec![gap()],
            crate::inventory::InventoryState::Partial,
        );
        let tick3 = render_tick(3, &snap3, Some(&snap2), 0);
        assert!(
            tick3.contains(
                "tick 3: state changed (status partial, processes 1, modules 1/1 verified)"
            ),
            "got: {tick3}"
        );
        assert!(
            tick3.contains("pid=11 comm=renamed"),
            "renamed block, got: {tick3}"
        );
    }

    #[test]
    fn human_tick_verbose_coalesces_repeated_gaps() {
        // Three identical gaps + one different gap at -v: one
        // group line with `: 3`, one with `: 1`, plus the header
        // with exact totals; level 0 keeps the counts line.
        let gap = |reason: crate::inventory::GapReason, pid: u32| crate::inventory::Gap {
            pid: Some(pid),
            device: Some(7),
            inode: Some(9),
            reason,
            errno: None,
            actor_euid: None,
        };
        let snap = tick_snapshot(
            vec![tick_process(11, "child")],
            vec![
                gap(crate::inventory::GapReason::IdentityUnverified, 11),
                gap(crate::inventory::GapReason::IdentityUnverified, 11),
                gap(crate::inventory::GapReason::IdentityUnverified, 11),
                gap(crate::inventory::GapReason::Deadline, 12),
            ],
            crate::inventory::InventoryState::Partial,
        );
        let out = render_tick(1, &snap, None, 1);
        assert!(
            out.contains("gaps (4 total in 2 groups):"),
            "coalesced header, got: {out}"
        );
        assert!(
            out.contains("identity_unverified device=7 pid=11: 3"),
            "group of three, got: {out}"
        );
        assert!(
            out.contains("deadline device=7 pid=12: 1"),
            "singleton group keeps its ids, got: {out}"
        );
        let quiet = render_tick(1, &snap, None, 0);
        assert!(
            quiet.contains("gaps: 4 (deadline=1 identity_unverified=3;"),
            "counts line, got: {quiet}"
        );
        assert!(
            !quiet.contains("total in"),
            "no groups at level 0, got: {quiet}"
        );
    }

    #[test]
    fn watch_words_match_json() {
        for (kind, word) in [
            (super::ChangeKind::ProcessSeen, "process_seen"),
            (super::ChangeKind::ModuleSeen, "module_seen"),
            (super::ChangeKind::ProcessNotSeen, "process_not_seen"),
            (super::ChangeKind::ModuleNotSeen, "module_not_seen"),
            (super::ChangeKind::VisibilityLost, "visibility_lost"),
        ] {
            assert_eq!(kind.word(), word);
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String(word.into())
            );
        }
        for (reason, word) in [
            (super::EndReason::Duration, "duration"),
            (super::EndReason::Interrupted, "interrupted"),
            (super::EndReason::ScopeUnavailable, "scope_unavailable"),
            (super::EndReason::Output, "output"),
        ] {
            assert_eq!(super::reason_word(reason), word);
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::Value::String(word.into())
            );
        }
    }

    // W2: human change lines carry the 12-char short hash at every
    // level, never the full 64-hex (machine records keep it).
    #[test]
    fn human_change_line_prints_short_hash() {
        use crate::inventory as inv;
        let sidecar = inv::resolve::ResolveSidecar::default();
        let paths = inv::resolve::TerminalPathWriter::new(false, false, &sidecar);
        let full = "ab".repeat(32);
        let change = super::Change {
            kind: super::ChangeKind::ModuleSeen,
            pid: 42,
            starttime: 7,
            module: Some(inv::ModuleRecord {
                info: inv::ModuleInfo {
                    sha256: full.clone(),
                    device: 1,
                    inode: 2,
                    size_bytes: 3,
                    architecture: inv::Architecture::X86_64,
                    kind: inv::ObjectKind::Other,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                    file_soname: None,
                    file_openssl_version: None,
                    file_version_status: inv::FileVersionStatus::Absent,
                },
                identity_status: inv::IdentityStatus::Verified,
                verified_path: None,
                verified_path_unavailable: None,
                maps_spelling: None,
            }),
        };
        let mut bytes = Vec::new();
        super::human_change_line(&mut bytes, &change, &paths).unwrap();
        let line = String::from_utf8(bytes).unwrap();
        assert!(line.contains("module_seen pid=42 starttime=7"), "{line}");
        assert!(line.contains("sha256=abababababab"), "{line}");
        assert!(!line.contains(&full), "full hash on human line: {line}");
    }

    // R13 follow-up (H8 review minor 3): flag-off change lines
    // carry acquired snapshot evidence — the verified path, the
    // explicitly-unverified maps hint, or the genuinely-
    // unacquirable placeholder — never omit what was acquired.
    #[test]
    fn human_change_line_flag_off_carries_acquired_path() {
        use crate::inventory as inv;
        let sidecar = inv::resolve::ResolveSidecar::default();
        let paths = inv::resolve::TerminalPathWriter::new(false, false, &sidecar);
        let record = |verified_path: Option<inv::VerifiedPath>,
                      maps_spelling: Option<inv::MapsSpelling>| {
            inv::ModuleRecord {
                info: inv::ModuleInfo {
                    sha256: "ab".repeat(32),
                    device: 1,
                    inode: 2,
                    size_bytes: 3,
                    architecture: inv::Architecture::X86_64,
                    kind: inv::ObjectKind::Other,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                    file_soname: None,
                    file_openssl_version: None,
                    file_version_status: inv::FileVersionStatus::Absent,
                },
                identity_status: inv::IdentityStatus::Verified,
                verified_path,
                verified_path_unavailable: None,
                maps_spelling,
            }
        };
        let render = |module: inv::ModuleRecord| {
            let change = super::Change {
                kind: super::ChangeKind::ModuleSeen,
                pid: 42,
                starttime: 7,
                module: Some(module),
            };
            let mut bytes = Vec::new();
            super::human_change_line(&mut bytes, &change, &paths).unwrap();
            String::from_utf8(bytes).unwrap()
        };
        let line = render(record(
            Some(inv::VerifiedPath {
                path: "/lib/x86_64-linux-gnu/libcrypto.so.3".to_string(),
                path_encoding: inv::PathEncoding::Utf8,
                locator_kind: inv::LocatorKind::HostDirect,
                capture_unix_ms: None,
            }),
            None,
        ));
        assert!(
            line.contains("path=/lib/x86_64-linux-gnu/libcrypto.so.3"),
            "{line}"
        );
        let line = render(record(
            None,
            Some(inv::MapsSpelling {
                spelling: "/mem/fd:deleted-lib.so".to_string(),
                source: inv::MapsSource::ProcMaps,
                verification: inv::MapsVerification::Unverified,
            }),
        ));
        assert!(
            line.contains("path=(unverified maps hint: /mem/fd:deleted-lib.so)"),
            "{line}"
        );
        let line = render(record(None, None));
        assert!(line.contains("path=(unavailable)"), "{line}");
    }

    // F8/H2: the run end status is cumulative, never the last
    // sample's status — a later complete sample never erases
    // earlier uncertainty. 4 means zero usable samples (all
    // unavailable, or none at all); 3 means usable data with an
    // uncertain history (same rule as the provider end record).
    #[test]
    fn cumulative_end_status_keeps_partial_and_unavailable_history() {
        let run = |exits: &[u8]| {
            let mut seen = super::Cumulative::default();
            for (i, &exit) in exits.iter().enumerate() {
                seen.observe(i as u64 + 1, exit);
            }
            seen.end_status()
        };
        assert_eq!(run(&[]), 4);
        assert_eq!(run(&[0]), 0);
        assert_eq!(run(&[0, 0]), 0);
        assert_eq!(run(&[3]), 3);
        assert_eq!(run(&[3, 0]), 3);
        assert_eq!(run(&[0, 3, 0]), 3);
        assert_eq!(run(&[4]), 4);
        assert_eq!(run(&[4, 4]), 4);
        assert_eq!(run(&[4, 0]), 3);
        assert_eq!(run(&[0, 4]), 3);
        assert_eq!(run(&[3, 4]), 3);
        assert_eq!(run(&[4, 3]), 3);
    }

    #[test]
    fn cumulative_firsts_name_earliest_uncertain_samples() {
        let mut seen = super::Cumulative::default();
        seen.observe(1, 0);
        seen.observe(2, 3);
        seen.observe(3, 0);
        seen.observe(4, 4);
        assert_eq!(seen.first_partial, Some(2));
        assert_eq!(seen.first_unavailable, Some(4));
        // An unavailable sample books the unavailable track only:
        // one note per track, never a double note for one sample.
        let mut seen = super::Cumulative::default();
        seen.observe(1, 4);
        assert_eq!(seen.first_partial, None);
        assert_eq!(seen.first_unavailable, Some(1));
    }

    fn module_record(status: crate::inventory::IdentityStatus) -> crate::inventory::ModuleRecord {
        crate::inventory::ModuleRecord {
            info: crate::inventory::ModuleInfo {
                sha256: "a".repeat(64),
                device: 7,
                inode: 9,
                size_bytes: 100,
                architecture: crate::inventory::Architecture::X86_64,
                kind: crate::inventory::ObjectKind::Other,
                exports: Vec::new(),
                depends_on_libcrypto: false,
                depends_on_libssl: false,
                file_soname: None,
                file_openssl_version: None,
                file_version_status: crate::inventory::FileVersionStatus::Absent,
            },
            identity_status: status,
            verified_path: None,
            verified_path_unavailable: None,
            maps_spelling: None,
        }
    }

    // W1: watch comparison must not ignore identity-status
    // changes (codex quiet-contract ruling), nor path, version,
    // or evidence changes on the same file.
    #[test]
    fn same_module_flags_identity_and_evidence_changes() {
        use crate::inventory::IdentityStatus;
        let base = module_record(IdentityStatus::Verified);
        assert!(super::same_module(&base, &base));
        assert!(!super::same_module(
            &base,
            &module_record(IdentityStatus::LocatorCandidate)
        ));
        let mut versioned = base.clone();
        versioned.info.file_openssl_version = Some("OpenSSL 3.0.0".to_string());
        assert!(!super::same_module(&base, &versioned));
        let mut pathed = base.clone();
        pathed.maps_spelling = Some(crate::inventory::MapsSpelling {
            spelling: "/lib/x.so".to_string(),
            source: crate::inventory::MapsSource::ProcMaps,
            verification: crate::inventory::MapsVerification::Unverified,
        });
        assert!(!super::same_module(&base, &pathed));
        let mut reasoned = base.clone();
        reasoned.verified_path_unavailable =
            Some(crate::inventory::PathUnavailableReason::UnverifiedIdentity);
        assert!(!super::same_module(&base, &reasoned));
    }

    #[test]
    fn same_module_ignores_per_sample_capture_time() {
        // `capture_unix_ms` is re-stamped every sample: comparing
        // it would flap every tick and kill the heartbeat. Only
        // the stable locator triple (path, encoding, kind) counts.
        let mut a = module_record(crate::inventory::IdentityStatus::Verified);
        let mut b = a.clone();
        for (slot, stamp) in [(&mut a, Some(100)), (&mut b, Some(200))] {
            slot.verified_path = Some(crate::inventory::VerifiedPath {
                path: "/lib/x.so".to_string(),
                path_encoding: crate::inventory::PathEncoding::Utf8,
                locator_kind: crate::inventory::LocatorKind::HostDirect,
                capture_unix_ms: stamp,
            });
        }
        assert!(super::same_module(&a, &b));
        b.verified_path.as_mut().unwrap().path = "/lib/y.so".to_string();
        assert!(!super::same_module(&a, &b));
    }
}
