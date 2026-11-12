// SPDX-License-Identifier: GPL-3.0-or-later
//! Cooperative public-ABI observation. No executed assets or target bootstrap.
use super::{
    IntervalCause, ObservationBatch, ObservationGap, ObservationLimits, ProviderSession, artifact,
};
use crate::inventory::{
    self,
    scope::{ScopedScanner, Selection},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
const SCHEMA: &str = "osslscope.discovery.provider.v1";
const HELP: &str = "usage: osslscope scan --observe-providers [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--duration S] [--interval S]] [--json]\n       osslscope inspect --pid PID --observe-providers [--json]\nObserve public provider APIs for 30 seconds by default; duration (0,3600]s, interval [0.05,3600]s (default 1s).\nStreams snapshot/observation/end records; activation before attachment remains unknown.\nAdvertisements do not prove execution; execution remains not_observed.\n";
const MEANING: &str = "Provider observation: historical activation unknown; advertisements do not prove execution; execution not_observed.\n";
/// Value-taking options of the scan parser below: the scan router
/// consumes the token after each of these, so flag-shaped values
/// never misroute. A new value-taking match arm MUST extend this list.
pub(crate) const VALUE_OPTIONS: &[&str] =
    &["--interval", "--duration", "--pid", "--module", "--cgroup"];
struct Options {
    selection: Selection,
    json: bool,
    watch: bool,
    interval: Duration,
    duration: Duration,
    /// Human detail level (`-v`/`--verbose` repeatable, `-vv` = 2,
    /// clamped at 2; default 0 is quiet). Gates detail volume
    /// only — exits, stderr, capability words, and JSON bytes are
    /// identical at every level. v0.6.0 P0-3:
    /// report/check/service human redesign stays P1.
    verbosity: u8,
}
fn seconds(text: &str, interval: bool) -> Result<Duration, ()> {
    let value: f64 = text.parse().map_err(|_| ())?;
    if !value.is_finite() || value <= 0.0 || value > 3600.0 || (interval && value < 0.05) {
        return Err(());
    }
    let result = Duration::try_from_secs_f64(value).map_err(|_| ())?;
    if result.is_zero() {
        Err(())
    } else {
        Ok(result)
    }
}
fn parse(args: &[String]) -> Result<Options, ()> {
    let command = args.first().map(String::as_str).ok_or(())?;
    if !matches!(command, "scan" | "inspect") {
        return Err(());
    }
    // R13 always-acquire (F-NEW-1): provider snapshots always
    // carry D1 path evidence — verified path or null + finite
    // reason — exactly like scan/inspect/watch/crypto (the
    // shared `acquire_paths` rule, unconditionally true). A
    // default (acquire-off) selection here emits bare-null path
    // triples on every production run, breaching P0-1.
    let mut selection = Selection {
        resolve_paths: true,
        ..Default::default()
    };
    let mut json = false;
    let mut watch = false;
    let mut observe = false;
    let mut interval = None;
    let mut duration = None;
    let mut verbosity = 0u8;
    let mut args = args[1..].iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--observe-providers" if !observe => observe = true,
            "--json" if !json => json = true,
            "--watch" if command == "scan" && !watch => watch = true,
            // Repeatable, clamped at 2 below. `-q`/`--quiet` stay
            // unknown (exit 2, empty stdout): the default is
            // already quiet, so no quiet flag exists.
            "-v" | "--verbose" => verbosity = verbosity.saturating_add(1),
            "-vv" => verbosity = 2,
            "--interval" if command == "scan" && interval.is_none() => {
                interval = Some(seconds(args.next().ok_or(())?, true)?)
            }
            "--duration" if command == "scan" && duration.is_none() => {
                duration = Some(seconds(args.next().ok_or(())?, false)?)
            }
            "--pid" => {
                let value = args.next().ok_or(())?;
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(());
                }
                let pid: u32 = value.parse().map_err(|_| ())?;
                if pid == 0 || pid > i32::MAX as u32 {
                    return Err(());
                }
                selection.pids.push(pid);
            }
            "--cgroup" if command == "scan" && selection.cgroup.is_none() => {
                selection.cgroup = Some(path(args.next())?)
            }
            "--module" if command == "scan" => selection.modules.push(path(args.next())?),
            _ => return Err(()),
        }
    }
    if !observe
        || (!watch && (interval.is_some() || duration.is_some()))
        || (command == "inspect" && selection.pids.len() != 1)
    {
        return Err(());
    }
    Ok(Options {
        selection,
        json,
        watch,
        interval: interval.unwrap_or(Duration::from_secs(1)),
        duration: duration.unwrap_or(Duration::from_secs(30)),
        verbosity: verbosity.min(2),
    })
}
fn path(value: Option<&String>) -> Result<PathBuf, ()> {
    value
        .filter(|s| !s.is_empty() && !s.starts_with("--"))
        .map(PathBuf::from)
        .ok_or(())
}
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn signal(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
/// Legacy per-route token, kept only for `focused_capture::run`
/// (out of v0.6.0-signals scope): this route's `run()`/`observe()`
/// use the shared `crate::shutdown::Shutdown` instead.
pub(crate) struct Signals(Vec<(libc::c_int, libc::sigaction)>);
impl Signals {
    pub(crate) fn cancel(&self) -> &AtomicBool {
        &INTERRUPTED
    }
    pub(crate) fn install() -> io::Result<Self> {
        INTERRUPTED.store(false, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for number in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: initialized sigaction storage and atomic-only handler.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous = action;
            action.sa_sigaction = signal as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(number, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            guard.0.push((number, previous));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (number, previous) in self.0.iter().rev() {
            unsafe {
                libc::sigaction(*number, previous, std::ptr::null_mut());
            }
        }
    }
}
#[derive(Serialize)]
struct Capabilities {
    inventory: &'static str,
    tracing: &'static str,
    historical_activation: &'static str,
    provider_interfaces: &'static str,
    execution: &'static str,
}
impl Capabilities {
    fn new(available: bool) -> Self {
        Self {
            inventory: "unavailable",
            tracing: if available {
                "available"
            } else {
                "unavailable"
            },
            historical_activation: "unknown",
            provider_interfaces: if available { "sampled" } else { "unknown" },
            execution: "not_observed",
        }
    }
}
#[derive(Serialize)]
struct Interval {
    started_elapsed_ns: u64,
    finished_elapsed_ns: u64,
    drain_lag_ns: u64,
}
#[derive(Serialize)]
struct Record<'a> {
    schema_version: &'static str,
    mode: &'static str,
    record: &'static str,
    sequence: u64,
    interval: Interval,
    poll_interval: Duration,
    snapshot: Option<&'a inventory::Snapshot>,
    facts: &'a [super::ObservationFact],
    gaps: &'a [ObservationGap],
    /// Human-only causes for the interval gaps in [`Self::gaps`],
    /// aligned in order (see
    /// [`ObservationBatch::interval_causes`]). Skipped by serde:
    /// the machine record is byte-identical.
    #[serde(skip)]
    interval_causes: &'a [IntervalCause],
    capabilities: &'a Capabilities,
    sampled_history: &'static str,
}
#[derive(Serialize)]
struct End<'a> {
    schema_version: &'static str,
    mode: &'static str,
    record: &'static str,
    sequence: u64,
    reason: inventory::watch::EndReason,
    status: u8,
    elapsed: Duration,
    limits: inventory::Limits,
    capabilities: &'a Capabilities,
    gap: Option<inventory::GapReason>,
    sampled_history: &'static str,
    /// Run-level sample history for the human end record only
    /// (F8/H2): skipped by serde, so the machine end shape is
    /// byte-identical.
    #[serde(skip)]
    cumulative: inventory::watch::Cumulative,
}
fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}
trait Render: Serialize {
    fn human(&self, writer: &mut impl Write, verbosity: u8) -> io::Result<()>;
}
fn finite(value: &impl Serialize) -> io::Result<String> {
    serde_json::to_string(value).map_err(io::Error::other)
}
fn human_capabilities(caps: &Capabilities, writer: &mut impl Write) -> io::Result<()> {
    writeln!(
        writer,
        "  tracing={} historical_activation={} provider_interfaces={} execution={}",
        caps.tracing, caps.historical_activation, caps.provider_interfaces, caps.execution
    )
}
impl Render for Record<'_> {
    fn human(&self, writer: &mut impl Write, verbosity: u8) -> io::Result<()> {
        // Verbosity gates detail volume only (0 = rows + grouped
        // gaps; 1 = + per-module exports + full per-process state;
        // 2 = + full fact payloads + per-object gap records + safe
        // counters + the jargon detail line); hashes stay short at
        // every level.
        let level = verbosity.min(2);
        // W5: the default header is plain words.
        // Observation-only batches (drain/close) carry no snapshot,
        // so they claim no module count — only batches with
        // inventory name one.
        match self.snapshot {
            Some(snapshot) => {
                let modules: usize = snapshot.processes.iter().map(|p| p.modules.len()).sum();
                writeln!(
                    writer,
                    "provider sample: {modules} modules, {} facts",
                    self.facts.len()
                )?;
            }
            None => writeln!(writer, "provider sample: {} facts", self.facts.len())?,
        }
        // The technical header moves to `-vv` verbatim (indented):
        // the interval range, drain lag, and record identity behind
        // the plain summary above.
        if level >= 2 {
            writeln!(
                writer,
                "  detail {} {}: interval_ns={}..{} drain_lag_ns={} facts={}",
                self.record,
                self.sequence,
                self.interval.started_elapsed_ns,
                self.interval.finished_elapsed_ns,
                self.interval.drain_lag_ns,
                self.facts.len()
            )?;
            human_capabilities(self.capabilities, writer)?;
        }
        if let Some(snapshot) = self.snapshot {
            writeln!(
                writer,
                "  inventory={}",
                finite(&snapshot.capabilities.inventory)?
            )?;
            let (verified, locator) = snapshot.identity_counts();
            write!(
                writer,
                "  {}",
                crate::inventory::identity_totals_line(verified, locator)
            )?;
            // R13 snapshot-evidence writer (F-NEW-1, b540ae8
            // pattern): the provider route has no
            // `--resolve-paths` flag, so live re-resolution
            // stays off and rows show acquired snapshot
            // evidence — never omit what was acquired (the
            // flag-off live branch is dead here).
            let paths =
                crate::inventory::resolve::TerminalPathWriter::new(false, false, &snapshot.resolve);
            for process in &snapshot.processes {
                write!(
                    writer,
                    "  process pid={} starttime={} comm={} exe={}",
                    process.pid,
                    process.starttime,
                    crate::inventory::cli::human_comm(process),
                    crate::inventory::cli::human_exe(process)
                )?;
                if level >= 1 {
                    write!(
                        writer,
                        " modules={} namespaces={} provider_activation={} provider_interfaces={} execution={}",
                        process.modules.len(),
                        crate::inventory::human_namespaces(&process.namespaces),
                        process.provider_activation.word(),
                        process.provider_interfaces.word(),
                        process.execution.word()
                    )?;
                }
                writeln!(writer)?;
                for module in &process.modules {
                    write!(
                        writer,
                        "    sha256={} kind={} identity={}",
                        crate::inventory::resolve::TerminalPathWriter::short_sha(
                            &module.info.sha256
                        ),
                        finite(&module.info.kind)?,
                        finite(&module.identity_status)?
                    )?;
                    // Scan-route shapes for the same record
                    // (`human_path`/`human_version`): verified
                    // path, explicitly-unverified maps hint, or
                    // the genuinely-unacquirable placeholder —
                    // null/missing never crashes.
                    write!(
                        writer,
                        " path={} version={}",
                        paths.human_path(module),
                        crate::inventory::resolve::TerminalPathWriter::human_version(&module.info),
                    )?;
                    if level >= 1 {
                        write!(
                            writer,
                            " {}",
                            crate::inventory::human_exports(&module.info.exports)
                        )?;
                    }
                    writeln!(writer)?;
                }
            }
            writer.write_all(inventory_gap_block(&snapshot.gaps)?.as_bytes())?;
            if level >= 2 {
                for gap in &snapshot.gaps {
                    writeln!(
                        writer,
                        "  gap pid={} device={} reason={} errno={}",
                        gap.pid.map_or("-".to_string(), |p| p.to_string()),
                        gap.device.map_or("-".to_string(), |d| d.to_string()),
                        gap.reason.word(),
                        gap.errno.map_or("-".to_string(), |e| e.to_string())
                    )?;
                }
                writeln!(
                    writer,
                    "  counters: read_bytes={} objects_inspected={}",
                    snapshot.totals.read_bytes, snapshot.totals.objects_inspected
                )?;
            }
        }
        for fact in self.facts {
            let hash: String = fact.object_sha256.clone().into();
            write!(
                writer,
                "  fact pid={} starttime={} sha256={} generation={} api={} source={} operation={} class={}",
                fact.pid,
                fact.starttime,
                crate::inventory::resolve::TerminalPathWriter::short_sha(&hash),
                fact.generation,
                finite(&fact.api)?,
                finite(&fact.source)?,
                finite(&fact.operation)?,
                finite(&fact.class)?,
            )?;
            // The monotonic timestamp is `-vv` technics (W5); the
            // default line keeps identity, operation, and
            // classification.
            if level >= 2 {
                write!(writer, " monotonic_ns={}", fact.monotonic_ns)?;
            }
            write!(
                writer,
                " context={} confidence={}",
                finite(&fact.context)?,
                finite(&fact.confidence)?
            )?;
            if let super::ObservationPayload::Algorithm {
                algorithm,
                alias_quality,
                ..
            }
            | super::ObservationPayload::Implementation {
                algorithm,
                alias_quality,
                ..
            } = &fact.payload
            {
                write!(
                    writer,
                    " algorithm={} alias_status={} weak={}",
                    algorithm.label(),
                    finite(&alias_quality.status)?,
                    alias_quality.weak
                )?;
            }
            // The full payload is a JSON dump: level 2 only.
            if level >= 2 {
                writeln!(writer, " payload={}", finite(&fact.payload)?)?;
            } else {
                writeln!(writer)?;
            }
        }
        writer.write_all(observation_gap_block(self.gaps, self.interval_causes)?.as_bytes())?;
        Ok(())
    }
}
impl Render for End<'_> {
    // The end record is status-critical: the verdict words above
    // stay byte-identical at every verbosity level (the cumulative
    // word and notes are history, never detail volume — H2: never
    // gated). Only the capabilities line is `-vv` technics (W5).
    fn human(&self, writer: &mut impl Write, verbosity: u8) -> io::Result<()> {
        writeln!(
            writer,
            "end {}: reason={} status={} elapsed_ns={} cumulative={}",
            self.sequence,
            finite(&self.reason)?,
            self.status,
            nanos(self.elapsed),
            self.cumulative.word()
        )?;
        writer.write_all(self.cumulative.notes().as_bytes())?;
        if verbosity.min(2) >= 2 {
            human_capabilities(self.capabilities, writer)?;
        }
        if let Some(gap) = self.gap {
            writeln!(writer, "  inventory_gap={}", finite(&gap)?)?;
        }
        Ok(())
    }
}
fn emit(
    value: &impl Render,
    writer: &mut impl Write,
    human: bool,
    verbosity: u8,
) -> io::Result<()> {
    if human {
        value.human(writer, verbosity)?;
    } else {
        serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
fn degraded(gaps: &[ObservationGap]) -> bool {
    gaps.iter().any(|g| {
        !matches!(
            g,
            ObservationGap::FirstQueryUnknown
                | ObservationGap::IntervalUnknown
                | ObservationGap::SamplingPartial
        )
    })
}
struct Stream<'a, W> {
    writer: &'a mut W,
    options: &'a Options,
    capabilities: Capabilities,
    started: Instant,
    sequence: u64,
    /// Previous snapshot batch digest (W1 heartbeat): `None`
    /// until the first snapshot batch renders full. Snapshots
    /// arrive borrowed, so the stream retains this owned digest
    /// instead of a full previous snapshot.
    prev: Option<ProviderDigest>,
    cumulative: inventory::watch::Cumulative,
}

/// Stable per-batch digest: sample exit, per-process digests,
/// and both gap multisets sorted (sample order never counts).
/// Observation gaps join the digest (not an emptiness check),
/// so a persistent identical gap set heartbeats while any gap
/// churn renders full.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProviderDigest {
    exit: u8,
    processes: Vec<inventory::WatchedProcessDigest>,
    gaps: Vec<inventory::Gap>,
    obs_gaps: Vec<String>,
}

fn digest_batch(
    snapshot: &inventory::Snapshot,
    gaps: &[ObservationGap],
) -> io::Result<ProviderDigest> {
    let mut snap_gaps = snapshot.gaps.clone();
    snap_gaps.sort();
    let mut obs: Vec<String> = Vec::with_capacity(gaps.len());
    for gap in gaps {
        obs.push(finite(gap)?);
    }
    obs.sort();
    Ok(ProviderDigest {
        exit: snapshot.exit_code(),
        processes: snapshot
            .processes
            .iter()
            .map(inventory::watched_process_digest)
            .collect(),
        gaps: snap_gaps,
        obs_gaps: obs,
    })
}

/// Stderr reason for provider exits 3/4, derived from the same
/// (cumulative, reason) pair `end` maps to the exit code.
/// `None` exactly when the status would be 0.
fn end_reason_text(
    seen: &inventory::watch::Cumulative,
    reason: inventory::watch::EndReason,
    gap: Option<inventory::GapReason>,
) -> Option<String> {
    if seen.usable
        && !seen.partial
        && !seen.unavailable
        && reason != inventory::watch::EndReason::Interrupted
    {
        return None;
    }
    if reason == inventory::watch::EndReason::ScopeUnavailable {
        let gap = gap.map(|g| format!(": {}", g.word())).unwrap_or_default();
        return Some(format!(
            "osslscope provider discovery: scope unavailable{gap} (see end record above)"
        ));
    }
    if !seen.usable {
        return Some(
            "osslscope provider discovery: providers unavailable (no usable snapshot; see records above)"
                .into(),
        );
    }
    if reason == inventory::watch::EndReason::Interrupted {
        return Some(
            "osslscope provider discovery: observation interrupted (partial; see records above)"
                .into(),
        );
    }
    Some("osslscope provider discovery: providers partial (see records above)".into())
}

/// Human inventory-gap block for one batch (buffered for this flush
/// only): typed gaps grouped by (word, device, pid). Empty when none.
fn inventory_gap_block(gaps: &[inventory::Gap]) -> io::Result<String> {
    Ok(crate::inventory::gap_groups_block(
        gaps.iter().map(|g| (g.reason.word(), g.device, g.pid)),
        "  ",
    ))
}

/// Human observation-gap block for one batch: non-interval
/// gaps group as before (`ObservationGap` carries no device/pid,
/// so groups key on the finite word only); each
/// `interval_unknown` renders its honest one-line cause once,
/// with `(x{n} more)` collapsing for repeats. Empty when none.
fn observation_gap_block(gaps: &[ObservationGap], causes: &[IntervalCause]) -> io::Result<String> {
    let mut words = Vec::new();
    // Pair interval gaps with their aligned causes in order; a
    // gap past the causes is causeless (explicit fallback, never
    // a guessed cause); a cause past the gaps is dropped (the
    // human line must not outclaim the machine record).
    let mut count_read = 0usize;
    let mut join_miss = 0usize;
    let mut causeless = 0usize;
    {
        let mut causes = causes.iter().copied();
        for gap in gaps {
            if *gap == ObservationGap::IntervalUnknown {
                match causes.next() {
                    Some(IntervalCause::CountRead) => count_read += 1,
                    Some(IntervalCause::JoinMiss) => join_miss += 1,
                    None => causeless += 1,
                }
            } else {
                words.push(finite(gap)?);
            }
        }
    }
    let mut out =
        crate::inventory::gap_groups_block(words.iter().map(|w| (w.as_str(), None, None)), "  ");
    for (cause, count) in [
        (IntervalCause::CountRead, count_read),
        (IntervalCause::JoinMiss, join_miss),
    ] {
        if count == 0 {
            continue;
        }
        out.push_str("  interval_unknown (timing/count gap: ");
        out.push_str(cause.text());
        out.push_str("; counts may be incomplete)");
        if count > 1 {
            out.push_str(&format!(" (x{} more)", count - 1));
        }
        out.push('\n');
    }
    if causeless > 0 {
        out.push_str(
            "  interval_unknown (timing/count gap: cause not recorded; counts may be incomplete)",
        );
        if causeless > 1 {
            out.push_str(&format!(" (x{} more)", causeless - 1));
        }
        out.push('\n');
    }
    Ok(out)
}
impl<W: Write> Stream<'_, W> {
    fn mode(&self) -> &'static str {
        if self.options.watch {
            "watch"
        } else {
            "snapshot"
        }
    }
    fn batch(
        &mut self,
        batch: ObservationBatch,
        snapshot: Option<&inventory::Snapshot>,
        begin: Duration,
        lag: Duration,
    ) -> io::Result<()> {
        // Relocation records contain privileged data and never enter rendering.
        let ObservationBatch {
            facts,
            mut gaps,
            interval_causes,
            refusals: _,
            learned_sites: _,
            static_candidates: _,
            api_activity: _,
            refreshed_processes: _,
            exec_witnesses: _,
            exec_deferred: _,
            additive_refreshes: _,
        } = batch;
        if let Some(snapshot) = snapshot {
            self.capabilities.inventory = match snapshot.capabilities.inventory {
                inventory::InventoryState::Complete => "complete",
                inventory::InventoryState::Partial => "partial",
                inventory::InventoryState::Unavailable => "unavailable",
            };
        }
        if lag > Duration::from_millis(200) && !gaps.contains(&ObservationGap::SnapshotLag) {
            gaps.push(ObservationGap::SnapshotLag);
        }
        let bad = degraded(&gaps);
        self.sequence += 1;
        // F8/H2: run-level history — a later clean batch never
        // erases earlier uncertainty. Exit-4 samples book the
        // unavailable track only (never a double note); degraded
        // batches without one book partial.
        if let Some(snapshot) = snapshot {
            self.cumulative.observe(self.sequence, snapshot.exit_code());
        }
        if bad && snapshot.is_none_or(|s| s.exit_code() != 4) {
            self.cumulative.note_partial(self.sequence);
        }
        // W1: an identical repeat batch (no facts, same gaps,
        // same snapshot state) heartbeats in human mode; machine
        // mode always renders the full record. Observation-only
        // batches (drain/close) always carry facts or gaps, so
        // they render full and leave the digest chain untouched.
        let digest = match snapshot {
            Some(snapshot) => Some(digest_batch(snapshot, &gaps)?),
            None => None,
        };
        let quiet = !self.options.json
            && facts.is_empty()
            && digest
                .as_ref()
                .is_some_and(|digest| self.prev.as_ref() == Some(digest));
        if let Some(digest) = digest {
            self.prev = Some(digest);
        }
        if quiet {
            // Proven by `quiet`: the digest exists only when the
            // snapshot does.
            let snapshot = snapshot.expect("quiet batch carries a snapshot");
            let (verified, locator) = snapshot.identity_counts();
            let status = if snapshot.exit_code() == 4 {
                "unavailable"
            } else if snapshot.exit_code() == 3 || bad {
                "partial"
            } else {
                "complete"
            };
            writeln!(
                self.writer,
                "tick {}: no changes (status {status}, processes {}, modules {verified}/{} verified)",
                self.sequence,
                snapshot.processes.len(),
                verified + locator
            )?;
            self.writer.flush()?;
            return Ok(());
        }
        emit(
            &Record {
                schema_version: SCHEMA,
                mode: self.mode(),
                record: if snapshot.is_some() {
                    "snapshot"
                } else {
                    "observation"
                },
                sequence: self.sequence,
                interval: Interval {
                    started_elapsed_ns: nanos(begin),
                    finished_elapsed_ns: nanos(self.started.elapsed()),
                    drain_lag_ns: nanos(lag),
                },
                poll_interval: self.options.interval,
                snapshot,
                facts: &facts,
                gaps: &gaps,
                interval_causes: &interval_causes,
                capabilities: &self.capabilities,
                sampled_history: "incomplete",
            },
            self.writer,
            !self.options.json,
            self.options.verbosity,
        )
    }
    fn end(
        &mut self,
        reason: inventory::watch::EndReason,
        gap: Option<inventory::GapReason>,
    ) -> io::Result<u8> {
        let status = if !self.cumulative.usable {
            4
        } else if self.cumulative.partial
            || self.cumulative.unavailable
            || reason == inventory::watch::EndReason::Interrupted
        {
            3
        } else {
            0
        };
        emit(
            &End {
                schema_version: SCHEMA,
                mode: self.mode(),
                record: "end",
                sequence: self.sequence,
                reason,
                status,
                elapsed: self.started.elapsed(),
                limits: inventory::Limits::default(),
                capabilities: &self.capabilities,
                gap,
                sampled_history: "incomplete",
                cumulative: self.cumulative.clone(),
            },
            self.writer,
            !self.options.json,
            self.options.verbosity,
        )?;
        if let Some(line) = end_reason_text(&self.cumulative, reason, gap) {
            crate::report::err_line(&line);
        }
        Ok(status)
    }
}
fn observe(
    options: &Options,
    writer: &mut impl Write,
    shutdown: &crate::shutdown::Shutdown,
) -> io::Result<u8> {
    let cancel = shutdown.cancel_flag();
    let started = Instant::now();
    if !options.json {
        writer.write_all(MEANING.as_bytes())?;
    }
    // Validate/acquire scope before loading a tracing companion. A denied trace
    // must never hide the independently obtained passive snapshot.
    let mut stream = Stream {
        writer,
        options,
        capabilities: Capabilities::new(false),
        started,
        sequence: 0,
        prev: None,
        cumulative: inventory::watch::Cumulative::default(),
    };
    let mut scanner =
        match ScopedScanner::new(options.selection.clone(), inventory::Limits::default()) {
            Ok(scanner) => scanner,
            Err(gap) => {
                return stream.end(inventory::watch::EndReason::ScopeUnavailable, Some(gap));
            }
        };
    let initial = scanner.snapshot_with_cancel(cancel);
    let opened = if shutdown.cancelled_and_acked() {
        Err(ObservationGap::IntervalUnknown)
    } else {
        artifact::load()
            .and_then(|bytes| ProviderSession::open(ObservationLimits::default(), &bytes))
    };
    let (mut session, mut initial_batch) = match opened {
        Ok(session) => (Some(session), ObservationBatch::default()),
        Err(gap) => (
            None,
            ObservationBatch {
                interval_causes: if gap == ObservationGap::IntervalUnknown {
                    // Cancel-before-open (the only interval gap
                    // born here — `open` never returns one): no
                    // window joined, so the join-miss text holds;
                    // the interruption itself rides the end record.
                    vec![IntervalCause::JoinMiss]
                } else {
                    Vec::new()
                },
                gaps: vec![gap],
                ..Default::default()
            },
        ),
    };
    stream.capabilities = Capabilities::new(session.is_some());
    if let Some(session) = &mut session {
        initial_batch = session.reconcile(&initial);
    }
    // The startup blocker prints once, before the first sample record:
    // the initial snapshot is the knowledge event.
    if !options.json
        && !shutdown.cancelled_and_acked()
        && inventory::snapshot_conclusively_without_openssl(&initial)
    {
        stream
            .writer
            .write_all(inventory::blindness_line().as_bytes())?;
    }
    stream.batch(
        initial_batch,
        Some(&initial),
        Duration::ZERO,
        started.elapsed(),
    )?;
    drop(initial);
    let mut next_snapshot = Instant::now() + options.interval;
    let mut last_drain = Instant::now();
    let end_reason = loop {
        if shutdown.cancelled_and_acked() {
            break inventory::watch::EndReason::Interrupted;
        }
        if started.elapsed() >= options.duration {
            break inventory::watch::EndReason::Duration;
        }
        let now = Instant::now();
        if now >= next_snapshot {
            let begin = started.elapsed();
            let snapshot = scanner.snapshot_with_cancel(cancel);
            let batch = session
                .as_mut()
                .map(|s| s.reconcile(&snapshot))
                .unwrap_or_default();
            stream.batch(batch, Some(&snapshot), begin, last_drain.elapsed())?;
            next_snapshot = Instant::now() + options.interval;
        }
        if last_drain.elapsed() >= Duration::from_millis(100) {
            let begin = started.elapsed();
            let lag = last_drain.elapsed();
            if let Some(session) = &mut session {
                let batch = session.drain(Instant::now() + Duration::from_millis(10));
                if !batch.facts.is_empty() || !batch.gaps.is_empty() {
                    stream.batch(batch, None, begin, lag)?;
                }
            }
            last_drain = Instant::now();
        }
        let wait = Duration::from_millis(25)
            .min(options.duration.saturating_sub(started.elapsed()))
            .min(next_snapshot.saturating_duration_since(Instant::now()));
        std::thread::sleep(wait);
    };
    if let Some(session) = session {
        let begin = started.elapsed();
        let batch = session.close();
        if !batch.facts.is_empty() || !batch.gaps.is_empty() {
            stream.batch(batch, None, begin, last_drain.elapsed())?;
        }
    }
    stream.end(end_reason, None)
}
/// Whole-command validation precedes any scope, companion or BPF acquisition.
pub fn run(args: &[String]) -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let help = args.len() == 3
        && args[1..].iter().any(|a| a == "--observe-providers")
        && args[1..]
            .iter()
            .any(|a| matches!(a.as_str(), "--help" | "-h"));
    let result = if help {
        output
            .write_all(HELP.as_bytes())
            .and_then(|()| {
                for line in crate::cli::exit_code_help_observation() {
                    writeln!(output, "{line}")?;
                }
                writeln!(output, "{}", crate::cli::blocked_pointer_sub())?;
                Ok(())
            })
            .and_then(|()| output.flush())
            .map(|()| 0)
    } else {
        let options = match parse(args) {
            Ok(options) => options,
            Err(()) => {
                crate::report::err_line(
                    "osslscope provider discovery: invalid arguments (see scan --observe-providers --help)",
                );
                return ExitCode::from(2);
            }
        };
        let shutdown = match crate::shutdown::Shutdown::install() {
            Ok(shutdown) => shutdown,
            Err(_) => {
                crate::report::err_line(
                    "osslscope provider discovery: observer signal setup failed",
                );
                return ExitCode::from(1);
            }
        };
        let code = observe(&options, &mut output, &shutdown);
        // Backstop ack for a signal racing the final end-record emit
        // (`None` when the in-loop ack already fired or no signal
        // arrived).
        if let Some(ack) = shutdown.ack() {
            crate::shutdown::write_ack(&ack);
        }
        code
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            crate::report::err_line("osslscope provider discovery: output failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_window_is_thirty_seconds_and_unknown_history_is_not_failure() {
        for args in [
            vec!["scan", "--observe-providers"],
            vec!["inspect", "--pid", "1", "--observe-providers"],
        ] {
            let parsed = parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).unwrap();
            assert_eq!(parsed.duration, Duration::from_secs(30));
            assert_eq!(parsed.interval, Duration::from_secs(1));
        }
        assert!(!degraded(&[
            ObservationGap::FirstQueryUnknown,
            ObservationGap::IntervalUnknown,
            ObservationGap::SamplingPartial
        ]));
        for gap in [
            ObservationGap::BpfUnavailable,
            ObservationGap::StateLimit,
            ObservationGap::AttachFailed,
            ObservationGap::QueueLoss,
            ObservationGap::SnapshotLag,
        ] {
            assert!(degraded(&[gap]));
        }
    }
    #[test]
    fn slow_startup_or_snapshot_records_typed_lag_even_without_a_session() {
        let args = ["scan", "--observe-providers", "--json"].map(String::from);
        let options = parse(&args).unwrap();
        let mut bytes = Vec::new();
        let mut stream = Stream {
            writer: &mut bytes,
            options: &options,
            capabilities: Capabilities::new(false),
            started: Instant::now(),
            sequence: 0,
            prev: None,
            cumulative: crate::inventory::watch::Cumulative {
                usable: true,
                partial: false,
                unavailable: false,
                first_partial: None,
                first_unavailable: None,
            },
        };
        stream
            .batch(
                ObservationBatch::default(),
                None,
                Duration::ZERO,
                Duration::from_millis(201),
            )
            .unwrap();
        assert!(stream.cumulative.partial);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["interval"]["drain_lag_ns"], 201000000);
        assert_eq!(value["gaps"], serde_json::json!(["snapshot_lag"]));
    }
    #[test]
    fn human_query_results_preserve_operation_class_and_fact_chronology() {
        let facts = [("digest", "digest", 9), ("cipher", "cipher", 10)].map(|(operation, class, monotonic_ns)| {
            serde_json::from_value::<super::super::ObservationFact>(serde_json::json!({
                "pid": 12, "starttime": 100, "object_sha256": "a".repeat(64), "generation": 1,
                "context": { "state": "unknown" }, "source": "provider_query", "api": "provider_query_callback",
                "operation": operation, "class": class, "monotonic_ns": monotonic_ns, "confidence": "unknown",
                "payload": { "kind": "query_result", "outcome": "success", "cacheability": "cacheable" }
            })).unwrap()
        });
        let capabilities = Capabilities::new(true);
        let record = Record {
            schema_version: SCHEMA,
            mode: "watch",
            record: "observation",
            sequence: 1,
            interval: Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: None,
            facts: &facts,
            gaps: &[],
            interval_causes: &[],
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let render = |verbosity: u8| {
            let mut bytes = Vec::new();
            emit(&record, &mut bytes, true, verbosity).unwrap();
            String::from_utf8(bytes).unwrap()
        };
        // W5: operation/class stay at default; the monotonic
        // timestamp is `-vv` technics.
        let l0 = render(0);
        let lines: Vec<_> = l0
            .lines()
            .filter(|line| line.starts_with("  fact "))
            .collect();
        assert_eq!(lines.len(), 2);
        for (line, operation, class) in [
            (lines[0], "operation=\"digest\"", "class=\"digest\""),
            (lines[1], "operation=\"cipher\"", "class=\"cipher\""),
        ] {
            for expected in [operation, class] {
                assert!(line.contains(expected), "{line}");
            }
            assert!(!line.contains("monotonic_ns="), "{line}");
        }
        assert_ne!(lines[0], lines[1]);
        let l2 = render(2);
        let stamped: Vec<_> = l2
            .lines()
            .filter(|line| line.starts_with("  fact "))
            .collect();
        assert_eq!(stamped.len(), 2);
        assert!(stamped[0].contains("monotonic_ns=9"), "{}", stamped[0]);
        assert!(stamped[1].contains("monotonic_ns=10"), "{}", stamped[1]);
        let mut json = Vec::new();
        emit(&record, &mut json, false, 0).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json["facts"][0]["operation"], "digest");
        assert_eq!(json["facts"][0]["class"], "digest");
        assert_eq!(json["facts"][0]["monotonic_ns"], 9);
        assert_eq!(json["facts"][1]["operation"], "cipher");
        assert_eq!(json["facts"][1]["class"], "cipher");
        assert_eq!(json["facts"][1]["monotonic_ns"], 10);
    }
    #[test]
    fn assembled_mixed_and_weak_aliases_reach_public_json_and_human() {
        use super::super::{
            assembly::Sequences,
            session::{ObservationBatch, assemble_payload},
            wire::{self, contract as c},
            *,
        };
        for (labels, expected_status, expected_weak) in [
            (vec!["AES-256-GCM", "MD5"], "mixed", true),
            (vec!["MD5"], "complete", true),
            (vec!["AES-256-GCM"], "complete", false),
        ] {
            let mut sequences = Sequences::default();
            let budget = ObservationBudget::default();
            let mut batch = ObservationBatch::default();
            let q = c::Record {
                version: c::VERSION,
                size: c::EVENT_SIZE as u32,
                kind: c::QUERY,
                api: c::QUERY_CALLBACK,
                pid: 1,
                tid: 2,
                cookie: 3,
                generation: 4,
                invocation: 5,
                outcome: 1,
                operation: 1,
                cacheability: 1,
                start_time_ns: 0x5A44,
                ..Default::default()
            };
            let mut assemble = |r: c::Record| {
                let bytes = unsafe {
                    std::slice::from_raw_parts((&r as *const c::Record).cast(), c::EVENT_SIZE)
                };
                assemble_payload(
                    wire::decode_transport(bytes).unwrap(),
                    &mut sequences,
                    &budget,
                    &mut batch,
                )
            };
            assemble(q).unwrap();
            assemble(c::Record {
                kind: c::ALGORITHM_BEGIN,
                ..q
            });
            for (index, label) in labels.iter().enumerate() {
                let id = crate::kinds::ALG_NAMES
                    .iter()
                    .position(|entry| entry.name == *label)
                    .unwrap();
                assemble(c::Record {
                    kind: c::ALIAS,
                    algorithm: id as u32,
                    function: crate::kinds::algorithm_semantic_id(label).unwrap() as u32,
                    outcome: u32::from(crate::kinds::is_weak_alg(label)),
                    status: index as u32,
                    ..q
                });
            }
            let algorithm = assemble(c::Record {
                kind: c::ALIAS_END,
                algorithm: c::OTHER,
                outcome: 0,
                function: labels.len() as u32,
                ..q
            })
            .unwrap();
            let implementation = assemble(c::Record {
                kind: c::IMPLEMENTATION,
                algorithm: c::OTHER,
                outcome: 0,
                function: 0,
                ..q
            })
            .unwrap();
            let facts: Vec<_> = [algorithm, implementation]
                .into_iter()
                .map(|payload| ObservationFact {
                    pid: 1,
                    starttime: 2,
                    object_sha256: "a".repeat(64).try_into().unwrap(),
                    generation: 4,
                    context: ContextIdentity::Unknown {},
                    source: ObservationSource::ProviderQuery,
                    api: ObservationApi::ProviderQueryCallback,
                    operation: Operation::Digest,
                    class: AlgorithmClass::Digest,
                    monotonic_ns: 0,
                    confidence: ScopeConfidence::Observed,
                    payload,
                })
                .collect();
            let capabilities = Capabilities::new(true);
            let record = Record {
                schema_version: SCHEMA,
                mode: "watch",
                record: "observation",
                sequence: 1,
                interval: Interval {
                    started_elapsed_ns: 0,
                    finished_elapsed_ns: 1,
                    drain_lag_ns: 0,
                },
                poll_interval: Duration::from_secs(1),
                snapshot: None,
                facts: &facts,
                gaps: &[],
                interval_causes: &[],
                capabilities: &capabilities,
                sampled_history: "incomplete",
            };
            let mut json = Vec::new();
            emit(&record, &mut json, false, 0).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            for fact in value["facts"].as_array().unwrap() {
                assert_eq!(fact["payload"]["alias_quality"]["status"], expected_status);
                assert_eq!(fact["payload"]["alias_quality"]["weak"], expected_weak);
            }
            let mut human = Vec::new();
            emit(&record, &mut human, true, 0).unwrap();
            let human = String::from_utf8(human).unwrap();
            assert_eq!(
                human
                    .matches(&format!(
                        "alias_status=\"{expected_status}\" weak={expected_weak}"
                    ))
                    .count(),
                2,
                "{human}"
            );
        }
    }

    #[test]
    fn human_facts_render_finite_algorithm_labels_and_safe_identity() {
        let fact: super::super::ObservationFact = serde_json::from_value(serde_json::json!({
            "pid": 12, "starttime": 100, "object_sha256": "a".repeat(64), "generation": 1,
            "context": { "state": "unknown" }, "source": "provider_query", "api": "provider_query_callback",
            "operation": "digest", "class": "digest", "monotonic_ns": 9, "confidence": "unknown",
            "payload": { "kind": "algorithm", "algorithm": 65535, "cacheability": "unknown" }
        })).unwrap();
        let capabilities = Capabilities::new(true);
        let record = Record {
            schema_version: SCHEMA,
            mode: "watch",
            record: "observation",
            sequence: 1,
            interval: Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: None,
            facts: &[fact],
            gaps: &[],
            interval_causes: &[],
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let mut bytes = Vec::new();
        emit(&record, &mut bytes, true, 0).unwrap();
        let human = String::from_utf8(bytes).unwrap();
        assert!(human.contains("algorithm=other"), "{human}");
        assert!(human.contains("pid=12"), "{human}");
        assert!(human.contains("sha256=aaaaaaaa"), "{human}");
        assert!(
            !human.contains("schema_version"),
            "human mode should be concise"
        );
    }

    #[test]
    fn end_reason_names_unusable_partial_and_scope() {
        use inventory::watch::{Cumulative, EndReason};
        let seen = |usable: bool, partial: bool| Cumulative {
            usable,
            partial,
            unavailable: false,
            first_partial: partial.then_some(1),
            first_unavailable: None,
        };
        assert_eq!(
            super::end_reason_text(&seen(true, false), EndReason::Duration, None),
            None
        );
        let scope = super::end_reason_text(
            &seen(false, false),
            EndReason::ScopeUnavailable,
            Some(inventory::GapReason::ProcessUnavailable),
        )
        .unwrap();
        assert!(
            scope.contains("scope unavailable") && scope.contains("process_unavailable"),
            "got: {scope}"
        );
        let unusable =
            super::end_reason_text(&seen(false, true), EndReason::Duration, None).unwrap();
        assert!(unusable.contains("unavailable"), "got: {unusable}");
        let partial = super::end_reason_text(&seen(true, true), EndReason::Duration, None).unwrap();
        assert!(partial.contains("partial"), "got: {partial}");
        let interrupted =
            super::end_reason_text(&seen(true, false), EndReason::Interrupted, None).unwrap();
        assert!(interrupted.contains("interrupted"), "got: {interrupted}");
    }

    #[test]
    fn human_snapshot_record_prints_identity_totals() {
        // Own-pid snapshot: counts vary by privilege, the line shape not.
        let snapshot = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![std::process::id()],
            resolve_paths: false,
            limits: crate::inventory::Limits::default(),
        });
        let capabilities = Capabilities::new(true);
        let record = Record {
            schema_version: SCHEMA,
            mode: "watch",
            record: "snapshot",
            sequence: 1,
            interval: Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: Some(&snapshot),
            facts: &[],
            gaps: &[],
            interval_causes: &[],
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let mut bytes = Vec::new();
        emit(&record, &mut bytes, true, 0).unwrap();
        let human = String::from_utf8(bytes).unwrap();
        let (verified, locator) = snapshot.identity_counts();
        if verified + locator == 0 {
            assert!(human.contains("identity: no modules"), "{human}");
        } else {
            assert!(
                human.contains("identity: ")
                    && human.contains(&format!("{verified} verified"))
                    && human.contains("% verified"),
                "{human}"
            );
        }
    }

    #[test]
    fn human_gap_blocks_coalesce_both_gap_kinds() {
        use crate::inventory::{Gap, GapReason};
        let gap = |reason: GapReason| Gap {
            pid: Some(11),
            device: Some(7),
            inode: None,
            reason,
            errno: None,
            actor_euid: None,
        };
        let inventory = super::inventory_gap_block(&[
            gap(GapReason::BackingUnavailable),
            gap(GapReason::BackingUnavailable),
            gap(GapReason::Deadline),
        ])
        .unwrap();
        assert!(
            inventory.contains("gaps (3 total in 2 groups):")
                && inventory.contains("backing_unavailable device=7 pid=11: 2"),
            "inventory gaps coalesced, got: {inventory}"
        );
        let observation = super::observation_gap_block(
            &[
                ObservationGap::BpfUnavailable,
                ObservationGap::BpfUnavailable,
                ObservationGap::SnapshotLag,
            ],
            &[],
        )
        .unwrap();
        assert!(
            observation.contains("gaps (3 total in 2 groups):"),
            "observation gaps coalesced, got: {observation}"
        );
        assert_eq!(super::inventory_gap_block(&[]).unwrap(), "");
        assert_eq!(super::observation_gap_block(&[], &[]).unwrap(), "");
    }

    // W5: the default record header is plain words; the four
    // jargon counters (`drain_lag_ns`, `facts=`, `tracing=`,
    // `monotonic_ns`) plus the interval range render at `-vv`
    // only. W3-shard: `interval_unknown` carries its honest
    // one-line cause, never a blanket "benign".
    #[test]
    fn human_default_has_plain_header_no_jargon_honest_interval() {
        let fact: super::super::ObservationFact = serde_json::from_value(serde_json::json!({
            "pid": 12, "starttime": 100, "object_sha256": "c".repeat(64), "generation": 1,
            "context": { "state": "unknown" }, "source": "provider_query", "api": "provider_query_callback",
            "operation": "digest", "class": "digest", "monotonic_ns": 9, "confidence": "unknown",
            "payload": { "kind": "query_result", "outcome": "success", "cacheability": "cacheable" }
        }))
        .unwrap();
        // Live own-pid snapshot: module counts vary by host, so the
        // header assertion computes them from the same snapshot.
        let snapshot = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![std::process::id()],
            resolve_paths: false,
            limits: crate::inventory::Limits::default(),
        });
        let modules: usize = snapshot.processes.iter().map(|p| p.modules.len()).sum();
        let capabilities = Capabilities::new(true);
        let gaps = [ObservationGap::IntervalUnknown];
        let causes = [IntervalCause::JoinMiss];
        let record = Record {
            schema_version: SCHEMA,
            mode: "watch",
            record: "snapshot",
            sequence: 1,
            interval: Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: Some(&snapshot),
            facts: &[fact],
            gaps: &gaps,
            interval_causes: &causes,
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let render = |verbosity: u8| {
            let mut bytes = Vec::new();
            emit(&record, &mut bytes, true, verbosity).unwrap();
            String::from_utf8(bytes).unwrap()
        };
        let l0 = render(0);
        assert!(
            l0.contains(&format!("provider sample: {modules} modules, 1 facts")),
            "{l0}"
        );
        for word in [
            "drain_lag_ns",
            "facts=",
            "tracing=",
            "monotonic_ns",
            "interval_ns",
        ] {
            assert!(!l0.contains(word), "{word} at level 0: {l0}");
        }
        assert!(
            l0.contains("interval_unknown (timing/count gap: observation window did not join; counts may be incomplete)"),
            "{l0}"
        );
        assert!(!l0.contains("benign"), "{l0}");
        let l1 = render(1);
        for word in [
            "drain_lag_ns",
            "facts=",
            "tracing=",
            "monotonic_ns",
            "interval_ns",
        ] {
            assert!(!l1.contains(word), "{word} at level 1: {l1}");
        }
        let l2 = render(2);
        for word in ["drain_lag_ns=", "facts=", "tracing=", "monotonic_ns=9"] {
            assert!(l2.contains(word), "{word} missing at level 2: {l2}");
        }
        // JSON keeps the full hash and every gap instance verbatim.
        let mut json = Vec::new();
        emit(&record, &mut json, false, 0).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json["facts"][0]["object_sha256"], "c".repeat(64));
        assert_eq!(json["gaps"], serde_json::json!(["interval_unknown"]));
    }

    // W3-shard: one honest line per interval cause plus `(x{n}
    // more)` collapsing; other gaps keep the grouped shape; a gap
    // without a recorded cause degrades to an explicit fallback,
    // never a guessed cause or a blanket "benign".
    #[test]
    fn observation_gap_block_explains_interval_unknown_with_cause() {
        let join = super::observation_gap_block(
            &[ObservationGap::IntervalUnknown],
            &[IntervalCause::JoinMiss],
        )
        .unwrap();
        assert_eq!(
            join,
            "  interval_unknown (timing/count gap: observation window did not join; counts may be incomplete)\n"
        );
        let read = super::observation_gap_block(
            &[ObservationGap::IntervalUnknown],
            &[IntervalCause::CountRead],
        )
        .unwrap();
        assert_eq!(
            read,
            "  interval_unknown (timing/count gap: engine counter read failed; counts may be incomplete)\n"
        );
        let repeats = super::observation_gap_block(
            &[
                ObservationGap::IntervalUnknown,
                ObservationGap::IntervalUnknown,
                ObservationGap::IntervalUnknown,
            ],
            &[IntervalCause::JoinMiss, IntervalCause::JoinMiss],
        )
        .unwrap();
        assert!(
            repeats
                .contains("observation window did not join; counts may be incomplete) (x1 more)"),
            "repeat collapsing, got: {repeats}"
        );
        assert!(
            repeats.contains("cause not recorded; counts may be incomplete)"),
            "causeless remainder stays honest, got: {repeats}"
        );
        let mixed = super::observation_gap_block(
            &[
                ObservationGap::BpfUnavailable,
                ObservationGap::IntervalUnknown,
            ],
            &[IntervalCause::JoinMiss],
        )
        .unwrap();
        assert!(
            mixed.contains("gaps (1 total in 1 group):")
                && mixed.contains("observation window did not join"),
            "mixed gaps, got: {mixed}"
        );
        for text in [&join, &read, &repeats, &mixed] {
            assert!(!text.contains("benign"), "{text}");
        }
    }

    #[test]
    fn verbosity_parses_repeatable_and_clamps_at_two() {
        let parse = |flags: &[&str]| {
            let mut args = vec!["scan".to_string()];
            args.extend(flags.iter().map(|f| f.to_string()));
            args.push("--observe-providers".to_string());
            super::parse(&args)
        };
        assert_eq!(parse(&[]).unwrap().verbosity, 0);
        assert_eq!(parse(&["-v"]).unwrap().verbosity, 1);
        assert_eq!(parse(&["--verbose"]).unwrap().verbosity, 1);
        assert_eq!(parse(&["-v", "--verbose"]).unwrap().verbosity, 2);
        assert_eq!(parse(&["-vv"]).unwrap().verbosity, 2);
        assert_eq!(parse(&["-vv", "-v"]).unwrap().verbosity, 2);
        // No quiet flag exists: the default is already quiet.
        assert!(parse(&["-q"]).is_err());
        assert!(parse(&["--quiet"]).is_err());
    }

    #[test]
    fn human_levels_add_state_exports_payload_records_counters() {
        let fact: super::super::ObservationFact = serde_json::from_value(serde_json::json!({
            "pid": 12, "starttime": 100, "object_sha256": "b".repeat(64), "generation": 1,
            "context": { "state": "unknown" }, "source": "provider_query", "api": "provider_query_callback",
            "operation": "digest", "class": "digest", "monotonic_ns": 9, "confidence": "unknown",
            "payload": { "kind": "query_result", "outcome": "success", "cacheability": "cacheable" }
        }))
        .unwrap();
        // Synthetic fixture (no live /proc read): one verified
        // module with exports, full namespaces, one gap, and known
        // totals — so the L1-exports/L2-records assertions below
        // always execute, like the inventory and crypto siblings.
        let snapshot = {
            use crate::inventory as inv;
            let module = inv::ModuleRecord {
                info: inv::ModuleInfo {
                    sha256: "a".repeat(64),
                    device: 0,
                    inode: 0,
                    size_bytes: 0,
                    architecture: inv::Architecture::X86_64,
                    kind: inv::ObjectKind::Other,
                    exports: vec![inv::Api::OsslProviderInit, inv::Api::EvpDigestUpdate],
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
            };
            let interval = || inv::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            };
            inv::Snapshot {
                interval: interval(),
                scope_record: inv::ScopeRecord::default(),
                schema_version: "osslscope.discovery.v1".into(),
                mode: inv::SnapshotMode::Snapshot,
                scope: inv::Scope::Pids,
                selected_pids: vec![1],
                processes: vec![inv::ProcessRecord {
                    interval: interval(),
                    namespaces: inv::NamespaceIds {
                        pid: Some(inv::NamespaceId {
                            device: 5,
                            inode: 123,
                        }),
                        mount: None,
                    },
                    pid: 1,
                    starttime: 0,
                    comm: None,
                    comm_status: inv::IdentityAvailability::Unreadable,
                    exe: None,
                    exe_status: inv::IdentityAvailability::Unreadable,
                    modules: vec![module],
                    other_objects: inv::OtherCounts::default(),
                    provider_activation: inv::ObservationState::Unknown,
                    provider_interfaces: inv::ObservationState::Unknown,
                    execution: inv::ObservationState::NotObserved,
                }],
                gaps: vec![inv::Gap {
                    pid: Some(7),
                    device: Some(1),
                    inode: Some(10),
                    reason: inv::GapReason::TooLarge,
                    errno: Some(libc::EPERM),
                    actor_euid: Some(1001),
                }],
                totals: inv::WorkTotals {
                    read_bytes: 4096,
                    objects_inspected: 7,
                    ..Default::default()
                },
                limits: inv::Limits::default(),
                capabilities: inv::Capabilities {
                    inventory: inv::InventoryState::Complete,
                    provider_activation: inv::ObservationState::Unknown,
                    provider_interfaces: inv::ObservationState::Unknown,
                    execution: inv::ObservationState::NotObserved,
                },
                resolve: inv::resolve::ResolveSidecar::default(),
                cgroup_identity: std::collections::BTreeMap::new(),
            }
        };
        let capabilities = Capabilities::new(true);
        let record = Record {
            schema_version: SCHEMA,
            mode: "watch",
            record: "snapshot",
            sequence: 1,
            interval: Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: Some(&snapshot),
            facts: &[fact],
            gaps: &[],
            interval_causes: &[],
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let render = |verbosity: u8| {
            let mut bytes = Vec::new();
            emit(&record, &mut bytes, true, verbosity).unwrap();
            String::from_utf8(bytes).unwrap()
        };
        let full_hash = "b".repeat(64);
        let l0 = render(0);
        // Fact one-liners stay at every level; the payload dump and
        // -v detail do not appear at level 0.
        assert!(l0.contains("  fact pid=12 starttime=100"), "{l0}");
        assert!(!l0.contains("payload="), "{l0}");
        assert!(!l0.contains("exports="), "{l0}");
        assert!(!l0.contains("namespaces="), "{l0}");
        assert!(!l0.contains("gap pid="), "{l0}");
        assert!(!l0.contains("counters:"), "{l0}");
        assert!(!l0.contains(&full_hash), "{l0}");
        let l1 = render(1);
        assert!(l1.contains("  fact pid=12 starttime=100"), "{l1}");
        assert!(!l1.contains("payload="), "{l1}");
        assert!(
            l1.contains("exports=[ossl_provider_init, evp_digest_update]"),
            "{l1}"
        );
        assert!(l1.contains("namespaces=pid=5:123,mount=-"), "{l1}");
        assert!(!l1.contains("gap pid="), "{l1}");
        assert!(!l1.contains("counters:"), "{l1}");
        assert!(!l1.contains(&full_hash), "{l1}");
        let l2 = render(2);
        assert!(l2.contains("payload="), "{l2}");
        assert!(
            l2.contains("counters: read_bytes=4096 objects_inspected=7"),
            "{l2}"
        );
        assert!(
            l2.contains("gap pid=7 device=1 reason=too_large errno=1"),
            "{l2}"
        );
        assert!(!l2.contains(&full_hash), "{l2}");
        assert!(l2.contains("sha256=bbbbbbbbbbbb"), "{l2}");
        // Level 0 stays a strict prefix of the process line: the -v
        // extension only appends.
        for line in l1.lines().filter(|l| l.starts_with("  process ")) {
            assert!(
                line.contains("starttime=") && line.contains("modules="),
                "{line}"
            );
        }
        // JSON ignores verbosity entirely.
        let mut j0 = Vec::new();
        emit(&record, &mut j0, false, 0).unwrap();
        let mut j2 = Vec::new();
        emit(&record, &mut j2, false, 2).unwrap();
        assert_eq!(j0, j2);
    }

    fn heartbeat_snapshot(state: crate::inventory::InventoryState) -> crate::inventory::Snapshot {
        use crate::inventory as inv;
        let interval = inv::CaptureInterval {
            started_unix_ms: None,
            finished_unix_ms: None,
            elapsed_ns: 0,
        };
        inv::Snapshot {
            interval: interval.clone(),
            scope_record: inv::ScopeRecord::default(),
            schema_version: "osslscope.discovery.v1".into(),
            mode: inv::SnapshotMode::Snapshot,
            scope: inv::Scope::Pids,
            selected_pids: vec![1],
            processes: vec![inv::ProcessRecord {
                interval: interval.clone(),
                namespaces: inv::NamespaceIds::default(),
                pid: 1,
                starttime: 0,
                comm: None,
                comm_status: inv::IdentityAvailability::Unreadable,
                exe: None,
                exe_status: inv::IdentityAvailability::Unreadable,
                modules: vec![inv::ModuleRecord {
                    info: inv::ModuleInfo {
                        sha256: "a".repeat(64),
                        device: 0,
                        inode: 0,
                        size_bytes: 0,
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
                }],
                other_objects: inv::OtherCounts::default(),
                provider_activation: inv::ObservationState::Unknown,
                provider_interfaces: inv::ObservationState::Unknown,
                execution: inv::ObservationState::NotObserved,
            }],
            gaps: Vec::new(),
            totals: inv::WorkTotals::default(),
            limits: inv::Limits::default(),
            capabilities: inv::Capabilities {
                inventory: state,
                provider_activation: inv::ObservationState::Unknown,
                provider_interfaces: inv::ObservationState::Unknown,
                execution: inv::ObservationState::NotObserved,
            },
            resolve: inv::resolve::ResolveSidecar::default(),
            cgroup_identity: std::collections::BTreeMap::new(),
        }
    }

    fn heartbeat_options(json: bool) -> Options {
        Options {
            selection: Selection::default(),
            json,
            watch: true,
            interval: Duration::from_secs(1),
            duration: Duration::from_secs(30),
            verbosity: 0,
        }
    }

    // W1 mirror: the first batch renders full; an identical
    // second batch (no facts, same gaps, same snapshot state)
    // prints the shared heartbeat line instead of a full block.
    #[test]
    fn stream_second_identical_snapshot_batch_is_a_heartbeat() {
        let options = heartbeat_options(false);
        let snapshot = heartbeat_snapshot(crate::inventory::InventoryState::Complete);
        let mut bytes = Vec::new();
        {
            let mut stream = Stream {
                writer: &mut bytes,
                options: &options,
                capabilities: Capabilities::new(true),
                started: Instant::now(),
                sequence: 0,
                prev: None,
                cumulative: crate::inventory::watch::Cumulative::default(),
            };
            stream
                .batch(
                    ObservationBatch::default(),
                    Some(&snapshot),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap();
            stream
                .batch(
                    ObservationBatch::default(),
                    Some(&snapshot),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap();
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("provider sample: 1 modules, 0 facts"),
            "first batch full, got: {text}"
        );
        assert!(
            text.contains(
                "tick 2: no changes (status complete, processes 1, modules 1/1 verified)"
            ),
            "no heartbeat, got: {text}"
        );
        assert!(!text.contains("snapshot 2:"), "re-dumped, got: {text}");
    }

    #[test]
    fn stream_heartbeat_never_filters_machine_records() {
        // Machine mode: full records every batch, no tick line.
        let options = heartbeat_options(true);
        let snapshot = heartbeat_snapshot(crate::inventory::InventoryState::Complete);
        let mut bytes = Vec::new();
        {
            let mut stream = Stream {
                writer: &mut bytes,
                options: &options,
                capabilities: Capabilities::new(true),
                started: Instant::now(),
                sequence: 0,
                prev: None,
                cumulative: crate::inventory::watch::Cumulative::default(),
            };
            for _ in 0..2 {
                stream
                    .batch(
                        ObservationBatch::default(),
                        Some(&snapshot),
                        Duration::ZERO,
                        Duration::ZERO,
                    )
                    .unwrap();
            }
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("tick "), "heartbeat in NDJSON: {text}");
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r["record"] == "snapshot"));
    }

    // F8 mirror: run-level partial history survives a later
    // complete batch — end status stays non-complete and the
    // human end record names the cumulative history. Machine
    // end shape gains no keys.
    #[test]
    fn stream_end_keeps_partial_history_across_batches() {
        let options = heartbeat_options(false);
        let partial = heartbeat_snapshot(crate::inventory::InventoryState::Partial);
        let complete = heartbeat_snapshot(crate::inventory::InventoryState::Complete);
        let mut bytes = Vec::new();
        let status;
        {
            let mut stream = Stream {
                writer: &mut bytes,
                options: &options,
                capabilities: Capabilities::new(true),
                started: Instant::now(),
                sequence: 0,
                prev: None,
                cumulative: crate::inventory::watch::Cumulative::default(),
            };
            stream
                .batch(
                    ObservationBatch::default(),
                    Some(&partial),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap();
            stream
                .batch(
                    ObservationBatch::default(),
                    Some(&complete),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap();
            status = stream
                .end(crate::inventory::watch::EndReason::Duration, None)
                .unwrap();
        }
        assert_eq!(status, 3);
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("cumulative=partial-seen"),
            "no cumulative word, got: {text}"
        );
        assert!(
            text.contains("note: sample 1 was partial; history remains uncertain"),
            "no uncertainty note, got: {text}"
        );
        // Machine end record: same keys (cumulative stays human-only).
        let options = heartbeat_options(true);
        let mut bytes = Vec::new();
        {
            let mut stream = Stream {
                writer: &mut bytes,
                options: &options,
                capabilities: Capabilities::new(true),
                started: Instant::now(),
                sequence: 0,
                prev: None,
                cumulative: crate::inventory::watch::Cumulative::default(),
            };
            stream
                .batch(
                    ObservationBatch::default(),
                    Some(&partial),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap();
            let status = stream
                .end(crate::inventory::watch::EndReason::Duration, None)
                .unwrap();
            assert_eq!(status, 3);
        }
        let text = String::from_utf8(bytes).unwrap();
        let end: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(end["record"], "end");
        assert_eq!(end["status"], 3);
        assert!(
            end.get("cumulative").is_none()
                && end.get("cumulative_partial").is_none()
                && end.get("cumulative_unavailable").is_none(),
            "machine end shape changed: {end}"
        );
    }

    // F-NEW-1 (R13 always-acquire): the provider arm parses to an
    // acquiring selection on BOTH commands — a default
    // (acquire-off) selection emits bare-null D1 path triples,
    // breaching P0-1 and the CHANGELOG always-acquire claim.
    #[test]
    fn parse_acquires_paths_by_default() {
        let scan = ["scan".to_string(), "--observe-providers".to_string()];
        assert!(
            super::parse(&scan).unwrap().selection.resolve_paths,
            "scan provider arm must acquire D1 path evidence"
        );
        let inspect = [
            "inspect".to_string(),
            "--pid".to_string(),
            "1".to_string(),
            "--observe-providers".to_string(),
        ];
        assert!(
            super::parse(&inspect).unwrap().selection.resolve_paths,
            "inspect provider arm must acquire D1 path evidence"
        );
    }

    // F-NEW-1 (H8 precedent, b540ae8 pattern): provider human
    // module rows carry `path=`/`version=` with the scan-route
    // shapes (`human_path`/`human_version`), and process lines
    // carry `comm=`/`exe=` with the scan verdict shapes
    // (`human_comm`/`human_exe`); null/missing renders
    // placeholders, never crashes.
    #[test]
    fn human_rows_carry_path_version_and_process_lines_carry_comm_exe() {
        use crate::inventory as inv;
        let module = |sha: &str,
                      status: inv::IdentityStatus,
                      verified: Option<inv::VerifiedPath>,
                      unavailable: Option<inv::PathUnavailableReason>,
                      maps: Option<inv::MapsSpelling>,
                      soname: Option<&str>,
                      version: Option<&str>| {
            inv::ModuleRecord {
                info: inv::ModuleInfo {
                    sha256: sha.to_string(),
                    device: 1,
                    inode: 2,
                    size_bytes: 3,
                    architecture: inv::Architecture::X86_64,
                    kind: inv::ObjectKind::Other,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                    file_soname: soname.map(str::to_string),
                    file_openssl_version: version.map(str::to_string),
                    file_version_status: inv::FileVersionStatus::Absent,
                },
                identity_status: status,
                verified_path: verified,
                verified_path_unavailable: unavailable,
                maps_spelling: maps,
            }
        };
        let interval = inv::CaptureInterval {
            started_unix_ms: None,
            finished_unix_ms: None,
            elapsed_ns: 0,
        };
        let snapshot = inv::Snapshot {
            interval: interval.clone(),
            scope_record: inv::ScopeRecord::default(),
            schema_version: "osslscope.discovery.v1".into(),
            mode: inv::SnapshotMode::Snapshot,
            scope: inv::Scope::Pids,
            selected_pids: vec![7, 9],
            processes: vec![
                inv::ProcessRecord {
                    interval: interval.clone(),
                    namespaces: inv::NamespaceIds::default(),
                    pid: 7,
                    starttime: 70,
                    comm: Some("python3".to_string()),
                    comm_status: inv::IdentityAvailability::Available,
                    exe: Some("/usr/bin/python3".to_string()),
                    exe_status: inv::IdentityAvailability::Available,
                    modules: vec![
                        module(
                            &"aa".repeat(32),
                            inv::IdentityStatus::Verified,
                            Some(inv::VerifiedPath {
                                path: "/lib/x86_64-linux-gnu/libcrypto.so.3".to_string(),
                                path_encoding: inv::PathEncoding::Utf8,
                                locator_kind: inv::LocatorKind::HostDirect,
                                capture_unix_ms: None,
                            }),
                            None,
                            Some(inv::MapsSpelling {
                                spelling: "/lib/x86_64-linux-gnu/libcrypto.so.3".to_string(),
                                source: inv::MapsSource::ProcMaps,
                                verification: inv::MapsVerification::Unverified,
                            }),
                            Some("libcrypto.so.3"),
                            Some("3.5.5"),
                        ),
                        module(
                            &"bb".repeat(32),
                            inv::IdentityStatus::LocatorCandidate,
                            None,
                            Some(inv::PathUnavailableReason::UnverifiedIdentity),
                            Some(inv::MapsSpelling {
                                spelling: "/mem/fd:deleted-lib.so".to_string(),
                                source: inv::MapsSource::ProcMaps,
                                verification: inv::MapsVerification::Unverified,
                            }),
                            None,
                            None,
                        ),
                        module(
                            &"cc".repeat(32),
                            inv::IdentityStatus::Verified,
                            None,
                            None,
                            None,
                            None,
                            None,
                        ),
                    ],
                    other_objects: inv::OtherCounts::default(),
                    provider_activation: inv::ObservationState::Unknown,
                    provider_interfaces: inv::ObservationState::Unknown,
                    execution: inv::ObservationState::NotObserved,
                },
                inv::ProcessRecord {
                    interval,
                    namespaces: inv::NamespaceIds::default(),
                    pid: 9,
                    starttime: 90,
                    comm: None,
                    comm_status: inv::IdentityAvailability::Unreadable,
                    exe: None,
                    exe_status: inv::IdentityAvailability::Changed,
                    modules: Vec::new(),
                    other_objects: inv::OtherCounts::default(),
                    provider_activation: inv::ObservationState::Unknown,
                    provider_interfaces: inv::ObservationState::Unknown,
                    execution: inv::ObservationState::NotObserved,
                },
            ],
            gaps: Vec::new(),
            totals: inv::WorkTotals::default(),
            limits: inv::Limits::default(),
            capabilities: inv::Capabilities {
                inventory: inv::InventoryState::Complete,
                provider_activation: inv::ObservationState::Unknown,
                provider_interfaces: inv::ObservationState::Unknown,
                execution: inv::ObservationState::NotObserved,
            },
            resolve: inv::resolve::ResolveSidecar::default(),
            cgroup_identity: std::collections::BTreeMap::new(),
        };
        let capabilities = super::Capabilities::new(true);
        let record = super::Record {
            schema_version: super::SCHEMA,
            mode: "watch",
            record: "snapshot",
            sequence: 1,
            interval: super::Interval {
                started_elapsed_ns: 0,
                finished_elapsed_ns: 10,
                drain_lag_ns: 10,
            },
            poll_interval: Duration::from_secs(1),
            snapshot: Some(&snapshot),
            facts: &[],
            gaps: &[],
            interval_causes: &[],
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let mut bytes = Vec::new();
        super::emit(&record, &mut bytes, true, 0).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let processes: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  process "))
            .collect();
        assert_eq!(processes.len(), 2, "{text}");
        assert!(
            processes[0].contains("comm=python3") && processes[0].contains("exe=bin/python3"),
            "scan verdict shapes, got: {}",
            processes[0]
        );
        assert!(
            processes[1].contains("comm=-") && processes[1].contains("exe=unavailable"),
            "null/missing placeholders, got: {}",
            processes[1]
        );
        let rows: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("    sha256="))
            .collect();
        assert_eq!(rows.len(), 3, "{text}");
        assert!(
            rows[0].contains("path=/lib/x86_64-linux-gnu/libcrypto.so.3")
                && rows[0].contains("version=3.5.5"),
            "verified evidence, got: {}",
            rows[0]
        );
        assert!(
            rows[1].contains("path=(unverified maps hint: /mem/fd:deleted-lib.so)")
                && rows[1].contains("version=none"),
            "maps hint + no version, got: {}",
            rows[1]
        );
        assert!(
            rows[2].contains("path=(unavailable)") && rows[2].contains("version=none"),
            "genuinely-unacquirable placeholders, got: {}",
            rows[2]
        );
    }
}
