// SPDX-License-Identifier: GPL-3.0-or-later
//! Cooperative public-ABI observation. No executed assets or target bootstrap.
use super::{ObservationBatch, ObservationGap, ObservationLimits, ProviderSession, artifact};
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
struct Options {
    selection: Selection,
    json: bool,
    watch: bool,
    interval: Duration,
    duration: Duration,
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
    let mut selection = Selection::default();
    let mut json = false;
    let mut watch = false;
    let mut observe = false;
    let mut interval = None;
    let mut duration = None;
    let mut args = args[1..].iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--observe-providers" if !observe => observe = true,
            "--json" if !json => json = true,
            "--watch" if command == "scan" && !watch => watch = true,
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
struct Signals(Vec<(libc::c_int, libc::sigaction)>);
impl Signals {
    fn install() -> io::Result<Self> {
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
}
fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}
trait Render: Serialize {
    fn human(&self, writer: &mut impl Write) -> io::Result<()>;
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
    fn human(&self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "{} {}: interval_ns={}..{} drain_lag_ns={} facts={}",
            self.record,
            self.sequence,
            self.interval.started_elapsed_ns,
            self.interval.finished_elapsed_ns,
            self.interval.drain_lag_ns,
            self.facts.len()
        )?;
        human_capabilities(self.capabilities, writer)?;
        if let Some(snapshot) = self.snapshot {
            writeln!(
                writer,
                "  inventory={}",
                finite(&snapshot.capabilities.inventory)?
            )?;
            for process in &snapshot.processes {
                writeln!(
                    writer,
                    "  process pid={} starttime={}",
                    process.pid, process.starttime
                )?;
                for module in &process.modules {
                    writeln!(
                        writer,
                        "    sha256={} kind={} identity={}",
                        module.info.sha256,
                        finite(&module.info.kind)?,
                        finite(&module.identity_status)?
                    )?;
                }
            }
            for gap in &snapshot.gaps {
                writeln!(
                    writer,
                    "  inventory_gap={} pid={}",
                    finite(&gap.reason)?,
                    gap.pid
                        .map_or_else(|| "unknown".to_string(), |pid| pid.to_string())
                )?;
            }
        }
        for fact in self.facts {
            let hash: String = fact.object_sha256.clone().into();
            write!(
                writer,
                "  fact pid={} starttime={} sha256={} generation={} api={} source={} operation={} class={} monotonic_ns={} context={} confidence={}",
                fact.pid,
                fact.starttime,
                hash,
                fact.generation,
                finite(&fact.api)?,
                finite(&fact.source)?,
                finite(&fact.operation)?,
                finite(&fact.class)?,
                fact.monotonic_ns,
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
            writeln!(writer, " payload={}", finite(&fact.payload)?)?;
        }
        for gap in self.gaps {
            writeln!(writer, "  gap={}", finite(gap)?)?;
        }
        Ok(())
    }
}
impl Render for End<'_> {
    fn human(&self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "end {}: reason={} status={} elapsed_ns={}",
            self.sequence,
            finite(&self.reason)?,
            self.status,
            nanos(self.elapsed)
        )?;
        human_capabilities(self.capabilities, writer)?;
        if let Some(gap) = self.gap {
            writeln!(writer, "  inventory_gap={}", finite(&gap)?)?;
        }
        Ok(())
    }
}
fn emit(value: &impl Render, writer: &mut impl Write, human: bool) -> io::Result<()> {
    if human {
        value.human(writer)?;
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
    usable: bool,
    partial: bool,
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
            learned_sites: _,
        } = batch;
        if let Some(snapshot) = snapshot {
            self.capabilities.inventory = match snapshot.capabilities.inventory {
                inventory::InventoryState::Complete => "complete",
                inventory::InventoryState::Partial => "partial",
                inventory::InventoryState::Unavailable => "unavailable",
            };
            self.usable |= snapshot.exit_code() != 4;
            self.partial |= snapshot.exit_code() != 0;
        }
        if lag > Duration::from_millis(200) && !gaps.contains(&ObservationGap::SnapshotLag) {
            gaps.push(ObservationGap::SnapshotLag);
        }
        self.partial |= degraded(&gaps);
        self.sequence += 1;
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
                capabilities: &self.capabilities,
                sampled_history: "incomplete",
            },
            self.writer,
            !self.options.json,
        )
    }
    fn end(
        &mut self,
        reason: inventory::watch::EndReason,
        gap: Option<inventory::GapReason>,
    ) -> io::Result<u8> {
        let status = if !self.usable {
            4
        } else if self.partial || reason == inventory::watch::EndReason::Interrupted {
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
            },
            self.writer,
            !self.options.json,
        )?;
        Ok(status)
    }
}
fn observe(options: &Options, writer: &mut impl Write, cancel: &AtomicBool) -> io::Result<u8> {
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
        usable: false,
        partial: false,
    };
    let mut scanner =
        match ScopedScanner::new(options.selection.clone(), inventory::Limits::default()) {
            Ok(scanner) => scanner,
            Err(gap) => {
                return stream.end(inventory::watch::EndReason::ScopeUnavailable, Some(gap));
            }
        };
    let initial = scanner.snapshot();
    let opened = if cancel.load(Ordering::Relaxed) {
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
                gaps: vec![gap],
                ..Default::default()
            },
        ),
    };
    stream.capabilities = Capabilities::new(session.is_some());
    if let Some(session) = &mut session {
        initial_batch = session.reconcile(&initial);
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
        if cancel.load(Ordering::Relaxed) {
            break inventory::watch::EndReason::Interrupted;
        }
        if started.elapsed() >= options.duration {
            break inventory::watch::EndReason::Duration;
        }
        let now = Instant::now();
        if now >= next_snapshot {
            let begin = started.elapsed();
            let snapshot = scanner.snapshot();
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
        let _signals = match Signals::install() {
            Ok(signals) => signals,
            Err(_) => {
                crate::report::err_line(
                    "osslscope provider discovery: observer signal setup failed",
                );
                return ExitCode::from(1);
            }
        };
        observe(&options, &mut output, &INTERRUPTED)
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
            usable: true,
            partial: false,
        };
        stream
            .batch(
                ObservationBatch::default(),
                None,
                Duration::ZERO,
                Duration::from_millis(201),
            )
            .unwrap();
        assert!(stream.partial);
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
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let mut human = Vec::new();
        emit(&record, &mut human, true).unwrap();
        let human = String::from_utf8(human).unwrap();
        let lines: Vec<_> = human
            .lines()
            .filter(|line| line.starts_with("  fact "))
            .collect();
        assert_eq!(lines.len(), 2);
        for (line, operation, class, timestamp) in [
            (
                lines[0],
                "operation=\"digest\"",
                "class=\"digest\"",
                "monotonic_ns=9",
            ),
            (
                lines[1],
                "operation=\"cipher\"",
                "class=\"cipher\"",
                "monotonic_ns=10",
            ),
        ] {
            for expected in [operation, class, timestamp] {
                assert!(line.contains(expected), "{line}");
            }
        }
        assert_ne!(lines[0], lines[1]);
        let mut json = Vec::new();
        emit(&record, &mut json, false).unwrap();
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
                size: 96,
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
                ..Default::default()
            };
            let mut assemble = |r: c::Record| {
                let bytes =
                    unsafe { std::slice::from_raw_parts((&r as *const c::Record).cast(), 96) };
                assemble_payload(
                    wire::decode_transport(bytes).unwrap(),
                    &mut sequences,
                    &budget,
                    &mut batch,
                )
            };
            assemble(q).unwrap();
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
                capabilities: &capabilities,
                sampled_history: "incomplete",
            };
            let mut json = Vec::new();
            emit(&record, &mut json, false).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            for fact in value["facts"].as_array().unwrap() {
                assert_eq!(fact["payload"]["alias_quality"]["status"], expected_status);
                assert_eq!(fact["payload"]["alias_quality"]["weak"], expected_weak);
            }
            let mut human = Vec::new();
            emit(&record, &mut human, true).unwrap();
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
            capabilities: &capabilities,
            sampled_history: "incomplete",
        };
        let mut bytes = Vec::new();
        emit(&record, &mut bytes, true).unwrap();
        let human = String::from_utf8(bytes).unwrap();
        assert!(human.contains("algorithm=other"), "{human}");
        assert!(human.contains("pid=12"), "{human}");
        assert!(human.contains("sha256=aaaaaaaa"), "{human}");
        assert!(
            !human.contains("schema_version"),
            "human mode should be concise"
        );
    }
}
