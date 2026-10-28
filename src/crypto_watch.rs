// SPDX-License-Identifier: GPL-3.0-or-later
//! Sampled scope coordinator. Each segment owns one exact foreign incarnation;
//! documents are streamed after link retirement, without cross-process totals.
use crate::{
    focused_capture::{FocusedConfig, FocusedObjects, FocusedSession, SessionProgress},
    inventory::{
        self, GapReason, ProcessRecord, Snapshot,
        scope::{ScopedScanner, Selection},
    },
    observation_memory::MemoryPool,
    provider_observation::cli::Signals,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const GLOBAL_BYTES: usize = 256 << 20;
// Four active slots, identity envelopes, serde's streaming stack, IO buffer,
// scalar records and a spare limit gap. Document storage stays in its session.
const COORDINATOR_BYTES: usize = 256 << 10;
#[derive(Clone, Debug)]
pub struct CryptoWatchConfig {
    pub selection: Selection,
    pub max_active: usize,
    pub max_state_bytes: usize,
    pub duration: Duration,
    pub interval: Duration,
}
impl Default for CryptoWatchConfig {
    fn default() -> Self {
        Self {
            selection: Selection::default(),
            max_active: 4,
            max_state_bytes: GLOBAL_BYTES,
            duration: Duration::from_secs(30),
            interval: Duration::from_secs(1),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Incarnation {
    pid: u32,
    starttime: u64,
    namespaces: inventory::NamespaceIds,
}
impl From<&ProcessRecord> for Incarnation {
    fn from(p: &ProcessRecord) -> Self {
        Self {
            pid: p.pid,
            starttime: p.starttime,
            namespaces: p.namespaces.clone(),
        }
    }
}
struct Active {
    identity: Incarnation,
    segment: u64,
    session: FocusedSession,
}
#[derive(Serialize)]
struct Envelope<T: Serialize> {
    schema_version: &'static str,
    sequence: u64,
    #[serde(flatten)]
    record: T,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record<'a> {
    Start {
        max_active: usize,
        max_state_bytes: usize,
        poll_interval: Duration,
        duration: Duration,
        membership: &'static str,
    },
    Discovery {
        process: &'a ProcessRecord,
    },
    TracingGap {
        reason: &'static str,
    },
    Membership {
        incarnation: &'a Incarnation,
        segment: u64,
        state: &'static str,
        reason: &'static str,
    },
    Limit {
        incarnation: &'a Incarnation,
        reason: &'static str,
    },
    Gap {
        gap: &'a inventory::Gap,
    },
    SessionGap {
        incarnation: &'a Incarnation,
        reason: &'static str,
    },
    ProcessObservation {
        incarnation: &'a Incarnation,
        segment: u64,
        retirement: &'static str,
        document: &'a serde_json::Value,
    },
    End {
        reason: &'static str,
        segments: u64,
        peak_accounted_bytes: usize,
        coverage: &'static str,
    },
}
struct Output<'a, W> {
    writer: &'a mut W,
    sequence: u64,
    json: bool,
}
impl<W: Write> Output<'_, W> {
    fn emit(&mut self, record: Record<'_>) -> io::Result<()> {
        if !self.json {
            self.human(&record)?;
            self.writer.flush()?;
            self.sequence += 1;
            return Ok(());
        }
        serde_json::to_writer(
            &mut *self.writer,
            &Envelope {
                schema_version: "crypto-watch-v1",
                sequence: self.sequence,
                record,
            },
        )
        .map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.sequence += 1;
        Ok(())
    }
    /// Fixed-size summaries per record. Never dump a document, raw path, symbol
    /// or target string; large object/gap populations get explicit omitted counts.
    fn human(&mut self, record: &Record<'_>) -> io::Result<()> {
        const ROWS: usize = 8;
        let w = &mut self.writer;
        match record {
            Record::Start {
                max_active,
                max_state_bytes,
                poll_interval,
                duration,
                ..
            } => writeln!(
                w,
                "Crypto watch: membership=sampled coverage=unknown max_active={max_active} accounted_limit_bytes={max_state_bytes} interval_s={} duration_s={}",
                poll_interval.as_secs_f64(),
                duration.as_secs_f64()
            ),
            Record::Discovery { process: p } => {
                writeln!(
                    w,
                    "Process {} start={} objects={} execution=not_observed coverage=unknown (passive inventory)",
                    p.pid,
                    p.starttime,
                    p.modules.len()
                )?;
                for m in p.modules.iter().take(ROWS) {
                    writeln!(
                        w,
                        "  Object sha256={} kind={:?} identity={:?} interfaces={}",
                        m.info.sha256.get(..12).unwrap_or("unknown"),
                        m.info.kind,
                        m.identity_status,
                        m.info.exports.len()
                    )?;
                }
                if p.modules.len() > ROWS {
                    writeln!(w, "  Objects omitted={}", p.modules.len() - ROWS)?;
                }
                Ok(())
            }
            Record::TracingGap { reason } => {
                writeln!(w, "Tracing unavailable: {reason}; coverage=unknown")
            }
            Record::Membership {
                incarnation: i,
                segment,
                state,
                reason,
            } => writeln!(
                w,
                "Membership pid={} start={} segment={segment} state={state} reason={reason}; sampled",
                i.pid, i.starttime
            ),
            Record::Limit {
                incarnation: i,
                reason,
            } => writeln!(
                w,
                "Limit pid={} start={}: {reason}; activity=unknown",
                i.pid, i.starttime
            ),
            Record::Gap { gap } => writeln!(
                w,
                "Discovery gap pid={:?}: {:?}; coverage=unknown",
                gap.pid, gap.reason
            ),
            Record::SessionGap {
                incarnation: i,
                reason,
            } => writeln!(
                w,
                "Process {} start={} unavailable: {reason}; coverage=unknown",
                i.pid, i.starttime
            ),
            Record::ProcessObservation {
                incarnation: i,
                segment,
                retirement,
                document: d,
            } => {
                let rows = |name: &str| d[name].as_array().map(Vec::as_slice).unwrap_or(&[]);
                let physical = rows("sites")
                    .iter()
                    .chain(rows("fenced").iter().flat_map(|epoch| {
                        epoch["sites"].as_array().map(Vec::as_slice).unwrap_or(&[])
                    }))
                    .try_fold(0u64, |n, r| n.checked_add(r["calls"].as_u64()?));
                let api = d["api_activity"].as_array().and_then(|rows| {
                    rows.iter()
                        .try_fold(0u64, |n, r| n.checked_add(r["entries"].as_u64()?))
                });
                let total =
                    |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "unknown".into());
                writeln!(
                    w,
                    "Process {} start={} segment={segment} retirement={retirement} objects={} physical_entries={} api_entries={} coverage=partial attribution=unknown",
                    i.pid,
                    i.starttime,
                    rows("objects").len(),
                    total(physical),
                    total(api)
                )?;
                let counters = d["completeness"]["counters"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                // Counter names are observer-owned finite vocabulary; limit text
                // width even if a future producer extends that vocabulary.
                for c in counters.iter().take(ROWS) {
                    let name = c["name"].as_str().unwrap_or("unknown");
                    let label: String = name
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
                        .take(80)
                        .collect();
                    writeln!(
                        w,
                        "  Gap {label} value={}",
                        c["value"].as_u64().unwrap_or(0)
                    )?;
                }
                if counters.len() > ROWS {
                    writeln!(w, "  Gaps omitted={}", counters.len() - ROWS)?;
                }
                Ok(())
            }
            Record::End {
                reason,
                segments,
                peak_accounted_bytes,
                coverage,
            } => writeln!(
                w,
                "Crypto watch end: reason={reason} segments={segments} peak_accounted_bytes={peak_accounted_bytes} coverage={coverage}; unsampled membership and unobserved activity remain unknown"
            ),
        }
    }
    fn finish(&mut self, active: Active, reason: &'static str) -> io::Result<()> {
        let Active {
            identity,
            segment,
            session,
        } = active;
        // finish closes all links before projection and releases foreign pins.
        // The result keeps the lease until the borrowed document is delivered.
        match session.finish(Instant::now() + Duration::from_millis(100)) {
            Ok(result) => self.emit(Record::ProcessObservation {
                incarnation: &identity,
                segment,
                retirement: reason,
                document: &crate::report::doc_json(&result.document),
            })?,
            Err(_) => self.emit(Record::SessionGap {
                incarnation: &identity,
                reason: "finalization_failed",
            })?,
        }
        self.emit(Record::Membership {
            incarnation: &identity,
            segment,
            state: "retired",
            reason,
        })
    }
}
fn eligible(record: &ProcessRecord) -> bool {
    record.modules.iter().any(|m| {
        matches!(
            m.info.kind,
            inventory::ObjectKind::OpenSslCompatible
                | inventory::ObjectKind::ProviderModule
                | inventory::ObjectKind::OpenSslConsumer
        )
    })
}
fn departure(identity: &Incarnation, snapshot: &Snapshot) -> Option<&'static str> {
    if snapshot
        .processes
        .iter()
        .any(|p| Incarnation::from(p) == *identity)
    {
        return None;
    }
    if snapshot.processes.iter().any(|p| p.pid == identity.pid) {
        return Some("incarnation_changed");
    }
    if snapshot.gaps.iter().any(|g| {
        (g.pid.is_none() || g.pid == Some(identity.pid))
            && g.reason != GapReason::IdentityUnverified
    }) {
        Some("visibility_lost")
    } else {
        Some("sampled_removal")
    }
}
fn observe(
    config: &CryptoWatchConfig,
    objects: FocusedObjects,
    pool: &MemoryPool,
    output: &mut impl Write,
    json: bool,
    cancel: &AtomicBool,
) -> io::Result<u8> {
    let mut out = Output {
        writer: output,
        sequence: 0,
        json,
    };
    let mut scanner = match ScopedScanner::new_budgeted(
        config.selection.clone(),
        inventory::Limits::default(),
        Some(pool.clone()),
    ) {
        Ok(s) => s,
        Err(reason) => {
            out.emit(Record::Gap {
                gap: &inventory::Gap {
                    pid: None,
                    device: None,
                    inode: None,
                    reason,
                },
            })?;
            out.emit(Record::End {
                reason: "scope_unavailable",
                segments: 0,
                peak_accounted_bytes: pool.peak(),
                coverage: "unknown",
            })?;
            return Ok(4);
        }
    };
    let tracing = !objects.observation.is_empty() && !objects.count.is_empty();
    if !tracing {
        out.emit(Record::TracingGap {
            reason: "companions_unavailable",
        })?;
    }
    let (tracing, reservation) = if tracing {
        match FocusedSession::reservation_bytes(&objects) {
            Ok(bytes) => (true, bytes),
            Err(_) => {
                out.emit(Record::TracingGap {
                    reason: "session_capacity_unavailable",
                })?;
                (false, 0)
            }
        }
    } else {
        (false, 0)
    };
    out.emit(Record::Start {
        max_active: config.max_active,
        max_state_bytes: config.max_state_bytes,
        poll_interval: config.interval,
        duration: config.duration,
        membership: "sampled; unsampled intervals and unseen members remain unknown",
    })?;
    let deadline = Instant::now() + config.duration;
    let mut next_scan = Instant::now();
    let mut active: Vec<Active> = Vec::new();
    let mut segments = 0;
    while Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        let now = Instant::now();
        // Drop each snapshot before acquiring the next; only the scanner cache
        // and active sessions retain metadata between samples.
        let sampled = if now >= next_scan {
            let snapshot = scanner.observation_snapshot_for(
                config.interval.min(deadline.saturating_duration_since(now)),
            );
            next_scan = Instant::now() + config.interval;
            for gap in &snapshot.snapshot.gaps {
                out.emit(Record::Gap { gap })?;
            }
            let mut i = 0;
            while i < active.len() {
                if let Some(reason) = departure(&active[i].identity, &snapshot.snapshot) {
                    out.finish(active.remove(i), reason)?;
                } else {
                    i += 1;
                }
            }
            for p in &snapshot.snapshot.processes {
                out.emit(Record::Discovery { process: p })?;
                if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                let identity = Incarnation::from(p);
                if active.iter().any(|a| a.identity == identity) {
                    continue;
                }
                if !eligible(p) {
                    let uncertain = snapshot.snapshot.gaps.iter().any(|g| {
                        (g.pid.is_none() || g.pid == Some(p.pid))
                            && g.reason != GapReason::IdentityUnverified
                    });
                    out.emit(Record::Membership {
                        incarnation: &identity,
                        segment: 0,
                        state: "sampled",
                        reason: if uncertain {
                            "candidate_visibility_unknown"
                        } else {
                            "no_candidate_interfaces_in_sample"
                        },
                    })?;
                    continue;
                }
                if !tracing {
                    out.emit(Record::Membership {
                        incarnation: &identity,
                        segment: 0,
                        state: "sampled",
                        reason: "tracing_unavailable",
                    })?;
                    continue;
                }
                if active.len() >= config.max_active {
                    out.emit(Record::Limit {
                        incarnation: &identity,
                        reason: "active_limit",
                    })?;
                    continue;
                }
                let Some(lease) = pool.reserve(reservation) else {
                    out.emit(Record::Limit {
                        incarnation: &identity,
                        reason: "global_state_limit",
                    })?;
                    continue;
                };
                let config = FocusedConfig {
                    duration: deadline.saturating_duration_since(Instant::now()),
                    ..Default::default()
                };
                match FocusedSession::open_scanned_reserved(
                    config,
                    objects.clone(),
                    (
                        deadline.min(Instant::now() + Duration::from_secs(60)),
                        deadline,
                    ),
                    cancel,
                    p,
                    lease,
                ) {
                    Ok(session) => {
                        segments += 1;
                        out.emit(Record::Membership {
                            incarnation: &identity,
                            segment: segments,
                            state: "observing",
                            reason: "sampled_admission",
                        })?;
                        active.push(Active {
                            identity,
                            segment: segments,
                            session,
                        });
                    }
                    Err(_) => out.emit(Record::SessionGap {
                        incarnation: &identity,
                        reason: if cancel.load(Ordering::Relaxed) {
                            "setup_cancelled"
                        } else if Instant::now() >= deadline {
                            "setup_deadline"
                        } else {
                            "acquisition_unavailable"
                        },
                    })?,
                }
            }
            Some(snapshot)
        } else {
            None
        };
        let mut i = 0;
        while i < active.len() {
            let records = sampled.as_ref().map(|s| {
                s.snapshot
                    .processes
                    .iter()
                    .find(|p| Incarnation::from(*p) == active[i].identity)
                    .map_or(&[][..], std::slice::from_ref)
            });
            let partial = sampled
                .as_ref()
                .is_some_and(|s| !s.snapshot.gaps.is_empty());
            let tick_deadline = deadline.min(Instant::now() + Duration::from_secs(1));
            let result = active[i].session.poll_scanned(
                Instant::now(),
                tick_deadline,
                cancel,
                records,
                partial,
            );
            let reason = match result {
                Ok(SessionProgress::Running) => {
                    i += 1;
                    continue;
                }
                Ok(SessionProgress::Exited) => "owned_exit",
                Ok(SessionProgress::Unverifiable) => "visibility_lost",
                Ok(SessionProgress::StopRequested) => {
                    if cancel.load(Ordering::Relaxed) {
                        "cancelled"
                    } else {
                        "duration"
                    }
                }
                Err(_) => "session_unavailable",
            };
            out.finish(active.remove(i), reason)?;
        }
        drop(sampled);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(25).min(remaining));
        }
    }
    let reason = if cancel.load(Ordering::Relaxed) {
        "cancelled"
    } else {
        "duration"
    };
    // Stop every member before potentially slow final projection/output. This
    // also propagates cancellation arriving between poll passes into documents.
    for a in &mut active {
        a.session.stop_admission(cancel);
    }
    for a in active {
        out.finish(a, reason)?;
    }
    out.emit(Record::End {
        reason,
        segments,
        peak_accounted_bytes: pool.peak(),
        coverage: "partial",
    })?;
    Ok(if segments == 0 { 4 } else { 3 })
}
/// Complete grammar admission precedes selectors, companion reads and signals.
pub fn run(args: &[String]) -> ExitCode {
    let invalid = || {
        crate::report::err_line(
            "osslscope crypto watch: invalid arguments (requires scan --watch --observe-crypto)",
        );
        ExitCode::from(2)
    };
    if args.first().is_none_or(|s| s != "scan")
        || args.iter().filter(|s| *s == "--observe-crypto").count() != 1
    {
        return invalid();
    }
    let pool = MemoryPool::new(GLOBAL_BYTES);
    let argument_bytes = args.iter().try_fold(COORDINATOR_BYTES, |n, a| {
        n.checked_add(a.len().saturating_mul(4).saturating_add(1024))
    });
    let Some(_coordinator) = argument_bytes.and_then(|n| pool.reserve(n)) else {
        return invalid();
    };
    let options = match inventory::cli::parse_crypto_watch(&args[1..]) {
        Ok(o) if o.watch => o,
        _ => return invalid(),
    };
    let config = CryptoWatchConfig {
        selection: Selection {
            pids: options.pids,
            cgroup: options.cgroup,
            modules: options.modules,
        },
        duration: options.duration.unwrap_or(Duration::from_secs(30)),
        interval: options.interval.unwrap_or(Duration::from_secs(1)),
        ..Default::default()
    };
    // Resolver admits at most two 16MiB objects, with bounded verification/read
    // copies. This phase ends before any session or parser is allocated.
    let Some(resolving) = pool.reserve(64 << 20) else {
        return ExitCode::from(4);
    };
    let objects = match crate::package::commands::resolve_focused_objects(None, None) {
        Ok(o) => o,
        Err(_) => {
            use sha2::{Digest, Sha256};
            FocusedObjects {
                observation: std::sync::Arc::from([]),
                count: std::sync::Arc::from([]),
                count_sha256: Sha256::digest([]).into(),
            }
        }
    };
    let object_bytes = objects.observation.len() + objects.count.len();
    drop(resolving);
    let Some(_objects) = pool.reserve(object_bytes) else {
        return ExitCode::from(4);
    };
    let _signals = match Signals::install() {
        Ok(s) => s,
        Err(_) => return ExitCode::from(1),
    };
    match observe(
        &config,
        objects,
        &pool,
        &mut io::stdout().lock(),
        options.json,
        _signals.cancel(),
    ) {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            crate::report::err_line("osslscope crypto watch: observation/output failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn objects() -> FocusedObjects {
        use sha2::{Digest, Sha256};
        FocusedObjects {
            observation: Arc::from([]),
            count: Arc::from([]),
            count_sha256: Sha256::digest([]).into(),
        }
    }
    #[test]
    fn human_summary_conserves_fenced_counts_and_bounds_gaps() {
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let document = serde_json::json!({
            "sites": [{"calls": 2}], "fenced": [{"sites": [{"calls": 3}]}],
            "api_activity": [{"entries": 7}], "objects": [{}, {}],
            "completeness": {"counters": (0..12).map(|_| serde_json::json!({"name": "focused.test", "value": 1})).collect::<Vec<_>>()}
        });
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
        };
        out.emit(Record::ProcessObservation {
            incarnation: &identity,
            segment: 4,
            retirement: "duration",
            document: &document,
        })
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("physical_entries=5 api_entries=7"));
        assert!(text.contains("start=123 segment=4") && text.contains("objects=2"));
        assert_eq!(text.lines().count(), 10);
        assert!(text.contains("Gaps omitted=4"));
        assert!(text.contains("coverage=partial attribution=unknown"));
    }
    #[test]
    fn two_normal_reservations_include_coordinator_scanner_and_stock_parser() {
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES + 32_768).unwrap();
        let _scanner = pool.reserve(4096 * 160 + 100 * 4096).unwrap();
        let cost = FocusedSession::reservation_bytes(&objects()).unwrap() + 29_480;
        let _a = pool.reserve(cost).unwrap();
        let _b = pool.reserve(cost).unwrap();
        let _parser = pool
            .reserve(inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
            .unwrap();
        assert!(pool.peak() <= GLOBAL_BYTES);
        assert!(pool.reserve(cost).is_none());
    }
    #[test]
    fn reincarnation_and_visibility_are_not_inferred_exits() {
        let mut snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![std::process::id()],
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        });
        let identity = Incarnation::from(&snapshot.processes[0]);
        assert_eq!(departure(&identity, &snapshot), None);
        snapshot.processes[0].starttime += 1;
        assert_eq!(departure(&identity, &snapshot), Some("incarnation_changed"));
        snapshot.processes.clear();
        assert_eq!(departure(&identity, &snapshot), Some("visibility_lost"));
        snapshot.gaps.clear();
        assert_eq!(departure(&identity, &snapshot), Some("sampled_removal"));
        snapshot.gaps.push(inventory::Gap {
            pid: None,
            device: None,
            inode: None,
            reason: GapReason::Deadline,
        });
        assert_eq!(departure(&identity, &snapshot), Some("visibility_lost"));
    }
    #[test]
    #[ignore = "requires explicit privileged observation/count companions"]
    fn focused_active_slot_limit_names_the_uncovered_member() {
        let mut children: Vec<_> = (0..2)
            .map(|_| {
                std::process::Command::new("openssl")
                    .args([
                        "speed", "-elapsed", "-seconds", "20", "-evp", "SHA512", "-bytes", "64",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        let config = CryptoWatchConfig {
            selection: Selection {
                pids: children.iter().map(|p| p.id()).collect(),
                ..Default::default()
            },
            max_active: 1,
            duration: Duration::from_secs(4),
            ..Default::default()
        };
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES).unwrap();
        let mut output = Vec::new();
        use sha2::{Digest, Sha256};
        let observation = std::fs::read(
            std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").expect("observation companion"),
        )
        .unwrap();
        let count = std::fs::read(
            std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").expect("count companion"),
        )
        .unwrap();
        let objects = FocusedObjects {
            observation: observation.into(),
            count_sha256: Sha256::digest(&count).into(),
            count: count.into(),
        };
        let result = observe(
            &config,
            objects,
            &pool,
            &mut output,
            true,
            &AtomicBool::new(false),
        );
        for child in &mut children {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        result.unwrap();
        let rows: Vec<serde_json::Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert!(rows.iter().any(|r| {
            r["kind"] == "limit"
                && r["reason"] == "active_limit"
                && config
                    .selection
                    .pids
                    .contains(&(r["incarnation"]["pid"].as_u64().unwrap() as u32))
        }));
    }
}
