// SPDX-License-Identifier: GPL-3.0-or-later
//! 6D live smoke cell (T8.2a): REAL attach, REAL provider ops. Ignored
//! unless `TRACE_LIVE_SMOKE=1` with root plus a fresh object in
//! `OSSL_PROVIDER_OBSERVATION_TEST_BPF`. A quiet run is VOID, not a pass.
use osslscope::inventory::{
    self,
    scope::{ScopedScanner, Selection},
};
use osslscope::provider_observation::{self as po, trace};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const OPS: u64 = 60;
const MIN_PAIRS: u64 = 100;

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

struct ScratchDir(std::path::PathBuf);
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn gated() -> Option<Vec<u8>> {
    if std::env::var("TRACE_LIVE_SMOKE").unwrap_or_default() != "1" {
        eprintln!("trace live smoke: set TRACE_LIVE_SMOKE=1; skipping");
        return None;
    }
    let id = Command::new("id").arg("-u").output();
    match id {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"0") => {}
        _ => {
            eprintln!("SKIP trace live smoke: need root");
            return None;
        }
    }
    let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")?;
    let object = fs::read(path).ok()?;
    Some(object)
}

fn build_workload(dir: &std::path::Path) -> std::path::PathBuf {
    let app = dir.join("trace_digest_loop");
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/trace_digest_loop.c"
            ))
            .args(["-lcrypto"])
            .status()
            .unwrap()
            .success()
    );
    app
}

fn spawn(app: &std::path::Path) -> (Owned, mpsc::Receiver<String>) {
    let mut child = Owned(
        Command::new(app)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut first = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    first.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in first.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    (child, rx)
}

fn drive(
    mode: u32,
) -> (
    trace::ClosedTraceWindow,
    trace::TraceTotals,
    po::ObservationBatch,
) {
    let object = gated().expect("live lane gates");
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-trace-smoke-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&scratch.0);
    fs::create_dir(&scratch.0).unwrap();
    let app = build_workload(&scratch.0);
    let (mut child, rx) = spawn(&app);
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.0.id()],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
    session.set_trace_mode(mode).unwrap();
    let setup = session.reconcile(&scanner.snapshot());
    assert!(
        !setup.gaps.iter().any(|g| matches!(
            g,
            po::ObservationGap::AttachFailed
                | po::ObservationGap::BpfUnavailable
                | po::ObservationGap::SymbolUnavailable
        )),
        "setup: {:?}",
        setup.gaps
    );
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let done = loop {
        if Instant::now() >= deadline {
            panic!("VOID: workload did not finish within 120s");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.starts_with("done ") => break line,
            Ok(_) => continue,
            Err(_) => {
                session.drain(Instant::now() + Duration::from_millis(100));
            }
        }
    };
    assert_eq!(done, format!("done ok={OPS} fetched={OPS}"));
    for _ in 0..5 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    let window = session.close_trace_window(0);
    let totals = session.trace_totals();
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let batch = session.close();
    (window, totals, batch)
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn trace_live_smoke_pairs_operational_edges() {
    if gated().is_none() {
        return;
    }
    let (window, totals, _batch) = drive(trace::TRACE_MODE_LATENCY);
    eprintln!(
        "smoke: paired={} unpaired_e={} unpaired_r={} op_attempts={} fetch_attempts={} ring_loss={:?} dropped={} capped={}",
        window.paired,
        window.unpaired_entries,
        window.unpaired_results,
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.ring_loss,
        window.dropped,
        window.capped,
    );
    assert_eq!(window.mode, trace::TRACE_MODE_LATENCY);
    if window.paired < MIN_PAIRS {
        panic!("VOID: quiet run (paired={} < {MIN_PAIRS})", window.paired);
    }
    if window.ring_loss.iter().any(|lane| *lane > 0) {
        panic!("VOID: ring loss in smoke cell: {:?}", window.ring_loss);
    }
    let received_attempts: u64 = window.received.attempts.iter().sum();
    let received_results: u64 = window.received.results.iter().sum();
    assert_eq!(received_attempts, window.paired + window.unpaired_entries);
    assert_eq!(received_results, window.paired + window.unpaired_results);
    assert!(
        window.received.attempts[trace::TraceFamily::PublicApi.index()] >= OPS,
        "operational attempts: {:?}",
        window.received.attempts
    );
    assert!(
        window.received.attempts[trace::TraceFamily::Fetch.index()] >= OPS,
        "fetch attempts: {:?}",
        window.received.attempts
    );
    assert!(window.pairs.iter().all(|pair| pair.class <= 4));
    assert!(window.pairs.iter().any(|pair| pair.class == 1));
    assert_eq!(totals.paired, window.paired);
    assert!(!window.capped);
    assert_eq!(window.dropped, 0);
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn trace_mode_gate_off_is_base_identical() {
    if gated().is_none() {
        return;
    }
    let (window, totals, batch) = drive(trace::TRACE_MODE_OFF);
    eprintln!(
        "off-gate: paired={} op_attempts={} fetch_attempts={} ring_loss={:?}",
        window.paired,
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.ring_loss,
    );
    assert_eq!(window.mode, trace::TRACE_MODE_OFF);
    assert_eq!(window.paired, 0);
    assert_eq!(window.unpaired_entries, 0);
    assert_eq!(window.unpaired_results, 0);
    assert_eq!(window.dropped, 0);
    assert!(window.detail.is_empty());
    assert!(window.pairs.is_empty());
    assert_eq!(
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        0,
        "off mode must emit no operational edges"
    );
    assert!(
        window.received.attempts[trace::TraceFamily::Fetch.index()] >= OPS,
        "fetch emission stays ungated: {:?}",
        window.received.attempts
    );
    assert_eq!(totals.paired, 0);
    let entries: u64 = batch.api_activity.iter().map(|row| row.row.entries).sum();
    assert!(
        entries >= OPS,
        "maps-only aggregates must observe the workload: {entries}"
    );
    for row in &batch.api_activity {
        assert_eq!(row.row.gaps.map, 0);
        assert_eq!(row.row.gaps.depth, 0);
        assert_eq!(row.row.gaps.unpaired, 0);
    }
}
