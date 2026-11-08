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

fn is_fetch_fact(fact: &po::ObservationFact) -> bool {
    matches!(
        fact.api,
        po::ObservationApi::Inventoried(
            osslscope::inventory::Api::EvpMdFetch
                | osslscope::inventory::Api::EvpCipherFetch
                | osslscope::inventory::Api::EvpMacFetch
                | osslscope::inventory::Api::EvpKdfFetch
                | osslscope::inventory::Api::EvpSignatureFetch
                | osslscope::inventory::Api::EvpKemFetch
        )
    )
}

struct Driven {
    window: trace::ClosedTraceWindow,
    totals: trace::TraceTotals,
    op_facts: u64,
    fetch_facts: u64,
    batch: po::ObservationBatch,
}

fn drive(mode: u32) -> Driven {
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
    // F1: tally cold facts across EVERY drain batch (facts are
    // emitted per drain — the close batch alone cannot witness a
    // per-edge leak into the fact ring).
    let mut op_facts = 0u64;
    let mut fetch_facts = 0u64;
    let mut tally = |batch: &po::ObservationBatch| {
        op_facts += batch
            .facts
            .iter()
            .filter(|f| matches!(f.api, po::ObservationApi::Operational(_)))
            .count() as u64;
        fetch_facts += batch.facts.iter().filter(|f| is_fetch_fact(f)).count() as u64;
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    let done = loop {
        if Instant::now() >= deadline {
            panic!("VOID: workload did not finish within 120s");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.starts_with("done ") => break line,
            Ok(_) => continue,
            Err(_) => {
                tally(&session.drain(Instant::now() + Duration::from_millis(100)));
            }
        }
    };
    assert_eq!(done, format!("done ok={OPS} fetched={OPS}"));
    for _ in 0..5 {
        tally(&session.drain(Instant::now() + Duration::from_millis(200)));
    }
    let window = session.close_trace_window(0);
    let totals = session.trace_totals();
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let batch = session.close();
    tally(&batch);
    Driven {
        window,
        totals,
        op_facts,
        fetch_facts,
        batch,
    }
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn trace_live_smoke_pairs_operational_edges() {
    if gated().is_none() {
        return;
    }
    let Driven {
        window,
        totals,
        op_facts,
        fetch_facts,
        ..
    } = drive(trace::TRACE_MODE_LATENCY);
    eprintln!(
        "smoke: paired={} unpaired_e={} unpaired_r={} op_attempts={} fetch_attempts={} ring_loss={:?} dropped={} capped={} classes={:?} op_facts={} fetch_facts={}",
        window.paired,
        window.unpaired_entries,
        window.unpaired_results,
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.ring_loss,
        window.dropped,
        window.capped,
        window.class_counts,
        op_facts,
        fetch_facts,
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
    assert_eq!(window.class_counts.iter().sum::<u64>(), window.paired);
    assert!(
        window.class_counts[1] >= 1,
        "operational successes fold class-1 (only operational folds nonzero): {:?}",
        window.class_counts
    );
    assert!(
        window.class_counts[0] >= 1,
        "fetch pairs fold class-0: {:?}",
        window.class_counts
    );
    for (c, h) in window.histograms.iter().enumerate() {
        assert_eq!(h.buckets[18], h.count, "class {c} cumulative invariant");
    }
    let hist_total: u64 = window.histograms.iter().map(|h| h.count).sum();
    assert!(
        hist_total + window.nonmonotonic_pairs + window.class_counts[0] >= window.paired,
        "histogram coverage: hist={hist_total} nonmono={} class0={} paired={}",
        window.nonmonotonic_pairs,
        window.class_counts[0],
        window.paired
    );
    assert_eq!(
        window.api_attempts.iter().sum::<u64>(),
        received_attempts,
        "per-API partition mirrors family received counts"
    );
    assert_eq!(window.api_results.iter().sum::<u64>(), received_results);
    assert_eq!(
        op_facts, 0,
        "F1: operational edges must not mint cold facts"
    );
    assert_eq!(
        fetch_facts,
        window.received.attempts[trace::TraceFamily::Fetch.index()]
            + window.received.results[trace::TraceFamily::Fetch.index()],
        "F1: every fetch edge still files its BASE cold fact"
    );
    assert_eq!(totals.paired, window.paired);
    assert_eq!(totals.class_counts, window.class_counts);
    assert!(!window.capped);
    assert_eq!(window.dropped, 0);
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn trace_mode_gate_off_is_base_identical() {
    if gated().is_none() {
        return;
    }
    for mode in [trace::TRACE_MODE_OFF, trace::TRACE_MODE_METADATA] {
        off_mode_matches_base(mode);
    }
}

fn off_mode_matches_base(mode: u32) {
    let Driven {
        window,
        totals,
        batch,
        ..
    } = drive(mode);
    eprintln!(
        "off-gate: paired={} op_attempts={} fetch_attempts={} ring_loss={:?}",
        window.paired,
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.ring_loss,
    );
    assert_eq!(window.mode, mode);
    assert_eq!(window.paired, 0, "mode {mode}");
    assert_eq!(window.unpaired_entries, 0);
    assert_eq!(window.unpaired_results, 0);
    assert_eq!(window.dropped, 0);
    assert!(window.detail.is_empty());
    assert_eq!(window.class_counts, [0; 5]);
    assert!(
        window.histograms.iter().all(|h| h.count == 0 && h.sum == 0),
        "no pairing in off modes"
    );
    assert!(window.api_attempts[20..=72].iter().all(|c| *c == 0));
    assert!(
        window.api_attempts[10] >= OPS,
        "fetch per-API counts fold ungated: {}",
        window.api_attempts[10]
    );
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

/// fix5 F3d (R5-1 shape): LOSS delta + attribution records queued for
/// DRAIN (not in carry) → reconcile (empty carry) → drain consumes.
/// The DRAIN batch must be downgraded + carry the lane gap; the
/// reconcile batch must carry no stolen signal. REAL throughout:
/// live attach, live flood overrun (no drain until after reconcile —
/// overrun by capacity arithmetic, not timing), real decode /
/// consume / drain path. Ring-mmap forging was refuted first: the
/// kernel refuses PROT_WRITE on ringbuf producer pages even as root
/// (EPERM), so only live BPF producers can queue drain content.
const FLOOD_BATCHES: usize = 40;

fn attributed_downgraded(batch: &po::ObservationBatch) -> (usize, usize) {
    let mut attributed = 0usize;
    let mut downgraded = 0usize;
    for fact in &batch.facts {
        let (algorithm, quality) = match &fact.payload {
            po::ObservationPayload::Algorithm {
                algorithm,
                alias_quality,
                ..
            }
            | po::ObservationPayload::Implementation {
                algorithm,
                alias_quality,
                ..
            } => (algorithm, alias_quality),
            _ => continue,
        };
        attributed += 1;
        if algorithm.label() == "other" && quality.status == po::AliasStatus::Unavailable {
            downgraded += 1;
        }
    }
    (attributed, downgraded)
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn fix5_f3d_queued_drain_loss_downgrades_drain_batch() {
    let object = match gated() {
        Some(object) => object,
        None => return,
    };
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-trace-f3d-{}", std::process::id())),
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
    session.set_trace_mode(trace::TRACE_MODE_LATENCY).unwrap();
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
    // Flood WITHOUT draining: 40 x 60 fetch+digest ops (~16 ring
    // records each, 112 B each — fix6) into the 1 MiB ring (~9.3k
    // records). ~38k records against ~9.3k slots overruns
    // LOSS_RING by capacity arithmetic; the ring retains the
    // oldest ~9.3k records (a queue, not an overwrite ring) with
    // complete head sequences. No session.drain until after reconcile.
    let stdin = child.0.stdin.as_mut().unwrap();
    for _ in 0..FLOOD_BATCHES {
        stdin.write_all(b"G").unwrap();
    }
    stdin.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    for n in 0..FLOOD_BATCHES {
        let line = loop {
            if Instant::now() >= deadline {
                panic!("VOID: flood batch {n} did not finish within 300s");
            }
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => continue,
            }
        };
        assert_eq!(
            line,
            format!("done ok={OPS} fetched={OPS}"),
            "flood batch {n}"
        );
    }
    // Reconcile with an empty carry (no retire ran — the child is
    // alive): the queued records stay queued for drain.
    let reconciled = session.reconcile(&scanner.snapshot());
    assert!(
        reconciled.facts.is_empty(),
        "premise: empty carry emits no facts: {:?}",
        reconciled.facts.iter().map(|f| &f.api).collect::<Vec<_>>()
    );
    assert!(
        !reconciled.gaps.contains(&po::ObservationGap::QueueLoss),
        "reconcile must not steal the drain's loss signal: {:?}",
        reconciled.gaps
    );
    // Drain consumes the queued survivors: the batch overlaps the
    // overrun, so every attribution in it downgrades + the lane
    // gap rides WITH the affected content.
    let drained = session.drain(Instant::now() + Duration::from_secs(30));
    eprintln!(
        "f3d: reconcile_gaps={:?} drain_facts={} drain_gaps={:?}",
        reconciled.gaps,
        drained.facts.len(),
        drained.gaps
    );
    assert!(
        drained.gaps.contains(&po::ObservationGap::QueueLoss),
        "drain batch must carry the overlapping lane gap: {:?}",
        drained.gaps
    );
    let (attributed, downgraded) = attributed_downgraded(&drained);
    assert!(
        attributed >= 1,
        "premise: queued survivors must attribute: facts={}",
        drained.facts.len()
    );
    assert_eq!(
        downgraded, attributed,
        "every queued attribution overlapping loss downgrades"
    );
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let _ = session.close();
}
