// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 1 fetch-surface live cell (P1-A1): REAL attach, REAL fetch
//! calls over the eight extension surfaces (73..=80). Ignored unless
//! `TRACE_LIVE_SMOKE=1` with root plus a fresh object in
//! `OSSL_PROVIDER_OBSERVATION_TEST_BPF` (same guest lane as the trace
//! smoke). A quiet run is VOID, not a pass. A REQUESTED run
//! (`TRACE_LIVE_SMOKE=1`) with missing prerequisites FAILS CLOSED
//! (never a silent skip): the guest lane must surface a broken setup,
//! not a green skip.
//!
//! Independent oracle: the fixture reports its own per-surface
//! attempt AND success counts (`done asym=8,7 ...`); every asserted
//! observer count is checked against that line, never against itself.
//! Per-surface totals are DISTINCT and every surface makes real
//! NULL-returning calls, so swapped probes and an always-success
//! classifier are both detected. The leg also pins the privacy gap
//! in BOTH serialized outputs (no property or algorithm-name string
//! may appear), and records an off-mode twin (pairing off:
//! zero pairs, edges still received, cold facts still flow).
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

/// Expected per-surface attempts (fixture `ATTEMPTS`, oracle `done` line).
const ATTEMPTS: [u64; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
/// Expected per-surface successes (fixture `ATTEMPTS - BOGUS`).
const SUCCESSES: [u64; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
/// Extension surface IDs in fixture order.
const SURFACES: [(u32, &str); 8] = [
    (73, "asym"),
    (74, "kexch"),
    (75, "kmgmt"),
    (76, "rand"),
    (77, "skey"),
    (78, "dec"),
    (79, "enc"),
    (80, "store"),
];
/// Property/name strings the observer must never capture (privacy pin).
const FORBIDDEN_STRINGS: [&str; 4] = ["BOGUS", "CTR-DRBG", "input=der", "output=text"];

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

/// Fail-closed prerequisite gate: unrequested runs skip (`None`); a
/// REQUESTED run (`TRACE_LIVE_SMOKE=1`) with missing root/object
/// panics — a broken guest setup must fail, never skip green.
fn gated() -> Option<Vec<u8>> {
    if std::env::var("TRACE_LIVE_SMOKE").unwrap_or_default() != "1" {
        eprintln!("fetch-surface live: set TRACE_LIVE_SMOKE=1; skipping");
        return None;
    }
    let id = Command::new("id").arg("-u").output();
    match id {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"0") => {}
        _ => panic!("FAIL-CLOSED: fetch-surface live requested but not root"),
    }
    let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
        .unwrap_or_else(|| panic!("FAIL-CLOSED: fetch-surface live requested but OSSL_PROVIDER_OBSERVATION_TEST_BPF is unset"));
    let object = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "FAIL-CLOSED: fetch-surface live requested but object unreadable ({}): {error}",
            path.to_string_lossy()
        )
    });
    Some(object)
}

fn api_for_surface(id: u32) -> po::ObservationApi {
    use osslscope::inventory::Api::*;
    po::ObservationApi::Inventoried(match id {
        73 => EvpAsymCipherFetch,
        74 => EvpKeyexchFetch,
        75 => EvpKeymgmtFetch,
        76 => EvpRandFetch,
        77 => EvpSkeymgmtFetch,
        78 => OsslDecoderFetch,
        79 => OsslEncoderFetch,
        80 => OsslStoreLoaderFetch,
        _ => unreachable!("extension surface {id}"),
    })
}

struct RoundReport {
    window: trace::ClosedTraceWindow,
    attempt_facts: [u64; 8],
    result_facts: [u64; 8],
    success_facts: [u64; 8],
    failure_facts: [u64; 8],
    fetch_facts: u64,
    all_facts: Vec<po::ObservationFact>,
    op_entries: u64,
    oracle_attempts: [u64; 8],
    oracle_successes: [u64; 8],
}

/// One fixture round under `mode`: build + spawn the fixture, attach,
/// release one `G` round, tally cold facts across EVERY drain batch
/// per surface, and parse the independent oracle line. Missing
/// prerequisites or counts lines fail closed (panic), never skip.
fn run_fetch_round(object: &[u8], mode: u32) -> RoundReport {
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-fetch-smoke-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&scratch.0);
    fs::create_dir(&scratch.0).unwrap();
    let app = scratch.0.join("fetch_surface_loop");
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/fetch_surface_loop.c"
            ))
            .args(["-lcrypto"])
            .status()
            .unwrap()
            .success()
    );
    let mut child = Owned(
        Command::new(&app)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut first = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    first.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n", "fixture must print its ready line");
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
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.0.id()],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), object).unwrap();
    session.set_trace_mode(mode).unwrap();
    let setup = session.reconcile(&scanner.snapshot());
    // Same quarantine contract as the trace smoke: exactly one
    // QuarantinedApi (API 21), no fatal attach gaps.
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
    assert_eq!(
        setup
            .gaps
            .iter()
            .filter(|g| matches!(g, po::ObservationGap::QuarantinedApi))
            .count(),
        1,
        "setup quarantine gap: {:?}",
        setup.gaps
    );
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    // Tally cold facts across EVERY drain batch, per surface.
    let mut attempt_facts = [0u64; 8];
    let mut result_facts = [0u64; 8];
    let mut success_facts = [0u64; 8];
    let mut failure_facts = [0u64; 8];
    let mut fetch_facts = 0u64;
    let mut all_facts = Vec::new();
    let mut op_entries = 0u64;
    let mut tally = |batch: &po::ObservationBatch| {
        // Drain gaps fail the leg below (VOID on ring loss; exact
        // counts after): a gapped drain cannot prove exactness, so a
        // lossy run never passes silently. Gaps print for diagnosis.
        if !batch.gaps.is_empty() {
            eprintln!(
                "fetchsmoke drain gaps: {:?} refusals={:?} facts={}",
                batch.gaps,
                batch.refusals,
                batch.facts.len()
            );
        }
        for fact in &batch.facts {
            all_facts.push(fact.clone());
            for (slot, (id, _)) in SURFACES.iter().enumerate() {
                if fact.api != api_for_surface(*id) {
                    continue;
                }
                fetch_facts += 1;
                match &fact.payload {
                    po::ObservationPayload::ApiAttempt { .. } => attempt_facts[slot] += 1,
                    po::ObservationPayload::ApiResult { outcome, .. } => {
                        result_facts[slot] += 1;
                        match outcome {
                            po::ApiOutcome::Success => success_facts[slot] += 1,
                            po::ApiOutcome::Failure => failure_facts[slot] += 1,
                            po::ApiOutcome::Unknown => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        for activity in &batch.api_activity {
            op_entries = op_entries.saturating_add(activity.row.entries);
        }
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
    // Independent oracle: the fixture's own per-surface attempts and
    // successes (`done asym=8,7 ...`). A missing counts line fails
    // closed — the leg never asserts against itself.
    let mut oracle_attempts = [0u64; 8];
    let mut oracle_successes = [0u64; 8];
    for (slot, (_, key)) in SURFACES.iter().enumerate() {
        let prefix = format!("{key}=");
        let part = done
            .split_whitespace()
            .find(|part| part.starts_with(&prefix))
            .unwrap_or_else(|| panic!("FAIL-CLOSED: oracle lacks {key}: {done}"));
        let (attempts, successes) = part[prefix.len()..]
            .split_once(',')
            .unwrap_or_else(|| panic!("FAIL-CLOSED: oracle lacks counts for {key}: {done}"));
        oracle_attempts[slot] = attempts.parse().unwrap_or_else(|_| {
            panic!("FAIL-CLOSED: oracle attempts unparsable for {key}: {done}")
        });
        oracle_successes[slot] = successes.parse().unwrap_or_else(|_| {
            panic!("FAIL-CLOSED: oracle successes unparsable for {key}: {done}")
        });
    }
    // Drain to quiescence (bounded 30s): fixed-count drains lose
    // tail records when snapshots lag (P2fix1 regression repair —
    // sealing early would silently drop edges the oracle vouches).
    // Quiescence = 3 consecutive drains with no gaps and no facts;
    // a stuck ring still fails honestly below.
    let qdeadline = Instant::now() + Duration::from_secs(30);
    let mut quiet = 0u32;
    while quiet < 3 && Instant::now() < qdeadline {
        let batch = session.drain(Instant::now() + Duration::from_millis(200));
        let busy = !batch.gaps.is_empty() || !batch.facts.is_empty();
        tally(&batch);
        if busy {
            quiet = 0;
        } else {
            quiet += 1;
        }
    }
    // Terminal seal AFTER the final poll (close_with_trace runs the
    // terminal drain first — sealing before it would strand trailing
    // edges in an unclosed window; c023 legs seal the same way).
    let (batch, window, _totals) = session.close_with_trace();
    tally(&batch);
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let per_api: Vec<u64> = SURFACES
        .iter()
        .map(|(id, _)| window.api_attempts[*id as usize])
        .collect();
    let per_api_results: Vec<u64> = SURFACES
        .iter()
        .map(|(id, _)| window.api_results[*id as usize])
        .collect();
    eprintln!(
        "fetchsmoke: paired={} unpaired_e={} unpaired_r={} fetch_attempts={} ring_loss={:?} dropped={} capped={} classes={:?} fetch_facts={} per_api_attempts={:?} per_api_results={:?} oracle_attempts={:?} oracle_successes={:?} success_facts={:?} failure_facts={:?}",
        window.paired,
        window.unpaired_entries,
        window.unpaired_results,
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.ring_loss,
        window.dropped,
        window.capped,
        window.class_counts,
        fetch_facts,
        per_api,
        per_api_results,
        oracle_attempts,
        oracle_successes,
        success_facts,
        failure_facts,
    );
    RoundReport {
        window,
        attempt_facts,
        result_facts,
        success_facts,
        failure_facts,
        fetch_facts,
        all_facts,
        op_entries,
        oracle_attempts,
        oracle_successes,
    }
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn fetch_surface_live_observes_all_8_extension_surfaces() {
    let Some(object) = gated() else { return };
    // The fixture's totals are distinct per surface (swapped probes
    // change the signature) and every surface fails for real
    // (an always-success classifier cannot match the oracle).
    for (slot, (_, key)) in SURFACES.iter().enumerate() {
        assert_ne!(ATTEMPTS[slot], 0, "surface {key} must attempt for real");
        assert!(
            SUCCESSES[slot] < ATTEMPTS[slot],
            "surface {key} must fail for real (real NULL returns)"
        );
    }
    let mut sorted_attempts = ATTEMPTS.to_vec();
    sorted_attempts.sort_unstable();
    sorted_attempts.dedup();
    assert_eq!(sorted_attempts.len(), 8, "attempts must be distinct");
    let mut sorted_successes = SUCCESSES.to_vec();
    sorted_successes.sort_unstable();
    sorted_successes.dedup();
    assert_eq!(sorted_successes.len(), 8, "successes must be distinct");
    let total: u64 = ATTEMPTS.iter().sum();
    let report = run_fetch_round(&object, trace::TRACE_MODE_LATENCY);
    let window = &report.window;
    if window.paired < total {
        panic!("VOID: quiet run (paired={} < {})", window.paired, total);
    }
    if window.ring_loss.iter().any(|lane| *lane > 0) {
        panic!("VOID: ring loss in fetch cell: {:?}", window.ring_loss);
    }
    // The oracle itself behaved (fixture made its distinct calls and
    // its bogus names really returned NULL).
    assert_eq!(report.oracle_attempts, ATTEMPTS, "oracle attempts");
    assert_eq!(report.oracle_successes, SUCCESSES, "oracle successes");
    // Per-surface exact counts against the oracle.
    for (slot, (id, key)) in SURFACES.iter().enumerate() {
        assert_eq!(
            report.attempt_facts[slot], report.oracle_attempts[slot],
            "surface {id} ({key}) attempts"
        );
        assert_eq!(
            report.result_facts[slot], report.oracle_attempts[slot],
            "surface {id} ({key}) results"
        );
        assert_eq!(
            report.success_facts[slot], report.oracle_successes[slot],
            "surface {id} ({key}) successes vs oracle"
        );
        assert_eq!(
            report.failure_facts[slot],
            report.oracle_attempts[slot] - report.oracle_successes[slot],
            "surface {id} ({key}) failures vs oracle (always-success detected here)"
        );
        assert_eq!(
            window.api_attempts[*id as usize], report.oracle_attempts[slot],
            "surface {id} ({key}) trace attempts"
        );
        assert_eq!(
            window.api_results[*id as usize], report.oracle_attempts[slot],
            "surface {id} ({key}) trace results"
        );
    }
    // F1 conservation over the fetch family: every fetch edge files
    // its BASE cold fact (any incidental internal fetch of another
    // surface would show here, never silently).
    let fetch_received = window.received.attempts[trace::TraceFamily::Fetch.index()]
        + window.received.results[trace::TraceFamily::Fetch.index()];
    let total_fetch_facts: u64 = report
        .all_facts
        .iter()
        .filter(|f| {
            matches!(
                f.api,
                po::ObservationApi::Inventoried(
                    osslscope::inventory::Api::EvpMdFetch
                        | osslscope::inventory::Api::EvpCipherFetch
                        | osslscope::inventory::Api::EvpMacFetch
                        | osslscope::inventory::Api::EvpKdfFetch
                        | osslscope::inventory::Api::EvpSignatureFetch
                        | osslscope::inventory::Api::EvpKemFetch
                        | osslscope::inventory::Api::EvpAsymCipherFetch
                        | osslscope::inventory::Api::EvpKeyexchFetch
                        | osslscope::inventory::Api::EvpKeymgmtFetch
                        | osslscope::inventory::Api::EvpRandFetch
                        | osslscope::inventory::Api::EvpSkeymgmtFetch
                        | osslscope::inventory::Api::OsslDecoderFetch
                        | osslscope::inventory::Api::OsslEncoderFetch
                        | osslscope::inventory::Api::OsslStoreLoaderFetch
                )
            )
        })
        .count() as u64;
    assert_eq!(
        total_fetch_facts, fetch_received,
        "every fetch edge files its BASE cold fact"
    );
    assert_eq!(
        report.fetch_facts,
        2 * total,
        "one attempt + one result fact per call"
    );
    // Extension pairs fold class-0 by function.
    assert!(
        window.class_counts[0] >= total,
        "fetch pairs fold class-0: {:?}",
        window.class_counts
    );
    assert_eq!(window.class_counts.iter().sum::<u64>(), window.paired);
    assert!(!window.capped);
    assert_eq!(window.dropped, 0);
    // End-to-end honesty: the collected facts fold into a request
    // section with all eight surfaces at oracle counts — and with
    // no load call observed (silent default auto-load), activation
    // stays Unknown rather than manufactured.
    let evidence = po::request_evidence::RequestEvidence::fold(
        &report.all_facts,
        po::request_evidence::RequestScope {
            operational_entries: Some(report.op_entries),
            fetch_armed: [10, 11, 12, 13, 14, 15, 73, 74, 75, 76, 77, 78, 79, 80]
                .into_iter()
                .collect(),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        },
    );
    assert_eq!(evidence.fetches.len(), 8);
    for (slot, row) in evidence.fetches.iter().enumerate() {
        assert_eq!(
            row.attempts, report.oracle_attempts[slot],
            "fold {}",
            row.export
        );
        assert_eq!(
            row.success, report.oracle_successes[slot],
            "fold {}",
            row.export
        );
        assert_eq!(
            row.failure,
            report.oracle_attempts[slot] - report.oracle_successes[slot],
            "fold {}",
            row.export
        );
    }
    assert_eq!(
        evidence.default_activation,
        po::request_evidence::ActivationState::Unknown
    );
    // Privacy gap in BOTH serialized outputs: no property string or
    // algorithm-name string the fixture passed may appear — only the
    // explicit gap marker.
    let json = serde_json::to_value(&evidence).unwrap();
    let json_text = serde_json::to_string(&json).unwrap();
    let human = evidence.human_section();
    for forbidden in FORBIDDEN_STRINGS {
        assert!(
            !json_text.contains(forbidden),
            "JSON must not capture {forbidden}: {json_text}"
        );
        assert!(
            !human.contains(forbidden),
            "human must not capture {forbidden}:\n{human}"
        );
    }
    assert!(
        json_text.contains("not_captured"),
        "JSON must carry the explicit gap: {json_text}"
    );
    assert!(
        human.contains("not_captured"),
        "human must carry the explicit gap:\n{human}"
    );
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn fetch_surface_off_mode_twin_pairs_nothing_but_observes() {
    // Off-mode twin for the extension surfaces: pairing off
    // (TRACE_MODE_OFF) means zero pairs — while the same stimulus
    // still arrives (received counts) and still files cold facts.
    // This is the control proving the main leg's pairs come from
    // observation under an edge-bearing mode, not from the fixture.
    let Some(object) = gated() else { return };
    let total: u64 = ATTEMPTS.iter().sum();
    let report = run_fetch_round(&object, trace::TRACE_MODE_OFF);
    let window = &report.window;
    assert_eq!(window.paired, 0, "off mode pairs nothing");
    assert_eq!(window.unpaired_entries, 0, "off mode pairs nothing");
    assert_eq!(window.unpaired_results, 0, "off mode pairs nothing");
    assert_eq!(
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        total,
        "off mode still receives every attempt edge"
    );
    assert_eq!(
        window.received.results[trace::TraceFamily::Fetch.index()],
        total,
        "off mode still receives every result edge"
    );
    assert_eq!(report.oracle_attempts, ATTEMPTS, "oracle attempts");
    assert_eq!(report.oracle_successes, SUCCESSES, "oracle successes");
    for (slot, (id, key)) in SURFACES.iter().enumerate() {
        assert_eq!(
            report.attempt_facts[slot], report.oracle_attempts[slot],
            "off-mode surface {id} ({key}) attempts still observed"
        );
        assert_eq!(
            report.result_facts[slot], report.oracle_attempts[slot],
            "off-mode surface {id} ({key}) results still observed"
        );
        assert_eq!(
            report.success_facts[slot], report.oracle_successes[slot],
            "off-mode surface {id} ({key}) successes still observed"
        );
    }
    if window.ring_loss.iter().any(|lane| *lane > 0) {
        panic!("VOID: ring loss in off-mode twin: {:?}", window.ring_loss);
    }
}
