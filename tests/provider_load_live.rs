// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 1 provider-load live cells (fix2 NEW-P5): REAL attach, REAL
//! explicit provider loads (`default` x2, `legacy` x1) plus REAL
//! property-bearing decoder/encoder fetches, through a real capture.
//! Ignored unless `TRACE_LIVE_SMOKE=1` with root plus a fresh object
//! in `OSSL_PROVIDER_OBSERVATION_TEST_BPF` (same guest lane as the
//! fetch leg). A quiet run is VOID, not a pass. A REQUESTED run
//! with missing prerequisites FAILS CLOSED (never a silent skip).
//!
//! Independent oracle: the fixture reports its own per-name load
//! and fetch attempts AND successes (`done default=2,2 ...`);
//! every asserted observer count is checked against that line,
//! never against itself. Per-name totals are DISTINCT (swapped
//! probes change the signature). Sections fold through the
//! PRODUCTION batch scope (the scan path — no hand-made coverage),
//! and operational planes derive from the REAL close batch (real
//! terminal receipts + real activity rows) through the production
//! `operational_plane` mapping. The reducer tests in
//! `request_evidence_phase1.rs` stay as unit evidence.
use osslscope::inventory::{
    self,
    scope::{ScopedScanner, Selection},
};
use osslscope::provider_observation::{self as po, trace};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Fixture round keys (every done line carries all four).
const ORACLE_KEYS: [&str; 4] = ["default", "legacy", "dec", "enc"];
/// Expected oracle per round kind: (attempts, successes) per key.
/// Rounds are split ('L' loads-only, 'F' fetches-only) so each
/// round's query fan-out fits the lane's lossless envelope.
const ORACLE_LOADS: [(u64, u64); 4] = [(2, 2), (1, 1), (0, 0), (0, 0)];
const ORACLE_FETCHES: [(u64, u64); 4] = [(0, 0), (0, 0), (2, 2), (1, 1)];
/// Property/name strings the observer must never capture (privacy pin).
const FORBIDDEN_STRINGS: [&str; 3] = ["input=der", "output=text", "RSA"];

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

fn build_fixture(app: &std::path::Path) {
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/provider_load_loop.c"
            ))
            .args(["-lcrypto"])
            .status()
            .unwrap()
            .success()
    );
    // Stimulus-presence pin: the workload really passes the property
    // strings (a fixture that stopped passing them fails here, so
    // the privacy asserts below cannot pass vacuously).
    let app_bytes = fs::read(app).unwrap();
    let app_text = String::from_utf8_lossy(&app_bytes);
    for stimulus in ["input=der", "output=text", "RSA"] {
        assert!(
            app_text.contains(stimulus),
            "fixture binary must carry the {stimulus} stimulus"
        );
    }
}

/// Spawn the fixture: returns the owned child, its stdout line
/// channel (past the `ready` + `pre` lines), its pid, and the
/// `pre` (pre-load handles) line.
fn spawn_fixture(app: &std::path::Path) -> (Owned, mpsc::Receiver<String>, u32, String) {
    let mut child = Owned(
        Command::new(app)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let mut first = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    first.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n", "fixture must print its ready line");
    let mut pre = String::new();
    first.read_line(&mut pre).unwrap();
    assert!(
        pre.starts_with("pre "),
        "fixture must print its pre-load line: {pre:?}"
    );
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
    (child, rx, pid, pre.trim_end().to_string())
}

/// Parse one `key=value` field off an oracle line (fail closed when
/// the key is absent — a leg never asserts against itself).
fn oracle_field<'a>(line: &'a str, what: &str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    let part = line
        .split_whitespace()
        .find(|part| part.starts_with(&prefix))
        .unwrap_or_else(|| panic!("FAIL-CLOSED: {what} oracle lacks {key}: {line}"));
    &part[prefix.len()..]
}

/// Wait for the fixture's `done ...` oracle line (fail closed past
/// the deadline); `pump` drains the observer while waiting.
fn wait_done(rx: &mpsc::Receiver<String>, mut pump: impl FnMut()) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if Instant::now() >= deadline {
            panic!("VOID: workload did not finish within 120s");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.starts_with("done ") => return line,
            Ok(_) => continue,
            Err(_) => pump(),
        }
    }
}

/// Fail-closed prerequisite gate: unrequested runs skip (`None`); a
/// REQUESTED run (`TRACE_LIVE_SMOKE=1`) with missing root/object
/// panics — a broken guest setup must fail, never skip green.
fn gated() -> Option<Vec<u8>> {
    if std::env::var("TRACE_LIVE_SMOKE").unwrap_or_default() != "1" {
        eprintln!("provider-load live: set TRACE_LIVE_SMOKE=1; skipping");
        return None;
    }
    let id = Command::new("id").arg("-u").output();
    match id {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"0") => {}
        _ => panic!("FAIL-CLOSED: provider-load live requested but not root"),
    }
    let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap_or_else(|| {
        panic!("FAIL-CLOSED: provider-load live requested but OSSL_PROVIDER_OBSERVATION_TEST_BPF is unset")
    });
    let object = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "FAIL-CLOSED: provider-load live requested but object unreadable ({}): {error}",
            path.to_string_lossy()
        )
    });
    Some(object)
}

fn is_load_api(api: osslscope::inventory::Api) -> bool {
    use osslscope::inventory::Api::*;
    matches!(
        api,
        OsslProviderLoad | OsslProviderTryLoad | OsslProviderLoadEx | OsslProviderTryLoadEx
    )
}

/// Per-name-class load tally entry: (class, (attempts, successes, failures)).
fn load_entry(
    loads: &mut Vec<(po::ProviderNameClass, (u64, u64, u64))>,
    name: po::ProviderNameClass,
) -> &mut (u64, u64, u64) {
    if !loads.iter().any(|(class, _)| *class == name) {
        loads.push((name, (0, 0, 0)));
    }
    &mut loads
        .iter_mut()
        .find(|(class, _)| *class == name)
        .unwrap()
        .1
}

fn observed_loads(
    loads: &[(po::ProviderNameClass, (u64, u64, u64))],
    name: po::ProviderNameClass,
) -> (u64, u64, u64) {
    loads
        .iter()
        .find(|(class, _)| *class == name)
        .map(|(_, counts)| *counts)
        .unwrap_or((0, 0, 0))
}

struct RoundReport {
    window: trace::ClosedTraceWindow,
    /// Per-name-class load (attempts, successes, failures).
    loads: Vec<(po::ProviderNameClass, (u64, u64, u64))>,
    /// Decoder/encoder fetch (attempts, successes).
    fetches: BTreeMap<u32, (u64, u64)>,
    load_facts: u64,
    all_facts: Vec<po::ObservationFact>,
    close_batch: po::ObservationBatch,
    fixture_pid: u32,
    oracle: BTreeMap<String, (u64, u64)>,
    /// Pre-load provider handles (`pre` line — NEW-P5 fix3).
    preload_default: String,
    preload_legacy: String,
    /// Round load handles (`provd`/`provl` on loads rounds only —
    /// NEW-P5 fix3; empty/`None` on fetches rounds).
    prov_default: Vec<String>,
    prov_legacy: Option<String>,
    /// Trace-plane operational attempts (ring events, summed over
    /// apis 20..=72) — the INDEPENDENT operational count the
    /// terminal totals cross-check against (NEW-P5 fix3).
    trace_op_attempts: u64,
}

/// One fixture round: build + spawn the fixture, attach, release one
/// `G` round, tally load/fetch facts across EVERY drain batch, keep
/// the REAL close batch (terminal receipts + activity rows), and
/// parse the independent oracle line. Missing prerequisites or
/// counts lines fail closed (panic), never skip.
/// Assert one done line against its expected per-key oracle
/// (fail closed on a missing/mismatched counts line).
fn assert_oracle(done: &str, what: &str, expected: [(u64, u64); 4]) {
    for (slot, key) in ORACLE_KEYS.iter().enumerate() {
        let prefix = format!("{key}=");
        let part = done
            .split_whitespace()
            .find(|part| part.starts_with(&prefix))
            .unwrap_or_else(|| panic!("FAIL-CLOSED: {what} oracle lacks {key}: {done}"));
        assert_eq!(
            &part[prefix.len()..],
            &format!("{},{}", expected[slot].0, expected[slot].1),
            "{what} oracle {key} behaved"
        );
    }
}

fn run_load_round(object: &[u8], round: u8) -> RoundReport {
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-load-smoke-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&scratch.0);
    fs::create_dir(&scratch.0).unwrap();
    let app = scratch.0.join("provider_load_loop");
    build_fixture(&app);
    let (mut child, rx, fixture_pid, pre) = spawn_fixture(&app);
    // NEW-P5 fix3: pre-load handles (fail closed on a malformed
    // line — the legs prove warm refcounts against these).
    let preload_default = oracle_field(&pre, "preload", "default").to_string();
    let preload_legacy = oracle_field(&pre, "preload", "legacy").to_string();
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![fixture_pid],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), object).unwrap();
    session.set_trace_mode(trace::TRACE_MODE_LATENCY).unwrap();
    let setup = session.reconcile(&scanner.snapshot());
    // Same quarantine contract as the fetch leg: exactly one
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
    // Settle: drain the attach backlog BEFORE the round starts,
    // so attach-time bursts never compound the round's fan-out.
    std::thread::sleep(Duration::from_secs(2));
    for _ in 0..3 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    child.0.stdin.as_mut().unwrap().write_all(&[round]).unwrap();
    // Fact-mix histogram (diagnostic, L2diag precedent): every cold
    // fact by (api, payload kind) — shows what each round's fan-out
    // actually emits when a leg goes lossy or quiet.
    let mut fact_mix: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut loads: Vec<(po::ProviderNameClass, (u64, u64, u64))> = Vec::new();
    let mut fetches: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    let mut load_facts = 0u64;
    let mut all_facts = Vec::new();
    let mut tally = |batch: &po::ObservationBatch| {
        if !batch.gaps.is_empty() {
            eprintln!(
                "loadsmoke drain gaps: {:?} refusals={:?} facts={}",
                batch.gaps,
                batch.refusals,
                batch.facts.len()
            );
        }
        for fact in &batch.facts {
            all_facts.push(fact.clone());
            let kind = match &fact.payload {
                po::ObservationPayload::ApiAttempt { .. } => "attempt",
                po::ObservationPayload::ApiResult { .. } => "result",
                po::ObservationPayload::InitResult { .. } => "init",
                po::ObservationPayload::QueryResult { .. } => "query",
                po::ObservationPayload::Algorithm { .. } => "algorithm",
                po::ObservationPayload::Implementation { .. } => "implementation",
                po::ObservationPayload::Invalidation { .. } => "invalidation",
            };
            *fact_mix
                .entry((format!("{:?}", fact.api), kind.to_string()))
                .or_insert(0) += 1;
            let po::ObservationApi::Inventoried(api) = fact.api else {
                continue;
            };
            if is_load_api(api) {
                load_facts += 1;
                match &fact.payload {
                    po::ObservationPayload::ApiAttempt { name } => {
                        load_entry(&mut loads, *name).0 += 1;
                    }
                    po::ObservationPayload::ApiResult { name, outcome } => {
                        let entry = load_entry(&mut loads, *name);
                        match outcome {
                            po::ApiOutcome::Success => entry.1 += 1,
                            po::ApiOutcome::Failure => entry.2 += 1,
                            po::ApiOutcome::Unknown => {}
                        }
                    }
                    _ => {}
                }
            }
            let surface = match api {
                osslscope::inventory::Api::OsslDecoderFetch => Some(78u32),
                osslscope::inventory::Api::OsslEncoderFetch => Some(79u32),
                _ => None,
            };
            if let Some(id) = surface {
                match &fact.payload {
                    po::ObservationPayload::ApiAttempt { .. } => {
                        fetches.entry(id).or_insert((0, 0)).0 += 1;
                    }
                    po::ObservationPayload::ApiResult { outcome, .. } => {
                        if matches!(outcome, po::ApiOutcome::Success) {
                            fetches.entry(id).or_insert((0, 0)).1 += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    };
    let done = wait_done(&rx, || {
        tally(&session.drain(Instant::now() + Duration::from_millis(50)));
    });
    // Independent oracle: per-name attempts,successes. A missing
    // counts line fails closed — the leg never asserts against
    // itself.
    let mut oracle = BTreeMap::new();
    for key in ORACLE_KEYS {
        let prefix = format!("{key}=");
        let part = done
            .split_whitespace()
            .find(|part| part.starts_with(&prefix))
            .unwrap_or_else(|| panic!("FAIL-CLOSED: oracle lacks {key}: {done}"));
        let (attempts, successes) = part[prefix.len()..]
            .split_once(',')
            .unwrap_or_else(|| panic!("FAIL-CLOSED: oracle lacks counts for {key}: {done}"));
        oracle.insert(
            key.to_string(),
            (
                attempts
                    .parse()
                    .unwrap_or_else(|_| panic!("FAIL-CLOSED: oracle attempts unparsable: {done}")),
                successes
                    .parse()
                    .unwrap_or_else(|_| panic!("FAIL-CLOSED: oracle successes unparsable: {done}")),
            ),
        );
    }
    // NEW-P5 fix3: round load handles on loads rounds (fail closed
    // when absent — the identity proof needs them); fetches rounds
    // carry none.
    let (prov_default, prov_legacy) = if round == b'L' {
        let pair = oracle_field(&done, "loads round", "provd");
        let (d1, d2) = pair.split_once(',').unwrap_or_else(|| {
            panic!("FAIL-CLOSED: loads round lacks two default handles: {done}")
        });
        (
            vec![d1.to_string(), d2.to_string()],
            Some(oracle_field(&done, "loads round", "provl").to_string()),
        )
    } else {
        (Vec::new(), None)
    };
    for _ in 0..5 {
        tally(&session.drain(Instant::now() + Duration::from_millis(200)));
    }
    // NEW-P5 fix3 (b): seal BEFORE exit (the fix2 seal-then-exit
    // lesson). The fixture's exit teardown makes
    // libcrypto-internal operational calls (observed live:
    // `EVP_RAND_CTX_free` x2) AFTER the round — oracle-invisible,
    // and structurally trace-invisible too (the post-exit retire
    // drops the target before the teardown backlog binds, so the
    // trace plane can never count it while the cumulative
    // terminal totals do). Sealing first puts both planes over the
    // SAME live interval [attach, seal] — binding intact
    // throughout, teardown outside both — so the terminal totals
    // and the trace attempts cross-check exactly.
    for _ in 0..5 {
        tally(&session.drain(Instant::now() + Duration::from_millis(200)));
    }
    let window = session.close_trace_window(0);
    let close_batch = session.close();
    tally(&close_batch);
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let mut mix: Vec<((String, String), u64)> = fact_mix.into_iter().collect();
    mix.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!(
        "loadsmoke fact mix (top 12): {:?}",
        &mix[..mix.len().min(12)]
    );
    let trace_op_attempts: u64 = window.api_attempts[20..=72].iter().sum();
    let op_rows: Vec<(&str, u64)> = close_batch
        .api_activity
        .iter()
        .filter_map(|a| (a.row.entries > 0).then_some((a.row.api.export_name(), a.row.entries)))
        .collect();
    eprintln!(
        "loadsmoke: round={} paired={} unpaired_e={} unpaired_r={} ring_loss={:?} dropped={} capped={} load_facts={} all_facts={} oracle_default={:?} oracle_legacy={:?} oracle_dec={:?} oracle_enc={:?} loads={:?} fetches={:?} receipts={:?} pre_default={} pre_legacy={} provd={:?} provl={:?} trace_op_attempts={} op_rows={:?}",
        round as char,
        window.paired,
        window.unpaired_entries,
        window.unpaired_results,
        window.ring_loss,
        window.dropped,
        window.capped,
        load_facts,
        all_facts.len(),
        oracle.get("default"),
        oracle.get("legacy"),
        oracle.get("dec"),
        oracle.get("enc"),
        loads,
        fetches,
        close_batch.terminal_scopes_observed,
        preload_default,
        preload_legacy,
        prov_default,
        prov_legacy,
        trace_op_attempts,
        op_rows,
    );
    RoundReport {
        window,
        loads,
        fetches,
        load_facts,
        all_facts,
        close_batch,
        fixture_pid,
        oracle,
        preload_default,
        preload_legacy,
        prov_default,
        prov_legacy,
        trace_op_attempts,
    }
}

fn assert_lossless(window: &trace::ClosedTraceWindow) {
    if window.ring_loss.iter().any(|lane| *lane > 0) {
        panic!(
            "VOID: ring loss in provider-load cell: {:?}",
            window.ring_loss
        );
    }
    assert!(!window.capped);
    assert_eq!(window.dropped, 0);
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn provider_load_live_observes_two_providers() {
    // NEW-P5(a) + NEW-P5 fix3: two providers (default x2, legacy
    // x1) through a REAL capture — two independently counted
    // name-class rows at the candidate tier in BOTH renderers,
    // DISTINCT provider identities verified by loaded handles
    // (legacy ≠ default), warm refcounts proven against the
    // pre-load handles (cold arrival outside the claim), and an
    // INDEPENDENT operational count (terminal BPF-map totals vs
    // the trace plane's ring-event attempts over the same live
    // attach→seal interval must agree, over receipted rows).
    // Loads-only round ('L').
    let Some(object) = gated() else { return };
    for (slot, key) in ORACLE_KEYS.iter().enumerate() {
        let (attempts, successes) = ORACLE_LOADS[slot];
        if *key == "default" || *key == "legacy" {
            assert_ne!(attempts, 0, "oracle {key} must attempt for real");
            assert_ne!(successes, 0, "oracle {key} must succeed for real");
        }
    }
    let report = run_load_round(&object, b'L');
    assert_lossless(&report.window);
    // The oracle itself behaved (fixture made its distinct calls).
    for (slot, key) in ORACLE_KEYS.iter().enumerate() {
        assert_eq!(
            report.oracle.get(*key),
            Some(&ORACLE_LOADS[slot]),
            "oracle {key} behaved"
        );
    }
    // Observer load counts match the oracle exactly, per name
    // class (distinct vectors — swapped probes change it).
    assert_eq!(
        observed_loads(&report.loads, po::ProviderNameClass::Default),
        (2, 2, 0),
        "default loads vs oracle"
    );
    assert_eq!(
        observed_loads(&report.loads, po::ProviderNameClass::Legacy),
        (1, 1, 0),
        "legacy loads vs oracle"
    );
    assert_eq!(
        report.load_facts, 6,
        "one attempt + one result fact per load call"
    );
    // NEW-P5 fix3 (a): DISTINCT provider identities in the
    // workload — the oracle's loaded handles (more than name
    // classes + timestamps): all three round loads returned live
    // providers, and the legacy identity differs from both
    // default identities (two distinct provider objects engaged).
    assert_eq!(
        report.prov_default.len(),
        2,
        "both default handles reported"
    );
    for handle in report.prov_default.iter().chain(report.prov_legacy.iter()) {
        assert_ne!(handle, "(nil)", "every round load returned a live provider");
    }
    let legacy = report.prov_legacy.as_ref().expect("legacy handle reported");
    assert!(
        !report.prov_default.contains(legacy),
        "legacy identity differs from default: {:?} vs {legacy}",
        report.prov_default
    );
    // NEW-P5 fix3 (c): cold module arrival stays OUTSIDE the
    // narrowed claim — both providers pre-loaded before attach
    // (live handles), and the round's loads hit the SAME (warm)
    // providers, so no round load is a cold arrival. The
    // oracle-exact count asserts above complete the exclusion:
    // the observed (2,2)+(1,1) equal the ROUND oracle, so the 2
    // pre-attach loads are NOT in the observation.
    assert_ne!(
        report.preload_default, "(nil)",
        "default pre-loaded before attach"
    );
    assert_ne!(
        report.preload_legacy, "(nil)",
        "legacy pre-loaded before attach"
    );
    for handle in &report.prov_default {
        assert_eq!(
            handle, &report.preload_default,
            "round default loads refcount the pre-loaded provider"
        );
    }
    assert_eq!(
        legacy, &report.preload_legacy,
        "round legacy load refcounts the pre-loaded provider"
    );
    // Two independent provider identities: two distinct load-call
    // groups (name + timestamp), never collapsed.
    let mut load_stamps: Vec<(po::ProviderNameClass, u64)> = report
        .all_facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            po::ObservationPayload::ApiAttempt { name } => {
                if let po::ObservationApi::Inventoried(api) = fact.api {
                    if is_load_api(api) {
                        return Some((*name, fact.monotonic_ns));
                    }
                }
                None
            }
            _ => None,
        })
        .collect();
    load_stamps.sort_by_key(|(_, ts)| *ts);
    load_stamps.dedup();
    assert_eq!(
        load_stamps.len(),
        3,
        "three distinct load calls: {load_stamps:?}"
    );
    assert_eq!(
        load_stamps
            .iter()
            .filter(|(n, _)| *n == po::ProviderNameClass::Default)
            .count(),
        2
    );
    assert_eq!(
        load_stamps
            .iter()
            .filter(|(n, _)| *n == po::ProviderNameClass::Legacy)
            .count(),
        1
    );
    // Production batch scope (the scan path — no hand-made
    // coverage): the real facts fold to two candidate load rows
    // with oracle-exact counts plus real activation.
    let evidence = po::request_evidence::RequestEvidence::fold(
        &report.all_facts,
        po::request_evidence::RequestScope::batch(),
    );
    assert_eq!(evidence.loads.len(), 2, "two name-class rows");
    for row in &evidence.loads {
        assert_eq!(row.tier, po::request_evidence::CandidateTier::Candidate);
        assert_eq!(row.candidates, row.success);
    }
    let row = evidence
        .loads
        .iter()
        .find(|r| r.name == po::ProviderNameClass::Default)
        .expect("default row");
    assert_eq!((row.attempts, row.success), (2, 2));
    let row = evidence
        .loads
        .iter()
        .find(|r| r.name == po::ProviderNameClass::Legacy)
        .expect("legacy row");
    assert_eq!((row.attempts, row.success), (1, 1));
    assert_eq!(
        evidence.default_activation,
        po::request_evidence::ActivationState::LoadObserved,
        "explicit in-window default loads are real activation"
    );
    // NEW-P5 fix3 (b): INDEPENDENT operational count — two real
    // independent planes over the same live interval must agree:
    // the terminal BPF-map totals and the trace plane's
    // ring-event attempts (both cover attach→seal with the
    // target alive throughout; exit teardown stays outside both
    // by seal-before-exit). The oracle pins the EXPLICIT
    // workload (3 loads, all request APIs); the planes
    // cross-check the full live count. Real terminal receipt +
    // real attached rows (GATE fix3: attached =
    // successful-read receipt) behind it.
    let scope_observed = report
        .close_batch
        .terminal_scopes_observed
        .iter()
        .any(|(pid, _)| *pid == report.fixture_pid);
    assert!(
        scope_observed,
        "real terminal receipt for the fixture incarnation: {:?}",
        report.close_batch.terminal_scopes_observed
    );
    assert!(
        !report.close_batch.api_activity.is_empty(),
        "real activity rows flow from the close batch"
    );
    assert!(
        report
            .close_batch
            .api_activity
            .iter()
            .any(|a| !a.row.gaps.not_attached),
        "at least one row carries a successful-read receipt"
    );
    let entries: u64 = report
        .close_batch
        .api_activity
        .iter()
        .map(|a| a.row.entries)
        .sum();
    assert_eq!(
        entries, report.trace_op_attempts,
        "terminal totals agree with the independent trace count"
    );
    let plane = po::request_evidence::RequestEvidence::operational_plane(entries, scope_observed);
    assert_eq!(
        plane,
        Some(entries),
        "receipted rows map to an observed plane at the cross-checked count"
    );
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["loads"][0]["tier"], "candidate");
    assert_eq!(json["default_activation"], "load_observed");
    let human = evidence.human_section();
    assert!(human.contains("tier=candidate"), ":\n{human}");
    assert!(human.contains("observed default-class load"), ":\n{human}");
    assert!(human.contains("load default:"), ":\n{human}");
    assert!(human.contains("load legacy:"), ":\n{human}");
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh object)"]
fn property_bearing_fetch_live_control() {
    // NEW-P5(b): property-bearing fetches (decoder x2 with
    // `input=der`, encoder x1 with `output=text`) through a REAL
    // capture — oracle-exact rows, candidate tier, explicit
    // `not_captured` gap, and no property leakage in BOTH
    // renderers. Fetches-only round ('F'): no loads observed
    // (silent auto-load), so activation stays Unknown.
    let Some(object) = gated() else { return };
    let report = run_load_round(&object, b'F');
    assert_lossless(&report.window);
    for (slot, key) in ORACLE_KEYS.iter().enumerate() {
        assert_eq!(
            report.oracle.get(*key),
            Some(&ORACLE_FETCHES[slot]),
            "oracle {key} behaved"
        );
    }
    assert_eq!(
        report.fetches.get(&78).copied().unwrap_or((0, 0)),
        (2, 2),
        "decoder fetches vs oracle"
    );
    assert_eq!(
        report.fetches.get(&79).copied().unwrap_or((0, 0)),
        (1, 1),
        "encoder fetches vs oracle"
    );
    assert!(
        report.loads.is_empty(),
        "fetches never load providers: {:?}",
        report.loads
    );
    let evidence = po::request_evidence::RequestEvidence::fold(
        &report.all_facts,
        po::request_evidence::RequestScope::batch(),
    );
    assert!(
        evidence.loads.is_empty(),
        "no load rows in a fetches-only round"
    );
    assert_eq!(
        evidence.default_activation,
        po::request_evidence::ActivationState::Unknown,
        "silent auto-load stays Unknown (never manufactured)"
    );
    assert!(
        !evidence.advertisements.is_empty(),
        "query traversals advertise algorithms"
    );
    assert!(
        evidence
            .advertisements
            .iter()
            .all(|r| r.tier == po::request_evidence::CandidateTier::Candidate),
        "every advert row carries the candidate tier"
    );
    for row in &evidence.fetches {
        assert_eq!(
            row.properties,
            po::request_evidence::FetchProperties::NotCaptured,
            "surface {} captures no properties",
            row.surface_id
        );
    }
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
    assert!(
        json_text.contains("candidate"),
        "JSON must carry the candidate tier: {json_text}"
    );
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + fresh objects)"]
fn window_document_carries_request_evidence_without_property_capture() {
    // NEW-P6 (window document): a REAL focused capture over the
    // provider-load workload — the ACTUAL window document (real
    // seal scope: real receipts, real effective coverage, real
    // cuts) through the ACTUAL renderers. Oracle-exact loads and
    // fetches, candidate tier, explicit `not_captured` gap, no
    // property leakage in BOTH outputs, all-14 effective coverage
    // (the NEW-P1-OPEN wiring pin: setup arms + lossless), and a
    // reconciled operational remainder.
    let Some(object) = gated() else { return };
    let count_path = std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap_or_else(|| {
        panic!("FAIL-CLOSED: window leg requested but OSSLSCOPE_FOCUSED_COUNT_OBJECT is unset")
    });
    let count_object = fs::read(&count_path).unwrap_or_else(|error| {
        panic!(
            "FAIL-CLOSED: window leg requested but count object unreadable ({}): {error}",
            count_path.to_string_lossy()
        )
    });
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-window-smoke-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&scratch.0);
    fs::create_dir(&scratch.0).unwrap();
    let app = scratch.0.join("provider_load_loop");
    build_fixture(&app);
    let (mut child, rx, fixture_pid, _pre) = spawn_fixture(&app);
    // The capture blocks the test thread, so a helper thread drives
    // the workload: attach settles (10s — cold attach completes in
    // ~2-5s; the oracle-exact asserts below fail closed if the
    // workload ever outruns the attach), then one loads round and
    // one fetches round 6s apart (split rounds fit the lossless
    // envelope; one combined round floods). `X` goes AFTER the seal
    // (main thread, below): a target that exits pre-seal is
    // retired, and retired attachments are absent from the seal
    // snapshot — the window must seal while its target lives.
    // NEW-P1 fix3: the settle wait is scheduling margin only —
    // it proves nothing about the blind setup prefix. Coverage is
    // earned structurally: the run path establishes the claimed
    // window start at effective admission (first completed
    // attach), so the setup arms precede the claim and the blind
    // prefix stays outside it. The all-14 assert below pins that
    // wiring on the real seal. The 15s settle covers cold-boot
    // attach (BPF verify + cold ELF reads can exceed the usual
    // 2-5s on a first-in-boot run); the oracle-exact asserts fail
    // closed if the workload ever still outruns the attach.
    let mut stdin = child.0.stdin.take().unwrap();
    let driver = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(15));
        stdin.write_all(b"L").unwrap();
        stdin.flush().unwrap();
        std::thread::sleep(Duration::from_secs(6));
        stdin.write_all(b"F").unwrap();
        stdin.flush().unwrap();
        stdin
    });
    let config = osslscope::focused_capture::FocusedConfig {
        duration: Duration::from_secs(35),
        timeout: Duration::from_secs(90),
        grace: Duration::from_secs(5),
        parsed_cache: None,
        trace_mode: osslscope::provider_observation::trace::TRACE_MODE_OFF,
        trace_by_api: false,
        allow_operational_trace: false,
        attach_ready: None,
    };
    let count_sha256: [u8; 32] = Sha256::digest(&count_object).into();
    let objects = osslscope::focused_capture::FocusedObjects {
        observation: Arc::from(object),
        count: Arc::from(count_object),
        count_sha256,
    };
    let result = osslscope::focused_capture::run(
        config,
        osslscope::capture::Target::Pid(fixture_pid),
        objects,
        Instant::now() + Duration::from_secs(60),
    )
    .expect("focused capture runs over the live fixture");
    let mut stdin = driver.join().expect("workload driver finishes");
    // Seal first, exit after (see above): the target must outlive
    // the window for the seal snapshot to see its attachments.
    stdin.write_all(b"X").unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    assert!(child.0.wait().unwrap().success());
    // Oracle: both split rounds behaved (fail closed on a missing
    // counts line — the child already exited, so every line is
    // buffered; `try_iter` never blocks here).
    let dones: Vec<String> = rx
        .try_iter()
        .filter(|line| line.starts_with("done "))
        .collect();
    assert_eq!(dones.len(), 2, "both rounds report: {dones:?}");
    assert_oracle(&dones[0], "window loads round", ORACLE_LOADS);
    assert_oracle(&dones[1], "window fetches round", ORACLE_FETCHES);
    // Lossless, or the coverage claims below are VOID.
    if result.loss_totals.iter().any(|lane| *lane > 0) || result.fence_withheld > 0 {
        panic!(
            "VOID: loss in window leg: totals={:?} withheld={}",
            result.loss_totals, result.fence_withheld
        );
    }
    let doc = &result.document;
    let section = doc
        .request_evidence
        .as_ref()
        .expect("a provider session ran, so the window carries its section");
    assert_eq!(section.loads.len(), 2, "two name-class rows");
    let row = section
        .loads
        .iter()
        .find(|r| r.name == po::ProviderNameClass::Default)
        .expect("default row");
    assert_eq!((row.attempts, row.success), (2, 2), "default vs oracle");
    let row = section
        .loads
        .iter()
        .find(|r| r.name == po::ProviderNameClass::Legacy)
        .expect("legacy row");
    assert_eq!((row.attempts, row.success), (1, 1), "legacy vs oracle");
    for row in &section.loads {
        assert_eq!(row.tier, po::request_evidence::CandidateTier::Candidate);
        assert_eq!(row.candidates, row.success);
    }
    let row = section
        .fetches
        .iter()
        .find(|r| r.surface_id == 78)
        .expect("decoder row");
    assert_eq!((row.attempts, row.success), (2, 2), "decoder vs oracle");
    let row = section
        .fetches
        .iter()
        .find(|r| r.surface_id == 79)
        .expect("encoder row");
    assert_eq!((row.attempts, row.success), (1, 1), "encoder vs oracle");
    assert_eq!(
        section.default_activation,
        po::request_evidence::ActivationState::LoadObserved
    );
    // NEW-P1-OPEN wiring: setup arms + lossless seal = all 14
    // surfaces effectively covered in the real document.
    assert_eq!(section.fetch_coverage.len(), 14);
    assert!(
        section.fetch_coverage.iter().all(|r| r.observed),
        "setup-armed lossless seal covers all 14: {:?}",
        section.fetch_coverage
    );
    // NEW-9 fix4 wiring: the real seal publishes the narrower
    // silence interval (window scope) — bound inside the
    // document's effective window, starting at/after the
    // requested start (effective admission narrows the capture
    // window, never widens it).
    let silence = section
        .silence_window
        .expect("window scope publishes its silence interval");
    assert!(
        silence.start_ns >= doc.window.requested_start_ns,
        "silence starts at/after the capture start: {silence:?} vs window {:?}",
        doc.window
    );
    assert!(
        silence.start_ns < silence.end_ns,
        "silence well-formed: {silence:?}"
    );
    // NEW-26 fix7: the seal samples its end instant AFTER closing
    // the writers, so the claimed silence ends at the writer cut
    // (at or before the effective end — the exact cut bound rides
    // the new26 unit pin with gate access; the leg asserts the
    // bound's document-visible coherence).
    assert!(
        silence.end_ns <= doc.window.effective_end_ns,
        "silence ends at/before the effective end: {silence:?} vs window {:?}",
        doc.window
    );
    // Real remainder reconciliation on real rows.
    let entries: u64 = doc.api_activity.iter().map(|row| row.entries).sum();
    assert_eq!(
        section.unattributed,
        po::request_evidence::Unattributed::Observed { ops: entries },
        "remainder reconciles with the real activity entry sum"
    );
    // ACTUAL renderers over the ACTUAL document.
    let json_bytes = osslscope::report::render_json(doc).expect("window renders JSON");
    let json_text = String::from_utf8(json_bytes).expect("window JSON is UTF-8");
    let human = osslscope::report::render_human(doc);
    for forbidden in FORBIDDEN_STRINGS {
        assert!(
            !json_text.contains(forbidden),
            "window JSON must not capture {forbidden}"
        );
        assert!(
            !human.contains(forbidden),
            "window human must not capture {forbidden}:\n{human}"
        );
    }
    for marker in [
        "not_captured",
        "candidate",
        "request_evidence",
        "silence_window",
    ] {
        assert!(
            json_text.contains(marker),
            "window JSON must carry {marker}"
        );
    }
    for marker in [
        "not_captured",
        "candidate",
        "request evidence",
        "silence window:",
    ] {
        assert!(
            human.contains(marker),
            "window human must carry {marker}:\n{human}"
        );
    }
    eprintln!(
        "windowdoc: loads={} fetches={} coverage_observed={} ops_remainder={entries} activity_rows={} silence_start={} silence_end={}",
        section.loads.len(),
        section.fetches.len(),
        section.fetch_coverage.iter().filter(|r| r.observed).count(),
        doc.api_activity.len(),
        silence.start_ns,
        silence.end_ns,
    );
}

/// Root-trusted staging for the just-built binary + BPF companions
/// (per-binary copy of the six_a helper — keep the gate in sync:
/// ordinary runs NEVER stage unless the guest runner explicitly
/// exports `OSSL_6A_ALLOW_PRIVILEGED_STAGE=1`).
struct StagedBinary {
    dir: std::path::PathBuf,
    binary: std::path::PathBuf,
}
impl Drop for StagedBinary {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf"])
            .arg(&self.dir)
            .status();
    }
}

fn stage_privileged_binary() -> Option<StagedBinary> {
    if std::env::var("OSSL_6A_ALLOW_PRIVILEGED_STAGE").unwrap_or_default() != "1" {
        eprintln!("INCONCLUSIVE: scan-binary leg needs OSSL_6A_ALLOW_PRIVILEGED_STAGE=1");
        return None;
    }
    let built = std::path::PathBuf::from(env!("CARGO_BIN_EXE_osslscope"));
    let release = built.ancestors().nth(2).map(|p| p.join("release")).unwrap();
    let obs = release.join("osslscope-provider-observation");
    let count = release.join("osslscope-focused-count");
    if !obs.is_file() || !count.is_file() {
        eprintln!("INCONCLUSIVE: BPF companions absent under {release:?}");
        return None;
    }
    let dir = std::path::PathBuf::from(format!(
        "/opt/ossl-scan-stage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let script = format!(
        "mkdir -p {} && cp {} {} {} {}/ && chown root:root {}/osslscope {}/osslscope-provider-observation {}/osslscope-focused-count && chmod 755 {}/osslscope && chmod 644 {}/osslscope-provider-observation {}/osslscope-focused-count",
        dir.display(),
        built.display(),
        obs.display(),
        count.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
    );
    let status = Command::new("sudo")
        .args(["-n", "sh", "-c", &script])
        .status()
        .unwrap();
    if !status.success() {
        eprintln!("INCONCLUSIVE: sudo -n staging refused");
        return None;
    }
    let binary = dir.join("osslscope");
    Some(StagedBinary { dir, binary })
}

/// Parse the scan outfile as it stands: (records, sections with
/// loads, sections with fetches). Partial trailing lines never
/// parse, so polling a live outfile is safe.
fn scan_progress(outfile: &std::path::Path) -> (usize, usize, usize) {
    let text = fs::read_to_string(outfile).unwrap_or_default();
    let mut records = 0usize;
    let mut with_loads = 0usize;
    let mut with_fetches = 0usize;
    for line in text.lines() {
        let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        records += 1;
        let Some(section) = row.get("request_evidence") else {
            continue;
        };
        if section
            .get("loads")
            .and_then(|l| l.as_array())
            .is_some_and(|l| !l.is_empty())
        {
            with_loads += 1;
        }
        if section
            .get("fetches")
            .and_then(|f| f.as_array())
            .is_some_and(|f| !f.is_empty())
        {
            with_fetches += 1;
        }
    }
    (records, with_loads, with_fetches)
}

/// Human-outfile progress: the row labels the human block renders
/// for observed loads/fetches.
fn scan_progress_text(outfile: &std::path::Path) -> (bool, bool) {
    let text = fs::read_to_string(outfile).unwrap_or_default();
    (
        text.contains("load default:"),
        text.contains("fetch OSSL_DECODER_fetch"),
    )
}

/// One real `scan` run over the PROVIDERS route (the batch/CLI path
/// whose records carry per-batch `request_evidence` sections plus
/// raw facts — NOT the crypto_watch event stream): drive fixture
/// rounds until the observer's own outfile proves each kind
/// observed (retry-proof — a round that outruns the attach is
/// re-driven, max 3 tries per kind, fail closed past that). Split
/// rounds ('L' then 'F') fit the lossless envelope. Returns the
/// observer's raw stdout bytes (JSONL records or human text) plus
/// the run's done lines.
fn run_scan_binary(
    binary: &std::path::Path,
    fixture_pid: u32,
    child_stdin: &mut std::process::ChildStdin,
    rx: &mpsc::Receiver<String>,
    json: bool,
    outfile: &std::path::Path,
) -> (Vec<u8>, Vec<String>) {
    let mut args = vec![
        "scan".to_string(),
        "--observe-providers".to_string(),
        "--watch".to_string(),
        "--pid".to_string(),
        fixture_pid.to_string(),
        "--duration".to_string(),
        "60".to_string(),
    ];
    if json {
        args.push("--json".to_string());
    } else {
        // NEW-P6 fix3: the human run exercises `-vv` — default
        // verbosity omits scan raw payloads, so only `-vv` proves
        // the raw-payload path (and its privacy) in human form.
        args.push("-vv".to_string());
    }
    let file = fs::File::create(outfile).unwrap();
    let mut observer = Command::new("sudo")
        .arg("-n")
        .arg(binary)
        .args(&args)
        .stdout(Stdio::from(file))
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    // The providers route emits records, not `kind` rows: settle
    // for attach, then let the retry loops synchronize (fail
    // closed past 3 tries per kind).
    std::thread::sleep(Duration::from_secs(7));
    let mut dones = Vec::new();
    for (round, check) in [(b'L', 0), (b'F', 1)] {
        let mut tries = 0;
        loop {
            tries += 1;
            child_stdin.write_all(&[round]).unwrap();
            child_stdin.flush().unwrap();
            dones.push(wait_done(rx, || {}));
            // The observer drains on its own cadence: allow one
            // interval for the round to land in the outfile.
            std::thread::sleep(Duration::from_secs(3));
            let seen = if json {
                let (_, with_loads, with_fetches) = scan_progress(outfile);
                if check == 0 { with_loads } else { with_fetches }
            } else {
                let (has_load, has_fetch) = scan_progress_text(outfile);
                if (check == 0 && has_load) || (check == 1 && has_fetch) {
                    1
                } else {
                    0
                }
            };
            if seen >= 1 {
                break;
            }
            assert!(
                tries < 3,
                "FAIL-CLOSED: scan never observed round {} after 3 tries",
                round as char
            );
        }
    }
    let status = observer.wait().unwrap();
    eprintln!(
        "scanbin run (json={json}): exit={} dones={}",
        status.code().unwrap_or(-1),
        dones.len()
    );
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    (fs::read(outfile).unwrap(), dones)
}

#[test]
#[ignore = "live lane only (TRACE_LIVE_SMOKE=1 + root + staged binary)"]
fn scan_binary_emits_request_evidence_without_property_capture() {
    // NEW-P6 (batch/CLI) + NEW-P6 fix3: the REAL `scan` binary over
    // the provider-load workload — sentinel/`not_captured` asserts
    // against ACTUAL observer outputs: JSONL records (per-batch
    // sections AND raw fact output) plus the human rendering at
    // `-vv` (default verbosity omits raw payloads, so the human
    // leg runs `-vv` and asserts the payload dump AND its privacy).
    let Some(_) = gated() else { return };
    let Some(staged) = stage_privileged_binary() else {
        return;
    };
    let scratch = ScratchDir(
        std::env::temp_dir().join(format!("osslscope-scan-smoke-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&scratch.0);
    fs::create_dir(&scratch.0).unwrap();
    let app = scratch.0.join("provider_load_loop");
    build_fixture(&app);
    let (mut child, rx, fixture_pid, _pre) = spawn_fixture(&app);
    // JSON run: parse every record; sections AND raw facts assert.
    let out_json = scratch.0.join("scan.jsonl");
    let (raw, json_dones) = run_scan_binary(
        &staged.binary,
        fixture_pid,
        child.0.stdin.as_mut().unwrap(),
        &rx,
        true,
        &out_json,
    );
    let text = String::from_utf8_lossy(&raw);
    let rows: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert!(!rows.is_empty(), "scan emitted no JSON records");
    let mut sections = 0u64;
    let mut sections_with_loads = 0u64;
    let mut sections_with_fetches = 0u64;
    let mut load_rows = 0u64;
    let mut fetch_rows = 0u64;
    let mut fact_count = 0u64;
    for row in &rows {
        if let Some(facts) = row.get("facts").and_then(|f| f.as_array()) {
            fact_count += facts.len() as u64;
        }
        let Some(section) = row.get("request_evidence") else {
            continue;
        };
        sections += 1;
        let loads = section
            .get("loads")
            .and_then(|l| l.as_array())
            .cloned()
            .unwrap_or_default();
        if !loads.is_empty() {
            sections_with_loads += 1;
        }
        for load in loads {
            load_rows += 1;
            assert_eq!(
                load.get("tier").and_then(|t| t.as_str()),
                Some("candidate"),
                "scan load rows carry the candidate tier: {load}"
            );
        }
        let fetches = section
            .get("fetches")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default();
        if !fetches.is_empty() {
            sections_with_fetches += 1;
        }
        for fetch in fetches {
            fetch_rows += 1;
            assert_eq!(
                fetch.get("properties").and_then(|p| p.as_str()),
                Some("not_captured"),
                "scan fetch rows capture no properties: {fetch}"
            );
        }
    }
    eprintln!(
        "scanbin: records={} sections={sections} with_loads={sections_with_loads} with_fetches={sections_with_fetches} load_rows={load_rows} fetch_rows={fetch_rows} facts={fact_count}",
        rows.len()
    );
    assert!(
        sections_with_loads >= 1 && sections_with_fetches >= 1,
        "scan emitted no load section or no fetch section (sections={sections} with_loads={sections_with_loads} with_fetches={sections_with_fetches} load_rows={load_rows} fetch_rows={fetch_rows})"
    );
    for forbidden in FORBIDDEN_STRINGS {
        assert!(
            !text.contains(forbidden),
            "scan JSONL (sections + raw facts) must not capture {forbidden}"
        );
    }
    for marker in ["not_captured", "candidate", "request_evidence"] {
        assert!(text.contains(marker), "scan JSONL must carry {marker}");
    }
    // The JSON run's rounds behaved (fail closed; retries may add
    // extra done lines, so assert the SET contains each shape).
    assert!(
        json_dones.len() >= 2,
        "scan JSON run drove both rounds: {json_dones:?}"
    );
    for (shape, name) in [(ORACLE_LOADS, "loads"), (ORACLE_FETCHES, "fetches")] {
        assert!(
            json_dones.iter().any(|done| {
                ORACLE_KEYS.iter().enumerate().all(|(slot, key)| {
                    let prefix = format!("{key}=");
                    done.split_whitespace().any(|part| {
                        part.starts_with(&prefix)
                            && part[prefix.len()..]
                                == format!("{},{}", shape[slot].0, shape[slot].1)
                    })
                })
            }),
            "scan JSON run has a behaved {name} round: {json_dones:?}"
        );
    }
    // Human run over a second round.
    let out_human = scratch.0.join("scan.txt");
    let (raw, human_dones) = run_scan_binary(
        &staged.binary,
        fixture_pid,
        child.0.stdin.as_mut().unwrap(),
        &rx,
        false,
        &out_human,
    );
    let human = String::from_utf8_lossy(&raw);
    for forbidden in FORBIDDEN_STRINGS {
        assert!(
            !human.contains(forbidden),
            "scan human output must not capture {forbidden}"
        );
    }
    for marker in [
        "not_captured",
        "candidate",
        "request evidence",
        "load default:",
        "fetch OSSL_DECODER_fetch",
    ] {
        assert!(
            human.contains(marker),
            "scan human output must carry {marker}"
        );
    }
    // NEW-P6 fix3: the `-vv` run really dumps raw fact payloads
    // (default verbosity would omit them — this assert fails
    // there), and the dump carries no property content (the
    // forbidden-strings asserts above now cover raw payloads too).
    let payloads = human.match_indices("payload=").count() as u64;
    eprintln!("scanbin_vv: payloads={payloads}");
    assert!(
        payloads > 0,
        "scan human -vv output must carry raw fact payloads"
    );
    assert_eq!(
        human_dones.len(),
        2,
        "scan human run drove both rounds once each: {human_dones:?}"
    );
    assert_oracle(&human_dones[0], "scan human loads round", ORACLE_LOADS);
    assert_oracle(&human_dones[1], "scan human fetches round", ORACLE_FETCHES);
    child.0.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
}
