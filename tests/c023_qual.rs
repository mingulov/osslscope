// SPDX-License-Identifier: GPL-3.0-or-later
//! C023/W102 qual cells (T8.2c §6D-10): REAL attach + REAL provider
//! ops in the guest lane only (`C023_QUAL=1` + root + fresh object).
//! Matched UNOBSERVED/AGGREGATE/LATENCY runs over the M = 6 + F = 1
//! workload (re-derived for OpenSSL 3.5.5), conservation + multiset
//! + fetch + lifecycle + unpaired assertions, harness-clock
//! estimators, rate cells at exactly 100k ops/s, and deliberate
//! VOID controls. Quiet runs are VOID, never passes.
use osslscope::inventory::{
    self,
    scope::{ScopedScanner, Selection},
};
use osslscope::provider_observation::{self as po, c023, trace};
use sha2::Digest;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// Latency/wall cells: the frozen N ≥ 1000 minimum at the
// detail-safe pace R = 10/s with 20 s trace windows (10 × 20 × 14
// = 2800 detail rows ≤ 3072 — the §6D-10 pace rule).
const OPS_LAT: u64 = 1000;
const PACE_LAT_NS: u64 = 100_000_000;
/// Mid-run trace-window close interval (keeps every latency/wall
/// window uncapped at N = 1000; rate/flood runs finish inside one
/// window so their single close is automatic).
const CLOSE_EVERY: Duration = Duration::from_secs(20);
const WARMUP: u64 = 50;
const REPS: usize = 5;
// Rate cells: exactly 100k offered ops/s.
const OPS_RATE: u64 = 100_000;
const PACE_RATE_NS: u64 = 10_000;
// Non-verdict legs (golden/fallback): op counts are free (only
// verdict cells need N ≥ 1000); 150 ops stay single-window.
const OPS_SMALL: u64 = 150;

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
    if std::env::var("C023_QUAL").unwrap_or_default() != "1" {
        eprintln!("c023 qual: set C023_QUAL=1; skipping");
        return None;
    }
    let id = Command::new("id").arg("-u").output();
    match id {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"0") => {}
        _ => {
            eprintln!("SKIP c023 qual: need root");
            return None;
        }
    }
    let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")?;
    let object = fs::read(path).ok()?;
    Some(object)
}

fn build_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let app = dir.join("c023_digest_loop");
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/c023_digest_loop.c"
            ))
            .args(["-lcrypto"])
            .status()
            .unwrap()
            .success()
    );
    app
}

struct Harness {
    child: Owned,
    rx: mpsc::Receiver<String>,
}

fn spawn(app: &std::path::Path, ops: u64, pace_ns: u64, timing: &std::path::Path) -> Harness {
    let mut child = Owned(
        Command::new(app)
            .arg(ops.to_string())
            .arg(pace_ns.to_string())
            .arg(WARMUP.to_string())
            .arg(timing)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
    Harness { child, rx }
}

/// Strictly parsed harness timing receipt (P2fix1 item 24:
/// malformed timing numbers are never silently zero — any
/// malformed line, missing key, or self-inconsistency clears
/// `valid` and the cell VOIDs via the evaluator).
struct TimingReceipt {
    per_op_ns: Vec<u64>,
    completed: u64,
    wall_ns: u64,
    max_late_ns: u64,
    origin_ns: u64,
    failed_at: Option<u64>,
    /// Final op's completion timestamp (its t1; P2fix2 item 12 —
    /// the DELTA-10 deadline compares this, never elapsed wall).
    final_completion_ns: u64,
    /// Footer checksum (P2fix3 NEW-6 — cross-checked against the
    /// stdout receipt; `None` until the footer parses).
    checksum: Option<i64>,
    valid: bool,
}

/// Child/receipt agreement (P2fix3 NEW-6): the timing file
/// agrees with the child's exit code AND its stdout `done` line —
/// exit 0 ⟺ no failure marker, exit 6 ⟺ failed_at; the done line
/// (`done completed=N [checksum=C | FAILED_AT=M]`, exact fixture
/// shapes, no duplicate/unknown fields) matches the file's
/// completed/failed_at/checksum. Anything else fails (the harness
/// VOIDs observed runs and fails bare runs on disagreement —
/// the receipt never stands alone).
fn receipt_agrees_with_child(
    receipt: &TimingReceipt,
    exit_code: Option<i32>,
    done_line: &str,
) -> bool {
    match (exit_code, receipt.failed_at) {
        (Some(0), None) => {}
        (Some(6), Some(_)) => {}
        _ => return false,
    }
    let Some(file_checksum) = receipt.checksum else {
        return false;
    };
    let mut words = done_line.split_whitespace();
    if words.next() != Some("done") {
        return false;
    }
    let mut completed: Option<u64> = None;
    let mut checksum: Option<i64> = None;
    let mut failed: Option<u64> = None;
    for w in words {
        let (k, v) = match w.split_once('=') {
            Some(p) => p,
            None => return false,
        };
        // Every PRESENT field parses strictly (P2fix4 NEW-6 — a
        // malformed present token rejects; it never collapses to
        // absence).
        match k {
            "completed" => {
                if completed.is_some() {
                    return false;
                }
                let n: u64 = match v.parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                completed = Some(n);
            }
            "checksum" => {
                if checksum.is_some() {
                    return false;
                }
                let n: i64 = match v.parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                checksum = Some(n);
            }
            "FAILED_AT" => {
                if failed.is_some() {
                    return false;
                }
                let n: u64 = match v.parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                failed = Some(n);
            }
            _ => return false,
        }
    }
    if completed != Some(receipt.completed) {
        return false;
    }
    if failed != receipt.failed_at {
        return false;
    }
    match receipt.failed_at {
        // Clean run: the done checksum matches the file.
        None => checksum == Some(file_checksum),
        // Failed run: the fixture prints no checksum (completed +
        // FAILED_AT carry the agreement).
        Some(_) => checksum.is_none(),
    }
}

fn parse_timings(path: &std::path::Path) -> TimingReceipt {
    let mut out = TimingReceipt {
        per_op_ns: vec![],
        completed: 0,
        wall_ns: 0,
        max_late_ns: 0,
        origin_ns: 0,
        failed_at: None,
        final_completion_ns: 0,
        checksum: None,
        valid: false,
    };
    let body = fs::read_to_string(path).unwrap_or_default();
    let mut saw_completed = false;
    let mut saw_checksum = false;
    let mut saw_failed = false;
    let mut late_max_seen = 0u64;
    let mut prev_t1 = 0u64;
    let mut first_row = true;
    let mut rows: Vec<(u64, u64)> = vec![];
    for line in body.lines() {
        if line.starts_with("completed=") {
            // ONE terminal footer (P2fix3 NEW-6): no duplicates, and
            // it ends the receipt (fixture shape: op lines, then at
            // most one op_failed, then the footer).
            if saw_completed {
                return out;
            }
            saw_completed = true;
            let mut have = [false; 5];
            for part in line.split_whitespace() {
                let (k, v) = part.split_once('=').unwrap_or(("", ""));
                let num: Option<u64> = v.parse().ok();
                // Duplicate fields reject (later copies never
                // overwrite silently).
                let slot = match k {
                    "completed" => 0,
                    "wall_ns" => 1,
                    "max_late_ns" => 2,
                    "origin_ns" => 3,
                    "checksum" => 4,
                    _ => return out,
                };
                if have[slot] {
                    return out;
                }
                match k {
                    "completed" => {
                        out.completed = num.unwrap_or(u64::MAX);
                        have[0] = num.is_some();
                    }
                    "wall_ns" => {
                        out.wall_ns = num.unwrap_or(u64::MAX);
                        have[1] = num.is_some();
                    }
                    "max_late_ns" => {
                        out.max_late_ns = num.unwrap_or(u64::MAX);
                        have[2] = num.is_some();
                    }
                    "origin_ns" => {
                        out.origin_ns = num.unwrap_or(u64::MAX);
                        have[3] = num.is_some();
                    }
                    "checksum" => {
                        have[4] = v.parse::<i64>().is_ok();
                        saw_checksum = have[4];
                        out.checksum = v.parse::<i64>().ok();
                    }
                    _ => return out,
                }
            }
            if have.iter().any(|h| !h) {
                return out;
            }
        } else if line.starts_with("op_failed") {
            // ONE failure marker, before the terminal footer and
            // after all op rows (P2fix3 NEW-6): the COMPLETE
            // grammar is exactly `op_failed <idx> <late>` (P2fix5
            // NEW-31 — both numeric, nothing trailing); the failed
            // op's lateness folds into the observed max (the
            // footer max includes it, so the receipt must bind it
            // — a failed op that sets the maximum never orphans
            // into timings-malformed). Correct indexing (failed_at
            // == completed) checks below against the footer.
            if saw_completed || saw_failed {
                return out;
            }
            saw_failed = true;
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() != 3 || toks[0] != "op_failed" {
                return out;
            }
            let (idx, late): (Option<u64>, Option<u64>) =
                (toks[1].parse().ok(), toks[2].parse().ok());
            match (idx, late) {
                (Some(i), Some(l)) => {
                    out.failed_at = Some(i);
                    late_max_seen = late_max_seen.max(l);
                }
                _ => return out,
            }
        } else {
            // Op rows precede the footer AND the failure marker.
            if saw_completed || saw_failed {
                return out;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 4 {
                return out;
            }
            let (t0, t1, late, seq): (Option<u64>, Option<u64>, Option<u64>, Option<u64>) = (
                parts[0].parse().ok(),
                parts[1].parse().ok(),
                parts[2].parse().ok(),
                parts[3].parse().ok(),
            );
            match (t0, t1, late, seq) {
                (Some(a), Some(b), Some(l), Some(s))
                    if b >= a && s == out.per_op_ns.len() as u64 =>
                {
                    // Exact op order (P2fix2 item 26): the seq must
                    // read 0, 1, 2, ... — duplicates, reorders, and
                    // gaps all break exactness (never silently
                    // re-sorted).
                    // Nonoverlap (P2fix4 NEW-6): the single-thread
                    // fixture runs ops sequentially — each op
                    // starts at/after the prior op's end (this
                    // subsumes per-endpoint monotonicity: b >= a
                    // above plus a >= prev_t1 orders every
                    // endpoint).
                    if !first_row && a < prev_t1 {
                        return out;
                    }
                    first_row = false;
                    prev_t1 = b;
                    rows.push((a, b));
                    out.per_op_ns.push(b - a);
                    late_max_seen = late_max_seen.max(l);
                    // Last op line's t1 is the run's final
                    // completion (order proven above).
                    out.final_completion_ns = b;
                }
                _ => return out,
            }
        }
    }
    if !saw_completed || !saw_checksum {
        return out;
    }
    // Self-consistency: per-op count matches the claim and the
    // claimed max lateness equals the observed per-op max.
    if out.per_op_ns.len() as u64 != out.completed {
        return out;
    }
    if late_max_seen != out.max_late_ns {
        return out;
    }
    // Correctly indexed failure marker (P2fix3 NEW-6): the failing
    // op is the first uncompleted one (fixture shape).
    if let Some(f) = out.failed_at {
        if f != out.completed {
            return out;
        }
    }
    // In-span timeline (P2fix3 NEW-6): every row lies within the
    // measured run (origin..origin+wall).
    let span_end = (out.origin_ns as u128).saturating_add(out.wall_ns as u128);
    for (a, b) in rows {
        if (a as u128) < out.origin_ns as u128 || (b as u128) > span_end {
            return out;
        }
    }
    out.valid = true;
    out
}

/// `/proc/<pid>/stat` starttime (field 22, clock ticks) — the
/// incarnation key the session receipts carry.
fn proc_starttime(pid: u32) -> Option<u64> {
    let body = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = body.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // Fields after `comm` start at field 3 (state): field 22 is
    // index 19 (field 23 would be vsize — a wrong incarnation
    // key fails the scoped-read receipt closed).
    fields.get(19)?.parse().ok()
}

#[test]
fn proc_starttime_matches_front_count() {
    // Cross-check the incarnation-key parser by an independent
    // count (front-indexed full line — our own comm carries no
    // spaces or parens, so field 22 sits at index 21).
    let mine = proc_starttime(std::process::id()).expect("self starttime");
    let body = fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<&str> = body.split_whitespace().collect();
    let front: u64 = fields[21].parse().unwrap();
    assert_eq!(mine, front);
    assert!(mine > 0);
}

struct Observed {
    cell: c023::CellData,
    #[allow(dead_code)]
    window: trace::ClosedTraceWindow,
    #[allow(dead_code)]
    totals: trace::TraceTotals,
    /// Run-level lane sums across all closed windows.
    lanes_sum: [u64; 8],
    /// Windows closed (mid-run + terminal).
    windows_closed: u64,
}

/// One observed run (attach after warmup, measured run, seal).
/// Trace windows close every [`CLOSE_EVERY`] during the run (each
/// latency/wall window stays uncapped at N = 1000) plus a terminal
/// seal; cell inputs SUM across windows (pairs, unpaired,
/// received, per-API vectors, lanes tile exactly — a mid-run close
/// never double-counts a terminal bucket).
fn run_observed(
    object: &[u8],
    dir: &std::path::Path,
    mode: u32,
    ops: u64,
    pace_ns: u64,
    tag: &str,
) -> Observed {
    let timing = dir.join(format!("timing-{tag}.txt"));
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, ops, pace_ns, &timing);
    let pid = child.0.id();
    let starttime = proc_starttime(pid);
    // Warmup OUTSIDE the measured run (provider load confined).
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "), "warmup: {warmed:?}");
    // Attach between warmup and the measured run.
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![pid],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), object).unwrap();
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
    // Drain during the run (rate cells: hot spin, no blocking wait),
    // closing a trace window every CLOSE_EVERY.
    let mut windows: Vec<trace::ClosedTraceWindow> = vec![];
    let mut next_seq = 0u64;
    let mut last_close = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(600);
    let done = loop {
        if Instant::now() >= deadline {
            panic!("VOID: {tag} workload did not finish within 600s");
        }
        if last_close.elapsed() >= CLOSE_EVERY {
            windows.push(session.close_trace_window(next_seq));
            next_seq += 1;
            last_close = Instant::now();
        }
        if pace_ns <= PACE_RATE_NS * 2 {
            match rx.try_recv() {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => {}
                Err(_) => {
                    session.drain(Instant::now() + Duration::from_millis(5));
                }
            }
        } else {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => {
                    session.drain(Instant::now() + Duration::from_millis(100));
                }
            }
        }
    };
    assert!(done.starts_with("done completed="), "done: {done:?}");
    let expect_fail = done.contains("FAILED_AT");
    for _ in 0..5 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    // Seal AFTER the final poll (close_with_trace runs the terminal
    // drain first — live dirty drains only peek) while the child is
    // alive-but-quiet (done received, all pairs drained): terminal
    // reads take live custody (the strongest), and no post-exit
    // retire can disturb the seal.
    let (batch, window, totals) = session.close_with_trace_seq(next_seq);
    windows.push(window);
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    let status = child.0.wait().unwrap();
    // An honest workload failure (exit 6 + FAILED_AT receipt) flows
    // to the evaluator as a shortfall — never a harness panic.
    assert!(
        status.success() || (expect_fail && status.code() == Some(6)),
        "{tag}: workload exit unexpected: {status:?} done={done:?}"
    );
    let last = windows.last().unwrap().clone();
    // Run-level sums across windows (terminal buckets tile exactly).
    let mut paired = 0u64;
    let mut unpaired_entries = 0u64;
    let mut unpaired_results = 0u64;
    let mut capped = false;
    let mut lanes = [0u64; 8];
    let mut rejected = 0u64;
    let mut dropped = 0u64;
    let mut nonmono = 0u64;
    let mut recv_att = [0u64; 3];
    let mut recv_res = [0u64; 3];
    let mut api_attempts = vec![0u64; 81];
    let mut api_results = vec![0u64; 81];
    for w in &windows {
        paired = paired.saturating_add(w.paired);
        unpaired_entries = unpaired_entries.saturating_add(w.unpaired_entries);
        unpaired_results = unpaired_results.saturating_add(w.unpaired_results);
        capped |= w.capped;
        for (i, lane) in w.ring_loss.iter().enumerate() {
            lanes[i] = lanes[i].saturating_add(*lane);
        }
        rejected = rejected.saturating_add(w.rejected_unknown_api);
        dropped = dropped.saturating_add(w.dropped);
        nonmono = nonmono.saturating_add(w.nonmonotonic_pairs);
        for i in 0..3 {
            recv_att[i] = recv_att[i].saturating_add(w.received.attempts[i]);
            recv_res[i] = recv_res[i].saturating_add(w.received.results[i]);
        }
        for (i, v) in w.api_attempts.iter().enumerate() {
            api_attempts[i] = api_attempts[i].saturating_add(*v);
        }
        for (i, v) in w.api_results.iter().enumerate() {
            api_results[i] = api_results[i].saturating_add(*v);
        }
    }
    // M-edge aggregate rows from the close batch (presence + gaps +
    // entries flow to the evaluator; a missing row is an unproven
    // zero — fail closed there, never a synthetic gap here).
    let mut m_edge_gaps = [(0u64, 0u64, 0u64); 6];
    let mut m_edge_entries = [0u64; 6];
    let mut m_rows_found = [false; 6];
    for row in &batch.api_activity {
        let id = u32::from(row.row.api);
        if let Some(i) = c023::M_APIS.iter().position(|m| *m == id) {
            m_edge_gaps[i] = (row.row.gaps.map, row.row.gaps.depth, row.row.gaps.unpaired);
            m_edge_entries[i] = row.row.entries;
            m_rows_found[i] = true;
        }
    }
    let scoped_read_ok = match starttime {
        Some(st) => batch.terminal_scopes_observed.contains(&(pid, st)),
        None => false,
    };
    let receipt = parse_timings(&timing);
    let deadline_ns = (receipt.origin_ns as u128) + (ops as u128) * (pace_ns as u128);
    let completion_deadline_ns = u128::min(deadline_ns, u64::MAX as u128) as u64;
    // Failure-receipt biconditional (P2fix2 item 26): a FAILED_AT
    // claim stands iff the run actually shortfell (a failure claim
    // with full completion, or a shortfall without one, is a
    // malformed receipt — the evaluator VOIDs it, never a
    // shortfall verdict on inconsistent inputs). Child/receipt
    // agreement (P2fix3 NEW-6): the file agrees with the child's
    // exit code AND its stdout receipt.
    let timings_valid = receipt.valid
        && (receipt.failed_at.is_some() == (receipt.completed != ops))
        && receipt_agrees_with_child(&receipt, status.code(), &done);
    // Producer pairing taint (P2fix3 NEW-12): any window's
    // pairing-uncertain signal (or the sticky epoch latch)
    // disqualifies the cell through the evaluator.
    let pairing_tainted = windows.iter().any(|w| w.pairing_uncertain) || totals.pairing_uncertain;
    let cell = c023::CellData {
        app_ops: ops,
        completed: receipt.completed,
        per_op_ns: receipt.per_op_ns,
        wall_ns: receipt.wall_ns,
        max_late_ns: receipt.max_late_ns,
        pace_ns,
        paired,
        unpaired_entries,
        unpaired_results,
        capped,
        ring_loss: lanes,
        rejected_unknown_api: rejected,
        pairing_tainted,
        api_attempts,
        api_results,
        received_attempts: recv_att.iter().sum(),
        received_results: recv_res.iter().sum(),
        m_edge_gaps,
        m_edge_entries,
        m_rows_found,
        scoped_read_ok,
        timings_valid,
        schedule_origin_ns: receipt.origin_ns,
        completion_deadline_ns,
        final_completion_ns: receipt.final_completion_ns,
    };
    let nwin = windows.len() as u64;
    eprintln!(
        "c023[{tag}]: mode={mode} app={ops} done={done:?} windows={nwin} paired={paired} unpaired_e={unpaired_entries} unpaired_r={unpaired_results} lanes={lanes:?} capped={capped} tainted={pairing_tainted} gaps={m_edge_gaps:?} entries={m_edge_entries:?} rows={m_rows_found:?} scoped={scoped_read_ok} key={pid}/{starttime:?} receipts={:?} wall_ns={} max_late_ns={} origin={} deadline={completion_deadline_ns} final={} failed_at={:?} valid={} rejected={rejected} dropped={dropped} nonmono={nonmono} recv_att={recv_att:?} recv_res={recv_res:?} batch_gaps={:?}",
        batch.terminal_scopes_observed,
        receipt.wall_ns,
        receipt.max_late_ns,
        receipt.origin_ns,
        receipt.final_completion_ns,
        receipt.failed_at,
        receipt.valid,
        batch.gaps,
    );
    Observed {
        cell,
        window: last,
        totals,
        lanes_sum: lanes,
        windows_closed: nwin,
    }
}

/// One unobserved run (bare fixture, harness clock only).
fn run_bare(dir: &std::path::Path, ops: u64, pace_ns: u64, tag: &str) -> c023::CellData {
    let timing = dir.join(format!("timing-{tag}.txt"));
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, ops, pace_ns, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "), "warmup: {warmed:?}");
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    let done = loop {
        if Instant::now() >= deadline {
            panic!("VOID: {tag} bare workload did not finish within 300s");
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) if line.starts_with("done ") => break line,
            Ok(_) => continue,
            Err(_) => continue,
        }
    };
    assert!(done.starts_with("done completed="), "done: {done:?}");
    let expect_fail = done.contains("FAILED_AT");
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    let status = child.0.wait().unwrap();
    assert!(
        status.success() || (expect_fail && status.code() == Some(6)),
        "{tag}: bare workload exit unexpected: {status:?} done={done:?}"
    );
    let receipt = parse_timings(&timing);
    // Strict matched timing receipts: an unobserved run with a
    // malformed receipt is a harness failure, never an estimator
    // input (observed runs VOID through the evaluator instead).
    // Same failure biconditional as observed runs (P2fix2 item 26)
    // plus child/receipt agreement (P2fix3 NEW-6).
    assert!(
        receipt.valid
            && (receipt.failed_at.is_some() == (receipt.completed != ops))
            && receipt_agrees_with_child(&receipt, status.code(), &done),
        "{tag}: bare timing receipt malformed"
    );
    eprintln!(
        "c023[{tag}]: bare app={ops} completed={} wall_ns={} origin={}",
        receipt.completed, receipt.wall_ns, receipt.origin_ns
    );
    c023::CellData {
        app_ops: ops,
        completed: receipt.completed,
        per_op_ns: receipt.per_op_ns,
        wall_ns: receipt.wall_ns,
        max_late_ns: receipt.max_late_ns,
        pace_ns,
        ..Default::default()
    }
}

fn scratch(tag: &str) -> ScratchDir {
    let dir = std::env::temp_dir().join(format!("osslscope-c023-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    ScratchDir(dir)
}

#[test]
fn timing_receipt_is_strict_host() {
    // Host-runnable (no BPF, no root): the REAL fixture binary runs
    // the W/G/X protocol and its receipt must parse strictly; every
    // corruption shape below must clear `valid` (malformed numbers
    // are never silently zero).
    let _scratch = scratch("receipt-host");
    let dir = &_scratch.0;
    let timing = dir.join("timing-host.txt");
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, 50, 1_000_000, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.starts_with("done completed="), "done: {done:?}");
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let good = parse_timings(&timing);
    assert!(good.valid, "real receipt must be strict-valid");
    assert_eq!(good.completed, 50);
    assert_eq!(good.per_op_ns.len(), 50);
    assert!(good.origin_ns > 0);
    // The DELTA-10 deadline derives exactly as origin + offered ×
    // pace; the paced run finishes inside twice the offered span
    // (generous host margin — exact end-by-deadline pins live).
    let span = 50u128 * 1_000_000u128;
    assert!((good.wall_ns as u128) <= 2 * span, "wall={}", good.wall_ns);
    // Per-op latencies measure the op (µs-scale), never the 1 ms
    // pace wait.
    assert!(
        good.per_op_ns.iter().all(|l| *l < 1_000_000),
        "per-op must exclude the pace wait: {:?}",
        &good.per_op_ns[..5.min(good.per_op_ns.len())]
    );
    // Corruption shapes: each must clear `valid`.
    let body = fs::read_to_string(&timing).unwrap();
    let corrupt = |f: &dyn Fn(String) -> String| {
        let path = dir.join(format!(
            "timing-corrupt-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, f(body.clone())).unwrap();
        parse_timings(&path)
    };
    // Bad number in an op line (first line's t1 → "xx").
    assert!(
        !corrupt(&|b| {
            let line = b.lines().next().unwrap().to_string();
            let mut p: Vec<&str> = line.split_whitespace().collect();
            p[1] = "xx";
            b.replacen(&line, &p.join(" "), 1)
        })
        .valid,
        "bad op number must invalidate"
    );
    // Bad number in the completed line.
    assert!(
        !corrupt(&|b| b.replace("wall_ns=", "wall_ns=zz")).valid,
        "bad wall number must invalidate"
    );
    // Dropped op line (count mismatch).
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<&str> = b.lines().collect();
            lines.remove(0);
            lines.join("\n") + "\n"
        })
        .valid,
        "count mismatch must invalidate"
    );
    // Missing checksum key.
    assert!(
        !corrupt(&|b| b.replace(" checksum=", " nosuch=")).valid,
        "missing checksum must invalidate"
    );
    // Backward timestamps.
    assert!(
        !corrupt(&|b| {
            let line = b.lines().next().unwrap().to_string();
            let mut p: Vec<&str> = line.split_whitespace().collect();
            p.swap(0, 1);
            b.replacen(&line, &p.join(" "), 1)
        })
        .valid,
        "t1 < t0 must invalidate"
    );
    // Duplicated op line (same seq twice).
    assert!(
        !corrupt(&|b| {
            let first = b.lines().next().unwrap().to_string();
            first.clone() + "\n" + &b
        })
        .valid,
        "duplicated op line must invalidate"
    );
    // Reordered op lines (first two swapped).
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<&str> = b.lines().collect();
            lines.swap(0, 1);
            lines.join("\n") + "\n"
        })
        .valid,
        "reordered op lines must invalidate"
    );
}

#[test]
fn new6_timing_receipt_structure_is_strict_host() {
    // Host-runnable (no BPF, no root): the REAL fixture's receipt
    // must carry ONE terminal footer (nothing after it, no
    // duplicate fields), at most ONE correctly indexed failure
    // marker (failed_at == completed), and a monotonic in-span
    // timeline (non-decreasing t0/t1 within origin..origin+wall).
    // Every structural break below clears `valid`.
    let _scratch = scratch("receipt-struct");
    let dir = &_scratch.0;
    let timing = dir.join("timing-struct.txt");
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, 50, 1_000_000, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.starts_with("done completed="), "done: {done:?}");
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let good = parse_timings(&timing);
    assert!(good.valid, "real receipt must be strict-valid");
    let body = fs::read_to_string(&timing).unwrap();
    let corrupt = |f: &dyn Fn(String) -> String| {
        let path = dir.join(format!(
            "timing-struct-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, f(body.clone())).unwrap();
        parse_timings(&path)
    };
    // Footer MUST be terminal: op rows after it reject.
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<&str> = b.lines().collect();
            let foot = lines.pop().unwrap().to_string();
            format!("{foot}\n{}", lines.join("\n")) + "\n"
        })
        .valid,
        "op rows after the footer must invalidate"
    );
    // Duplicate footer field (completed twice — same value).
    assert!(
        !corrupt(&|b| b.replacen("completed=", "completed=50 completed=", 1)).valid,
        "duplicate footer field must invalidate"
    );
    // Second failure marker (on a success receipt).
    assert!(
        !corrupt(&|b| format!("op_failed 5 0\n{b}")).valid,
        "failure marker on a clean receipt must invalidate"
    );
    // Non-monotonic t0 (seqs stay exact — timestamps swap).
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<String> = b.lines().map(str::to_string).collect();
            let a: Vec<String> = lines[4].split_whitespace().map(str::to_string).collect();
            let c: Vec<String> = lines[5].split_whitespace().map(str::to_string).collect();
            lines[4] = format!("{} {} {} {}", c[0], c[1], a[2], a[3]);
            lines[5] = format!("{} {} {} {}", a[0], a[1], c[2], c[3]);
            lines.join("\n") + "\n"
        })
        .valid,
        "non-monotonic timeline must invalidate"
    );
    // Overlapping ops (P2fix4 NEW-6): the single-thread
    // fixture never overlaps — op 5 starts mid-op-4 while both
    // endpoints still advance (the old per-endpoint check passes
    // this; nonoverlap rejects it).
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<String> = b.lines().map(str::to_string).collect();
            let a: Vec<u64> = lines[4]
                .split_whitespace()
                .map(|x| x.parse().unwrap())
                .collect();
            let c: Vec<String> = lines[5].split_whitespace().map(str::to_string).collect();
            assert!(a[1] > a[0] + 1, "premise: op 4 spans >1ns");
            let mid = a[0] + (a[1] - a[0]) / 2;
            lines[5] = format!("{mid} {} {} {}", c[1], c[2], c[3]);
            lines.join("\n") + "\n"
        })
        .valid,
        "overlapping ops must invalidate"
    );
    // Out-of-span t0 (before the origin).
    assert!(
        !corrupt(&|b| {
            let line = b.lines().next().unwrap().to_string();
            let p: Vec<&str> = line.split_whitespace().collect();
            let t0: u64 = p[0].parse().unwrap();
            let early = t0.saturating_sub(10_000_000);
            let early_line = format!("{early} {} {} {}", p[1], p[2], p[3]);
            b.replacen(&line, &early_line, 1)
        })
        .valid,
        "out-of-span t0 must invalidate"
    );
    // Out-of-span t1 (past origin+wall).
    assert!(
        !corrupt(&|b| {
            let mut lines: Vec<String> = b.lines().map(str::to_string).collect();
            let last_op = lines.len() - 2;
            let p: Vec<&str> = lines[last_op].split_whitespace().collect();
            let t1: u64 = p[1].parse().unwrap();
            lines[last_op] = format!("{} {} {} {}", p[0], t1 + 10_000_000, p[2], p[3]);
            lines.join("\n") + "\n"
        })
        .valid,
        "out-of-span t1 must invalidate"
    );
    // Wrongly indexed failure marker (failed_at != completed).
    let timing_f = dir.join("timing-struct-fail.txt");
    let app_f = build_fixture(dir);
    // SAFETY: serial test; no other thread reads this var.
    unsafe { std::env::set_var("C023_FAIL_AT_OP", "3") };
    let Harness { mut child, rx } = spawn(&app_f, 50, 1_000_000, &timing_f);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.contains("FAILED_AT=3"), "done: {done:?}");
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert_eq!(child.0.wait().unwrap().code(), Some(6));
    unsafe { std::env::remove_var("C023_FAIL_AT_OP") };
    let fail_body = fs::read_to_string(&timing_f).unwrap();
    let fail_corrupt = |f: &dyn Fn(String) -> String| {
        let path = dir.join(format!(
            "timing-struct-f{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, f(fail_body.clone())).unwrap();
        parse_timings(&path)
    };
    // [p2fix5 NEW-31: the marker binds lateness
    // (`op_failed <idx> <late>`) — surgery preserves it.]
    let marker_line = fail_body
        .lines()
        .find(|l| l.starts_with("op_failed"))
        .expect("premise: failure marker present")
        .to_string();
    assert!(
        !fail_corrupt(&|b| {
            let late = marker_line.split_whitespace().nth(2).unwrap();
            b.replace(&marker_line, &format!("op_failed 5 {late}"))
        })
        .valid,
        "wrongly indexed failure marker must invalidate"
    );
    // Doubled failure marker.
    assert!(
        !fail_corrupt(&|b| b.replace(&marker_line, &format!("{marker_line}\n{marker_line}"))).valid,
        "doubled failure marker must invalidate"
    );
}

/// Marker lateness + strict row dominance from an UNEDITED
/// timing file (P2fix6 NEW-31 shared assert): the `op_failed`
/// marker's lateness equals the parsed footer max and strictly
/// exceeds every op row's lateness.
fn assert_failed_op_supplies_max(timing: &std::path::Path, receipt: &TimingReceipt, failed: u64) {
    let body = fs::read_to_string(timing).unwrap();
    let marker = body
        .lines()
        .find(|l| l.starts_with("op_failed"))
        .expect("premise: failure marker present")
        .to_string();
    let toks: Vec<&str> = marker.split_whitespace().collect();
    assert_eq!(toks.len(), 3, "marker binds lateness: {marker:?}");
    assert_eq!(toks[1], failed.to_string(), "marker indexes the failed op");
    let marker_late: u64 = toks[2].parse().expect("marker late parses");
    assert_eq!(
        marker_late, receipt.max_late_ns,
        "the failed op supplies the footer maximum (unedited)"
    );
    let mut row_max = 0u64;
    let mut rows = 0u64;
    for line in body.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() == 4 && toks[0].parse::<u64>().is_ok() {
            let late: u64 = toks[2].parse().expect("row late parses");
            row_max = row_max.max(late);
            rows += 1;
        }
    }
    assert!(rows > 0, "premise: op rows present");
    assert!(
        marker_late > row_max,
        "the failed op strictly dominates every row (marker {marker_late} vs row max {row_max})"
    );
}

#[test]
fn new31_failed_op_supplies_max_unedited() {
    // P2fix6 NEW-31 host pin (the real-execution shape): op 48
    // busy-spins 50 ms so the FAILED op 49 starts ~50 ms late —
    // the UNEDITED receipt's marker lateness strictly dominates
    // every row and equals the footer max (no rewrite — the
    // fix5 rewritten-receipt maximum is insufficient). The guest
    // twin (`new31_failed_op_supplies_max_reaches_shortfall`)
    // carries the same shape through the evaluator to
    // schedule-shortfall.
    let _scratch = scratch("receipt-failed-max");
    let dir = &_scratch.0;
    let timing = dir.join("timing-failed-max.txt");
    let app = build_fixture(dir);
    let _busy = BusyOp::arm(48, 50_000_000);
    let _fail = FailAtOp::arm(49);
    let Harness { mut child, rx } = spawn(&app, 50, 1_000_000, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.contains("FAILED_AT=49"), "done: {done:?}");
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert_eq!(child.0.wait().unwrap().code(), Some(6));
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "paced failure receipt must be strict-valid");
    assert_eq!(receipt.failed_at, Some(49));
    assert_eq!(receipt.completed, 49);
    assert_failed_op_supplies_max(&timing, &receipt, 49);
}

#[test]
fn new31_failed_op_lateness_bound_in_receipt() {
    // P2fix5 NEW-31: the failure marker binds the failed op's
    // lateness (`op_failed <idx> <late>`) — the footer's max
    // reconciles INCLUDING the failed op, so a paced failure
    // whose failed op sets the maximum stays strict-valid (the
    // footer max never orphans a real exit-6 into
    // timings-malformed) and reaches shortfall evaluation. The
    // complete marker grammar (exactly 3 numeric tokens) rejects
    // lateness-less, garbage-trailing, and non-numeric markers.
    let _scratch = scratch("receipt-failed-late");
    let dir = &_scratch.0;
    let timing = dir.join("timing-failed-late.txt");
    let app = build_fixture(dir);
    // Paced failure at the FINAL op (49 of 50, 1ms pace).
    // SAFETY: serial test; no other thread reads this var.
    unsafe { std::env::set_var("C023_FAIL_AT_OP", "49") };
    let Harness { mut child, rx } = spawn(&app, 50, 1_000_000, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.contains("FAILED_AT=49"), "done: {done:?}");
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert_eq!(child.0.wait().unwrap().code(), Some(6));
    unsafe { std::env::remove_var("C023_FAIL_AT_OP") };
    let body = fs::read_to_string(&timing).unwrap();
    // The real marker binds lateness (premise = feature).
    let marker = body
        .lines()
        .find(|l| l.starts_with("op_failed"))
        .expect("premise: failure marker present")
        .to_string();
    let toks: Vec<&str> = marker.split_whitespace().collect();
    assert_eq!(toks.len(), 3, "marker binds lateness: {marker:?}");
    assert_eq!(toks[0], "op_failed");
    toks[2].parse::<u64>().expect("marker late parses");
    assert_eq!(toks[1], "49");
    // The real paced failure receipt is strict-valid (no
    // timings-malformed orphan) with the failure indexed.
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "paced failure receipt must be strict-valid");
    assert_eq!(receipt.failed_at, Some(49));
    assert_eq!(receipt.completed, 49);
    // The marker lateness ALONE can set the footer max: zero
    // every ROW late, pin the marker late + footer max to a
    // distinctive value — valid iff the marker binds into the
    // max (its sole contributor here).
    let rewrite = |f: &dyn Fn(String) -> String| {
        let path = dir.join(format!(
            "timing-failed-late-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, f(body.clone())).unwrap();
        parse_timings(&path)
    };
    let zero_rows_pin_marker = |late: u64, max: u64| {
        move |b: String| {
            let mut lines: Vec<String> = b.lines().map(str::to_string).collect();
            for line in lines.iter_mut() {
                if line.starts_with("op_failed") {
                    *line = format!("op_failed 49 {late}");
                } else if line.starts_with("completed=") {
                    let parts: Vec<String> = line
                        .split_whitespace()
                        .map(|p| {
                            if p.starts_with("max_late_ns=") {
                                format!("max_late_ns={max}")
                            } else {
                                p.to_string()
                            }
                        })
                        .collect();
                    *line = parts.join(" ");
                } else {
                    let p: Vec<&str> = line.split_whitespace().collect();
                    *line = format!("{} {} 0 {}", p[0], p[1], p[3]);
                }
            }
            lines.join("\n") + "\n"
        }
    };
    assert!(
        rewrite(&zero_rows_pin_marker(424242, 424242)).valid,
        "marker lateness must bind into the footer max"
    );
    // ... and an unbound max still orphans honestly (marker 424242
    // against a foreign max).
    assert!(
        !rewrite(&zero_rows_pin_marker(424242, 424243)).valid,
        "foreign footer max must invalidate"
    );
    // Complete grammar: lateness-less, trailing-garbage, and
    // non-numeric markers all reject.
    assert!(
        !rewrite(&|b: String| {
            b.lines()
                .map(|l| {
                    if l.starts_with("op_failed") {
                        "op_failed 49".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        })
        .valid,
        "lateness-less marker must invalidate"
    );
    assert!(
        !rewrite(&|b: String| {
            b.lines()
                .map(|l| {
                    if l.starts_with("op_failed") {
                        format!("{l} trailing")
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        })
        .valid,
        "trailing-garbage marker must invalidate"
    );
    assert!(
        !rewrite(&|b: String| {
            b.lines()
                .map(|l| {
                    if l.starts_with("op_failed") {
                        "op_failed 49 bogus".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        })
        .valid,
        "non-numeric marker lateness must invalidate"
    );
}

#[test]
fn new6_child_receipt_agreement() {
    // P2fix3 NEW-6: the timing receipt agrees with the child's
    // exit code AND its stdout receipt — exit 0 ⟺ no failure,
    // exit 6 ⟺ failed_at; done-line completed/FAILED_AT/checksum
    // match the file. Any disagreement fails the agreement (the
    // harness VOIDs observed runs / fails bare runs on it).
    let file = |completed: u64, failed_at: Option<u64>, checksum: i64| TimingReceipt {
        per_op_ns: vec![],
        completed,
        wall_ns: 0,
        max_late_ns: 0,
        origin_ns: 0,
        failed_at,
        final_completion_ns: 0,
        checksum: Some(checksum),
        valid: true,
    };
    // Clean run: exit 0, matching done line.
    assert!(receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "done completed=50 checksum=99"
    ));
    // Failed run: exit 6, matching FAILED_AT.
    assert!(receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(6),
        "done completed=3 FAILED_AT=3"
    ));
    // Exit/receipt disagreement.
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(6),
        "done completed=50 checksum=99"
    ));
    assert!(!receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(0),
        "done completed=3 FAILED_AT=3"
    ));
    // Stdout/file disagreement (each field).
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "done completed=49 checksum=99"
    ));
    assert!(!receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(6),
        "done completed=3 FAILED_AT=4"
    ));
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "done completed=50 checksum=98"
    ));
    assert!(!receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(6),
        "done completed=3"
    ));
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "garbage line"
    ));
    // Malformed PRESENT fields never collapse to absence (P2fix4
    // NEW-6): a malformed FAILED_AT on a clean run must not read
    // as "no failure", and a malformed checksum on a failed run
    // must not read as "no checksum".
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "done completed=50 checksum=99 FAILED_AT=xyz"
    ));
    assert!(!receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(6),
        "done completed=3 FAILED_AT=3 checksum=xyz"
    ));
    assert!(!receipt_agrees_with_child(
        &file(50, None, 99),
        Some(0),
        "done completed=xyz checksum=99"
    ));
    assert!(!receipt_agrees_with_child(
        &file(3, Some(3), 7),
        Some(6),
        "done completed=3 FAILED_AT=xyz"
    ));
}

#[test]
fn failure_receipt_is_strict_host() {
    // Host-runnable (no BPF, no root): the REAL fixture binary fails
    // op 3 post-emit through the genuine exit-6 + FAILED_AT path —
    // the receipt must parse strict-valid with failed_at == Some(3)
    // and completed == 3; the failed child waits for X (no harness
    // panic on the stdin write) and exits 6.
    let _scratch = scratch("fail-host");
    let dir = &_scratch.0;
    let timing = dir.join("timing-fail.txt");
    let app = build_fixture(dir);
    // SAFETY: serial test; no other thread reads this var.
    unsafe { std::env::set_var("C023_FAIL_AT_OP", "3") };
    let Harness { mut child, rx } = spawn(&app, 50, 1_000_000, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(done.contains("FAILED_AT=3"), "done: {done:?}");
    // Tolerant X write (P2fix2 item 26): a failed (possibly exited)
    // child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    let status = child.0.wait().unwrap();
    unsafe { std::env::remove_var("C023_FAIL_AT_OP") };
    assert_eq!(status.code(), Some(6), "actual child failure exits 6");
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "failure receipt must be strict-valid");
    assert_eq!(receipt.completed, 3);
    assert_eq!(receipt.failed_at, Some(3));
    assert_eq!(receipt.per_op_ns.len(), 3);
    assert!(receipt.final_completion_ns > receipt.origin_ns);
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_latency_wall_verdict_cells() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("latwall");
    let dir = &_scratch.0;
    let mut diffs2: Vec<i128> = vec![];
    let mut walls: Vec<(u64, u64)> = vec![];
    for rep in 0..REPS {
        let bare = run_bare(dir, OPS_LAT, PACE_LAT_NS, &format!("r{rep}-unobs"));
        assert_eq!(bare.completed, OPS_LAT, "rep {rep} unobserved shortfall");
        let agg = run_observed(
            &object,
            dir,
            trace::TRACE_MODE_OFF,
            OPS_LAT,
            PACE_LAT_NS,
            &format!("r{rep}-agg"),
        );
        let lat = run_observed(
            &object,
            dir,
            trace::TRACE_MODE_LATENCY,
            OPS_LAT,
            PACE_LAT_NS,
            &format!("r{rep}-lat"),
        );
        // Cell validity (VOID publishes numbers, never passes).
        // The LATENCY run is the verdict run (full observer-side
        // validity); the AGGREGATE run is a harness-timings
        // diagnostic (trace=off pairs nothing by design — asserted
        // as the off-mode twin, not VOIDed).
        assert_eq!(agg.cell.paired, 0, "rep {rep} agg must pair nothing");
        assert_eq!(
            agg.cell.completed, OPS_LAT,
            "rep {rep} agg harness shortfall"
        );
        assert_eq!(
            agg.cell.per_op_ns.len() as u64,
            agg.cell.completed,
            "rep {rep} agg timings incomplete"
        );
        // Taint wiring (P2fix3 NEW-12 — independent control):
        // the cell's taint bit equals the live producer signal.
        assert_eq!(
            lat.cell.pairing_tainted, lat.totals.pairing_uncertain,
            "rep {rep} lat taint wiring"
        );
        assert_eq!(
            agg.cell.pairing_tainted, agg.totals.pairing_uncertain,
            "rep {rep} agg taint wiring"
        );
        match c023::evaluate_cell(&lat.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall) {
            c023::Verdict::Valid => {}
            other => panic!("VOID: rep {rep} lat cell: {other:?}"),
        }
        // The N = 1000 run spans several 20 s windows (no window
        // may cap); the AGG twin closes the same way.
        assert!(
            lat.windows_closed > 1,
            "rep {rep} lat run must span windows"
        );
        assert!(
            agg.windows_closed > 1,
            "rep {rep} agg run must span windows"
        );
        // Exact verdict inputs (compared before any division) plus
        // the diagnostic display values (documented rounding, no
        // verdict force).
        let d2 = c023::added_diff2_ns(&lat.cell.per_op_ns, &bare.per_op_ns);
        let a = c023::added_per_callback_ns(&lat.cell.per_op_ns, &bare.per_op_ns);
        let r = c023::wall_ratio(lat.cell.wall_ns, bare.wall_ns);
        // Cost-decomposition diagnostic (no verdict force).
        let inc = c023::median_ns(lat.cell.per_op_ns.clone()) as i64
            - c023::median_ns(agg.cell.per_op_ns.clone()) as i64;
        eprintln!(
            "c023[rep{rep}]: added_diff2={d2} added_ns_per_cb={a} wall_c={} wall_a={} wall_ratio={r:.3} latency_increment_ns={inc}",
            lat.cell.wall_ns, bare.wall_ns
        );
        diffs2.push(d2);
        walls.push((lat.cell.wall_ns, bare.wall_ns));
    }
    eprintln!("c023: diffs2={diffs2:?} walls={walls:?}");
    // Characterization outcome (P2fix1 item 2a): valid cells with
    // published estimators, gate OPEN on added latency. If this
    // pin ever flips (gate closes), that is a re-qualification
    // event — update by reviewed amendment, never silently.
    assert!(
        !c023::latency_wall_verdict_exact(&diffs2, &walls),
        "C023 latency/wall gate CLOSED — re-qualify by reviewed amendment: diffs2={diffs2:?} walls={walls:?}"
    );
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_rate_verdict_cells() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("rate");
    let dir = &_scratch.0;
    let mut verdicts = vec![];
    for rep in 0..REPS {
        let lat = run_observed(
            &object,
            dir,
            trace::TRACE_MODE_LATENCY,
            OPS_RATE,
            PACE_RATE_NS,
            &format!("rate{rep}"),
        );
        // Taint wiring (P2fix3 NEW-12 — independent control).
        assert_eq!(
            lat.cell.pairing_tainted, lat.totals.pairing_uncertain,
            "rep {rep} rate taint wiring"
        );
        let verdict = c023::evaluate_cell(&lat.cell, &c023::QUAL_3_5, c023::CellKind::Rate);
        eprintln!(
            "c023[rate{rep}]: {verdict:?} completed={} capped={} paired={} tainted={} windows={}",
            lat.cell.completed,
            lat.cell.capped,
            lat.cell.paired,
            lat.cell.pairing_tainted,
            lat.windows_closed
        );
        assert_eq!(
            lat.windows_closed, 1,
            "rep {rep} rate run finishes inside one window"
        );
        verdicts.push(verdict);
    }
    // Honest outcome (P2fix1 item 2a): the 100k/s offered load
    // overruns the trace ring by capacity arithmetic (~1.4M
    // records vs ~9.3k slots, plus FactLimit drain pressure), so
    // every cell VOIDs on ring-loss EXACTLY (no other arm fires
    // first — conservation still balances, aggregates stay
    // lossless). A non-ring outcome here is a real signal:
    // investigate, never loosen.
    assert_eq!(
        verdicts,
        vec![
            c023::Verdict::Void {
                reason: "ring-loss"
            };
            REPS
        ],
        "C023 rate cells must VOID on ring-loss exactly"
    );
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_rate_characterization_sweep() {
    // NON-VERDICT characterization (numbers disclosed, never
    // verdicts): paced runs at increasing offered rates with
    // FactLimit-clean op counts (6000 ops × 2 fetch facts = 12000
    // < 16384), locating the sustained-conservation ceiling with
    // default limits. Only the frozen 100k recipe yields verdicts.
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("sweep");
    let dir = &_scratch.0;
    for (rate, pace_ns) in [
        (2_000u64, 500_000u64),
        (5_000, 200_000),
        (10_000, 100_000),
        (20_000, 50_000),
        (40_000, 25_000),
        (80_000, 12_500),
    ] {
        let run = run_observed(
            &object,
            dir,
            trace::TRACE_MODE_LATENCY,
            6_000,
            pace_ns,
            &format!("sweep{rate}"),
        );
        let verdict = c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::Rate);
        eprintln!(
            "c023[sweep {rate}/s]: {verdict:?} completed={} max_late={} paired={} unpaired={}/{} lanes={:?} capped={}",
            run.cell.completed,
            run.cell.max_late_ns,
            run.cell.paired,
            run.cell.unpaired_entries,
            run.cell.unpaired_results,
            run.lanes_sum,
            run.cell.capped,
        );
    }
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_scoped_receipt_smoke() {
    // Fast receipt smoke (one small observed run): a clean run
    // earns its terminal scoped-read receipt (close-while-live
    // custody), finishes in one window, and VOIDs quiet (paired
    // floor before the op floor — pinned order).
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("receipt-smoke");
    let run = run_observed(
        &object,
        &_scratch.0,
        trace::TRACE_MODE_LATENCY,
        50,
        10_000_000,
        "smoke",
    );
    assert_eq!(run.windows_closed, 1);
    assert!(run.cell.scoped_read_ok, "clean run earns its receipt");
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void { reason: "quiet" }
    );
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_void_control_quiet() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("void-quiet");
    // 10 ops × 7 = 70 paired < 1000 ⇒ VOID quiet.
    let run = run_observed(
        &object,
        &_scratch.0,
        trace::TRACE_MODE_LATENCY,
        10,
        0,
        "quiet",
    );
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void { reason: "quiet" }
    );
    eprintln!("c023[void-quiet]: observed VOID as required");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_void_control_multiset_deviation() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("void-multiset");
    let run = run_observed(
        &object,
        &_scratch.0,
        trace::TRACE_MODE_LATENCY,
        OPS_LAT,
        PACE_LAT_NS,
        "multiset",
    );
    // Deliberately wrong expectation: the taken-path assumption
    // "broke" ⇒ the fail-safe must VOID, never pass.
    let mut wrong = run.cell.clone();
    wrong.app_ops = OPS_LAT + 1;
    assert_eq!(
        c023::evaluate_cell(&wrong, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void {
            reason: "multiset-deviation"
        }
    );
    eprintln!("c023[void-multiset]: observed VOID as required");
    // Deliberate evaluator-arm controls (P2fix1 item 24): one live
    // valid-shaped cell, one perturbation per arm — each proves the
    // arm fires on real observed data with the perturbation as the
    // sole cause (arm mapping is also pinned host-side in
    // `c023::tests::each_void_condition_fires`).
    let arms: Vec<(&str, Box<dyn Fn(&mut c023::CellData)>)> = vec![
        ("aggregate-gap", Box::new(|c| c.m_edge_gaps[2] = (0, 1, 0))),
        ("aggregate-bridge", Box::new(|c| c.m_edge_entries[0] -= 1)),
        ("result-deviation", Box::new(|c| c.api_results[22] -= 1)),
        (
            "conservation-attempt",
            Box::new(|c| c.received_attempts -= 1),
        ),
        ("conservation-result", Box::new(|c| c.received_results += 1)),
        ("timings-malformed", Box::new(|c| c.timings_valid = false)),
        ("scoped-read", Box::new(|c| c.scoped_read_ok = false)),
        ("fetch-deviation", Box::new(|c| c.api_attempts[77] = 1)),
    ];
    for (reason, perturb) in arms {
        // The unperturbed cell must be valid-shaped (else the
        // perturbation is not the sole cause).
        assert_eq!(
            c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
            c023::Verdict::Valid,
            "control base must be valid-shaped"
        );
        let mut cell = run.cell.clone();
        perturb(&mut cell);
        assert_eq!(
            c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
            c023::Verdict::Void { reason },
            "evaluator arm {reason}"
        );
        eprintln!("c023[evaluator-control]: arm {reason} fires on live data");
    }
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_void_control_unpaired_finalize() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("void-unpaired");
    let dir = &_scratch.0;
    // Unpaced flood + STOP/CONT sampling: freeze an in-flight op so
    // its ATTEMPT lands finalized-unpaired (retry ≤10; unpaced duty
    // ≈ 100% makes all-miss vanishingly unlikely). The frozen cell
    // flows through the verdict evaluator (not a printed VOID).
    /// Frozen probe-run artifacts (window + batch + timing path +
    /// identity + child transcript for agreement).
    type SavedAttempt = (
        trace::ClosedTraceWindow,
        po::ObservationBatch,
        std::path::PathBuf,
        u32,
        Option<u64>,
        String,
        Option<i32>,
    );
    let mut saved: Option<SavedAttempt> = None;
    for attempt in 0..10 {
        let timing = dir.join(format!("timing-stop{attempt}.txt"));
        let app = build_fixture(dir);
        let Harness { mut child, rx } = spawn(&app, 50_000, 0, &timing);
        let pid = child.0.id();
        let starttime = proc_starttime(pid);
        child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
        let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(warmed.starts_with("warmed "));
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: vec![pid],
                ..Default::default()
            },
            inventory::Limits::default(),
        )
        .unwrap();
        let mut session =
            po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
        session.set_trace_mode(trace::TRACE_MODE_LATENCY).unwrap();
        let _ = session.reconcile(&scanner.snapshot());
        child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
        // Let the flood start (~30k unpaced ops, no drain — the ring
        // overruns by capacity arithmetic), then freeze mid-flight.
        std::thread::sleep(Duration::from_millis(30));
        unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
        std::thread::sleep(Duration::from_millis(200));
        for _ in 0..10 {
            session.drain(Instant::now() + Duration::from_millis(50));
        }
        session.trace_finalize();
        let window = session.close_trace_window(0);
        unsafe { libc::kill(pid as i32, libc::SIGCONT) };
        // Finish the run cleanly (no strays).
        let deadline = Instant::now() + Duration::from_secs(120);
        let done = loop {
            if Instant::now() >= deadline {
                break String::new();
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => {
                    session.drain(Instant::now() + Duration::from_millis(50));
                }
            }
        };
        // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
        let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
        drop(child.0.stdin.take());
        let status = child.0.wait().unwrap();
        let batch = session.close();
        eprintln!(
            "c023[void-unpaired attempt{attempt}]: unpaired_e={} unpaired_r={} lanes={:?} capped={} paired={}",
            window.unpaired_entries,
            window.unpaired_results,
            window.ring_loss,
            window.capped,
            window.paired,
        );
        if window.unpaired_entries > 0 || window.unpaired_results > 0 {
            saved = Some((window, batch, timing, pid, starttime, done, status.code()));
            break;
        }
    }
    let (window, batch, timing, pid, starttime, done, exit_code) =
        saved.expect("VOID control failed to trigger unpaired-positive in 10 attempts");
    // The flood overruns the ring by construction (no pre-freeze
    // drain): lanes are positive, so the rate-kind verdict is
    // exactly ring-loss; latency/wall VOIDs on whichever arm fires
    // first (capped or ring-loss — both honest, logged).
    assert!(
        window.ring_loss.iter().any(|lane| *lane > 0),
        "flood must trip a lane"
    );
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "freeze-run receipt must be strict-valid");
    // Child/receipt agreement (P2fix3 NEW-6).
    let flood_timings_valid =
        receipt.valid && receipt_agrees_with_child(&receipt, exit_code, &done);
    let mut api_attempts = vec![0u64; 81];
    let mut api_results = vec![0u64; 81];
    for (i, v) in window.api_attempts.iter().enumerate() {
        api_attempts[i] = *v;
    }
    for (i, v) in window.api_results.iter().enumerate() {
        api_results[i] = *v;
    }
    let mut m_edge_gaps = [(0u64, 0u64, 0u64); 6];
    let mut m_edge_entries = [0u64; 6];
    let mut m_rows_found = [false; 6];
    for row in &batch.api_activity {
        let id = u32::from(row.row.api);
        if let Some(i) = c023::M_APIS.iter().position(|m| *m == id) {
            m_edge_gaps[i] = (row.row.gaps.map, row.row.gaps.depth, row.row.gaps.unpaired);
            m_edge_entries[i] = row.row.entries;
            m_rows_found[i] = true;
        }
    }
    let cell = c023::CellData {
        app_ops: 50_000,
        completed: receipt.completed,
        per_op_ns: receipt.per_op_ns,
        wall_ns: receipt.wall_ns,
        max_late_ns: receipt.max_late_ns,
        pace_ns: 0,
        paired: window.paired,
        unpaired_entries: window.unpaired_entries,
        unpaired_results: window.unpaired_results,
        capped: window.capped,
        ring_loss: window.ring_loss,
        rejected_unknown_api: window.rejected_unknown_api,
        pairing_tainted: window.pairing_uncertain,
        api_attempts,
        api_results,
        received_attempts: window.received.attempts.iter().sum(),
        received_results: window.received.results.iter().sum(),
        m_edge_gaps,
        m_edge_entries,
        m_rows_found,
        scoped_read_ok: match starttime {
            Some(st) => batch.terminal_scopes_observed.contains(&(pid, st)),
            None => false,
        },
        timings_valid: flood_timings_valid,
        schedule_origin_ns: receipt.origin_ns,
        completion_deadline_ns: receipt.origin_ns,
        final_completion_ns: receipt.final_completion_ns,
    };
    assert_eq!(
        c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::Rate),
        c023::Verdict::Void {
            reason: "ring-loss"
        }
    );
    let lat = c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall);
    assert!(
        matches!(lat, c023::Verdict::Void { .. }),
        "freeze cell must VOID for latency/wall, got {lat:?}"
    );
    eprintln!("c023[void-unpaired]: evaluator VOIDs (rate=ring-loss, latwall={lat:?})");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_unpaired_finalize_independent() {
    // P2fix2 item 13 (codex NEW-P2g): `unpaired-finalize` exercised
    // INDEPENDENTLY — a live cell with finalized-unpaired edges and
    // EVERY other arm clean (zero lanes, uncapped, exact multiset,
    // receipts earned) evaluates to exactly
    // Void{unpaired-finalize} for BOTH cell kinds. STOP-probe
    // cycles (STOP → drain → finalize → close → CONT) freeze
    // in-flight ops of an unpaced N = 1000 run (duty ≈ 100%, so a
    // cycle during the run hits; windows stay small and drained,
    // so no lane trips and nothing caps); retry ≤5 whole runs.
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("void-unpaired-indep");
    let dir = &_scratch.0;
    for attempt in 0..5 {
        let timing = dir.join(format!("timing-uindep{attempt}.txt"));
        let app = build_fixture(dir);
        let Harness { mut child, rx } = spawn(&app, 1000, 0, &timing);
        let pid = child.0.id();
        let starttime = proc_starttime(pid);
        child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
        let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(warmed.starts_with("warmed "));
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: vec![pid],
                ..Default::default()
            },
            inventory::Limits::default(),
        )
        .unwrap();
        let mut session =
            po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
        session.set_trace_mode(trace::TRACE_MODE_LATENCY).unwrap();
        let _ = session.reconcile(&scanner.snapshot());
        child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
        // Probe cycles until the run finishes.
        let mut windows: Vec<trace::ClosedTraceWindow> = vec![];
        let mut next_seq = 0u64;
        let deadline = Instant::now() + Duration::from_secs(120);
        let done = loop {
            if Instant::now() >= deadline {
                // Release a possibly STOPped child (SIGCONT on a
                // running process is a no-op) before failing.
                unsafe { libc::kill(pid as i32, libc::SIGCONT) };
                panic!("unpaired-independent run did not finish");
            }
            match rx.recv_timeout(Duration::from_millis(5)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => {
                    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
                    for _ in 0..3 {
                        session.drain(Instant::now() + Duration::from_millis(20));
                    }
                    session.trace_finalize();
                    windows.push(session.close_trace_window(next_seq));
                    next_seq += 1;
                    unsafe { libc::kill(pid as i32, libc::SIGCONT) };
                }
            }
        };
        assert!(done.starts_with("done completed=1000"), "done: {done:?}");
        for _ in 0..5 {
            session.drain(Instant::now() + Duration::from_millis(200));
        }
        let (batch, window, totals) = session.close_with_trace_seq(next_seq);
        windows.push(window);
        // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
        let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
        drop(child.0.stdin.take());
        let status = child.0.wait().unwrap();
        assert!(status.success(), "probe run must succeed: {status:?}");
        let unpaired_e: u64 = windows.iter().map(|w| w.unpaired_entries).sum();
        let unpaired_r: u64 = windows.iter().map(|w| w.unpaired_results).sum();
        let lanes: [u64; 8] = windows.iter().fold([0; 8], |mut acc, w| {
            for (i, lane) in w.ring_loss.iter().enumerate() {
                acc[i] += lane;
            }
            acc
        });
        eprintln!(
            "c023[uindep attempt{attempt}]: unpaired={unpaired_e}/{unpaired_r} lanes={lanes:?} windows={}",
            windows.len()
        );
        if unpaired_e == 0 || unpaired_r == 0 {
            eprintln!("c023[uindep attempt{attempt}]: no frozen in-flight — retry");
            continue;
        }
        // Sum the run's windows into one cell (terminal buckets tile
        // exactly across mid-run closes).
        let mut paired = 0u64;
        let mut capped = false;
        let mut lanes_sum = [0u64; 8];
        let mut recv_att = [0u64; 3];
        let mut recv_res = [0u64; 3];
        let mut api_attempts = vec![0u64; 81];
        let mut api_results = vec![0u64; 81];
        for w in &windows {
            paired = paired.saturating_add(w.paired);
            capped |= w.capped;
            for (i, lane) in w.ring_loss.iter().enumerate() {
                lanes_sum[i] = lanes_sum[i].saturating_add(*lane);
            }
            for i in 0..3 {
                recv_att[i] = recv_att[i].saturating_add(w.received.attempts[i]);
                recv_res[i] = recv_res[i].saturating_add(w.received.results[i]);
            }
            for (i, v) in w.api_attempts.iter().enumerate() {
                api_attempts[i] = api_attempts[i].saturating_add(*v);
            }
            for (i, v) in w.api_results.iter().enumerate() {
                api_results[i] = api_results[i].saturating_add(*v);
            }
        }
        let mut m_edge_gaps = [(0u64, 0u64, 0u64); 6];
        let mut m_edge_entries = [0u64; 6];
        let mut m_rows_found = [false; 6];
        for row in &batch.api_activity {
            let id = u32::from(row.row.api);
            if let Some(i) = c023::M_APIS.iter().position(|m| *m == id) {
                m_edge_gaps[i] = (row.row.gaps.map, row.row.gaps.depth, row.row.gaps.unpaired);
                m_edge_entries[i] = row.row.entries;
                m_rows_found[i] = true;
            }
        }
        let receipt = parse_timings(&timing);
        assert!(receipt.valid, "probe-run receipt must be strict-valid");
        // Child/receipt agreement (P2fix3 NEW-6).
        let probe_timings_valid =
            receipt.valid && receipt_agrees_with_child(&receipt, status.code(), &done);
        // Producer taint wiring (P2fix3 NEW-12 — the independent
        // control: the cell's taint bit equals the live producer
        // signal, never a hardcoded constant).
        let pairing_tainted =
            windows.iter().any(|w| w.pairing_uncertain) || totals.pairing_uncertain;
        eprintln!("c023[uindep]: tainted={pairing_tainted}");
        let cell = c023::CellData {
            app_ops: 1000,
            completed: receipt.completed,
            per_op_ns: receipt.per_op_ns,
            wall_ns: receipt.wall_ns,
            max_late_ns: receipt.max_late_ns,
            pace_ns: 0,
            paired,
            unpaired_entries: unpaired_e,
            unpaired_results: unpaired_r,
            capped,
            ring_loss: lanes_sum,
            rejected_unknown_api: windows.iter().map(|w| w.rejected_unknown_api).sum(),
            pairing_tainted,
            api_attempts,
            api_results,
            received_attempts: recv_att.iter().sum(),
            received_results: recv_res.iter().sum(),
            m_edge_gaps,
            m_edge_entries,
            m_rows_found,
            scoped_read_ok: match starttime {
                Some(st) => batch.terminal_scopes_observed.contains(&(pid, st)),
                None => false,
            },
            timings_valid: probe_timings_valid
                && (receipt.failed_at.is_some() == (receipt.completed != 1000)),
            schedule_origin_ns: receipt.origin_ns,
            completion_deadline_ns: receipt.origin_ns,
            final_completion_ns: receipt.final_completion_ns,
        };
        // Independence: every other arm is clean (zero lanes,
        // uncapped, exact multiset implied by the verdict below).
        assert!(
            lanes_sum.iter().all(|l| *l == 0),
            "lanes must be zero: {lanes_sum:?}"
        );
        assert!(!capped, "no window may cap");
        assert_eq!(
            c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::Rate),
            c023::Verdict::Void {
                reason: "unpaired-finalize"
            }
        );
        assert_eq!(
            c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
            c023::Verdict::Void {
                reason: "unpaired-finalize"
            }
        );
        eprintln!("c023[uindep]: evaluator VOIDs unpaired-finalize independently");
        return;
    }
    panic!("unpaired-independent leg missed in-flight in 5 runs");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_void_control_lane_and_cap() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("void-lane");
    // 20000 unpaced ops × 14 rows = 280k records against ~9.3k ring
    // slots with NO drain until done: LOSS_RING by capacity
    // arithmetic + capped detail ⇒ VOID on both arms (through the
    // verdict evaluator, not a printed VOID).
    let timing = _scratch.0.join("timing-flood.txt");
    let app = build_fixture(&_scratch.0);
    let Harness { mut child, rx } = spawn(&app, 20_000, 0, &timing);
    let pid = child.0.id();
    let starttime = proc_starttime(pid);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "));
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![pid],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
    session.set_trace_mode(trace::TRACE_MODE_LATENCY).unwrap();
    let _ = session.reconcile(&scanner.snapshot());
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    let done = loop {
        if Instant::now() >= deadline {
            panic!("VOID: flood workload did not finish within 300s");
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if line.starts_with("done ") => break line,
            Ok(_) => continue,
            Err(_) => continue,
        }
    };
    for _ in 0..10 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    let status = child.0.wait().unwrap();
    let (batch, window, _) = session.close_with_trace();
    eprintln!(
        "c023[void-lane]: lanes={:?} capped={} paired={}",
        window.ring_loss, window.capped, window.paired
    );
    assert!(
        window.ring_loss.iter().any(|lane| *lane > 0),
        "flood must trip a lane"
    );
    assert!(window.capped, "flood must cap detail");
    assert!(
        window.paired >= c023::MIN_PAIRED,
        "flood must stay non-quiet for the arm pins"
    );
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "flood receipt must be strict-valid");
    // Child/receipt agreement (P2fix3 NEW-6).
    let lane_timings_valid =
        receipt.valid && receipt_agrees_with_child(&receipt, status.code(), &done);
    let mut api_attempts = vec![0u64; 81];
    let mut api_results = vec![0u64; 81];
    for (i, v) in window.api_attempts.iter().enumerate() {
        api_attempts[i] = *v;
    }
    for (i, v) in window.api_results.iter().enumerate() {
        api_results[i] = *v;
    }
    let mut m_edge_gaps = [(0u64, 0u64, 0u64); 6];
    let mut m_edge_entries = [0u64; 6];
    let mut m_rows_found = [false; 6];
    for row in &batch.api_activity {
        let id = u32::from(row.row.api);
        if let Some(i) = c023::M_APIS.iter().position(|m| *m == id) {
            m_edge_gaps[i] = (row.row.gaps.map, row.row.gaps.depth, row.row.gaps.unpaired);
            m_edge_entries[i] = row.row.entries;
            m_rows_found[i] = true;
        }
    }
    // Real M-edge gaps are logged when the flood produces them
    // (evidence that the aggregate-gap arm is live-reachable; the
    // arm mapping itself pins in the evaluator controls above).
    eprintln!("c023[void-lane]: m_edge_gaps={m_edge_gaps:?} rows={m_rows_found:?}");
    let cell = c023::CellData {
        app_ops: 20_000,
        completed: receipt.completed,
        per_op_ns: receipt.per_op_ns,
        wall_ns: receipt.wall_ns,
        max_late_ns: receipt.max_late_ns,
        pace_ns: 0,
        paired: window.paired,
        unpaired_entries: window.unpaired_entries,
        unpaired_results: window.unpaired_results,
        capped: window.capped,
        ring_loss: window.ring_loss,
        rejected_unknown_api: window.rejected_unknown_api,
        pairing_tainted: window.pairing_uncertain,
        api_attempts,
        api_results,
        received_attempts: window.received.attempts.iter().sum(),
        received_results: window.received.results.iter().sum(),
        m_edge_gaps,
        m_edge_entries,
        m_rows_found,
        scoped_read_ok: match starttime {
            Some(st) => batch.terminal_scopes_observed.contains(&(pid, st)),
            None => false,
        },
        timings_valid: lane_timings_valid,
        schedule_origin_ns: receipt.origin_ns,
        completion_deadline_ns: receipt.origin_ns,
        final_completion_ns: receipt.final_completion_ns,
    };
    assert_eq!(
        c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void { reason: "capped" }
    );
    assert_eq!(
        c023::evaluate_cell(&cell, &c023::QUAL_3_5, c023::CellKind::Rate),
        c023::Verdict::Void {
            reason: "ring-loss"
        }
    );
    eprintln!("c023[void-lane]: evaluator VOIDs (latwall=capped, rate=ring-loss)");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_trace_golden_inputs() {
    // Golden-input leg (§6C-13): ONE live latency leg with the
    // by-api opt-in; the REAL sealed summary + REAL api_activity
    // rows stamp a doc shell whose trace plane is 100% live-real
    // (lanes/sites/counters stay the standard empty fixture —
    // disclosed in the compat notes, not hand-written payloads).
    // Attach BEFORE warmup (not a verdict cell): first-call
    // coverage establishes, so the M APIs read `covered` and the
    // by_api block populates with real data.
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("golden");
    let dir = &_scratch.0;
    let timing = dir.join("timing-golden.txt");
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, OPS_SMALL, PACE_LAT_NS, &timing);
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
    session.set_trace_histogram_by_api(true);
    let setup = session.reconcile(&scanner.snapshot());
    assert_eq!(
        setup
            .gaps
            .iter()
            .filter(|g| matches!(g, po::ObservationGap::QuarantinedApi))
            .count(),
        1
    );
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "));
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() >= deadline {
            panic!("VOID: golden workload did not finish within 300s");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.starts_with("done ") => break,
            Ok(_) => continue,
            Err(_) => {
                session.drain(Instant::now() + Duration::from_millis(100));
            }
        }
    }
    for _ in 0..5 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let (batch, window, totals) = session.close_with_trace();
    // Availability from the REAL close-batch rows (§6D-3 rule).
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        let found = batch
            .api_activity
            .iter()
            .find(|r| u32::from(r.row.api) == id);
        if c023::M_APIS.contains(&id) {
            eprintln!(
                "c023[golden]: api{id} row={}",
                found
                    .map(|r| format!(
                        "entries={} not_attached={} attachment={} finality={}",
                        r.row.entries,
                        r.row.gaps.not_attached,
                        r.row.gaps.attachment,
                        r.row.gaps.finality
                    ))
                    .unwrap_or_else(|| "MISSING".to_string())
            );
        }
        let word = found
            .map(|r| {
                if r.row.gaps.not_attached {
                    "not_attached"
                } else if r.row.gaps.attachment || r.row.gaps.finality {
                    "partial_coverage"
                } else {
                    "covered"
                }
            })
            .unwrap_or("not_attached");
        avail.insert(id, word.to_string());
    }
    let summary = trace::summarize(&window, &totals, "latency", Some(&avail));
    summary.validate().expect("live summary validates");
    // Stamp onto the standard empty shell + REAL activity rows.
    let mut doc = osslscope::capture::empty_document();
    doc.api_activity = batch.api_activity.iter().map(|a| a.row.clone()).collect();
    osslscope::evidence::stamp_trace_summary(&mut doc, summary);
    assert_eq!(doc.schema, osslscope::evidence::CAPTURE_SCHEMA_V2_9);
    let out = dir.join("trace-golden-doc.json");
    std::fs::write(&out, serde_json::to_string(&doc).unwrap()).unwrap();
    // Optional shared-dir copy (guest /tmp is overlayfs — the doc
    // would vanish with the guest otherwise).
    if let Some(shared) = std::env::var_os("C023_GOLDEN_OUT") {
        std::fs::write(&shared, serde_json::to_string(&doc).unwrap()).unwrap();
        eprintln!("c023[golden]: shared copy at {}", shared.to_string_lossy());
    }
    eprintln!(
        "c023[golden]: paired={} classes={:?} by_api={} doc={} bytes={}",
        window.paired,
        window.class_counts,
        doc.trace_summary
            .as_ref()
            .and_then(|s| s.by_api.as_ref())
            .map(|m| m.len())
            .unwrap_or(0),
        out.display(),
        std::fs::metadata(&out).unwrap().len(),
    );
    // Assert the nonvacuous oracle: warmup + measured = 200 ops
    // × 7 edges, plus warmup lifecycle pairs (class-0).
    assert_eq!(window.api_attempts[64], WARMUP + OPS_SMALL);
    assert_eq!(window.api_attempts[10], WARMUP + OPS_SMALL);
    assert_eq!(window.class_counts[1], (WARMUP + OPS_SMALL) * 6);
    assert!(window.paired >= (WARMUP + OPS_SMALL) * 7);
    // Availability honesty: current producers hard-set
    // attachment+finality on terminal rows (first-call coverage
    // and cut synchronization are never established), so every
    // API honestly reads `partial_coverage` and the L1 block
    // stays empty (sparse). The dense map + entries still flow.
    let avail = doc
        .trace_summary
        .as_ref()
        .and_then(|s| s.by_api_availability.as_ref())
        .expect("dense availability");
    assert_eq!(avail.len(), 53);
    assert_eq!(avail["20"], "partial_coverage");
    assert_eq!(avail["64"], "partial_coverage");
    let l1 = doc
        .trace_summary
        .as_ref()
        .and_then(|s| s.by_api.as_ref())
        .expect("by_api block");
    assert!(l1.is_empty(), "L1 keeps covered APIs only (none)");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh objects)"]
fn c023_focused_latency_status_documents() {
    // DELTA-9 qualification documents (P2fix1 item 15): REAL
    // focused captures (direct FocusedCapture drive — the public
    // CLI degrades operational modes while C023 is OPEN) in
    // latency + status modes over the M = 6 + F = 1 workload, with
    // actual loss/completeness preserved. Saved for the compat
    // focused goldens (C023_FOCUSED_OUT dir).
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let count_path = std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
        .unwrap_or_else(|| panic!("FAIL-CLOSED: focused docs need OSSLSCOPE_FOCUSED_COUNT_OBJECT"));
    let count_object = fs::read(&count_path).unwrap();
    let out_dir = std::env::var_os("C023_FOCUSED_OUT").map(std::path::PathBuf::from);
    if let Some(dir) = out_dir.as_ref() {
        fs::create_dir_all(dir).unwrap();
    }
    let _scratch = scratch("focused-docs");
    let dir = &_scratch.0;
    for (mode, word, want_histograms) in [
        (trace::TRACE_MODE_LATENCY, "latency", true),
        (trace::TRACE_MODE_STATUS, "status", false),
    ] {
        let timing = dir.join(format!("timing-focused-{word}.txt"));
        let app = build_fixture(dir);
        let Harness { mut child, rx } = spawn(&app, OPS_SMALL, PACE_LAT_NS, &timing);
        let pid = child.0.id();
        child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
        let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(warmed.starts_with("warmed "), "warmup: {warmed:?}");
        // Focused capture on a helper thread; the workload runs
        // inside its window (warmup outside, like verdict cells).
        // The config builds INSIDE the thread (it owns
        // thread-local state — only plain bytes cross, plus the
        // handshake sender). G waits for the ATTACH-READINESS
        // HANDSHAKE (P2fix2 item 11 — the fixed 20 s sleep is
        // replaced: early ops before admission would escape
        // observation entirely, so the capture fires readiness as
        // its cold attach completes instead of the leg guessing).
        let obs = object.clone();
        let cnt = count_object.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let config = osslscope::focused_capture::FocusedConfig {
                duration: Duration::from_secs(60),
                timeout: Duration::from_secs(120),
                grace: Duration::from_secs(5),
                parsed_cache: None,
                trace_mode: mode,
                trace_by_api: false,
                // Isolated qual harness: program the requested
                // operational mode (public CLI paths stay forced).
                allow_operational_trace: true,
                attach_ready: Some(ready_tx),
            };
            let count_sha256: [u8; 32] = sha2::Sha256::digest(&cnt).into();
            let objects = osslscope::focused_capture::FocusedObjects {
                observation: std::sync::Arc::from(obs),
                count: std::sync::Arc::from(cnt),
                count_sha256,
            };
            // The result owns thread-local pools (!Send) — the
            // DOCUMENT crosses as JSON (round-tripped below).
            let result = osslscope::focused_capture::run(
                config,
                osslscope::capture::Target::Pid(pid),
                objects,
                Instant::now() + Duration::from_secs(120),
            )
            .expect("focused capture runs");
            serde_json::to_value(&result.document).expect("doc serializes")
        });
        ready_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("focused capture must handshake attach-readiness (no blind sleep)");
        eprintln!("c023[focused-{word}]: attach handshake received");
        child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if Instant::now() >= deadline {
                panic!("VOID: focused-{word} workload did not finish");
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.starts_with("done ") => break,
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        let doc_value = worker.join().expect("focused worker finishes");
        // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
        let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
        drop(child.0.stdin.take());
        assert!(child.0.wait().unwrap().success());
        let doc: osslscope::evidence::CaptureDocument =
            serde_json::from_value(doc_value).expect("doc round-trips");
        // Diagnostics BEFORE asserting (they must survive failure).
        eprintln!(
            "c023[focused-{word}]: activity_rows={} sites={} attach_diag={:?}",
            doc.api_activity.len(),
            doc.sites.len(),
            doc.attach_diagnostics,
        );
        if let Some(ts) = doc.trace_summary.as_ref() {
            eprintln!(
                "c023[focused-{word}]: paired={} unpaired={}/{} lanes={:?} capped={} rejected={} dropped={} status={:?}",
                ts.window.paired,
                ts.window.trace_unpaired_entries,
                ts.window.trace_unpaired_results,
                ts.window.ring_loss,
                ts.window.trace_capped,
                ts.window.trace_rejected_unknown_api,
                ts.window.trace_dropped,
                doc.status,
            );
        } else {
            eprintln!(
                "c023[focused-{word}]: NO trace_summary status={:?}",
                doc.status
            );
        }
        // Nonvacuous oracle: 150 ops × 7 edges, exact classes.
        let ts = doc.trace_summary.as_ref().expect("trace_summary seals");
        assert_eq!(ts.mode, word);
        assert!(!ts.fallback, "direct drive keeps the requested mode");
        assert_eq!(ts.window.paired, OPS_SMALL * 7);
        let cw = ts.window.class_window.as_ref().expect("window classes");
        assert_eq!((cw.success, cw.unknown), (OPS_SMALL * 6, OPS_SMALL));
        let ce = ts.class_epoch.as_ref().expect("epoch classes");
        assert_eq!((ce.success, ce.unknown), (OPS_SMALL * 6, OPS_SMALL));
        assert_eq!(ts.histograms.is_some(), want_histograms);
        assert_eq!(ts.window.trace_unpaired_entries, 0);
        assert_eq!(ts.window.trace_unpaired_results, 0);
        assert!(ts.window.ring_loss.iter().all(|lane| *lane == 0));
        assert!(!ts.window.trace_capped);
        ts.validate().expect("focused summary validates");
        // Actual loss/completeness preserved (focused windows carry
        // the two structural unknowns; a clean run adds no
        // trace-loss reasons).
        let status = serde_json::to_value(&doc.status).unwrap();
        eprintln!(
            "c023[focused-{word}]: paired={} status={} counters={} doc_bytes={}",
            ts.window.paired,
            status,
            doc.counters.len(),
            serde_json::to_string(&doc).unwrap().len(),
        );
        assert!(
            matches!(
                doc.status,
                osslscope::evidence::Completeness::Partial { .. }
            ),
            "focused doc carries its structural unknowns"
        );
        let reasons = match &doc.status {
            osslscope::evidence::Completeness::Partial { reasons } => reasons.clone(),
            _ => vec![],
        };
        assert!(
            !reasons.iter().any(|r| matches!(
                r,
                osslscope::evidence::GapReason::Loss { counter, .. }
                    if counter.starts_with("trace_")
            )),
            "clean run carries no trace-loss reasons: {reasons:?}"
        );
        if let Some(dir) = out_dir.as_ref() {
            let path = dir.join(format!("focused-{word}-doc.json"));
            std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
            eprintln!("c023[focused-{word}]: saved {}", path.display());
        }
    }
}

/// Scoped `C023_FAIL_AT_OP` trigger (the fixture fails that op
/// post-emit through the real exit-6 + FAILED_AT path). Removed on
/// drop so no other leg inherits it (legs run serially).
/// Controlled scheduling delay (P2fix6 NEW-31): op M
/// busy-spins T ns after its op-only timing closes, so op M+1
/// starts ~T late (its lateness deterministically dominates).
/// Serial-test env guard (mirrors `FailAtOp`).
struct BusyOp;
impl BusyOp {
    fn arm(op: u64, ns: u64) -> Self {
        // SAFETY: qual legs run serially (RUST_TEST_THREADS=1); no
        // other thread reads these vars concurrently.
        unsafe { std::env::set_var("C023_BUSY_AT_OP", op.to_string()) };
        unsafe { std::env::set_var("C023_BUSY_NS", ns.to_string()) };
        BusyOp
    }
}
impl Drop for BusyOp {
    fn drop(&mut self) {
        // SAFETY: same seriality as above.
        unsafe { std::env::remove_var("C023_BUSY_AT_OP") };
        unsafe { std::env::remove_var("C023_BUSY_NS") };
    }
}

struct FailAtOp;
impl FailAtOp {
    fn arm(op: u64) -> Self {
        // SAFETY: qual legs run serially (RUST_TEST_THREADS=1); no
        // other thread reads this var concurrently.
        unsafe { std::env::set_var("C023_FAIL_AT_OP", op.to_string()) };
        FailAtOp
    }
}
impl Drop for FailAtOp {
    fn drop(&mut self) {
        // SAFETY: same seriality as above.
        unsafe { std::env::remove_var("C023_FAIL_AT_OP") };
    }
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_shortfall_control_actual_child_failure() {
    // P2fix2 item 26 (codex NEW-6): completion shortfall via an
    // ACTUAL child-process failure — the fixture fails its LAST op
    // (post-emit, so all 1000 offered ops' edges are observed and
    // every prior evaluator arm passes) through the real exit-6 +
    // FAILED_AT path, and the workload-failure arm reaches the
    // evaluator (no harness panic on the failed-child stdin write):
    // Rate OPENS schedule-shortfall, LatencyWall VOIDs it.
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("shortfall");
    let dir = &_scratch.0;
    let _fail = FailAtOp::arm(OPS_LAT - 1);
    let run = run_observed(
        &object,
        dir,
        trace::TRACE_MODE_LATENCY,
        OPS_LAT,
        PACE_LAT_NS,
        "shortfall",
    );
    assert_eq!(run.cell.completed, OPS_LAT - 1, "one op failed");
    // The failure receipt is real (re-parsed from the timing file).
    let receipt = parse_timings(&dir.join("timing-shortfall.txt"));
    assert!(receipt.valid, "failure receipt must be strict-valid");
    assert_eq!(receipt.failed_at, Some(OPS_LAT - 1));
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::Rate),
        c023::Verdict::Open {
            reason: "schedule-shortfall"
        }
    );
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void {
            reason: "schedule-shortfall"
        }
    );
    eprintln!("c023[shortfall]: evaluator reaches schedule-shortfall on actual child failure");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn new31_failed_op_supplies_max_reaches_shortfall() {
    // P2fix6 NEW-31: a REAL paced execution (1000 ops, 100 ms
    // pace) where op 998's 500 ms busy delay makes the FAILED op
    // 999's lateness the run maximum (the delay must exceed the
    // pace — a 50 ms delay is absorbed by the 100 ms pace wait
    // and leaves the failed op on time) — the UNEDITED receipt
    // carries marker == footer max with strict row dominance
    // (never a rewritten-receipt maximum) AND reaches
    // schedule-shortfall (Rate Open, LatencyWall Void).
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("shortfall-max");
    let dir = &_scratch.0;
    let _busy = BusyOp::arm(OPS_LAT - 2, 500_000_000);
    let _fail = FailAtOp::arm(OPS_LAT - 1);
    let run = run_observed(
        &object,
        dir,
        trace::TRACE_MODE_LATENCY,
        OPS_LAT,
        PACE_LAT_NS,
        "shortfall-max",
    );
    assert_eq!(run.cell.completed, OPS_LAT - 1, "one op failed");
    // The failure receipt is real (re-parsed from the timing file).
    let timing = dir.join("timing-shortfall-max.txt");
    let receipt = parse_timings(&timing);
    assert!(receipt.valid, "failure receipt must be strict-valid");
    assert_eq!(receipt.failed_at, Some(OPS_LAT - 1));
    assert_failed_op_supplies_max(&timing, &receipt, OPS_LAT - 1);
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::Rate),
        c023::Verdict::Open {
            reason: "schedule-shortfall"
        }
    );
    assert_eq!(
        c023::evaluate_cell(&run.cell, &c023::QUAL_3_5, c023::CellKind::LatencyWall),
        c023::Verdict::Void {
            reason: "schedule-shortfall"
        }
    );
    eprintln!("c023[shortfall-max]: unedited failed-op-max receipt reaches schedule-shortfall");
}

/// Stage the real binary + BPF companions for privileged scan
/// legs (root-owned, like the provider_load_live staging).
struct StagedScan {
    dir: std::path::PathBuf,
    binary: std::path::PathBuf,
}
impl Drop for StagedScan {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "rm", "-rf"])
            .arg(&self.dir)
            .status();
    }
}
fn stage_scan_binary() -> Option<StagedScan> {
    if std::env::var("OSSL_6A_ALLOW_PRIVILEGED_STAGE").unwrap_or_default() != "1" {
        eprintln!("INCONCLUSIVE: scan-trace leg needs OSSL_6A_ALLOW_PRIVILEGED_STAGE=1");
        return None;
    }
    let built = std::path::PathBuf::from(env!("CARGO_BIN_EXE_osslscope"));
    let release = built.ancestors().nth(2).map(|p| p.join("release"))?;
    let obs = release.join("osslscope-provider-observation");
    let count = release.join("osslscope-focused-count");
    if !obs.is_file() || !count.is_file() {
        eprintln!("INCONCLUSIVE: BPF companions absent under {release:?}");
        return None;
    }
    let dir = std::path::PathBuf::from(format!(
        "/opt/ossl-scan-trace-{}-{}",
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
    let status = std::process::Command::new("sudo")
        .args(["-n", "sh", "-c", &script])
        .status()
        .unwrap();
    if !status.success() {
        eprintln!("INCONCLUSIVE: sudo -n staging refused");
        return None;
    }
    let binary = dir.join("osslscope");
    Some(StagedScan { dir, binary })
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object + staged binary)"]
fn c023_scan_trace_executable_shape() {
    // P2fix2 item 13 (codex NEW-P2d): EXECUTABLE scan checks for
    // effective mode, bounded detail, and withholding — the REAL
    // scan binary over a small burst (50 unpaced ops fired after
    // attach): the public path degrades --trace latency to the
    // aggregate-only fallback (stderr note + effective metadata
    // word), the JSON end record carries the bounded seal
    // (detail_total + first-64 detail, fetch-only classes, no
    // histograms), and the human TRACE section matches.
    let _object = match gated() {
        Some(o) => o,
        None => return,
    };
    let Some(staged) = stage_scan_binary() else {
        return;
    };
    let _scratch = scratch("scan-trace");
    let dir = &_scratch.0;
    for json in [true, false] {
        let timing = dir.join(format!("timing-scan-{json}.txt"));
        let app = build_fixture(dir);
        // Slow paced burst (50 × 400 ms = 20 s — P2fix5 scan-harden:
        // scan exposes no attach-readiness handshake (the first
        // snapshot is a discovery record, not an arming signal),
        // and attach takes seconds under load (see the report
        // leg's identical note) — so the burst must comfortably
        // outlast attach instead of racing a ~1ms unpaced window
        // off it. Attach lands mid-burst; post-attach fetch pairs
        // seal. Duration covers burst + attach + seal tail.
        let Harness { mut child, rx } = spawn(&app, 50, 400_000_000, &timing);
        let pid = child.0.id();
        child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
        let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(warmed.starts_with("warmed "));
        let mut cmd = std::process::Command::new(&staged.binary);
        cmd.args(["scan", "--observe-providers", "--pid", &pid.to_string()]);
        cmd.args([
            "--watch",
            "--trace",
            "latency",
            "--duration",
            "30",
            "--interval",
            "1",
        ]);
        if json {
            cmd.arg("--json");
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut scan = cmd.spawn().unwrap();
        // Drain thread (collects every stdout line for the shape
        // asserts below — firing no longer waits on it).
        let stdout = scan.stdout.take().unwrap();
        let reader = std::sync::Arc::new(std::sync::Mutex::new(BufReader::new(stdout)));
        let reader2 = reader.clone();
        let watcher = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader2.lock().unwrap().read_line(&mut line).unwrap_or(0);
                if n == 0 {
                    break;
                }
                out.push(line.clone());
            }
            out
        });
        // Fire the slow burst while the capture attaches (report
        // pattern — attach lands mid-burst, post-attach fetch
        // pairs seal).
        child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let done = loop {
            if Instant::now() >= deadline {
                panic!("scan-trace workload did not finish");
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => continue,
            }
        };
        assert!(done.starts_with("done completed=50"), "done: {done:?}");
        let lines = watcher.join().unwrap();
        let status = scan.wait().unwrap();
        let mut err = String::new();
        use std::io::Read as _;
        scan.stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
        let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
        drop(child.0.stdin.take());
        assert!(child.0.wait().unwrap().success());
        eprintln!(
            "c023[scan-trace json={json}]: exit={status:?} records={}",
            lines.len()
        );
        assert!(
            matches!(status.code(), Some(0 | 3)),
            "scan exit: {status:?}"
        );
        // The public path degrades through the REAL binary (the
        // stderr note proves the request parsed and degraded).
        assert!(
            err.contains("degraded to the aggregate-only fallback"),
            "stderr: {err:?}"
        );
        if json {
            let rows: Vec<serde_json::Value> = lines
                .iter()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let end = rows
                .iter()
                .find(|r| r["record"] == "end")
                .expect("scan emits an end record");
            // Effective mode: degraded to aggregate-only while OPEN.
            assert_eq!(end["trace_mode"], "metadata");
            let trace = end.get("trace").expect("end carries the trace seal");
            assert_eq!(trace["mode"], "metadata");
            assert_eq!(trace["fallback"], true);
            // Withholding: fetch-only classes, no histograms, no
            // by_api (operational interpretations unreachable).
            // Shape-pinned, not exact-count (P2fix5 scan-harden:
            // attach lands mid-burst, so pre-attach ops never
            // seal — every sealed pair is class-0, exact N varies
            // with attach timing; the old exact-50 raced a ~1ms
            // burst off the discovery snapshot and flaked quiet
            // under load).
            let paired = trace["paired"].as_u64().expect("paired");
            let unknown = trace["class_window"]["unknown"]
                .as_u64()
                .expect("unknown class");
            assert!(paired > 0, "post-attach fetch pairs seal: {trace:?}");
            assert_eq!(unknown, paired, "every pair is class-0: {trace:?}");
            assert_eq!(trace["class_window"]["success"], 0);
            assert!(trace.get("histograms").is_none(), "no histograms: {trace}");
            assert!(trace.get("by_api").is_none(), "no by_api: {trace}");
            // Bounded detail: first-64 rows + retained total (2
            // rows per pair — attempt + result).
            let detail_total = trace["detail_total"].as_u64().expect("detail_total");
            let detail = trace["detail"].as_array().expect("detail rows");
            assert_eq!(
                detail_total,
                2 * paired,
                "fetch pairs retain 2 rows each: {trace:?}"
            );
            assert!(detail.len() <= 64, "detail bound: {}", detail.len());
        } else {
            let text = lines.join("");
            assert!(text.contains("TRACE mode=metadata"), "{text:?}");
            assert!(text.contains("fallback=true"), "{text:?}");
            assert!(text.contains("histograms: none"), "{text:?}");
        }
    }
    eprintln!("c023[scan-trace]: executable shape pins hold (json + human)");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object + staged binary)"]
fn new40_scan_post_attachment_controlled_counts() {
    // P2fix6 NEW-40: CONTROLLED post-attachment workload with
    // INDEPENDENTLY counted fetches — scan exposes no
    // attach-readiness handshake, so the workload idles through
    // a 12 s settle (the proven attach budget — attach takes
    // seconds under load) and THEN fires a known-N burst; the
    // sealed pairs must equal the INDEPENDENT count exactly
    // (done line + timing receipt — never the observer's own
    // number), with positive, conserved class-0 evidence in BOTH
    // formats and zero loss. If attach lagged into the burst,
    // paired<N fails honestly. The paced-burst shape leg above
    // stays as timing smoke.
    let _object = match gated() {
        Some(o) => o,
        None => return,
    };
    let Some(staged) = stage_scan_binary() else {
        return;
    };
    let _scratch = scratch("scan-controlled");
    let dir = &_scratch.0;
    const OPS: u64 = 20;
    for json in [true, false] {
        let timing = dir.join(format!("timing-scanctl-{json}.txt"));
        let app = build_fixture(dir);
        let Harness { mut child, rx } = spawn(&app, OPS, 100_000_000, &timing);
        let pid = child.0.id();
        child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
        let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(warmed.starts_with("warmed "));
        let mut cmd = std::process::Command::new(&staged.binary);
        cmd.args(["scan", "--observe-providers", "--pid", &pid.to_string()]);
        cmd.args([
            "--watch",
            "--trace",
            "latency",
            "--duration",
            "30",
            "--interval",
            "1",
        ]);
        if json {
            cmd.arg("--json");
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut scan = cmd.spawn().unwrap();
        let stdout = scan.stdout.take().unwrap();
        let reader = std::sync::Arc::new(std::sync::Mutex::new(BufReader::new(stdout)));
        let reader2 = reader.clone();
        let watcher = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader2.lock().unwrap().read_line(&mut line).unwrap_or(0);
                if n == 0 {
                    break;
                }
                out.push(line.clone());
            }
            out
        });
        // Controlled post-attachment burst: the workload idled
        // since warmup (no ops during attach), so every op below
        // is post-settle — the exact-count proof below is the
        // attachment evidence.
        std::thread::sleep(Duration::from_secs(12));
        child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let done = loop {
            if Instant::now() >= deadline {
                panic!("scan-controlled workload did not finish");
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.starts_with("done ") => break line,
                Ok(_) => continue,
                Err(_) => continue,
            }
        };
        // Independent count, two sources (done line + timing
        // receipt — the observer's number never enters).
        assert!(
            done.starts_with(&format!("done completed={OPS}")),
            "done: {done:?}"
        );
        let receipt = parse_timings(&timing);
        assert!(receipt.valid, "timing receipt must be strict-valid");
        assert_eq!(receipt.completed, OPS, "receipt counts {OPS}");
        let lines = watcher.join().unwrap();
        let status = scan.wait().unwrap();
        let mut err = String::new();
        use std::io::Read as _;
        scan.stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
        drop(child.0.stdin.take());
        assert!(child.0.wait().unwrap().success());
        eprintln!(
            "c023[scan-controlled json={json}]: exit={status:?} records={}",
            lines.len()
        );
        assert!(
            matches!(status.code(), Some(0 | 3)),
            "scan exit: {status:?}"
        );
        assert!(
            err.contains("degraded to the aggregate-only fallback"),
            "stderr: {err:?}"
        );
        if json {
            let rows: Vec<serde_json::Value> = lines
                .iter()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let end = rows
                .iter()
                .find(|r| r["record"] == "end")
                .expect("scan emits an end record");
            assert_eq!(end["trace_mode"], "metadata");
            let trace = end.get("trace").expect("end carries the trace seal");
            assert_eq!(trace["mode"], "metadata");
            assert_eq!(trace["fallback"], true);
            // Positive, conserved class-0 evidence against the
            // INDEPENDENT count (every post-settle fetch pairs;
            // no loss; every pair class-0).
            let paired = trace["paired"].as_u64().expect("paired");
            assert_eq!(
                paired, OPS,
                "every post-settle fetch pairs (independent {OPS}): {trace:?}"
            );
            assert_eq!(
                trace["class_window"]["unknown"], OPS,
                "every pair is class-0: {trace:?}"
            );
            assert_eq!(trace["class_window"]["success"], 0);
            assert_eq!(trace["class_window"]["failure"], 0);
            assert_eq!(trace["class_window"]["empty"], 0);
            assert_eq!(trace["class_window"]["retry"], 0);
            assert!(trace.get("histograms").is_none(), "no histograms: {trace}");
            assert!(trace.get("by_api").is_none(), "no by_api: {trace}");
            assert_eq!(
                trace["detail_total"],
                2 * OPS,
                "fetch pairs retain 2 rows each: {trace:?}"
            );
            let detail = trace["detail"].as_array().expect("detail rows");
            assert_eq!(
                detail.len() as u64,
                2 * OPS,
                "all detail rows retained: {trace:?}"
            );
            assert_eq!(
                trace["ring_loss"],
                serde_json::json!([0, 0, 0, 0, 0, 0, 0, 0]),
                "zero ring loss: {trace:?}"
            );
            assert_eq!(trace["trace_unpaired_entries"], 0);
            assert_eq!(trace["trace_unpaired_results"], 0);
        } else {
            // Human legs carry the same positive counts (a quiet
            // human trace must NOT pass).
            let text = lines.join("");
            assert!(
                text.contains(&format!("TRACE mode=metadata paired={OPS} ")),
                "human pairs positive + exact: {text:?}"
            );
            assert!(
                text.contains("unpaired_e=0 unpaired_r=0"),
                "human unpaired zero: {text:?}"
            );
            assert!(
                text.contains(&format!("class=0/0/0/0/{OPS}")),
                "human class-0 conserved: {text:?}"
            );
            assert!(text.contains("ring=[-]"), "human ring clean: {text:?}");
            assert!(text.contains("fallback=true"), "{text:?}");
            assert!(text.contains("histograms: none"), "{text:?}");
        }
    }
    eprintln!("c023[scan-controlled]: post-attachment counts hold (json + human)");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object + staged binary)"]
fn c023_report_binary_degrades_and_withholds() {
    // P2fix2 item 13 (codex NEW-P2d): EXECUTABLE report control —
    // the REAL report binary with an operational --trace request
    // degrades to the aggregate-only fallback (stderr note +
    // effective metadata word) and the degraded document withholds
    // operational interpretations (no histograms, fetch-only
    // classes, every pair class-0) — end-to-end withholding
    // through the public report path.
    let _object = match gated() {
        Some(o) => o,
        None => return,
    };
    let Some(staged) = stage_scan_binary() else {
        return;
    };
    let _scratch = scratch("report-degrade");
    let dir = &_scratch.0;
    let timing = dir.join("timing-report.txt");
    let app = build_fixture(dir);
    // Slow paced burst (40 × 500 ms = 20 s): report exposes no
    // attach-readiness handshake, so the burst must comfortably
    // outlast even loaded attach (seconds) — attach lands
    // mid-burst and post-attach fetch pairs seal.
    let Harness { mut child, rx } = spawn(&app, 40, 500_000_000, &timing);
    let pid = child.0.id();
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "));
    let out_doc = dir.join("report-doc.json");
    let mut report = std::process::Command::new(&staged.binary)
        .args([
            "report",
            "--pid",
            &pid.to_string(),
            "--trace",
            "latency",
            "--trace-histogram-by-api",
            "--format",
            "json",
            "--duration",
            "30",
            "--out",
            out_doc.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Fire the slow burst while the capture attaches (attach lands
    // mid-burst — post-attach fetch pairs seal).
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let done = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(done.starts_with("done completed=40"), "done: {done:?}");
    let status = report.wait().unwrap();
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    let child_status = child.0.wait().unwrap();
    assert!(child_status.success(), "workload must succeed");
    assert!(
        matches!(status.code(), Some(0 | 3)),
        "report exit: {status:?}"
    );
    let mut err = String::new();
    use std::io::Read as _;
    report
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        err.contains("degraded to the aggregate-only fallback"),
        "degrade note: {err:?}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_doc).unwrap()).unwrap();
    let trace = doc.get("trace_summary").expect("trace seals");
    assert_eq!(trace["mode"], "metadata");
    assert_eq!(trace["fallback"], true);
    assert!(trace.get("histograms").is_none(), "no histograms");
    assert!(trace.get("by_api").is_none(), "no by_api");
    // Every sealed pair is class-0 (fallback pairs fetch only —
    // operational interpretations unreachable end-to-end).
    let cw = &trace["window"]["class_window"];
    assert_eq!(cw["success"], 0);
    assert_eq!(cw["failure"], 0);
    assert_eq!(cw["empty"], 0);
    assert_eq!(cw["retry"], 0);
    assert_eq!(trace["window"]["paired"], cw["unknown"]);
    assert!(
        cw["unknown"].as_u64().unwrap() > 0,
        "post-attach fetch pairs seal: {trace:?}"
    );
    eprintln!("c023[report-degrade]: executable degradation + withholding pins hold");
}

#[test]
#[ignore = "live lane only (C023_QUAL=1 + root + fresh object)"]
fn c023_fallback_leg_stays_aggregate_only() {
    let object = match gated() {
        Some(o) => o,
        None => return,
    };
    let _scratch = scratch("fallback");
    let dir = &_scratch.0;
    // D0-6 enforcement leg: fallback ⇒ BPF emits no operational
    // edges; fetch pairs (class-0); histograms empty.
    let timing = dir.join("timing-fallback.txt");
    let app = build_fixture(dir);
    let Harness { mut child, rx } = spawn(&app, OPS_SMALL, PACE_LAT_NS, &timing);
    child.0.stdin.as_mut().unwrap().write_all(b"W").unwrap();
    let warmed = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    assert!(warmed.starts_with("warmed "));
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.0.id()],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
    session.set_trace_fallback().unwrap();
    let setup = session.reconcile(&scanner.snapshot());
    assert_eq!(
        setup
            .gaps
            .iter()
            .filter(|g| matches!(g, po::ObservationGap::QuarantinedApi))
            .count(),
        1
    );
    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() >= deadline {
            panic!("VOID: fallback workload did not finish within 300s");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.starts_with("done ") => break,
            Ok(_) => continue,
            Err(_) => {
                session.drain(Instant::now() + Duration::from_millis(100));
            }
        }
    }
    for _ in 0..5 {
        session.drain(Instant::now() + Duration::from_millis(200));
    }
    // Tolerant X (P2fix2 item 26): a failed (possibly exited) child must never panic the harness — status is checked after.
    let _ = child.0.stdin.as_mut().unwrap().write_all(b"X");
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let (batch, window, _) = session.close_with_trace();
    eprintln!(
        "c023[fallback]: paired={} classes={:?} op_attempts={} fetch_attempts={} fallback={}",
        window.paired,
        window.class_counts,
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        window.fallback,
    );
    assert!(window.fallback);
    assert_eq!(
        window.received.attempts[trace::TraceFamily::PublicApi.index()],
        0
    );
    assert_eq!(
        window.received.attempts[trace::TraceFamily::Fetch.index()],
        OPS_SMALL
    );
    assert_eq!(window.paired, OPS_SMALL);
    assert_eq!(window.class_counts, [OPS_SMALL, 0, 0, 0, 0]);
    assert!(window.histograms.iter().all(|h| h.count == 0));
    // Aggregates stay (maps-only path observes the workload).
    let entries: u64 = batch.api_activity.iter().map(|row| row.row.entries).sum();
    assert!(entries >= OPS_SMALL, "aggregates must observe the workload");
}
