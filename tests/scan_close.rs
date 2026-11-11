//! SPDX-License-Identifier: GPL-3.0-or-later
//! Trailing-closure controls (findings 6–7): window-edge finish,
//! hung-scan abandonment, and governor composition with the real
//! capture loop. These failed before the fix (opens stuck past
//! the window; zero attempt-rate at 250ms spacing; idle polls
//! never releasing the throttle).

use osslscope::scan::governor::{DutyThrottle, StormAction, StormDetector, ThrottleAction};
use osslscope::scan::oracle::*;
use osslscope_ebpf_common as wire;
use serde_json::Value;

const TID: u32 = 4242;
const ARR: u64 = 0x7000;
const OP: u32 = 7;

fn call(seq: u64, hint: bool, cause: u8) -> wire::ScanCallEvent {
    wire::ScanCallEvent {
        kind: wire::KIND_SCAN_CALL,
        op: OP,
        tid: TID,
        flags: wire::make_call_flags(hint, cause),
        seq,
    }
}

fn ret(seq: u64) -> wire::ScanRetEvent {
    wire::ScanRetEvent {
        kind: wire::KIND_SCAN_RET,
        op: OP,
        flags: 0,
        tid: TID,
        seq,
        arr: ARR,
        generation: 0,
    }
}

fn alg(seq: u64, idx: u64, status: u8) -> wire::ScanAlgEvent {
    wire::ScanAlgEvent {
        kind: wire::KIND_SCAN_ALG,
        op: OP,
        class: if status == wire::ALG_OK {
            1
        } else {
            wire::OTHER_CLASS
        },
        status,
        weak: 0,
        _pad: 0,
        arr: ARR,
        idx,
        generation: 0,
        tid: TID,
        _pad2: 0,
        seq,
    }
}

/// Finding 6: the window edge closes trailing queries — RET-joined
/// opens evaluate on retained evidence (backstop), RET-less opens
/// taint both correlated sequences (never dropped, never standing
/// on mixed evidence).
#[test]
fn fix1_finish_closes_trailing() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(0));
    b.push_alg(alg(0, 0, wire::ALG_OK));
    b.push_alg(alg(0, 1, wire::ALG_EMPTY));
    b.push_call(call(1, false, wire::SKIP_ADMITTED)); // no RET: dangling
    o.ingest(&b);
    // R35 quiescence: the successor take marks seq 0, the quiet
    // batch retires it; seq 1 trails with no RET.
    o.ingest(&ScanBatch {
        quiesced: false,
        now_ns: 1_500,
        ..ScanBatch::default()
    });
    assert_eq!(o.open_count(), 1);
    assert_eq!(o.done().len(), 1);
    o.finish(2_000);
    assert_eq!(o.open_count(), 0);
    assert_eq!(o.done().len(), 2);
    let s0 = o.done().iter().find(|w| w.seq == 0).unwrap();
    assert!(
        matches!(s0.outcome, Outcome::Tainted { .. }),
        "dangling successor taints the correlated record: {s0:?}"
    );
    let s1 = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(matches!(s1.outcome, Outcome::Tainted { .. }));
    assert_eq!(s1.op, UNKNOWN_OP);
    // A lone completed query with NO successor trails honestly
    // open mid-window, then the backstop evaluates it.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(0));
    b.push_alg(alg(0, 0, wire::ALG_OK));
    b.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b);
    assert_eq!(o.open_count(), 1);
    assert!(o.done().is_empty());
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Complete { true_t: 1, .. }
    ));
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
}

/// Finding 6: the 5s sticky abandonment fires on age (RET-less
/// opens only), cascades to same-tid RET-less outers, and a late
/// RET joins as LATE with the verdict standing.
#[test]
fn fix1_hung_abandonment_and_late_ret() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 0,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_call(call(1, true, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 2);
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: HUNG_NS + 1,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert_eq!(o.open_count(), 0, "aged RET-less opens abandon");
    assert!(
        o.done().iter().all(|w| matches!(
            w.outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Hung
            }
        )),
        "{:?}",
        o.done()
    );
    // A late RET joins as LATE (coverage noted, verdict stands —
    // no resurrection, no orphan either).
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: HUNG_NS + 2,
        ..ScanBatch::default()
    };
    b3.push_ret(ret(0));
    o.ingest(&b3);
    assert_eq!(o.done().len(), 2, "verdict stands");
    assert!(o.findings().contains(&Finding::LateRet {
        tid: TID,
        seq: 0,
        arr: ARR
    }));
}

/// Finding 6: RET-joined opens never hang-abandon (evidence in
/// hand closes on succession/finish, not on age).
#[test]
fn fix1_hung_spares_ret_joined() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 0,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(0));
    b1.push_alg(alg(0, 0, wire::ALG_OK));
    b1.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b1);
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: 2 * HUNG_NS,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert_eq!(o.open_count(), 1, "RET-joined opens survive aging");
    assert!(o.done().is_empty());
}

/// Finding 7: the storm detector trips at the real 250ms capture
/// spacing (1200/s over sparse polls — the trailing-100ms
/// first-sample rule reported zero).
#[test]
fn fix1_storm_detector_sparse_polls_trip() {
    let mut d = StormDetector::new();
    assert_eq!(d.observe(0, 0), None);
    // 200 over 250ms = 800/s: under the line.
    assert_eq!(d.observe(250_000_000, 200), None);
    // 300 more over the next 250ms = 1200/s: trips.
    assert_eq!(
        d.observe(500_000_000, 500),
        Some(StormAction::Detach),
        "300 attempts over 250ms = 1200/s must trip"
    );
    assert!(d.detached());
}

/// Round-2 F6: late-RET recovery survives production drains —
/// the RET for a hung-abandoned invocation joins as LATE even
/// after `take_done` consumed the verdict (no orphaning).
#[test]
fn fix2_late_ret_after_production_drain() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    // Age past the 5s hung line, then drain like production
    // (every poll takes `done`).
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: 6_000_000_001,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert!(o.done().iter().any(|w| w.seq == 0
        && matches!(
            w.outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Hung
            }
        )));
    let drained = o.take_done();
    assert_eq!(drained.len(), 1);
    assert!(o.done().is_empty());
    // The late RET arrives after the drain: LATE join, verdict
    // standing — never an orphan.
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 6_000_000_002,
        ..ScanBatch::default()
    };
    b3.push_ret(ret(0));
    o.ingest(&b3);
    assert!(
        o.findings().contains(&Finding::LateRet {
            tid: TID,
            seq: 0,
            arr: ARR
        }),
        "late RET after drain must join LATE: {:?}",
        o.findings()
    );
    assert!(
        !o.findings()
            .iter()
            .any(|f| matches!(f, Finding::OrphanRet { seq: 0, .. }))
    );
}

/// Round-2 F6: straggler records for consumed invocations are not
/// orphans (cross-CPU ring skew delivers them after the close;
/// the oracle retains the outcome evidence across drains).
#[test]
fn fix2_consumed_no_false_orphans() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(0));
    b1.push_alg(alg(0, 0, wire::ALG_OK));
    b1.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    let _ = o.take_done();
    // Stragglers for the consumed key arrive late: absorbed, not
    // orphan findings.
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 3_000,
        ..ScanBatch::default()
    };
    b3.push_alg(alg(0, 2, wire::ALG_OK));
    b3.push_guard(wire::GuardEvent {
        kind: wire::KIND_GUARD,
        op: OP,
        verdict: wire::GUARD_EMPTY,
        tid: TID,
        seq: 0,
        arr: ARR,
        generation: 0,
    });
    o.ingest(&b3);
    assert!(
        !o.findings().iter().any(|f| matches!(
            f,
            Finding::OrphanAlg { seq: 0, .. } | Finding::OrphanGuard { seq: 0, .. }
        )),
        "consumed-key stragglers must not orphan: {:?}",
        o.findings()
    );
    // A truly unknown key still orphans.
    let mut b4 = ScanBatch {
        quiesced: false,
        now_ns: 4_000,
        ..ScanBatch::default()
    };
    b4.push_alg(alg(9, 0, wire::ALG_OK));
    o.ingest(&b4);
    assert!(
        o.findings()
            .iter()
            .any(|f| matches!(f, Finding::OrphanAlg { seq: 9, .. }))
    );
}

/// Finding 7: idle polls age the tier-2 window (an engaged
/// throttle releases once the trailing cost decays, without
/// needing a completion to trigger the recheck).
#[test]
fn fix1_tier2_idle_aging_releases() {
    let mut t = DutyThrottle::new();
    for i in 0..1000u64 {
        t.observe(i * 100_000, 511);
    }
    assert!(t.throttled());
    assert_eq!(t.age(3_000_000_000), Some(ThrottleAction::ReleaseSkipAll));
    assert!(!t.throttled());
}

#[test]
fn v060_sigint_during_setup_phase_acks_and_exits_3() {
    // Setup phase: SIGINT within 200ms of spawn, before the first
    // sample completes. Must ack + exit 3, never hang in setup.
    // Task 5 (d): the observed workload must survive the observer.
    let workload = match Workload::spawn() {
        Some(workload) => workload,
        None => {
            eprintln!("skip: need python3 with ssl for the workload");
            return;
        }
    };
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["scan", "--watch", "--interval", "1", "--duration", "60"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("shutting down"));
    workload.assert_alive("setup phase");
}

#[test]
fn v060_sigint_mid_scan_acks_and_exits_3() {
    // Task 5 (d): the observed workload must survive the observer.
    let workload = match Workload::spawn() {
        Some(workload) => workload,
        None => {
            eprintln!("skip: need python3 with ssl for the workload");
            return;
        }
    };
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["scan", "--watch", "--interval", "30", "--duration", "120"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let pid = child.id() as i32;
    libc_kill::kill(pid, libc_kill::SIGINT);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("shutting down"), "no ack: {err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Watch ended:"), "no end record");
    workload.assert_alive("mid-scan");
}

// Minimal kill without a new dependency.
mod libc_kill {
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;
    pub fn kill(pid: i32, signo: i32) {
        assert_eq!(unsafe { libc::kill(pid, signo) }, 0);
    }
}

/// Passive TLS workload for the Task 5 phase matrix (gaps §4.4
/// recipe): a python `ssl` import asleep for 300s. The observer
/// under test must never signal it — every leg asserts /proc
/// aliveness after the observer exits. Killed + reaped on drop.
struct Workload {
    child: std::process::Child,
}

impl Workload {
    /// Probe-then-spawn: `None` (the caller skips honestly) when
    /// python3+ssl is unavailable — the harvest-test precedent.
    fn spawn() -> Option<Self> {
        let probe = std::process::Command::new("python3")
            .args(["-c", "import ssl"])
            .output();
        match probe {
            Ok(output) if output.status.success() => {}
            _ => return None,
        }
        let child = std::process::Command::new("python3")
            .args(["-c", "import ssl, time; time.sleep(300)"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        // Let the interpreter reach the sleep so the workload is a
        // settled TLS process (libcrypto mapped) before any scan.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let workload = Self { child };
        assert!(workload.alive(), "workload died right after spawn");
        Some(workload)
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Brief-literal (d): /proc presence, not just `try_wait`.
    fn alive(&self) -> bool {
        let pid = self.pid();
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    fn assert_alive(&self, leg: &str) {
        let pid = self.pid();
        assert!(
            self.alive(),
            "{leg}: workload pid {pid} gone — the observer must never signal it"
        );
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Unique file sink for one signaled observer's stdout: a file
/// never deadlocks a bounded `try_wait` poll, while a 300KB
/// full-system record would fill a pipe the polling parent is not
/// draining. Tags are unique per leg; the pid disambiguates
/// concurrent test binaries.
fn stdout_sink(tag: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    std::env::temp_dir().join(format!("osslscope-sig-{tag}-{pid}.out"))
}

/// Bounded reap for signaled observers (shutdown liveness IS the
/// assertion: a hang fails instead of hanging the suite).
/// Stdout must NOT be piped — see [`stdout_sink`]; the small
/// piped stderr (ack + reason lines) is drained after the reap.
fn wait_bounded(
    child: &mut std::process::Child,
    limit: std::time::Duration,
    leg: &str,
) -> (std::process::ExitStatus, Vec<u8>) {
    let started = std::time::Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read as _;
                    pipe.read_to_end(&mut stderr).expect("drain stderr");
                }
                return (status, stderr);
            }
            None => {
                if started.elapsed() >= limit {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{leg}: observer still alive after {limit:?} — shutdown hung");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Brief-literal bare full-system scan (runs 1 and 3 of the
/// acquisition leg): self-terminating, so the repo-idiomatic
/// unbounded `wait_with_output` applies. Returns the wall time —
/// run 1 doubles as the acquisition baseline the middle run's
/// signal timing self-calibrates against.
fn bare_full_scan(workload: &Workload, run: u8) -> std::time::Duration {
    let started = std::time::Instant::now();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["scan", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let wall = started.elapsed();
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(3) | Some(4)),
        "run {run}: bare scan exit {code:?}"
    );
    // No-corruption clause, whole-document form: one-shot --json
    // renders a single pretty document, so the bytes must parse
    // whole (the NDJSON line form belongs to the watch run).
    let doc: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("run {run}: stdout must parse as one JSON document: {e}"));
    let wpid = workload.pid() as u64;
    assert!(
        doc["processes"]
            .as_array()
            .is_some_and(|p| p.iter().any(|r| r["pid"].as_u64() == Some(wpid))),
        "run {run}: full sample must name workload pid {wpid}"
    );
    workload.assert_alive(&format!("run {run}"));
    wall
}

/// Acquisition phase (Task 5 b, ADAPTED — Task-4-N1 family): the
/// brief-literal bare `scan` cannot ack — one-shot scan/inspect
/// routes are deliberately uninstrumented (no Shutdown; SIGINT
/// kills with 128+signo — `service/signals.rs`, Task-3 N2/M3,
/// reviewed). The acquisition phase that DOES share Shutdown is
/// the in-flight sample of `scan --watch`, so only the signaled
/// middle run is a watch; runs 1 and 3 stay brief-literal bare
/// full-system scans (baseline + no-pollution, with full samples
/// proving the workload is really observed).
#[test]
fn v060_sigint_mid_acquisition_acks_and_exits_3() {
    let workload = match Workload::spawn() {
        Some(workload) => workload,
        None => {
            eprintln!("skip: need python3 with ssl for the workload");
            return;
        }
    };
    // Run 1: baseline. A full watch sample costs ~= this (same
    // scope + snapshot work), so the middle run signals at half
    // the baseline — mid-sample-1 on any host whose full sample
    // outlasts the 200ms setup floor (measured 3.4s here).
    let baseline = bare_full_scan(&workload, 1);
    // Run 2: full-system watch, SIGINT self-calibrated to
    // mid-acquisition.
    let signal_after = (baseline / 2).clamp(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(2),
    );
    let stdout_path = stdout_sink("acq2");
    let sink = std::fs::File::create(&stdout_path).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--json",
            "--interval",
            "1",
            "--duration",
            "120",
        ])
        .stdout(sink)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(signal_after);
    libc_kill::kill(child.id() as i32, libc_kill::SIGINT);
    let (status, stderr) = wait_bounded(
        &mut child,
        std::time::Duration::from_secs(15),
        "acquisition run",
    );
    assert_eq!(status.code(), Some(3));
    let err = String::from_utf8_lossy(&stderr);
    assert!(
        err.contains("shutting down") && err.contains("SIGINT"),
        "no SIGINT ack: {err}"
    );
    let text = std::fs::read_to_string(&stdout_path).unwrap();
    let _ = std::fs::remove_file(&stdout_path);
    // No-corruption clause, NDJSON form: watch --json emits one
    // record per line — every line must parse (a signal only flips
    // the cancel flag, never tears a write), and the last line is
    // the interrupted end record (always present, even when the
    // signal lands before the first sample).
    let mut records = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        records.push(
            serde_json::from_str::<Value>(line).expect("every stdout line must parse as JSON"),
        );
    }
    assert!(!records.is_empty(), "watch must always emit its end record");
    let end = records.last().unwrap();
    assert_eq!(end["record"].as_str(), Some("end"));
    assert_eq!(end["reason"].as_str(), Some("interrupted"));
    assert_eq!(end["status"].as_u64(), Some(3));
    // Proven-acquisition marker (gated on a proven precondition):
    // with ≥300ms between the signal and the earliest possible
    // sample end, the in-flight sample was provably cut early, so
    // it carries Deadline gaps (Task 2: cancel ends acquisition
    // with the same gap a timeout produces). Skipped only on
    // hosts too fast to prove the phase — the contract above
    // holds regardless of where the signal lands.
    if signal_after + std::time::Duration::from_millis(300) < baseline {
        assert!(
            records
                .iter()
                .any(|r| r["record"].as_str() == Some("snapshot")
                    && r["snapshot"]["gaps"].as_array().is_some_and(|g| g
                        .iter()
                        .any(|gap| gap["reason"].as_str() == Some("deadline")))),
            "signal provably mid-sample but no deadline gap"
        );
    }
    workload.assert_alive("acquisition run");
    // Run 3: the environment is unpolluted (same full-sample
    // proofs as run 1).
    bare_full_scan(&workload, 3);
}

/// Observation-phase SIGTERM (Task 5 c): `--watch` scoped to the
/// workload pid, whose samples take milliseconds — the 1.5s
/// signal lands in the inter-sample wait, post-acquisition. The
/// ack must NAME the signal.
#[test]
fn v060_sigterm_during_watch_acks_sigterm_and_exits_3() {
    let workload = match Workload::spawn() {
        Some(workload) => workload,
        None => {
            eprintln!("skip: need python3 with ssl for the workload");
            return;
        }
    };
    let pid = workload.pid().to_string();
    let stdout_path = stdout_sink("term");
    let sink = std::fs::File::create(&stdout_path).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            pid.as_str(),
            "--interval",
            "1",
            "--duration",
            "60",
        ])
        .stdout(sink)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    libc_kill::kill(child.id() as i32, libc_kill::SIGTERM);
    let (status, stderr) = wait_bounded(
        &mut child,
        std::time::Duration::from_secs(15),
        "sigterm run",
    );
    assert_eq!(status.code(), Some(3));
    let err = String::from_utf8_lossy(&stderr);
    assert!(
        err.contains("SIGTERM") && err.contains("shutting down"),
        "ack must name SIGTERM: {err}"
    );
    let text = std::fs::read_to_string(&stdout_path).unwrap();
    let _ = std::fs::remove_file(&stdout_path);
    assert!(
        text.contains("Watch ended:") && text.contains("interrupted"),
        "no interrupted end record"
    );
    workload.assert_alive("sigterm run");
}
