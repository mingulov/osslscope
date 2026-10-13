//! SPDX-License-Identifier: GPL-3.0-or-later
//! R07 CLI admission (F08/F15/I03): `inspect` shares the bounded
//! float parser/defaults with `report`/`check`, and empty provider
//! matchers are usage errors on every occurrence — all before any
//! provider read, BPF preparation, or child creation.

use std::process::ExitCode;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Inspect base: bogus provider/object paths. Anything past parsing
/// fails harvest setup (exit 4), so exit 2 proves rejection happened
/// in the parser, before provider reads/BPF preparation.
fn base_inspect(extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "--pid",
        "1",
        "--provider",
        "/nonexistent-r07/provider.so",
        "--object",
        "/nonexistent-r07/harvest.bpf.o",
    ];
    v.extend(extra.iter());
    argv(&v)
}

/// Report/check base (cf. cli_limits): bogus BPF objects, same
/// 2-vs-4 discriminator.
fn base_capture(extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "--provider",
        "p",
        "--object",
        "/nonexistent-r07-o.so",
        "--count-object",
        "/nonexistent-r07-c.so",
    ];
    v.extend(extra.iter());
    argv(&v)
}

fn run_report(args: &[String]) -> ExitCode {
    osslscope::report::run(args)
}

fn run_check(args: &[String]) -> ExitCode {
    osslscope::check::run(args)
}

fn run_inspect(args: &[String]) -> ExitCode {
    osslscope::inspect::run(args)
}

#[test]
fn cross_verb_timeout_settle_matrix() {
    // (flag, accepted values, rejected values). Accepted values must
    // reach setup (exit 4 on the bogus paths); rejected values must
    // be usage errors (exit 2) on every verb.
    let matrix: &[(&str, &[&str], &[&str])] = &[
        (
            "--timeout",
            &["0", "0.5", "2", "60", "120"],
            &[
                "120.000001",
                "121",
                "18446744073709551615",
                "NaN",
                "inf",
                "-inf",
                "+infinity",
                "1e30",
                "1e-300",
                "1e-9999",
                "-1",
                "-0.5",
                "abc",
                "",
            ],
        ),
        (
            "--settle",
            &["0", "0.5", "2", "30"],
            &[
                "30.000001",
                "31",
                "18446744073709551615",
                "NaN",
                "inf",
                "-inf",
                "+infinity",
                "1e30",
                "1e-300",
                "1e-9999",
                "-1",
                "abc",
                "",
            ],
        ),
    ];
    for (flag, accepted, rejected) in matrix {
        for value in *accepted {
            let r = run_report(&base_capture(&[flag, value, "--pid", "1"]));
            assert_eq!(r, ExitCode::from(4), "report {flag} {value} accepted");
            let c = run_check(&base_capture(&[flag, value, "--deny-weak", "--pid", "1"]));
            assert_eq!(c, ExitCode::from(4), "check {flag} {value} accepted");
            let i = run_inspect(&base_inspect(&[flag, value]));
            assert_eq!(i, ExitCode::from(4), "inspect {flag} {value} accepted");
        }
        for value in *rejected {
            let r = run_report(&base_capture(&[flag, value, "--pid", "1"]));
            assert_eq!(r, ExitCode::from(2), "report {flag} {value:?} rejected");
            let c = run_check(&base_capture(&[flag, value, "--deny-weak", "--pid", "1"]));
            assert_eq!(c, ExitCode::from(2), "check {flag} {value:?} rejected");
            let i = run_inspect(&base_inspect(&[flag, value]));
            assert_eq!(i, ExitCode::from(2), "inspect {flag} {value:?} rejected");
        }
    }
}

#[test]
fn inspect_usage_errors_are_exit2() {
    // Unknown flags, missing values, and missing required args never
    // reach harvest setup.
    for extra in [
        vec!["--bogus", "1"],
        vec!["--timeout"],
        vec!["--settle"],
        vec!["--pid"],
        vec!["--provider"],
        vec!["--object"],
    ] {
        let code = run_inspect(&base_inspect(&extra));
        assert_eq!(code, ExitCode::from(2), "inspect {extra:?}");
    }
    // Missing --pid entirely.
    let no_pid = argv(&[
        "--provider",
        "/nonexistent-r07/provider.so",
        "--object",
        "/nonexistent-r07/harvest.bpf.o",
    ]);
    assert_eq!(run_inspect(&no_pid), ExitCode::from(2));
    // Missing --object entirely.
    let no_object = argv(&["--pid", "1", "--provider", "/nonexistent-r07/provider.so"]);
    assert_eq!(run_inspect(&no_object), ExitCode::from(2));
}

// ------------------------------- admission-before-effects ordering
//
// Finding-1 fix: explicit verb selection (each case names its verb;
// no routing heuristic) and observable effect spies with positive
// controls.
//
// Spy design (report/check): `--out` artifact presence. Both verbs
// attempt every requested artifact even on setup failure (F-E/B4),
// so on the bogus BPF objects valid input reaches setup and WRITES
// the spy file (positive control, exit 4), while invalid input must
// exit 2 with NO spy file — proving admission rejected before setup
// ran. BPF preparation, provider reads, and child creation all live
// inside setup (child creation additionally after BPF resolution),
// so setup-not-reached transitively proves none of them ran. (The
// old `touch` sentinel proved nothing: BPF resolution fails before
// any spawn, and a stopped child never execs.)
//
// Coupling: every check case carries a valid rule (`--deny-weak`)
// so the invalid numeric/matcher is the ONLY possible usage error —
// removing validation flips these cases to exit 4 + spy file
// (demonstrated by mutation in the fix report).

use std::sync::atomic::{AtomicUsize, Ordering};

static SPY_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Unique pre-removed spy path (parallel-safe within/across runs).
fn spy_path(tag: &str) -> std::path::PathBuf {
    let n = SPY_SEQ.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "osslscope-r07-{}-{}-{}.json",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn capture_with_spy(extra: &[&str], spy: &std::path::Path) -> Vec<String> {
    let mut v = base_capture(extra);
    // `--out` must precede `run`: everything after the separator is
    // the target command, not CLI flags.
    match v.iter().position(|a| a == "run") {
        Some(pos) => {
            v.insert(pos, "--out".to_string());
            v.insert(pos + 1, spy.to_string_lossy().to_string());
        }
        None => {
            v.push("--out".to_string());
            v.push(spy.to_string_lossy().to_string());
        }
    }
    v
}

#[test]
fn ordering_report_invalid_input_precedes_setup() {
    // Explicit verb: report::run only.
    let invalid: &[&[&str]] = &[
        &["--timeout", "121", "--pid", "1"],
        &["--timeout", "NaN", "--pid", "1"],
        &["--timeout", "1e-300", "--pid", "1"],
        &["--settle", "31", "--pid", "1"],
        &["--settle", "1e30", "--pid", "1"],
        &["--bogus", "1", "--pid", "1"],
        // Spawn-target shape: `run --` with an invalid numeric still
        // rejects before setup (child creation lives inside setup).
        &["--timeout", "121", "run", "--", "/bin/true"],
        &["--settle", "31", "run", "--", "/bin/true"],
    ];
    for extra in invalid {
        let spy = spy_path("report-invalid");
        let code = run_report(&capture_with_spy(extra, &spy));
        assert_eq!(code, ExitCode::from(2), "report {extra:?}");
        assert!(
            !spy.exists(),
            "report {extra:?}: no artifact on usage error (setup never reached)"
        );
        let _ = std::fs::remove_file(&spy);
    }
    // Positive controls: valid input reaches setup (exit 4 on the
    // bogus BPF objects) AND writes the spy artifact — the spy
    // mechanism fires when setup runs.
    for extra in [
        vec!["--timeout", "60", "--pid", "1"],
        vec![
            "--timeout",
            "0.5",
            "--settle",
            "30",
            "run",
            "--",
            "/bin/true",
        ],
    ] {
        let spy = spy_path("report-valid");
        let code = run_report(&capture_with_spy(&extra, &spy));
        assert_eq!(code, ExitCode::from(4), "report {extra:?}");
        assert!(spy.exists(), "report {extra:?}: setup writes the spy");
        assert!(
            std::fs::metadata(&spy).map(|m| m.len()).unwrap_or(0) > 0,
            "report {extra:?}: spy artifact is nonempty"
        );
        let _ = std::fs::remove_file(&spy);
    }
}

#[test]
fn ordering_check_invalid_input_precedes_setup() {
    // Explicit verb: check::run only. Every invalid-numeric case
    // carries a valid rule (--deny-weak) so the numeric is the ONLY
    // possible usage error: removing numeric validation flips the
    // case to exit 4 + spy file (coupling proof by mutation).
    let invalid: &[&[&str]] = &[
        &["--deny-weak", "--timeout", "121", "--pid", "1"],
        &["--deny-weak", "--timeout", "NaN", "--pid", "1"],
        &["--deny-weak", "--settle", "31", "--pid", "1"],
        &["--deny-weak", "--settle", "1e30", "--pid", "1"],
        &["--deny-weak", "--timeout", "121", "run", "--", "/bin/true"],
        // Empty provider matchers are admission errors too (matcher
        // guard coupling: removing the guard admits the rule and
        // reaches setup).
        &["--deny-provider", "", "--pid", "1"],
        &["--require-provider", "", "--pid", "1"],
        &["--deny-provider", "", "run", "--", "/bin/true"],
    ];
    for extra in invalid {
        let spy = spy_path("check-invalid");
        let code = run_check(&capture_with_spy(extra, &spy));
        assert_eq!(code, ExitCode::from(2), "check {extra:?}");
        assert!(
            !spy.exists(),
            "check {extra:?}: no artifact on usage error (setup never reached)"
        );
        let _ = std::fs::remove_file(&spy);
    }
    // Positive controls: valid input + valid rule reaches setup
    // (exit 4) and writes the spy.
    for extra in [
        vec!["--deny-weak", "--timeout", "60", "--pid", "1"],
        vec!["--deny-weak", "run", "--", "/bin/true"],
        vec!["--require-provider", "third-party:deadbeef", "--pid", "1"],
    ] {
        let spy = spy_path("check-valid");
        let code = run_check(&capture_with_spy(&extra, &spy));
        assert_eq!(code, ExitCode::from(4), "check {extra:?}");
        assert!(spy.exists(), "check {extra:?}: setup writes the spy");
        assert!(
            std::fs::metadata(&spy).map(|m| m.len()).unwrap_or(0) > 0,
            "check {extra:?}: spy artifact is nonempty"
        );
        let _ = std::fs::remove_file(&spy);
    }
}

#[test]
fn ordering_inspect_invalid_input_precedes_effects() {
    // Explicit verb: inspect::run only, plus the pure parse() seam
    // (parse performs no IO by construction: Err proves the parser
    // itself rejected, before any provider/BPF effect is reachable).
    let invalid: &[&[&str]] = &[
        &["--timeout", "121"],
        &["--timeout", "NaN"],
        &["--settle", "31"],
        &["--bogus", "1"],
    ];
    for extra in invalid {
        assert!(
            osslscope::inspect::parse(&base_inspect(extra)).is_err(),
            "inspect parse rejects {extra:?}"
        );
        let spy = spy_path("inspect-invalid");
        let mut args = base_inspect(extra);
        args.push("--out".to_string());
        args.push(spy.to_string_lossy().to_string());
        assert_eq!(run_inspect(&args), ExitCode::from(2), "inspect {extra:?}");
        assert!(
            !spy.exists(),
            "inspect {extra:?}: no artifact on usage error"
        );
        let _ = std::fs::remove_file(&spy);
    }
    // Positive controls: valid input parses (60/2 defaults) and
    // reaches setup (exit 4 on bogus paths). Inspect emits nothing
    // on setup failure (pinned by inspect_outcome_environment_is_exit4),
    // so no spy file here is EXPECTED — the file-spy mechanism
    // itself is proved by the production-emitter tests below.
    let parsed = osslscope::inspect::parse(&base_inspect(&[])).expect("minimal args parse");
    assert_eq!(parsed.timeout, std::time::Duration::from_secs(60));
    let spy = spy_path("inspect-valid");
    let mut args = base_inspect(&[]);
    args.push("--out".to_string());
    args.push(spy.to_string_lossy().to_string());
    assert_eq!(run_inspect(&args), ExitCode::from(4));
    assert!(!spy.exists(), "inspect emits nothing on setup failure");
    let _ = std::fs::remove_file(&spy);
}

#[test]
fn ordering_inspect_harvest_spy_fires_on_valid_stays_zero_on_invalid() {
    // Fix-round-2 (re-review F1): production harvest-call spy.
    // inspect emits nothing on setup failure, so the --out file spy
    // cannot distinguish "setup ran" from "setup never reached" —
    // both leave the file absent. This spy counts PRODUCTION
    // harvest invocations (thread-local): it must fire exactly once
    // for valid input (exit 4 on the bogus paths) and stay at zero
    // for invalid input (exit 2), proving invalid input is rejected
    // before any provider read / BPF preparation.
    use osslscope::inspect::{harvest_calls, reset_harvest_calls};
    let invalid: &[&[&str]] = &[
        &["--timeout", "121"],
        &["--timeout", "NaN"],
        &["--timeout", "1e-300"],
        &["--settle", "31"],
        &["--settle", "1e30"],
        &["--bogus", "1"],
        &["--timeout"],
    ];
    for extra in invalid {
        reset_harvest_calls();
        assert_eq!(
            run_inspect(&base_inspect(extra)),
            ExitCode::from(2),
            "inspect {extra:?}"
        );
        assert_eq!(
            harvest_calls(),
            0,
            "inspect {extra:?}: usage rejection precedes harvest setup (no provider read)"
        );
    }
    // Missing required args are usage errors too.
    reset_harvest_calls();
    assert_eq!(run_inspect(&argv(&["--pid", "1"])), ExitCode::from(2));
    assert_eq!(harvest_calls(), 0, "missing args precede harvest setup");
    // Positive controls: valid input reaches production harvest
    // (exit 4 on the bogus BPF objects) and the spy fires exactly
    // once per run.
    for extra in [
        Vec::<&str>::new(),
        vec!["--timeout", "0.5", "--settle", "30"],
    ] {
        reset_harvest_calls();
        assert_eq!(
            run_inspect(&base_inspect(&extra)),
            ExitCode::from(4),
            "inspect {extra:?}"
        );
        assert_eq!(
            harvest_calls(),
            1,
            "inspect {extra:?}: setup ran exactly once"
        );
    }
}

#[test]
fn ordering_inspect_harvest_spy_is_cumulative_across_runs() {
    // Cumulativity pin for the harvest spy (renamed in fix round 3:
    // the round-2 name overclaimed — a forced setup attempt in one
    // run followed by a usage rejection in the NEXT run proves the
    // counter is cumulative, not that it would catch a genuine
    // premature read inside the rejected invocation. That closure is
    // ordering_inspect_no_read_syscall_before_admission below).
    use osslscope::inspect::{harvest_calls, reset_harvest_calls};
    reset_harvest_calls();
    // Force a REAL production provider-read attempt first: valid
    // admission reaches harvest::run, whose first effect is
    // fs::read(&cfg.provider) (bogus here → setup exit 4).
    assert_eq!(run_inspect(&base_inspect(&[])), ExitCode::from(4));
    assert_eq!(harvest_calls(), 1, "the forced setup attempt fired the spy");
    // ... followed by a normal usage rejection (which itself must
    // fire nothing further).
    assert_eq!(
        run_inspect(&base_inspect(&["--timeout", "121"])),
        ExitCode::from(2)
    );
    assert_eq!(
        harvest_calls(),
        1,
        "usage rejection adds no setup call, but the earlier attempt stays observed"
    );
    // The invalid-path control (zero spy) must FAIL now: the spy is
    // cumulative, so the earlier setup attempt is still observed.
    let control_holds = harvest_calls() == 0;
    assert!(
        !control_holds,
        "zero-spy control must FAIL after a setup attempt (calls observed: {})",
        harvest_calls()
    );
}

// ---------- premature-read boundary control (fix round 3, Linux-only)
//
// Root cause addressed: the harvest-call counter proves *invocation*
// ordering (run() reaches harvest::run exactly once per admitted
// call), but it observes only its own marked call site. An ignored
// `std::fs::read(provider)` before parse() performs genuine IO while
// leaving the counter unchanged — all counter assertions stay green.
// This control ties the proof to the ACTUAL read boundary instead:
// per-thread read-syscall counters from /proc. ANY genuine read() on
// this thread moves them, wherever the call site hides, so a
// premature read before admission cannot pass. (Per-thread counters
// keep parallel tests isolated: each test runs on its own thread and
// measures deltas around a single run_inspect call.)

/// (rchar, syscr) for the CURRENT thread, via one fixed-cost snapshot
/// (open + exactly ONE read() call + close — never a read loop — so
/// the snapshot's own syscall cost is exactly 1, immune to digit-width
/// and chunk-boundary shifts).
#[cfg(target_os = "linux")]
fn thread_io() -> (u64, u64) {
    use std::io::Read;
    let tid = unsafe { libc::gettid() };
    let path = format!("/proc/self/task/{tid}/io");
    let mut f = std::fs::File::open(&path).expect("per-thread io counters readable");
    let mut buf = [0u8; 4096];
    let n = f
        .read(&mut buf)
        .expect("single read of io counters issues one read()");
    assert!(
        n < buf.len(),
        "io counters fit one read (got {n} full-buffer bytes?)"
    );
    let text = std::str::from_utf8(&buf[..n]).expect("io counters are utf8");
    let mut rchar = None;
    let mut syscr = None;
    for line in text.lines() {
        let (k, v) = line.split_once(": ").expect("io line is 'key: value'");
        match k {
            "rchar" => rchar = Some(v.trim().parse::<u64>().expect("rchar numeric")),
            "syscr" => syscr = Some(v.trim().parse::<u64>().expect("syscr numeric")),
            _ => {}
        }
    }
    (rchar.expect("rchar present"), syscr.expect("syscr present"))
}

/// Genuine read cost of `f` as (rchar bytes, read() syscalls):
/// double-snapshot cancels the snapshot's own cost, so the result is
/// exactly the reads `f` performed.
#[cfg(target_os = "linux")]
fn read_cost(f: impl FnOnce()) -> (u64, u64) {
    let (r0, s0) = thread_io();
    let (r1, s1) = thread_io();
    f();
    let (r2, s2) = thread_io();
    (
        r2.saturating_sub(r1).saturating_sub(r1 - r0),
        s2.saturating_sub(s1).saturating_sub(s1 - s0),
    )
}

/// Real provider fixture: actual bytes on disk. A premature read must
/// move real bytes through read() to be observable — a bogus path
/// fails at open with no read syscall at all.
#[cfg(target_os = "linux")]
fn provider_fixture(tag: &str) -> std::path::PathBuf {
    let p = spy_path(tag);
    let bytes: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    std::fs::write(&p, &bytes).expect("fixture written");
    p
}

#[cfg(target_os = "linux")]
fn base_inspect_real_provider(provider: &std::path::Path, extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "--pid".to_string(),
        "1".to_string(),
        "--provider".to_string(),
        provider.to_string_lossy().to_string(),
        "--object".to_string(),
        "/nonexistent-r07/harvest.bpf.o".to_string(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

#[test]
#[cfg(target_os = "linux")]
fn ordering_inspect_no_read_syscall_before_admission() {
    // Calibration first: a direct genuine read MUST move the counters
    // in this environment — otherwise every assertion below would be
    // vacuous. Loud failure here, never a silent skip.
    let cal = provider_fixture("prov-cal");
    let (cal_r, cal_s) = read_cost(|| {
        let b = std::fs::read(&cal).expect("calibration read works");
        assert_eq!(b.len(), 4096);
    });
    assert!(
        cal_s > 0,
        "calibration: fixture read issues read() syscalls (syscr +{cal_s})"
    );
    assert!(
        cal_r >= 4000,
        "calibration: fixture read moves real bytes (rchar +{cal_r})"
    );
    let _ = std::fs::remove_file(&cal);

    // Invalid input against a REAL provider file: rejected (exit 2)
    // with ZERO read() syscalls on this thread — no provider read,
    // wherever a premature call site hides.
    let invalid: &[&[&str]] = &[
        &["--timeout", "121"],
        &["--timeout", "NaN"],
        &["--timeout", "1e-300"],
        &["--settle", "31"],
        &["--settle", "1e30"],
        &["--bogus", "1"],
        &["--timeout"],
    ];
    for extra in invalid {
        let prov = provider_fixture("prov-invalid");
        let args = base_inspect_real_provider(&prov, extra);
        let (rc, sc) = read_cost(|| {
            assert_eq!(run_inspect(&args), ExitCode::from(2), "inspect {extra:?}");
        });
        assert_eq!(
            sc, 0,
            "inspect {extra:?}: rejected before any read() syscall"
        );
        assert!(
            rc <= 8,
            "inspect {extra:?}: no bytes read (rchar +{rc}; slack covers counter digit-width shifts)"
        );
        let _ = std::fs::remove_file(&prov);
    }
    // Missing required args clear the same bar.
    for args in [
        argv(&["--pid", "1"]),
        argv(&["--pid", "1", "--provider", "/nonexistent-r07/provider.so"]),
    ] {
        let (rc, sc) = read_cost(|| {
            assert_eq!(run_inspect(&args), ExitCode::from(2), "{args:?}");
        });
        assert_eq!(sc, 0, "missing args rejected before any read() syscall");
        assert!(rc <= 8, "missing args read no bytes (rchar +{rc})");
    }

    // Positive controls: valid admission reaches the REAL
    // provider-read boundary (harvest::run's first effect is
    // fs::read(&cfg.provider)) — genuine bytes move through read() —
    // then setup fails on the bogus BPF object (exit 4). The counters
    // observe the actual boundary, not a marker.
    for extra in [
        Vec::<&str>::new(),
        vec!["--timeout", "0.5", "--settle", "30"],
    ] {
        let prov = provider_fixture("prov-valid");
        let args = base_inspect_real_provider(&prov, &extra);
        let (rc, sc) = read_cost(|| {
            assert_eq!(run_inspect(&args), ExitCode::from(4), "inspect {extra:?}");
        });
        assert!(
            sc > 0,
            "inspect {extra:?}: setup performs read() syscalls (syscr +{sc})"
        );
        assert!(
            rc >= 4000,
            "inspect {extra:?}: setup reads real provider bytes (rchar +{rc})"
        );
        let _ = std::fs::remove_file(&prov);
    }
}

#[test]
fn provider_matchers_reject_empty_on_every_occurrence() {
    // Each matrix row must be a usage error (exit 2), even with
    // missing BPF objects that would fail setup (4) if admitted.
    let cases: &[&[&str]] = &[
        &["--deny-provider", ""],
        &["--require-provider", ""],
        &["--deny-provider", "default", "--deny-provider", ""],
        &["--deny-provider", "", "--deny-provider", "default"],
        &["--require-provider", "default", "--require-provider", ""],
        &["--require-provider", "", "--require-provider", "default"],
        &["--deny-provider", "default", "--require-provider", ""],
        &["--require-provider", "default", "--deny-provider", ""],
        &["--deny-provider", "", "--deny-weak"],
    ];
    for extra in cases {
        let mut full: Vec<&str> = extra.to_vec();
        full.push("--pid");
        full.push("1");
        let code = run_check(&base_capture(&full));
        assert_eq!(code, ExitCode::from(2), "check {extra:?}");
    }
}

#[test]
fn provider_matchers_accept_nonempty_third_party() {
    // Opaque third-party ids (open-ended, never enumerated) parse and
    // reach setup (exit 4 on the bogus objects). A bare space is
    // nonempty: matchers are NOT trimmed.
    for extra in [
        vec!["--require-provider", "third-party:deadbeef"],
        vec!["--deny-provider", "third-party:deadbeef"],
        vec!["--deny-provider", "acme-widget:1.0"],
        vec!["--require-provider", "x"],
        vec!["--deny-provider", " "],
        vec![
            "--require-provider",
            "default",
            "--deny-provider",
            "third-party:deadbeef",
        ],
    ] {
        let mut full = extra.clone();
        full.push("--pid");
        full.push("1");
        let code = run_check(&base_capture(&full));
        assert_eq!(code, ExitCode::from(4), "check {extra:?}");
    }
}

// ------------------------------------------------- inspect parse seam

#[test]
fn inspect_defaults_are_timeout60_settle2() {
    use std::time::Duration;
    assert_eq!(osslscope::inspect::DEFAULT_TIMEOUT, Duration::from_secs(60));
    assert_eq!(osslscope::inspect::DEFAULT_SETTLE, Duration::from_secs(2));
    let parsed = osslscope::inspect::parse(&base_inspect(&[])).expect("minimal args parse");
    assert_eq!(parsed.timeout, Duration::from_secs(60));
    assert_eq!(parsed.settle, Duration::from_secs(2));
    assert_eq!(parsed.pid, 1);
    // Explicit values override defaults exactly, including floats.
    let parsed = osslscope::inspect::parse(&base_inspect(&["--timeout", "0.5", "--settle", "30"]))
        .expect("explicit times parse");
    assert_eq!(parsed.timeout, Duration::from_millis(500));
    assert_eq!(parsed.settle, Duration::from_secs(30));
}

// ------------------------------------------ injectable inspect outcomes

use osslscope::discovery::harvest::{Config as HarvestConfig, Recycled};
use std::cell::Cell;

fn harvest_cfg() -> HarvestConfig {
    HarvestConfig {
        pid: 1,
        provider: "/nonexistent-r07/provider.so".into(),
        object: "/nonexistent-r07/harvest.bpf.o".into(),
        settle: std::time::Duration::from_secs(2),
        timeout: std::time::Duration::from_secs(60),
        cmdline_marker: None,
        builtin: false,
        legacy: false,
        table: None,
        force_offset: None,
        observed_from_birth: false,
    }
}

/// COMPLETE provider docs carry no `status` key (P1 byte-compat).
fn complete_doc() -> serde_json::Value {
    serde_json::json!({
        "provider": "p",
        "trigger_observed": true,
        "gen": 0,
        "rows": [{"op": 1, "alg_class": "SHA2-256", "weak": false,
                  "status": "ok", "funcid": 7}],
    })
}

/// Relevant PARTIAL: explicit frozen-vocabulary reason plus gaps.
fn partial_doc() -> serde_json::Value {
    serde_json::json!({
        "provider": "p",
        "trigger_observed": false,
        "gen": 0,
        "rows": [],
        "status": "PARTIAL",
        "reason": "no-query-trigger",
        "uninstrumented_ops": 11,
    })
}

#[test]
fn inspect_outcome_normal_is_exit0() {
    assert!(!osslscope::inspect::is_partial_doc(&complete_doc()));
    let emitted = Cell::new(0);
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |cfg| {
            assert_eq!(cfg.timeout, std::time::Duration::from_secs(60));
            assert_eq!(cfg.settle, std::time::Duration::from_secs(2));
            Ok(complete_doc())
        },
        |doc| {
            emitted.set(emitted.get() + 1);
            assert_eq!(doc["provider"], "p");
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(0));
    assert_eq!(emitted.get(), 1, "normal path emits exactly once");
}

#[test]
fn inspect_outcome_relevant_partial_is_exit3() {
    assert!(osslscope::inspect::is_partial_doc(&partial_doc()));
    // A bare unknown status is not PARTIAL (COMPLETE carries none).
    assert!(!osslscope::inspect::is_partial_doc(
        &serde_json::json!({"status": "COMPLETE"})
    ));
    let emitted = Cell::new(0);
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(partial_doc()),
        |doc| {
            emitted.set(emitted.get() + 1);
            assert_eq!(doc["reason"], "no-query-trigger");
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(3));
    assert_eq!(emitted.get(), 1, "PARTIAL doc still travels");
}

#[test]
fn inspect_outcome_environment_is_exit4() {
    let emitted = Cell::new(0);
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Err::<serde_json::Value, _>(anyhow::anyhow!("target 1 vanished: test environment")),
        |_| {
            emitted.set(emitted.get() + 1);
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(4));
    assert_eq!(emitted.get(), 0, "environment failure emits nothing");
}

#[test]
fn inspect_outcome_recycle_is_exit4() {
    // Recycle is already 4: the discard doc travels, never rows.
    let emitted = Cell::new(0);
    let discard = serde_json::json!({
        "provider": "p", "trigger_observed": false, "gen": 0, "rows": [],
        "status": "PARTIAL", "reason": "pid-recycled", "pid_recycled": 1,
    });
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Err::<serde_json::Value, _>(anyhow::Error::new(Recycled { doc: discard })),
        |doc| {
            emitted.set(emitted.get() + 1);
            assert_eq!(doc["reason"], "pid-recycled");
            assert!(doc["rows"].as_array().unwrap().is_empty());
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(4));
    assert_eq!(emitted.get(), 1, "recycle discard doc travels");
}

#[test]
fn inspect_outcome_delivery_failure_is_exit1() {
    // Normal harvest + failed artifact write: delivery failure 1.
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(complete_doc()),
        |_| Err("write /nonexistent-r07-dir/out.json: test delivery".to_string()),
    );
    assert_eq!(code, ExitCode::from(1));
    // Recycle harvest + failed discard write: the discard delivery
    // is still ATTEMPTED (emit called once) and its failure
    // reported, but recycle/no-verdict 4 precedes artifact failure 1
    // (plan exit precedence 2 → 4/no-verdict → 10 → 1 → ...).
    let emitted = Cell::new(0);
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Err::<serde_json::Value, _>(anyhow::Error::new(Recycled { doc: partial_doc() })),
        |doc| {
            emitted.set(emitted.get() + 1);
            assert_eq!(doc["reason"], "no-query-trigger");
            Err("write /nonexistent-r07-dir/out.json: test delivery".to_string())
        },
    );
    assert_eq!(code, ExitCode::from(4));
    assert_eq!(emitted.get(), 1, "recycle discard delivery is attempted");
}

#[test]
fn inspect_outcome_production_emitter_file_delivery() {
    // Real file delivery through the PRODUCTION emitter (replaces
    // the old harvest-setup-masked case): unwritable --out maps to
    // exit 1, never confused with usage 2 or setup 4.
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(complete_doc()),
        |doc| {
            osslscope::inspect::emit_doc(
                doc,
                Some(std::path::Path::new("/nonexistent-r07-dir/out.json")),
                &mut std::io::sink(),
            )
        },
    );
    assert_eq!(code, ExitCode::from(1));
    // Positive control: the production emitter writes --out files.
    let spy = spy_path("inspect-emit");
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(complete_doc()),
        |doc| osslscope::inspect::emit_doc(doc, Some(&spy), &mut std::io::sink()),
    );
    assert_eq!(code, ExitCode::from(0));
    let text = std::fs::read_to_string(&spy).expect("spy file written");
    let back: serde_json::Value = serde_json::from_str(&text).expect("spy is JSON");
    assert_eq!(back["provider"], "p");
    let _ = std::fs::remove_file(&spy);
    // Setup precedes delivery at run() level (labeled ordering pin,
    // not a delivery test): valid admission + unwritable --out +
    // bogus BPF fails harvest setup first (exit 4).
    let code = run_inspect(&base_inspect(&["--out", "/nonexistent-r07-dir/out.json"]));
    assert_eq!(code, ExitCode::from(4));
}

#[test]
fn inspect_outcome_broken_pipe_stdout_is_exit1_without_panic() {
    use std::os::unix::net::UnixStream;
    // Real OS-level broken pipe through the PRODUCTION emitter: a
    // socketpair with the peer closed makes the kernel return EPIPE
    // on write (Rust ignores SIGPIPE, so no signal death — the
    // failure must surface as delivery exit 1, never a panic/101).
    let (mut broken, peer) = UnixStream::pair().expect("socketpair");
    drop(peer);
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(complete_doc()),
        |doc| osslscope::inspect::emit_doc(doc, None, &mut broken),
    );
    assert_eq!(code, ExitCode::from(1));
    // Direct seam proof: the production emitter maps the real EPIPE
    // to Err (never panics).
    let (mut broken, peer) = UnixStream::pair().expect("socketpair");
    drop(peer);
    let err = osslscope::inspect::emit_doc(&complete_doc(), None, &mut broken)
        .expect_err("EPIPE must surface as Err, not panic");
    assert!(err.contains("stdout"), "names the failed sink: {err}");
    assert!(err.contains("Broken pipe"), "carries the OS cause: {err}");
    // Positive control: stdout delivery to a live writer succeeds
    // byte-identically (pretty JSON + trailing newline, ex-println!).
    let mut buf = Vec::new();
    osslscope::inspect::emit_doc(&complete_doc(), None, &mut buf).expect("live writer delivers");
    assert!(buf.ends_with(b"\n"), "trailing newline preserved");
    let back: serde_json::Value = serde_json::from_slice(&buf).expect("stdout bytes are JSON");
    assert_eq!(back["provider"], "p");
}

#[test]
fn inspect_outcome_usage_is_exit2() {
    for args in [
        base_inspect(&["--timeout", "NaN"]),
        base_inspect(&["--settle", "1e30"]),
        base_inspect(&["--timeout", "121"]),
        argv(&["--pid", "1"]),
    ] {
        assert_eq!(run_inspect(&args), ExitCode::from(2), "{args:?}");
    }
    // Help still exits 0.
    assert_eq!(run_inspect(&argv(&["--help"])), ExitCode::from(0));
    assert_eq!(run_inspect(&base_inspect(&["--help"])), ExitCode::from(0));
}
