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

#[test]
fn setup_spy_invalid_input_precedes_effects() {
    // Invalid numerics exit 2 on deliberately missing-file setup
    // (valid input reaches setup and fails 4): admission precedes
    // provider reads and BPF preparation on every verb.
    assert_eq!(
        run_inspect(&base_inspect(&["--timeout", "121"])),
        ExitCode::from(2)
    );
    assert_eq!(
        run_inspect(&base_inspect(&["--settle", "31"])),
        ExitCode::from(2)
    );
    assert_eq!(
        run_inspect(&base_inspect(&["--timeout", "60"])),
        ExitCode::from(4)
    );
    // Invalid input also precedes child creation: the `run --`
    // command would touch this sentinel if parsing let it through.
    let sentinel =
        std::env::temp_dir().join(format!("osslscope-r07-nospawn-{}", std::process::id()));
    let _ = std::fs::remove_file(&sentinel);
    let touch = format!("touch {}", sentinel.display());
    for args in [
        base_capture(&["--timeout", "121", "run", "--", "/bin/sh", "-c", &touch]),
        base_capture(&[
            "--deny-weak",
            "--settle",
            "31",
            "run",
            "--",
            "/bin/sh",
            "-c",
            &touch,
        ]),
        // Empty provider matchers are admission errors too.
        base_capture(&["--deny-provider", "", "run", "--", "/bin/sh", "-c", &touch]),
        base_capture(&[
            "--require-provider",
            "",
            "run",
            "--",
            "/bin/sh",
            "-c",
            &touch,
        ]),
    ] {
        // Route by rule presence: --deny-provider/--require-provider/
        // --deny-weak imply check, else report.
        let is_check = args
            .iter()
            .any(|a| a.contains("provider") || a == "--deny-weak");
        let code = if is_check {
            run_check(&args)
        } else {
            run_report(&args)
        };
        assert_eq!(code, ExitCode::from(2), "no-spawn {args:?}");
    }
    assert!(!sentinel.exists(), "child must not spawn on invalid input");
    let _ = std::fs::remove_file(&sentinel);
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
    // Normal harvest + failed artifact write.
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Ok(complete_doc()),
        |_| Err("write /nonexistent-r07-dir/out.json: test delivery".to_string()),
    );
    assert_eq!(code, ExitCode::from(1));
    // Recycle harvest + failed discard write: delivery still 1.
    let code = osslscope::inspect::run_with(
        &harvest_cfg(),
        |_| Err::<serde_json::Value, _>(anyhow::Error::new(Recycled { doc: partial_doc() })),
        |_| Err("write /nonexistent-r07-dir/out.json: test delivery".to_string()),
    );
    assert_eq!(code, ExitCode::from(1));
    // Real delivery failure through run(): unwritable --out dir with
    // valid admission fails the artifact write — but harvest setup on
    // bogus paths fails first (exit 4), proving delivery is ordered
    // after harvest, not confused with usage.
    let code = run_inspect(&base_inspect(&["--out", "/nonexistent-r07-dir/out.json"]));
    assert_eq!(code, ExitCode::from(4));
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
