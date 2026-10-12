//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 CLI numeric limits (R08) and argv redaction (R07): huge,
//! non-finite, negative and zero-rounding durations exit 2 before any
//! target/BPF side effect; secret argv bytes never reach artifacts.

use osslscope::args::{
    MAX_DURATION_SECS, MAX_GRACE_SECS, MAX_SETTLE_SECS, MAX_TIMEOUT_SECS, REDACTED_CMDLINE,
    parse_seconds,
};
use std::process::ExitCode;
use std::time::Duration;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Full flag set with bogus object paths: anything past parsing fails
/// in capture (exit 4), so exit 2 proves rejection happened in the
/// parser, before target/BPF side effects.
fn base_report(extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "--provider",
        "p",
        "--object",
        "/nonexistent-o.so",
        "--count-object",
        "/nonexistent-c.so",
    ];
    v.extend(extra.iter());
    argv(&v)
}

#[test]
fn r08_upper_boundaries_are_exact() {
    assert_eq!(MAX_DURATION_SECS, 3600.0);
    assert_eq!(MAX_TIMEOUT_SECS, 120.0);
    assert_eq!(MAX_SETTLE_SECS, 30.0);
    assert_eq!(MAX_GRACE_SECS, 30.0);
    // Exactly at the boundary: accepted.
    assert_eq!(
        parse_seconds("--duration", "3600").unwrap(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        parse_seconds("--timeout", "120").unwrap(),
        Duration::from_secs(120)
    );
    assert_eq!(
        parse_seconds("--settle", "30").unwrap(),
        Duration::from_secs(30)
    );
    assert_eq!(
        parse_seconds("--grace", "30").unwrap(),
        Duration::from_secs(30)
    );
    // Just above: rejected.
    assert!(parse_seconds("--duration", "3600.000001").is_err());
    assert!(parse_seconds("--timeout", "120.000001").is_err());
    assert!(parse_seconds("--settle", "30.000001").is_err());
    assert!(parse_seconds("--grace", "30.000001").is_err());
}

#[test]
fn huge_and_nonfinite_values_are_rejected() {
    for flag in ["--duration", "--timeout", "--settle", "--grace"] {
        for bad in [
            "1e30", "1E30", "NaN", "nan", "inf", "-inf", "+inf", "infinity",
        ] {
            assert!(
                parse_seconds(flag, bad).is_err(),
                "{flag} {bad} must be rejected"
            );
        }
    }
    // The audit reproducers (exit 101 panics) are now usage errors.
    assert!(parse_seconds("--duration", "1e30").is_err());
}

#[test]
fn negatives_rejected_zero_grace_accepted() {
    for flag in ["--duration", "--timeout", "--settle", "--grace"] {
        assert!(parse_seconds(flag, "-1").is_err(), "{flag} -1");
        assert!(parse_seconds(flag, "-0.5").is_err(), "{flag} -0.5");
        assert!(parse_seconds(flag, "-1e-9999").is_err(), "{flag} -1e-9999");
    }
    assert!(parse_seconds("--duration", "0").is_err());
    assert!(parse_seconds("--duration", "0.0").is_err());
    assert_eq!(
        parse_seconds("--grace", "0").unwrap(),
        Duration::ZERO,
        "zero grace is valid"
    );
    assert_eq!(parse_seconds("--settle", "0").unwrap(), Duration::ZERO);
    assert_eq!(parse_seconds("--timeout", "0").unwrap(), Duration::ZERO);
    // Genuine zero with a nonzero exponent is still zero.
    for zero in ["0e1", "0E5", "0.0e-10", "00.00"] {
        assert_eq!(
            parse_seconds("--grace", zero).unwrap(),
            Duration::ZERO,
            "{zero} is a true zero"
        );
    }
}

#[test]
fn positive_values_rounded_to_zero_are_invalid() {
    // Parses to a nonzero f64 below Duration resolution ...
    for flag in ["--duration", "--timeout", "--settle", "--grace"] {
        assert!(
            parse_seconds(flag, "1e-300").is_err(),
            "{flag} 1e-300 rounds to zero"
        );
        // ... and values that underflow f64 parsing itself.
        assert!(
            parse_seconds(flag, "1e-9999").is_err(),
            "{flag} 1e-9999 underflows to zero"
        );
    }
}

#[test]
fn malformed_values_and_flags_are_usage_errors() {
    assert_eq!(
        parse_seconds("--duration", "abc").unwrap_err(),
        "--duration needs seconds"
    );
    assert!(parse_seconds("--grace", "").is_err());
    assert!(parse_seconds("--bogus", "5").is_err());
    // Ordinary values convert exactly.
    assert_eq!(
        parse_seconds("--settle", "2.5").unwrap(),
        Duration::from_millis(2500)
    );
}

#[test]
fn checked_deadline_helpers() {
    assert!(osslscope::args::checked_add(Duration::from_secs(1), Duration::from_secs(2)).is_ok());
    assert!(osslscope::args::checked_add(Duration::MAX, Duration::from_secs(1)).is_err());
    let now = std::time::Instant::now();
    assert!(osslscope::args::deadline_at(now, Duration::from_secs(30)).is_some());
    assert!(osslscope::args::deadline_at(now, Duration::MAX).is_none());
}

#[test]
fn report_rejects_bad_numerics_with_exit2_before_side_effects() {
    for extra in [
        vec!["--duration", "1e30", "--pid", "1"],
        vec!["--duration", "NaN", "--pid", "1"],
        vec!["--duration", "inf", "--pid", "1"],
        vec!["--duration", "-5", "--pid", "1"],
        vec!["--duration", "0", "--pid", "1"],
        vec!["--duration", "3601", "--pid", "1"],
        vec!["--duration", "1e-300", "--pid", "1"],
        vec!["--settle", "31", "--pid", "1"],
        vec!["--settle", "-1", "--pid", "1"],
        vec!["--timeout", "121", "--pid", "1"],
        vec!["--grace", "31", "--pid", "1"],
        vec!["--grace", "-1", "--pid", "1"],
    ] {
        let code = osslscope::report::run(&base_report(&extra));
        assert_eq!(code, ExitCode::from(2), "report {extra:?}");
    }
    // Boundary-accepted values parse, then fail loading the bogus
    // BPF object (exit 4) — proving the parser accepted them.
    for extra in [
        vec!["--duration", "3600", "--pid", "1"],
        vec!["--grace", "0", "--pid", "1"],
        vec!["--settle", "30", "--timeout", "120", "--pid", "1"],
    ] {
        let code = osslscope::report::run(&base_report(&extra));
        assert_eq!(code, ExitCode::from(4), "report {extra:?}");
    }
}

#[test]
fn check_rejects_bad_numerics_with_exit2_before_side_effects() {
    // Audit reproducer: `check --duration 1e30 --deny-weak ... --pid 1`
    // panicked (exit 101); now exit 2 with no capture attempted.
    let mut bad = base_report(&["--duration", "1e30", "--deny-weak", "--pid", "1"]);
    assert_eq!(osslscope::check::run(&bad), ExitCode::from(2));
    bad = base_report(&["--duration", "3601", "--deny-weak", "--pid", "1"]);
    assert_eq!(osslscope::check::run(&bad), ExitCode::from(2));
    bad = base_report(&["--grace", "-1", "--deny-weak", "--pid", "1"]);
    assert_eq!(osslscope::check::run(&bad), ExitCode::from(2));
    // Accepted values reach capture and fail on the bogus objects.
    bad = base_report(&["--duration", "3600", "--deny-weak", "--pid", "1"]);
    assert_eq!(osslscope::check::run(&bad), ExitCode::from(4));
}

#[test]
fn invalid_numerics_spawn_no_child() {
    // The `run --` command would touch this file if the parser let a
    // bad duration through to target creation. (Exit 2 already proves
    // capture was never entered — parsing strictly precedes it — so
    // this file assert is defense-in-depth, including against future
    // environments where the object paths below become loadable; a
    // live-BPF variant belongs to the installed acceptance task.)
    let sentinel =
        std::env::temp_dir().join(format!("osslscope-t04-nospawn-{}", std::process::id()));
    let _ = std::fs::remove_file(&sentinel);
    let touch = format!("touch {}", sentinel.display());
    let args = base_report(&["--duration", "1e30", "run", "--", "/bin/sh", "-c", &touch]);
    assert_eq!(osslscope::report::run(&args), ExitCode::from(2));
    assert!(
        !sentinel.exists(),
        "child must not spawn on invalid numerics"
    );
    let _ = std::fs::remove_file(&sentinel);
}

#[test]
fn h9_t6_workload_dest_flags_rejected_with_exit2() {
    // T6 (RED): both destinations → usage error (exit 2), no spawn.
    let sentinel =
        std::env::temp_dir().join(format!("osslscope-h9-nospawn-{}", std::process::id()));
    let _ = std::fs::remove_file(&sentinel);
    let touch = format!("touch {}", sentinel.display());
    for verb in ["report", "check"] {
        let args = base_report(&[
            "--deny-weak",
            "--workload-out",
            "/tmp/h9-x.log",
            "--workload-out-fd",
            "7",
            "run",
            "--",
            "/bin/sh",
            "-c",
            &touch,
        ]);
        // --deny-weak is check-only: strip for report.
        let args = if verb == "report" {
            args.into_iter().filter(|a| a != "--deny-weak").collect()
        } else {
            args
        };
        let code = if verb == "report" {
            osslscope::report::run(&args)
        } else {
            osslscope::check::run(&args)
        };
        assert_eq!(code, ExitCode::from(2), "{verb} both flags");
    }
    assert!(!sentinel.exists(), "child must not spawn");
    let _ = std::fs::remove_file(&sentinel);
    // Non-numeric fd → usage error.
    for (verb, extra) in [
        (
            "report",
            vec!["--workload-out-fd", "seven", "run", "--", "/bin/true"],
        ),
        (
            "check",
            vec![
                "--deny-weak",
                "--workload-out-fd",
                "seven",
                "run",
                "--",
                "/bin/true",
            ],
        ),
    ] {
        let args = base_report(&extra);
        let code = if verb == "report" {
            osslscope::report::run(&args)
        } else {
            osslscope::check::run(&args)
        };
        assert_eq!(code, ExitCode::from(2), "{verb} bad fd");
    }
    // Destinations without `run --` are not silently ignored.
    for (verb, extra) in [
        (
            "report",
            vec!["--workload-out", "/tmp/h9-x.log", "--pid", "1"],
        ),
        (
            "check",
            vec!["--deny-weak", "--workload-out-fd", "7", "--pid", "1"],
        ),
    ] {
        let args = base_report(&extra);
        let code = if verb == "report" {
            osslscope::report::run(&args)
        } else {
            osslscope::check::run(&args)
        };
        assert_eq!(code, ExitCode::from(2), "{verb} dest without run");
    }
    // Accepted values parse, then fail loading the bogus BPF
    // objects (exit 4) — proving the parser accepted them.
    for (verb, extra) in [
        (
            "report",
            vec!["--workload-out", "/tmp/h9-x.log", "run", "--", "/bin/true"],
        ),
        (
            "check",
            vec![
                "--deny-weak",
                "--workload-out-fd",
                "7",
                "run",
                "--",
                "/bin/true",
            ],
        ),
    ] {
        let args = base_report(&extra);
        let code = if verb == "report" {
            osslscope::report::run(&args)
        } else {
            osslscope::check::run(&args)
        };
        assert_eq!(code, ExitCode::from(4), "{verb} dest accepted");
    }
}

const SECRET: &str = "T04-SENTINEL-s3cr3t-argv";

#[test]
fn spawn_argv_is_redacted() {
    let argv = vec!["/bin/sh".to_string(), SECRET.to_string(), "-c".to_string()];
    let out = osslscope::args::redact_spawn_argv(&argv);
    assert_eq!(out, REDACTED_CMDLINE);
    assert!(!out.contains(&SECRET[..8]), "secret bytes must not escape");
}

#[test]
fn redaction_wiring_is_present_in_capture() {
    // Tripwire in the repo's scan-test style (cf. privacy_allowlist):
    // helper unit tests alone would not catch a call-site restoration
    // of raw argv into artifacts, so the acquisition call sites and the
    // absence of the deleted raw renderers are pinned here.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cap = std::fs::read_to_string(root.join("src/capture.rs")).unwrap();
    assert!(
        cap.contains("redact_spawn_argv(&argv)"),
        "spawn argv redaction call site"
    );
    assert!(
        cap.contains("redact_proc_cmdline(&raw)"),
        "pid cmdline redaction call site"
    );
    assert!(
        !cap.contains("fn render_cmdline"),
        "raw argv renderer must stay deleted"
    );
    assert!(
        !cap.contains("fn cmdline_of"),
        "raw cmdline reader must stay deleted"
    );
    assert!(
        !cap.contains("argv.join("),
        "argv must not be joined into artifacts"
    );
    for f in ["src/report.rs", "src/check.rs"] {
        let src = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(
            src.contains("parse_seconds(\"--duration\""),
            "{f} routes duration through the safe parser"
        );
        assert!(
            !src.contains("from_secs_f64(duration)"),
            "{f} must not convert unvalidated floats"
        );
    }
}

#[test]
fn non_utf8_argv_exits_without_panic() {
    // std::env::args() panics on non-UTF8 argv (exit 101); the entry
    // point must reject non-UTF-8 with exit 2, never execute altered
    // bytes. F-G/Bm2: the duration here is VALID, so encoding is the
    // only defect (the old 1e30 masked it behind a second error).
    use std::os::unix::ffi::OsStringExt;
    let secret = std::ffi::OsString::from_vec(b"T04-\xff-secret".to_vec());
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let out = std::process::Command::new(bin)
        .arg("report")
        .args(["--duration", "30", "--provider"])
        .arg(&secret)
        .args(["--object", "o", "--count-object", "c", "--pid", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "must be a usage error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
    assert!(
        stderr.to_lowercase().contains("utf-8") || stderr.to_lowercase().contains("utf8"),
        "must diagnose encoding: {stderr}"
    );
}

#[test]
fn non_utf8_target_argv_is_rejected_before_spawning() {
    // F-G/Bm2: target arguments after `run --` are executed bytes —
    // lossy conversion would run DIFFERENT bytes than typed. The
    // entry point must refuse with exit 2 (never proceed to capture).
    use std::os::unix::ffi::OsStringExt;
    let bad = std::ffi::OsString::from_vec(b"/bin/echo-\xff".to_vec());
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let out = std::process::Command::new(bin)
        .args([
            "report",
            "--object",
            "o",
            "--count-object",
            "c",
            "run",
            "--",
        ])
        .arg(&bad)
        .arg("sentinel")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "non-UTF-8 target argv must be a usage error, never capture"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("utf-8") || stderr.to_lowercase().contains("utf8"),
        "must diagnose encoding: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
}

#[test]
fn pid_cmdline_bytes_are_redacted() {
    let mut raw = b"/usr/bin/app\0--token\0".to_vec();
    raw.extend(SECRET.bytes());
    raw.push(0);
    let out = osslscope::args::redact_proc_cmdline(&raw);
    assert_eq!(out, REDACTED_CMDLINE);
    assert!(!out.contains(&SECRET[..8]), "secret bytes must not escape");
    assert!(out.contains("redacted"), "redaction must be explicit");
}
