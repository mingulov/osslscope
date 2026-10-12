//! H7 CLI pins (spawned binary, hermetic — onboarding fails before
//! any side effect, so no BPF/target is ever touched).
//!
//! - T2: setup failure (bad BPF object path) keeps the
//!   no-evidence path and exit 4.
//! - T5-spawn: closed stderr never panics (no 101) and never
//!   perturbs the exit — diagnostics are advisory.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_osslscope")
}

#[test]
fn h7_setup_failure_bad_object_exits_4() {
    // T2 (PIN, green now): missing BPF objects fail onboarding —
    // typed no-evidence doc, exit 4, doctor hint on stderr.
    let out = Command::new(bin())
        .args([
            "report",
            "--object",
            "/nonexistent-h7/probe.bpf.o",
            "--count-object",
            "/nonexistent-h7/count.bpf.o",
            "run",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4), "setup failure must stay exit 4");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("osslscope report:"),
        "setup error must be diagnosed: {stderr}"
    );
}

#[test]
fn h7_broken_stderr_keeps_exit_table() {
    // T5-spawn (RED pre-H7: eprintln! panics on ENOSPC → exit 101,
    // verified live): stderr to /dev/full (every write fails),
    // primary delivery fails (bad --out dir, so diagnostics lines
    // exist to emit) — no panic; the exit stays 4 (PRD §14: the
    // setup-no-verdict dominates the delivery failure).
    //
    // Why /dev/full and not a closed fd: Rust's startup fd
    // sanitization reopens a closed fd 2 to /dev/null, so a
    // closed-stderr spawn passes vacuously (writes succeed into the
    // void); ENOSPC is the honest failing sink.
    let full = std::fs::File::create("/dev/full").unwrap();
    let out = Command::new(bin())
        .stderr(full)
        .args([
            "report",
            "--object",
            "/nonexistent-h7/probe.bpf.o",
            "--count-object",
            "/nonexistent-h7/count.bpf.o",
            "--out",
            "/nonexistent-h7-dir/out.json",
            "run",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "broken stderr must not panic (101) nor perturb the exit"
    );
}

#[test]
fn h7_broken_stderr_alone_perturbs_nothing() {
    // T5-spawn isolation: setup failure with a DELIVERED artifact
    // (stdout) and broken stderr — exit stays 4 (stderr health
    // perturbs nothing) with no panic.
    let full = std::fs::File::create("/dev/full").unwrap();
    let out = Command::new(bin())
        .stderr(full)
        .args([
            "report",
            "--object",
            "/nonexistent-h7/probe.bpf.o",
            "--count-object",
            "/nonexistent-h7/count.bpf.o",
            "run",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "broken stderr alone must keep exit 4 with no panic"
    );
    // The artifact still delivered on stdout (a fatal JSON doc).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\"") || stdout.contains("FATAL") || stdout.contains("fatal"),
        "primary artifact must still deliver: {stdout:?}"
    );
}
