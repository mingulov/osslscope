// SPDX-License-Identifier: GPL-3.0-or-later
//! Doctor CLI routing: `--pid`/`--exe`/object flags reach the sectioned
//! preflight (self_attach/foreign_backing/target); bare `doctor` keeps
//! the scanner-owned self controls.
use std::path::PathBuf;
use std::process::Command;

fn doctor(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .arg("doctor")
        .args(args)
        .output()
        .expect("run doctor")
}

/// Explicit role objects for admitted runs (built by the nightly BPF
/// toolchain; absent on hosts without it).
fn role_objects() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates/ebpf/target/bpfel-unknown-none/release");
    let harvest = dir.join("osslscope-harvest");
    let count = dir.join("osslscope-count");
    let members = dir.join("osslscope-members");
    if harvest.is_file() && count.is_file() && members.is_file() {
        Some((harvest, count, members))
    } else {
        eprintln!("skip admitted doctor pin: BPF role objects not built");
        None
    }
}

#[test]
fn doctor_pid_reaches_sectioned_preflight() {
    // Routing shape only (no admission needed): the sectioned
    // renderer prints section headers; the focused self-controls
    // never do — not even on the admission-failure path.
    let pid = std::process::id().to_string();
    let out = doctor(&["--pid", &pid]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("== self_attach =="),
        "sectioned output, got: {stdout}"
    );
}

#[test]
fn doctor_pid_admitted_shows_all_sections() {
    let Some((harvest, count, members)) = role_objects() else {
        return;
    };
    let pid = std::process::id().to_string();
    let out = doctor(&[
        "--pid",
        &pid,
        "--object",
        harvest.to_str().unwrap(),
        "--count-object",
        count.to_str().unwrap(),
        "--members-object",
        members.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for section in ["== self_attach ==", "== foreign_backing ==", "== target =="] {
        assert!(stdout.contains(section), "missing {section}, got: {stdout}");
    }
    assert!(stdout.contains("verdict: "), "verdict line, got: {stdout}");
}

#[test]
fn doctor_object_flags_reach_sectioned_json() {
    // The live-workflow invocation shape (live-known-n.yml): explicit
    // objects, no target, JSON gate view.
    let Some((harvest, count, members)) = role_objects() else {
        return;
    };
    let out = doctor(&[
        "--object",
        harvest.to_str().unwrap(),
        "--count-object",
        count.to_str().unwrap(),
        "--members-object",
        members.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("doctor prints gate JSON");
    let checks = doc["checks"].as_array().expect("checks array");
    assert!(!checks.is_empty(), "admitted run must emit checks");
    assert!(
        checks.iter().any(|c| c["section"] == "self_attach"),
        "self_attach rows, got: {stdout}"
    );
}

#[test]
fn doctor_bare_still_runs_self_controls() {
    let out = doctor(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Focused capability checks"),
        "default route unchanged, got: {stdout}"
    );
}
