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
    // No-target foreign section: capability controls plus an explicit
    // pointer — never an undifferentiated foreign-ready verdict.
    let foreign: Vec<&str> = checks
        .iter()
        .filter(|c| c["section"] == "foreign_backing")
        .filter_map(|c| c["id"].as_str())
        .collect();
    for required in [
        "self-map-files",
        "self-pagemap",
        "owned-child-map-files",
        "foreign-target",
    ] {
        assert!(
            foreign.contains(&required),
            "missing {required} in {foreign:?}"
        );
    }
}

#[test]
fn doctor_flag_shaped_companion_value_stays_focused() {
    // A companion file literally named `--pid`: the value must not
    // select the sectioned route (regression: naive token scanning
    // misrouted this to sectioned, which rejects --observation-object).
    // The file must be a VALID observation object, so the focused
    // run proceeds past companion validation to its checks.
    let obs = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates/ebpf/target/bpfel-unknown-none/release/osslscope-provider-observation");
    if !obs.is_file() {
        eprintln!("skip flag-value pin: BPF observation object not built");
        return;
    }
    let dir = std::env::temp_dir().join(format!("osslscope-doctor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(&obs, dir.join("--pid")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .arg("doctor")
        .args(["--observation-object", "--pid"])
        .current_dir(&dir)
        .output()
        .expect("run doctor");
    std::fs::remove_dir_all(&dir).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Focused capability checks"),
        "focused route keeps flag-shaped values, got: {stdout}"
    );
    assert!(
        !stdout.contains("== self_attach =="),
        "must not reach sectioned output, got: {stdout}"
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

#[test]
fn doctor_sectioned_help_names_exit_codes() {
    let out = doctor(&["--pid", "1", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit 3:") && stdout.contains("exit 4:"),
        "sectioned help must name exit codes, got: {stdout}"
    );
    assert!(
        stdout.contains("first run blocked?"),
        "sectioned help must point first runs at doctor, got: {stdout}"
    );
}

#[test]
fn doctor_focused_help_names_exit_codes() {
    let out = doctor(&["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit 3:") && stdout.contains("exit 4:"),
        "focused help must name exit codes, got: {stdout}"
    );
    assert!(
        stdout.contains("first run blocked?"),
        "focused help must point first runs at doctor, got: {stdout}"
    );
}

#[test]
fn doctor_profiled_help_names_exit_codes() {
    let out = doctor(&["--libcrypto", "x", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit 3:") && stdout.contains("exit 4:"),
        "profiled help must name exit codes, got: {stdout}"
    );
    assert!(
        stdout.contains("first run blocked?"),
        "profiled help must point first runs at doctor, got: {stdout}"
    );
}

#[test]
fn doctor_discovery_help_names_exit_codes() {
    let out = doctor(&["--discovery", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit 3:") && stdout.contains("exit 4:"),
        "discovery help must name exit codes, got: {stdout}"
    );
    assert!(
        stdout.contains("first run blocked?"),
        "discovery help must point first runs at doctor, got: {stdout}"
    );
}

#[test]
fn doctor_discovery_exit3_names_reason_on_stderr() {
    let out = doctor(&["--discovery"]);
    if out.status.code() != Some(3) {
        eprintln!("SKIP: discovery passed on this host");
        return;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|l| l.contains("osslscope doctor:"))
            .count(),
        1,
        "exactly one stderr reason, got: {stderr}"
    );
}

#[test]
fn doctor_focused_exit3_names_reason_on_stderr() {
    let out = doctor(&[]);
    if out.status.code() != Some(3) {
        eprintln!("SKIP: focused passed on this host");
        return;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|l| l.contains("osslscope doctor:"))
            .count(),
        1,
        "exactly one stderr reason, got: {stderr}"
    );
}

#[test]
fn doctor_bogus_objects_package_refusal_names_itself_on_stderr() {
    // Explicit nonexistent object overrides fail package admission before any
    // check runs: exit 4 with a stderr reason that names the admission refusal.
    let out = doctor(&[
        "--object",
        "/nonexistent-osslscope-a.o",
        "--count-object",
        "/nonexistent-osslscope-b.o",
        "--members-object",
        "/nonexistent-osslscope-c.o",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("package admission refused"),
        "stderr names the admission refusal, got:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verdict: FAIL-CLOSED (admission refused:"),
        "human stdout carries the verdict line with cause, got:\n{stdout}"
    );
}

#[test]
fn doctor_dead_pid_exit2_names_no_such_process() {
    // CLI admission (before any object resolution): a pid with no /proc
    // entry is a usage error, exit 2, with the established reason line.
    let out = doctor(&["--pid", "424242"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("osslscope doctor: no such process 424242"),
        "stderr names the dead pid, got: {stderr}"
    );
}

#[test]
fn doctor_profiled_exit4_names_reason_on_stderr() {
    let out = doctor(&["--libcrypto", "/bin/true"]);
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|l| l.contains("osslscope doctor:"))
            .count(),
        1,
        "exactly one stderr reason, got: {stderr}"
    );
}
