//! SPDX-License-Identifier: GPL-3.0-or-later
//! 6B bounded-service controls (§9 executable specifications).
//!
//! Admission legs call the library entry in-process; lifecycle legs
//! spawn the real binary. RED-before-GREEN: behavioral legs fail
//! until the service implements the frozen D-record.

use std::process::Command;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

fn run_service(words: &[&str]) -> u8 {
    let code = osslscope::service::run(&argv(words));
    // ExitCode has no stable value reader; map the known constants.
    if code == std::process::ExitCode::SUCCESS {
        0
    } else if code == std::process::ExitCode::from(2) {
        2
    } else if code == std::process::ExitCode::from(3) {
        3
    } else if code == std::process::ExitCode::from(4) {
        4
    } else if code == std::process::ExitCode::from(10) {
        10
    } else if code == std::process::ExitCode::from(11) {
        11
    } else {
        1
    }
}

fn bin() -> Command {
    let exe = env!("CARGO_BIN_EXE_osslscope");
    let mut c = Command::new(exe);
    c.arg("service");
    c
}

fn fresh_dir(name: &str) -> std::path::PathBuf {
    let root = std::env::var("OSSL_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = root.join(format!(
        "sixb-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- §1 admission (exit 2, pre-side-effect) ---

#[test]
fn sixb_flag_equals_rejected() {
    assert_eq!(run_service(&["--out=/tmp/x", "--pid", "1"]), 2);
}

#[test]
fn sixb_second_cgroup_rejected() {
    assert_eq!(
        run_service(&["--out", "/tmp/x", "--cgroup", "/a", "--cgroup", "/b"]),
        2
    );
}

#[test]
fn sixb_missing_selector_rejected() {
    let dir = fresh_dir("no-selector");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--module", "/x.so"]),
        2
    );
}

#[test]
fn sixb_missing_out_rejected() {
    assert_eq!(run_service(&["--pid", "1"]), 2);
}

#[test]
fn sixb_zero_timeout_rejected_by_positivity() {
    let dir = fresh_dir("zero-timeout");
    assert_eq!(
        run_service(&[
            "--out",
            dir.to_str().unwrap(),
            "--pid",
            "1",
            "--timeout",
            "0"
        ]),
        2
    );
}

#[test]
fn sixb_zero_grace_rejected_by_positivity() {
    let dir = fresh_dir("zero-grace");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "1", "--grace", "0"]),
        2
    );
}

#[test]
fn sixb_bad_format_rejected() {
    let dir = fresh_dir("bad-format");
    assert_eq!(
        run_service(&[
            "--out",
            dir.to_str().unwrap(),
            "--pid",
            "1",
            "--format",
            "yaml"
        ]),
        2
    );
}

#[test]
fn sixb_unknown_flag_rejected() {
    let dir = fresh_dir("unknown-flag");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "1", "--forever"]),
        2
    );
}

#[test]
fn sixb_no_spawn_mode() {
    let dir = fresh_dir("no-spawn");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "run", "--", "true"]),
        2
    );
}

#[test]
fn sixb_bad_pid_rejected() {
    let dir = fresh_dir("bad-pid");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "0"]),
        2
    );
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "abc"]),
        2
    );
}

#[test]
fn sixb_bad_counts_rejected() {
    let dir = fresh_dir("bad-counts");
    let d = dir.to_str().unwrap();
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-bytes", "x"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-bytes", "1"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-events", "63"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--retain-windows", "0"]),
        2
    );
    assert_eq!(run_service(&["--out", d, "--pid", "1", "--window", "0"]), 2);
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--window", "3601"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--interval", "0.04"]),
        2
    );
}

#[test]
fn sixb_help_exits_zero() {
    assert_eq!(run_service(&["--help"]), 0);
}

// --- Behavioral REDs (need the implemented service) ---

/// One window against a live sleeper target: the DIR must hold a
/// `service-window-v1` envelope plus sequence state after SIGTERM.
#[test]
fn sixb_one_window_finalizes() {
    let dir = fresh_dir("one-window");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        status.code() == Some(3),
        "cancel-after-windows exits 3, got {status:?}"
    );
    let win = dir.join("window-0000000000.json");
    assert!(win.is_file(), "window 0 published, dir: {dir:?}");
    let body = std::fs::read_to_string(&win).unwrap();
    assert!(body.contains("\"service-window-v1\""), "envelope schema");
    assert!(dir.join("sequence.json").is_file(), "sequence state");
    assert!(dir.join("run-summary.json").is_file(), "run summary");
}

/// Second coordinator on a live out-DIR refuses pre-start (exit 2).
#[test]
fn sixb_double_coordinator_refused() {
    let dir = fresh_dir("double-coord");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_millis(800));
    let probe = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .status()
        .expect("spawn probe");
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let _ = svc.wait();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(probe.code(), Some(2), "out-DIR locked refuses exit 2");
}

/// Mixed double-signal (SIGINT + SIGTERM) stages two `Term`s in one
/// drain batch: immediate stop — the in-flight window is abandoned
/// (never published), the reservation is marked `double_signal`, and
/// the run exits 3 with the abandonment in the summary.
///
/// Determinism: SIGSTOP freezes the service first (polled `T` state
/// via /proc), so both signals are pending before any consume —
/// no iteration-boundary race. Same-signo rapid pairs coalesce in
/// the kernel and are observed once (single stop); mixed pairs do
/// not merge. STOP/CONT are test staging, unobserved by the service.
#[test]
fn sixb_mixed_double_signal_abandons_immediately() {
    let dir = fresh_dir("double-signal");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let svc_pid = svc.id() as i32;
    unsafe { libc::kill(svc_pid, libc::SIGSTOP) };
    // Poll until stopped (T state) — bounded, fail-loud on timeout.
    let state_path = format!("/proc/{svc_pid}/stat");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let stat = std::fs::read_to_string(&state_path).unwrap_or_default();
        let stopped = stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.split_whitespace().next() == Some("T"));
        if stopped || std::time::Instant::now() >= deadline {
            assert!(stopped, "service did not stop for staging");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unsafe {
        libc::kill(svc_pid, libc::SIGINT);
        libc::kill(svc_pid, libc::SIGTERM);
        libc::kill(svc_pid, libc::SIGCONT);
    }
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    // Zero finalized + interrupted → 4 (§7.3: "double-signal with
    // zero finalized windows exits 4" — priority 3 beats 6).
    assert_eq!(
        status.code(),
        Some(4),
        "double-signal zero-finalized exits 4"
    );
    assert!(
        !dir.join("window-0000000000.json").exists(),
        "in-flight window abandoned, never published"
    );
    let seq = std::fs::read_to_string(dir.join("sequence.json")).expect("sequence");
    assert!(seq.contains("\"double_signal\""), "mark reason: {seq}");
    let summary = std::fs::read_to_string(dir.join("run-summary.json")).expect("summary");
    assert!(
        summary.contains("\"double_signal\""),
        "abandoned note: {summary}"
    );
}
