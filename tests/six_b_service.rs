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
    // Strict structural parse (regression pin for the splice: the
    // file MUST be valid JSON with the `crypto_watch` key present —
    // substring checks pass on malformed files).
    let doc: serde_json::Value = serde_json::from_str(&body).expect("window 0 is valid JSON");
    assert_eq!(doc["schema"], "service-window-v1", "envelope schema");
    assert_eq!(doc["seq"], 0, "window seq");
    assert!(doc["crypto_watch"].is_array(), "crypto_watch array present");
    assert!(doc["window"].is_object(), "window span present");
    assert!(doc["document"].is_object(), "snapshot document present");
    assert!(dir.join("sequence.json").is_file(), "sequence state");
    let seq_body = std::fs::read_to_string(dir.join("sequence.json")).unwrap();
    let _: serde_json::Value = serde_json::from_str(&seq_body).expect("sequence is valid JSON");
    assert!(dir.join("run-summary.json").is_file(), "run summary");
    let sum_body = std::fs::read_to_string(dir.join("run-summary.json")).unwrap();
    let sum: serde_json::Value = serde_json::from_str(&sum_body).expect("summary is valid JSON");
    assert_eq!(sum["schema"], "service-run-v1", "summary schema");
    // Clean close drops no diagnostics (the abandonment wake is not
    // a diagnostic — regression pin).
    assert_eq!(sum["diagnostics_dropped"], 0, "no drops on clean close");
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

/// Latch hold (§6.2 MUST): a restart into a latched out-DIR exits 4
/// with a byte-identical DIR (the refused start restores even the
/// lock bytes).
///
/// Honest hostile environment, no forged state: run 1 fills the DIR
/// (retain 1); the oldest window file becomes an undeletable
/// directory (external fs condition — unlink fails); run 2 hits
/// deletion-failure → quota-stop latch → exit 1; the DIR goes
/// read-only (deletion provably impossible); legs A and B refuse
/// with 4 and leave every byte identical.
#[test]
fn sixb_latch_hold_exits_4_byte_identical() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = fresh_dir("latch-hold");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let flags = |cmd: &mut Command| {
        cmd.arg("--out")
            .arg(&dir)
            .arg("--pid")
            .arg(&pid)
            .arg("--window")
            .arg("1")
            .arg("--interval")
            .arg("0.2")
            .arg("--retain-windows")
            .arg("1");
    };
    // Run 1: fill + graceful cut.
    let mut run1 = bin();
    flags(&mut run1);
    let mut run1 = run1.spawn().expect("spawn run 1");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run1.id() as i32, libc::SIGTERM) };
    let st1 = run1.wait().expect("wait run 1");
    assert_eq!(st1.code(), Some(3), "run 1 cuts gracefully");
    // Surgery: the oldest window file becomes a non-empty directory.
    let mut wins: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("window-"))
        .collect();
    wins.sort();
    assert!(!wins.is_empty(), "run 1 published windows");
    let victim = dir.join(&wins[0]);
    std::fs::remove_file(&victim).unwrap();
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("junk"), b"undeletable-by-unlink").unwrap();
    // Run 2: eviction fails → deletion-failure latch → exit 1 (self).
    let mut run2 = bin();
    flags(&mut run2);
    let mut run2 = run2.spawn().expect("spawn run 2");
    let st2 = wait_bounded(&mut run2, 30).expect("run 2 exits itself");
    assert_eq!(st2.code(), Some(1), "run 2 quota-stops with 1");
    assert!(dir.join("quota-stop.json").is_file(), "latch written");
    // Read-only: deletion provably impossible from here on.
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&dir, perms).unwrap();
    let snap0 = dir_snapshot(&dir);
    // Legs A and B: refuse 4, byte-identical (including service.lock).
    for leg in ["A", "B"] {
        let mut cmd = bin();
        flags(&mut cmd);
        let mut proc = cmd.spawn().expect("spawn latch leg");
        let st = wait_bounded(&mut proc, 30).expect("latch leg exits");
        assert_eq!(st.code(), Some(4), "leg {leg} refuses with 4");
        assert_eq!(dir_snapshot(&dir), snap0, "leg {leg} byte-identical");
    }
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&dir, perms).unwrap();
    let _ = child.kill();
    let _ = child.wait();
}

/// Resident-stream restart admits (R1 finding 5a): `--stream` given
/// as the out-DIR resolves to the resident `stream.jsonl`, which is
/// the tap's own file — never evidence. A restart with the tap
/// resident must NOT refuse exit 2 (the alias check covers RESERVED
/// artifacts only).
#[test]
fn sixb_resident_stream_restart_admits() {
    let dir = fresh_dir("resident-restart");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let flags = |cmd: &mut Command| {
        cmd.arg("--out")
            .arg(&dir)
            .arg("--pid")
            .arg(&pid)
            .arg("--window")
            .arg("1")
            .arg("--interval")
            .arg("0.2")
            .arg("--stream")
            .arg(&dir);
    };
    // Run 1: publish + cut; the resident tap now exists.
    let mut run1 = bin();
    flags(&mut run1);
    let mut run1 = run1.spawn().expect("spawn run 1");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run1.id() as i32, libc::SIGTERM) };
    let st1 = run1.wait().expect("wait run 1");
    assert_eq!(st1.code(), Some(3), "run 1 cuts gracefully");
    assert!(
        dir.join("stream.jsonl").is_file(),
        "resident tap exists after run 1"
    );
    // Run 2 (restart): the resident tap must admit.
    let mut run2 = bin();
    flags(&mut run2);
    let mut run2 = run2.spawn().expect("spawn run 2");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run2.id() as i32, libc::SIGTERM) };
    let st2 = run2.wait().expect("wait run 2");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(st2.code(), Some(3), "resident restart admits (cuts 3)");
}

/// Reserved-alias taps refuse pre-open (R1 finding 5 guard): a
/// non-reserved FILENAME hard-linked to a RESERVED identity
/// (sequence.json) still refuses exit 2 — the identity half of the
/// §4.1 rule survives the F5a restriction to reserved artifacts.
#[test]
fn sixb_reserved_alias_tap_refused_preopen() {
    let dir = fresh_dir("reserved-alias");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    // Seed run: create sequence.json (state).
    let mut seed = bin();
    seed.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2");
    let mut seed = seed.spawn().expect("spawn seed");
    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe { libc::kill(seed.id() as i32, libc::SIGTERM) };
    let st = seed.wait().expect("wait seed");
    assert_eq!(st.code(), Some(3), "seed cuts gracefully");
    assert!(dir.join("sequence.json").is_file(), "seed wrote state");
    // Non-reserved name, reserved identity.
    let evil = dir.join("evil-tap.jsonl");
    std::fs::hard_link(dir.join("sequence.json"), &evil).unwrap();
    let probe = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--stream")
        .arg(&evil)
        .status()
        .expect("spawn probe");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(probe.code(), Some(2), "reserved-alias tap refuses exit 2");
}

/// Post-open hard-link swap fails the run as a tool failure (R1
/// finding 5b): the tap admits clean, then the PATH is swapped to a
/// hard link of a RESERVED window file before the first tap open.
/// The post-open fstat check must catch it: fd closed before any
/// write (the window stays byte-identical — an unchecked open would
/// splice stream bytes into published evidence), run-level tool
/// failure (exit 1 — windows finalized).
#[test]
fn sixb_postopen_reserved_swap_fails_tool_failure() {
    let dir = fresh_dir("postopen-swap");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    // Seed run: publish window 0 (the reserved swap target).
    let mut seed = bin();
    seed.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2");
    let mut seed = seed.spawn().expect("spawn seed");
    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe { libc::kill(seed.id() as i32, libc::SIGTERM) };
    let st = seed.wait().expect("wait seed");
    assert_eq!(st.code(), Some(3), "seed cuts gracefully");
    let win0 = dir.join("window-0000000000.json");
    assert!(win0.is_file(), "seed published window 0");
    let win0_bytes = std::fs::read(&win0).unwrap();
    // Run 2: tap ABSENT at admission (clean admit), swapped to
    // the reserved window before the first tap open (the final
    // close drives the tap). Pre-creating it would trip the F5a
    // self-refusal instead of the post-open path.
    let tap = dir.join("stream.jsonl");
    let mut svc = bin();
    svc.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .arg("--interval")
        .arg("0.2")
        .arg("--stream")
        .arg(&tap);
    let mut svc = svc.spawn().expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(dir.join("sequence.json").is_file(), "admission wrote state");
    std::fs::hard_link(&win0, &tap).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let st = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        st.code(),
        Some(1),
        "post-open reserved swap fails as tool failure (exit 1), got {st:?}"
    );
    assert_eq!(
        std::fs::read(&win0).unwrap(),
        win0_bytes,
        "window 0 byte-identical (fd closed pre-write)"
    );
}

/// Bounded wait for a self-exiting child (poll — fail-loud timeout).
fn wait_bounded(child: &mut std::process::Child, secs: u64) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return Some(st);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Full-DIR content snapshot (every regular file incl. service.lock).
fn dir_snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}
