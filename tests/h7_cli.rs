// SPDX-License-Identifier: GPL-3.0-or-later

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
fn preview_deferred_tables_refuse_without_opening_fifo() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let dir = std::env::temp_dir().join(format!("osslscope-deferred-fifo-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let fifo = dir.join("table");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for verb in ["report", "check"] {
        for flag in ["--table", "--provider-table"] {
            let mut command = Command::new(bin());
            command
                .args([verb, "--libcrypto", "/missing", flag])
                .arg(&fifo);
            if verb == "check" {
                command.args(["--require-executed", "SHA256"]);
            }
            let mut child = command
                .args(["run", "--", "/bin/true"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let timely = child.try_wait().unwrap().is_some();
            if !timely {
                child.kill().unwrap();
            }
            let output = child.wait_with_output().unwrap();
            if !timely {
                std::fs::remove_dir_all(&dir).unwrap();
            }
            assert!(timely, "{verb} {flag} waited for a FIFO writer");
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("deferred"));
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn h7_setup_failure_bad_object_exits_4() {
    // T2 (PIN, green now): missing BPF objects fail onboarding —
    // typed no-evidence doc, exit 4, doctor hint on stderr.
    let out = Command::new(bin())
        .args([
            "report",
            "--libcrypto",
            "/nonexistent-h7/libcrypto.so.3",
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
            "--libcrypto",
            "/nonexistent-h7/libcrypto.so.3",
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
            "--libcrypto",
            "/nonexistent-h7/libcrypto.so.3",
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

#[test]
fn g1_spawned_setup_attempts_both_artifacts_with_broken_stderr() {
    for command in ["report", "check"] {
        for fail_primary in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "osslscope-g1-cli-{}-{command}-{fail_primary}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let primary = dir.join(if fail_primary {
                "missing/primary.json"
            } else {
                "primary.json"
            });
            let cbom = dir.join(if fail_primary {
                "cbom.json"
            } else {
                "missing/cbom.json"
            });
            let mut cmd = Command::new(bin());
            cmd.stderr(std::fs::File::create("/dev/full").unwrap())
                .args([
                    command,
                    "--format",
                    "json",
                    "--libcrypto",
                    "/nonexistent-h7/libcrypto.so.3",
                    "--count-object",
                    "/nonexistent-h7/count.bpf.o",
                    "--out",
                ])
                .arg(&primary)
                .arg("--cbom")
                .arg(&cbom);
            if command == "check" {
                cmd.args(["--require-executed", "SHA256"]);
            }
            let out = cmd.args(["run", "--", "/bin/true"]).output().unwrap();
            assert_eq!(out.status.code(), Some(4));
            assert_eq!(primary.is_file(), !fail_primary);
            assert_eq!(cbom.is_file(), fail_primary);
            if !fail_primary {
                let value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(primary).unwrap()).unwrap();
                osslscope::schema::validate_v2(&value).unwrap();
                osslscope::schema::check_v2_semantics(&value).unwrap();
                assert_eq!(value["completeness"]["fatal_kind"]["kind"], "environment");
                if command == "check" {
                    assert_eq!(value["policy"]["verdict"], "no-verdict");
                }
            } else {
                let value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(cbom).unwrap()).unwrap();
                assert_eq!(value["bomFormat"], "CycloneDX");
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
