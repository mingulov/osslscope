//! SPDX-License-Identifier: GPL-3.0-or-later
//! Policy admission rejects invalid configuration before workload/output effects.
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn reject(name: &str, content: Option<&[u8]>, extra: &[&str], diagnostic: &str) {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-policy-cli-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).unwrap();
    let policy = dir.join("policy.toml");
    match content {
        Some(bytes) => std::fs::write(&policy, bytes).unwrap(),
        None => {
            let path = CString::new(policy.as_os_str().as_bytes()).unwrap();
            // A FIFO with no writer must be rejected without blocking in open/read.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }
    }
    let marker = dir.join("marker");
    let primary = dir.join("report.json");
    let cbom = dir.join("cbom.json");
    let workload = dir.join("workload.log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_osslscope"));
    command
        .arg("check")
        .arg("--policy")
        .arg(&policy)
        .args(extra)
        .arg("--out")
        .arg(&primary)
        .arg("--cbom")
        .arg(&cbom)
        .arg("--workload-out")
        .arg(&workload)
        .args(["run", "--", "/bin/sh", "-c", "printf ran > \"$1\"", "sh"])
        .arg(&marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("policy admission blocked for {name}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{name}: {output:?}");
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains("PRIVATE_POLICY_CANARY"),
            "{name}: leaked input"
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(diagnostic),
        "{name}: {output:?}"
    );
    for path in [&marker, &primary, &cbom, &workload] {
        assert!(
            !Path::new(path).exists(),
            "{name}: created {}",
            path.display()
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn oversized_policy_has_no_effects() {
    let mut bytes = b"version=1\ndeny-weak=true\n#".to_vec();
    bytes.resize(65_537, b' ');
    reject(
        "oversized",
        Some(&bytes),
        &[],
        "policy file exceeds 65536 bytes",
    );
}

#[test]
fn fifo_policy_is_rejected_without_waiting() {
    reject("fifo", None, &[], "policy file must be a regular file");
}

#[test]
fn duplicate_policy_is_a_usage_error() {
    reject(
        "duplicate",
        Some(b"version=1\ndeny-weak=true"),
        &["--policy", "unused.toml"],
        "--policy may occur only once",
    );
}

#[test]
fn contradictory_file_and_cli_have_no_effects() {
    reject(
        "contradiction",
        Some(b"version=1\nrequire-provider=['default']"),
        &["--deny-provider", "default"],
        "contradictory policy",
    );
}

#[test]
fn malformed_policy_diagnostics_redact_private_content() {
    reject(
        "syntax",
        Some(b"version=1\nrequire-provider = [ PRIVATE_POLICY_CANARY"),
        &[],
        "invalid policy TOML at line",
    );
    reject(
        "unknown",
        Some(b"version=1\nPRIVATE_POLICY_CANARY = true"),
        &[],
        "invalid policy TOML at line",
    );
    reject(
        "value",
        Some(b"version=1\nrequire-executed=['PRIVATE_POLICY_CANARY']"),
        &[],
        "require-executed[0]",
    );
}
