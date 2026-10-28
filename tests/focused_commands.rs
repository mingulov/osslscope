// SPDX-License-Identifier: GPL-3.0-or-later
//! Public routing: invalid observer input cannot start a workload, and
//! unavailable tracing still yields an honest selected-process document.
use std::{
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
fn cli(command: &str, options: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_osslscope"));
    c.arg(command);
    if command == "check" {
        c.args(["--deny-algorithm", "SHA256"]);
    }
    c.args(options).output().unwrap()
}
fn parsed(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}
#[test]
fn normal_pid_is_partial_without_profile_enrollment() {
    let pid = std::process::id().to_string();
    for (command, code) in [("report", 3), ("check", 11)] {
        let out = cli(
            command,
            &["--pid", &pid, "--duration", "0.01", "--format", "json"],
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc = parsed(&out);
        assert_eq!(doc["disposition"]["outcome"], "foreign-observed");
        assert!(doc["coverage"].to_string().contains("unknown"));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("--libcrypto is required"));
    }
}
#[test]
fn normal_run_uses_owned_target_and_preserves_workload_flag_names() {
    for (command, code) in [("report", 3), ("check", 11)] {
        let out = cli(
            command,
            &[
                "--duration",
                "0.2",
                "--format",
                "json",
                "run",
                "--",
                "/bin/true",
                "--libcrypto",
                "--provider",
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(parsed(&out)["disposition"]["outcome"], "exited");
    }
}
#[test]
fn invalid_observer_options_do_not_execute_workload() {
    let marker = std::env::temp_dir().join(format!(
        "osslscope-invalid-command-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let script = format!("touch {}", marker.display());
    let cases: &[&[&str]] = &[
        &["--pid", "1", "--pid", "2"],
        &["--pid", "0"],
        &["--pid", "2147483648"],
        &["--pid", "1"],
        &["--duration", "NaN"],
        &["--duration", "inf"],
        &["--duration", "3601"],
        &["--duration", "0"],
        &["--timeout", "0"],
        &["--timeout", "121"],
        &["--grace", "0"],
        &["--grace", "31"],
        &["--provider", "/missing"],
        &["--builtin"],
        &["--object", "/missing"],
        &["--force-offset", "1"],
        &["--settle", "1"],
        &["--members-object", "/missing"],
        &["--dev-bundle", "/missing"],
        &["--image-digest", "a"],
        &["--table", "/missing"],
        &["--observation-object", "/missing"],
    ];
    for command in ["report", "check"] {
        for options in cases {
            let mut argv = options.to_vec();
            argv.extend(["run", "--", "/bin/sh", "-c", &script]);
            let out = cli(command, &argv);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{command} {options:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!marker.exists(), "invalid input executed the child");
        }
    }
}
#[test]
fn legacy_selection_conflicts_and_nonempty_rules_are_usage_errors() {
    for command in ["report", "check"] {
        assert_eq!(
            cli(command, &["--libcrypto", "/missing", "--pid", "1"])
                .status
                .code(),
            Some(2)
        );
        assert_eq!(
            cli(
                command,
                &[
                    "--libcrypto",
                    "/missing",
                    "--observation-object",
                    "/missing",
                    "run",
                    "--",
                    "/bin/true"
                ]
            )
            .status
            .code(),
            Some(2)
        );
        let out = cli(
            command,
            &["--libcrypto", "/missing", "run", "--", "/bin/true"],
        );
        assert_eq!(out.status.code(), Some(4));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Count")
                || String::from_utf8_lossy(&out.stderr).contains("libcrypto")
        );
    }
    let out = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["check", "--pid", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least one rule"));
}
#[test]
fn output_failure_overrides_partial_and_inconclusive() {
    let pid = std::process::id().to_string();
    for command in ["report", "check"] {
        let out = cli(
            command,
            &[
                "--pid",
                &pid,
                "--duration",
                "0.01",
                "--out",
                "/dev/null/impossible",
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn unavailable_process_is_no_observation() {
    for command in ["report", "check"] {
        let out = cli(
            command,
            &[
                "--pid",
                "2147483647",
                "--duration",
                "0.01",
                "--format",
                "json",
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        parsed(&out);
    }
}
#[test]
fn default_doctor_checks_focused_capability_without_profile() {
    let out = cli("doctor", &["--json"]);
    assert!(
        matches!(out.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parsed(&out);
    assert_eq!(doc["record"], "doctor");
    assert!(doc["capabilities"]["count_companion"].is_string());
    assert!(doc["capabilities"]["pid_namespace"].is_string());
}

#[test]
fn explicit_bad_companions_are_rejected_before_workload_effects() {
    let dir = std::env::temp_dir().join(format!("osslscope-bad-companion-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let bad = dir.join("bad.o");
    // Syntactically ELF64/EM_BPF but missing the required maps/program ABI.
    let mut elf = [0u8; 64];
    elf[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
    elf[16] = 1;
    elf[18] = 247;
    elf[20] = 1;
    elf[52] = 64;
    std::fs::write(&bad, elf).unwrap();
    let marker = dir.join("executed");
    let script = format!("touch {}", marker.display());
    for command in ["report", "check"] {
        for flag in ["--observation-object", "--count-object"] {
            let out = cli(
                command,
                &[
                    flag,
                    bad.to_str().unwrap(),
                    "run",
                    "--",
                    "/bin/sh",
                    "-c",
                    &script,
                ],
            );
            assert_eq!(
                out.status.code(),
                Some(2),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!marker.exists());
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_or_symlink_replaced_installed_companions_stay_explicitly_unavailable() {
    use std::os::unix::fs::symlink;
    let dir = std::env::temp_dir().join(format!(
        "osslscope-installed-command-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("lib/osslscope")).unwrap();
    let binary = dir.join("bin/osslscope");
    if std::fs::hard_link(env!("CARGO_BIN_EXE_osslscope"), &binary).is_err() {
        std::fs::copy(env!("CARGO_BIN_EXE_osslscope"), &binary).unwrap();
    }
    let pid = std::process::id().to_string();
    for replaced in [false, true] {
        if replaced {
            for name in ["osslscope-provider-observation", "osslscope-focused-count"] {
                let path = dir.join("lib/osslscope").join(name);
                std::fs::write(&path, b"original companion").unwrap();
                std::fs::remove_file(&path).unwrap();
                symlink(env!("CARGO_BIN_EXE_osslscope"), path).unwrap();
            }
        }
        for (command, code) in [("report", 3), ("check", 11)] {
            let mut invocation = Command::new(&binary);
            invocation.arg(command);
            if command == "check" {
                invocation.args(["--deny-algorithm", "SHA256"]);
            }
            let out = invocation
                .args(["--pid", &pid, "--duration", "0.01", "--format", "json"])
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let doc = parsed(&out);
            assert!(
                doc["completeness"]["counters"]
                    .to_string()
                    .contains("focused.tracing_unavailable")
            );
            assert!(
                doc.get("count_object")
                    .is_none_or(serde_json::Value::is_null)
            );
            assert!(
                doc.get("selected_objects")
                    .is_none_or(serde_json::Value::is_null)
            );
            assert!(!String::from_utf8_lossy(&out.stderr).contains("focused callbacks attached"));
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn released_sleeping_child_survives_observation_timeout() {
    let out = cli(
        "report",
        &[
            "--duration",
            "0.03",
            "--format",
            "json",
            "run",
            "--",
            "/bin/sleep",
            "5",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parsed(&out);
    let pid = doc["disposition"]["pid"].as_u64().unwrap() as libc::pid_t;
    struct Cleanup(libc::pid_t);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
            }
        }
    }
    let _cleanup = Cleanup(pid);
    assert_eq!(doc["disposition"]["outcome"], "detached-running");
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        0,
        "released child was signalled at observation expiry"
    );
}

#[test]
#[ignore = "requires explicitly supplied freshly built focused companions; pure ABI/retention gate"]
fn actual_explicit_companions_use_focused_abi_and_retained_bytes() {
    let observation = std::fs::read(
        std::env::var("OSSLSCOPE_PROVIDER_OBSERVATION_OBJECT")
            .expect("fresh observation object required"),
    )
    .unwrap();
    let count = std::fs::read(
        std::env::var("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
            .expect("fresh focused Count object required"),
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("osslscope-explicit-pair-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let opath = dir.join("observation");
    let cpath = dir.join("count");
    std::fs::write(&opath, &observation).unwrap();
    std::fs::write(&cpath, &count).unwrap();
    let admitted =
        osslscope::package::commands::resolve_focused_objects(Some(&opath), Some(&cpath));
    std::fs::remove_dir_all(&dir).unwrap();
    let admitted = admitted.unwrap();
    assert_eq!(admitted.observation.as_ref(), observation);
    assert_eq!(admitted.count.as_ref(), count);
    // The admitted bytes remain usable after removal/replacement of locators.
    osslscope::loader::prepare_focused_count(&admitted.count).unwrap();
}

#[test]
fn workload_delivery_setup_failure_is_runtime_failure() {
    for command in ["report", "check"] {
        let out = cli(
            command,
            &[
                "--workload-out",
                "/dev/null/impossible",
                "run",
                "--",
                "/bin/true",
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn focused_output_and_cbom_share_the_actual_document() {
    let dir = std::env::temp_dir().join(format!("osslscope-focused-output-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let primary = dir.join("report.json");
    let cbom = dir.join("cbom.json");
    let workload = dir.join("workload.out");
    let out = cli(
        "check",
        &[
            "--duration",
            "0.2",
            "--format",
            "json",
            "--out",
            primary.to_str().unwrap(),
            "--cbom",
            cbom.to_str().unwrap(),
            "--workload-out",
            workload.to_str().unwrap(),
            "run",
            "--",
            "/bin/echo",
            "fixture-output",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(11),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let doc = serde_json::from_slice(&std::fs::read(primary).unwrap()).unwrap();
    osslscope::schema::validate_v2(&doc).unwrap();
    osslscope::schema::check_v2_semantics(&doc).unwrap();
    assert_eq!(doc["policy"]["verdict"], "inconclusive");
    let bom: serde_json::Value = serde_json::from_slice(&std::fs::read(cbom).unwrap()).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert!(bom["components"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::read(workload).unwrap(), b"fixture-output\n");
    std::fs::remove_dir_all(dir).unwrap();
}

fn assert_closed_workload_fd_delivers_failure_artifacts(command: &str) {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-closed-workload-fd-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let marker = dir.join("workload-executed");
    let script = format!("touch {}", marker.display());
    for primary_file in [false, true] {
        let primary = dir.join(format!("{command}-{primary_file}.json"));
        let cbom = dir.join(format!("{command}-{primary_file}.cdx.json"));
        let mut args = vec![
            "--format",
            "json",
            "--cbom",
            cbom.to_str().unwrap(),
            "--workload-out-fd",
            "2147483647",
        ];
        if primary_file {
            args.extend(["--out", primary.to_str().unwrap()]);
        }
        args.extend(["run", "--", "/bin/sh", "-c", &script]);
        let out = cli(command, &args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{command}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!marker.exists(), "invalid sink executed the workload");
        let doc: serde_json::Value = if primary_file {
            assert!(out.stdout.is_empty());
            serde_json::from_slice(&std::fs::read(primary).unwrap()).unwrap()
        } else {
            parsed(&out)
        };
        osslscope::schema::validate_v2(&doc).unwrap();
        osslscope::schema::check_v2_semantics(&doc).unwrap();
        assert_eq!(doc["completeness"]["status"], "FATAL");
        if command == "check" {
            assert_eq!(doc["policy"]["verdict"], "no-verdict");
        }
        let bom: serde_json::Value = serde_json::from_slice(&std::fs::read(cbom).unwrap()).unwrap();
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("focused callbacks attached"));
    }
}

#[test]
fn report_closed_workload_fd_delivers_failure_artifacts_without_workload() {
    assert_closed_workload_fd_delivers_failure_artifacts("report");
}
#[test]
fn check_closed_workload_fd_delivers_failure_artifacts_without_workload() {
    assert_closed_workload_fd_delivers_failure_artifacts("check");
}

#[test]
#[ignore = "requires an explicitly supplied legacy Count object; no BPF load"]
fn legacy_closed_workload_fd_preserves_entrypoint_preflight() {
    let count =
        std::env::var("OSSLSCOPE_LEGACY_COUNT_OBJECT").expect("legacy Count object required");
    let marker =
        std::env::temp_dir().join(format!("osslscope-legacy-closed-fd-{}", std::process::id()));
    let script = format!("touch {}", marker.display());
    for command in ["report", "check"] {
        let out = cli(
            command,
            &[
                "--libcrypto",
                "/missing-library",
                "--count-object",
                &count,
                "--format",
                "json",
                "--workload-out-fd",
                "2147483647",
                "run",
                "--",
                "/bin/sh",
                "-c",
                &script,
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("workload fd:"),
            "legacy route did not reach main's existing preflight: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !marker.exists(),
            "legacy invalid sink executed the workload"
        );
    }
}

/// Privileged installed lane: unchanged short applications, with no readiness,
/// query protocol, internal backend selection or explicit object paths.
#[test]
#[ignore = "requires an installed privileged focused CLI"]
fn installed_short_digest_retains_prearmed_entries() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let dir = native_dir("short");
    for algorithm in ["-sha512", "-sha3-256"] {
        let output = dir.join(algorithm);
        let expected = Command::new("/usr/bin/openssl")
            .args(["dgst", algorithm, "/dev/null"])
            .output()
            .unwrap();
        assert!(expected.status.success());
        let out = Command::new(&binary)
            .arg("report")
            .arg("--workload-out")
            .arg(&output)
            .args([
                "--duration",
                "5",
                "--format",
                "json",
                "run",
                "--",
                "/usr/bin/openssl",
                "dgst",
                algorithm,
                "/dev/null",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc = parsed(&out);
        assert_eq!(doc["disposition"]["outcome"], "exited");
        assert_eq!(doc["disposition"]["code"], 0);
        assert_eq!(std::fs::read(output).unwrap(), expected.stdout);
        let calls: u64 = doc["sites"]
            .as_array()
            .unwrap()
            .iter()
            .chain(
                doc["fenced"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|g| g["sites"].as_array().unwrap()),
            )
            .map(|s| s["calls"].as_u64().unwrap())
            .sum();
        assert!(
            calls > 0,
            "ordinary short {algorithm} exited without retained physical entry evidence"
        );
        println!(
            "{algorithm}: {calls} retained physical entries; child exit0; exact workload output preserved"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires an installed privileged focused CLI"]
fn installed_sustained_owned_digest_preserves_first_mapping_counts() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let out = Command::new(binary)
        .args([
            "report",
            "--duration",
            "10",
            "--format",
            "json",
            "run",
            "--",
            "/usr/bin/openssl",
            "speed",
            "-elapsed",
            "-seconds",
            "4",
            "-evp",
            "SHA512",
            "-bytes",
            "64",
        ])
        .output()
        .unwrap();
    let doc = parsed(&out);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(doc["disposition"]["outcome"], "exited");
    assert_eq!(doc["disposition"]["code"], 0);
    let rows: Vec<_> = doc["sites"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            doc["fenced"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|g| g["sites"].as_array().unwrap()),
        )
        .collect();
    let keys: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|r| {
            (
                r["object"].as_str().unwrap(),
                r["device"].as_u64().unwrap(),
                r["inode"].as_u64().unwrap(),
                r["offset"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        keys.len(),
        rows.len(),
        "first mapping must not duplicate a physical cookie"
    );
    let first = rows
        .iter()
        .filter(|r| r["calls"].as_u64().unwrap() > 0)
        .map(|r| r["first_ns"].as_u64().unwrap())
        .min()
        .unwrap();
    let last = rows
        .iter()
        .map(|r| r["last_ns"].as_u64().unwrap_or(0))
        .max()
        .unwrap();
    assert!(
        last - first > 2_000_000_000,
        "entry evidence must continue across first rescan"
    );
    assert!(
        !doc["completeness"]["counters"]
            .to_string()
            .contains("focused_resource")
    );
    println!(
        "{} unique sites, entry span {}ns, child exit0",
        rows.len(),
        last - first
    );
}

fn native_dir(label: &str) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let p = std::env::temp_dir().join(format!(
        "osslscope-{label}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}
#[test]
#[ignore = "requires an installed privileged focused CLI and C compiler"]
fn installed_origin_layout_and_late_module_remain_partial() {
    use std::os::unix::fs::MetadataExt;
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let dir = native_dir("origin");
    std::fs::create_dir(dir.join("lib")).unwrap();
    let lib = dir.join("lib/libcrypto.so.3");
    std::fs::copy("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", &lib).unwrap();
    let exe = dir.join("workload");
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&exe)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/runtime/preview_workload.c"
            ))
            .args(["-Wl,-rpath,$ORIGIN/lib", "-lcrypto", "-lpthread"])
            .status()
            .unwrap()
            .success()
    );
    let out = Command::new(&binary)
        .args(["report", "--duration", "5", "--format", "json", "run", "--"])
        .arg(exe)
        .args(["sha", "37"])
        .output()
        .unwrap();
    let doc = parsed(&out);
    assert_eq!(doc["disposition"]["code"], 0);
    let rows: Vec<_> = doc["sites"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            doc["fenced"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|g| g["sites"].as_array().unwrap()),
        )
        .collect();
    let inode = std::fs::metadata(lib).unwrap().ino();
    assert!(
        rows.iter()
            .any(|r| r["inode"].as_u64() == Some(inode) && r["calls"].as_u64().unwrap() > 0),
        "actual alternate dependency must have retained entry evidence"
    );
    let late = Command::new(binary)
        .args([
            "report",
            "--duration",
            "5",
            "--format",
            "json",
            "run",
            "--",
            "/usr/bin/openssl",
            "dgst",
            "-provider",
            "legacy",
            "-md4",
            "/dev/null",
        ])
        .output()
        .unwrap();
    let late = parsed(&late);
    assert_eq!(late["disposition"]["code"], 0);
    assert_eq!(late["completeness"]["status"], "PARTIAL");
    assert!(
        late["completeness"]["counters"]
            .to_string()
            .contains("focused.interval_unknown")
    );
    for row in late["sites"].as_array().unwrap().iter().chain(
        late["fenced"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["sites"].as_array().unwrap()),
    ) {
        assert_eq!(row["candidates_coverage"], "unknown");
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
#[ignore = "requires an installed privileged focused CLI"]
fn installed_setup_cancellation_keeps_child_held_until_cleanup() {
    use std::time::{Duration, Instant};
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let dir = native_dir("cancel");
    let output = dir.join("workload.out");
    let observer = Command::new(binary)
        .arg("report")
        .arg("--workload-out")
        .arg(&output)
        .args([
            "--duration",
            "5",
            "--format",
            "json",
            "run",
            "--",
            "/usr/bin/openssl",
            "dgst",
            "-sha512",
            "/dev/null",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let observer_pid = observer.id();
    let until = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        assert!(Instant::now() < until, "observer never acquired held child");
        let children =
            std::fs::read_to_string(format!("/proc/{observer_pid}/task/{observer_pid}/children"))
                .unwrap_or_default();
        if let Some(pid) = children
            .split_whitespace()
            .next()
            .and_then(|p| p.parse::<u32>().ok())
        {
            if std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|s| s.rsplit_once(')').unwrap().1.starts_with(" T"))
            {
                break pid;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(unsafe { libc::kill(observer_pid as i32, libc::SIGTERM) }, 0);
    let out = observer.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(
        std::fs::read(&output).unwrap_or_default().is_empty(),
        "cancelled held target executed"
    );
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "cancelled child not reaped"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires an installed privileged focused CLI"]
fn installed_warm_pid_keeps_candidates_across_discovery_deadline() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let mut workload = Command::new("/usr/bin/openssl")
        .args([
            "speed", "-elapsed", "-seconds", "8", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = Command::new(binary)
        .args([
            "report",
            "--pid",
            &workload.id().to_string(),
            "--duration",
            "4",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(workload.wait().unwrap().success());
    let doc = parsed(&out);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(doc["disposition"]["outcome"], "foreign-observed");
    let calls: u64 = doc["sites"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            doc["fenced"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|g| g["sites"].as_array().unwrap()),
        )
        .map(|s| s["calls"].as_u64().unwrap())
        .sum();
    assert!(
        calls > 0,
        "available warm candidates were discarded at a discovery deadline"
    );
    println!("warm PID: {calls} entries; workload survived and exited0");
}
