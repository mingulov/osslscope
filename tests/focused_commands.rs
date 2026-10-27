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
