//! SPDX-License-Identifier: GPL-3.0-or-later
//! F8b: shipped unit + default service-config contract (D-record §1.4).
//!
//! The unit bytes are frozen: any change needs a §1.4 amendment
//! (+ minor bump). The default config is behavior-pinned (valid
//! fields, StateDirectory out-DIR, loud refusal without targets).

use std::path::PathBuf;
use std::time::Duration;

fn deb_input(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("packaging/deb")
        .join(name)
}

/// Frozen D-record §1.4 unit bytes (directives) + the standard
/// `[Unit]`/`[Install]` scaffolding the brief's enable/start/stop/
/// restart lifecycle requires (`[Install]` carries `WantedBy`, so
/// `enable` works; `StartLimit*` live in `[Unit]` per systemd.unit).
/// Wave 3 added exit 2 to the prevention list (config-failure must
/// not restart-loop); ratified by §1.4 Amendment A2.
const FROZEN_UNIT: &str = "# D-record §1.4 frozen — changes need a §1.4 amendment (+ minor bump).\n[Unit]\nDescription=osslscope continuous OpenSSL observer service\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart=/usr/bin/osslscope service --config /etc/osslscope/service.toml\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=5\n# +exit 2 to RestartPreventExitStatus: §1.4 Amendment A2\n# (ratified) — stock config selects no targets → service refuses\n# with exit 2 → without prevention the unit restart-loops 5×/300s\n# then fails; exit 2 is config-refused (never a crash), so holding\n# the unit stopped is correct.\nRestartPreventExitStatus=2 4\nStateDirectory=osslscope\n# +CAP_SYS_PTRACE: §1.4 grants it iff foreign-uid targets are\n# selected. The unit runs as root, so any non-root target is\n# foreign — the shipped unit carries it. Drop it only when every\n# target runs as root.\n# +CAP_CHECKPOINT_RESTORE +CAP_DAC_READ_SEARCH: §1.4 Amendment A1\n# (ratified) — required for foreign-identity verification; without\n# them foreign members gap identity_unverified and attach finds\n# zero sites.\nCapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_CHECKPOINT_RESTORE CAP_DAC_READ_SEARCH\n\n[Install]\nWantedBy=multi-user.target\n";

#[test]
fn deb_unit_file_matches_frozen_section_1_4() {
    let bytes = std::fs::read(deb_input("osslscope-service.service"))
        .expect("shipped unit packaging/deb/osslscope-service.service present");
    let text = String::from_utf8(bytes).expect("shipped unit is UTF-8 (systemd requirement)");
    assert_eq!(text, FROZEN_UNIT);
}

#[test]
fn deb_unit_file_excludes_config_failure_from_restart() {
    // S1: the stock config selects no targets, so a fresh enable
    // exits 2 — the unit must NOT restart that (nor the exit-4
    // scope refusal); only abnormal deaths restart.
    let bytes = std::fs::read(deb_input("osslscope-service.service"))
        .expect("shipped unit packaging/deb/osslscope-service.service present");
    let text = String::from_utf8(bytes).expect("shipped unit is UTF-8 (systemd requirement)");
    let line = text
        .lines()
        .find(|l| l.starts_with("RestartPreventExitStatus="))
        .expect("unit carries a RestartPreventExitStatus stanza");
    let statuses: Vec<&str> = line["RestartPreventExitStatus=".len()..]
        .split_whitespace()
        .collect();
    assert!(
        statuses.contains(&"2"),
        "config-failure exit 2 must not restart: {line}"
    );
    assert!(
        statuses.contains(&"4"),
        "scope-refusal exit 4 must not restart: {line}"
    );
    assert!(
        text.lines().any(|l| l == "Restart=on-failure"),
        "restart policy stays on-failure"
    );
}

#[test]
fn default_service_toml_refuses_without_targets() {
    let path = deb_input("service.toml").to_string_lossy().into_owned();
    let err = osslscope::service::cli::parse(&["--config".to_string(), path]).unwrap_err();
    // All default fields validate; only the target selection is
    // missing — and the template refuses LOUDLY (never a silent
    // observe-nothing service).
    assert_eq!(err, "service requires at least one of --pid/--cgroup");
}

#[test]
fn default_service_toml_plus_cli_pid_admits_with_state_directory_out() {
    let path = deb_input("service.toml").to_string_lossy().into_owned();
    let me = std::process::id().to_string();
    let cfg = osslscope::service::cli::parse(&[
        "--config".to_string(),
        path,
        "--pid".to_string(),
        me.clone(),
    ])
    .expect("default config + one CLI pid admits");
    // §1.4: StateDirectory out-DIR passed via config.
    assert_eq!(cfg.out, PathBuf::from("/var/lib/osslscope/windows"));
    // Pinned code defaults (explicit in the shipped file).
    assert_eq!(cfg.window, Duration::from_secs(30));
    assert_eq!(cfg.interval, Duration::from_secs(1));
    assert_eq!(cfg.timeout, Duration::from_secs(60));
    assert_eq!(cfg.grace, Duration::from_secs(5));
    assert_eq!(cfg.pids, vec![me.parse::<u32>().unwrap()]);
    assert_eq!(cfg.retain_windows, 2880);
}
