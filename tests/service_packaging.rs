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
const FROZEN_UNIT: &str = "# D-record §1.4 frozen — changes need a §1.4 amendment (+ minor bump).\n[Unit]\nDescription=osslscope continuous OpenSSL observer service\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart=/usr/bin/osslscope service --config /etc/osslscope/service.toml\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=5\nRestartPreventExitStatus=4\nStateDirectory=osslscope\n# +CAP_SYS_PTRACE: §1.4 grants it iff foreign-uid targets are\n# selected. The unit runs as root, so any non-root target is\n# foreign — the shipped unit carries it. Drop it only when every\n# target runs as root.\nCapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE\n\n[Install]\nWantedBy=multi-user.target\n";

#[test]
fn deb_unit_file_matches_frozen_section_1_4() {
    let bytes = std::fs::read(deb_input("osslscope-service.service"))
        .expect("shipped unit packaging/deb/osslscope-service.service present");
    let text = String::from_utf8(bytes).expect("shipped unit is UTF-8 (systemd requirement)");
    assert_eq!(text, FROZEN_UNIT);
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
