//! SPDX-License-Identifier: GPL-3.0-or-later
//! R06 fork-errno: the fork diagnostic must carry fork's own errno
//! even though disposal runs first. Own integration-test target
//! (own process): the NPROC window is process-global and must not
//! touch siblings (ruling V2-24).

use osslscope::target::{OwnedTarget, WorkloadDest};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

/// Unique scratch dir (duplicated from tests/target_lifecycle.rs).
fn r06_scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("r06-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Sentinel argv: touches `sentinel`, then sleeps. The sentinel must
/// NEVER exist after a failed setup (duplicated from
/// tests/target_lifecycle.rs).
fn r06_sentinel_argv(sentinel: &Path) -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("touch '{}'; sleep 30", sentinel.display()),
    ]
}

#[test]
fn fork_failure_reports_fork_errno_not_disposal_errno() {
    // R06 fork-errno minor: the fork diagnostic must carry fork's
    // own errno even though disposal runs first. RLIMIT_NPROC=0
    // fails fork with EAGAIN; the Drop guard restores the limit
    // even on panic (window is one spawn call, ~100us).
    // WorkloadDest::Null reaches fork (no worker thread spawns
    // before it, unlike File sinks — ruling V2-23).
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut old) }, 0);
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: old.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &zero) }, 0);
    struct Restore(libc::rlimit);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &self.0) };
        }
    }
    let _restore = Restore(old);
    let dir = r06_scratch("fork-errno");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let err = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(30),
        &cancel,
    )
    .err()
    .expect("fork must fail under RLIMIT_NPROC=0");
    let msg = err.to_string();
    assert!(
        msg.contains("Resource temporarily unavailable"),
        "fork EAGAIN, not disposal errno: {msg}"
    );
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}
