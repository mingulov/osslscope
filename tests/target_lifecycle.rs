//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 owned-target custody lifecycle (R05): explicit stopped /
//! released / reaped / detached states on every return; no owned
//! stopped child or zombie after cleanup; external `--pid` targets
//! are never signaled. No BPF or privileges needed.

use osslscope::target::{CustodyState, OwnedTarget, TargetDisposition, WorkloadDest};
use std::time::{Duration, Instant};

/// Poll until the child is reaped or the budget expires.
fn wait_for_exit(t: &mut OwnedTarget, budget: Duration) -> Option<i32> {
    let end = Instant::now() + budget;
    loop {
        let got = t.poll_exit().expect("poll_exit");
        if got.is_some() {
            return got;
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Assert the pid is fully gone: no /proc entry AND waitpid reports
/// ECHILD (reaped — a zombie would still be waitable).
fn assert_reaped_no_zombie(pid: u32) {
    assert!(
        std::fs::metadata(format!("/proc/{pid}")).is_err(),
        "pid {pid} still has /proc entry"
    );
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "pid {pid} still waitable (zombie?)");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "pid {pid} waitpid errno"
    );
}

/// Kernel state letter from /proc/<pid>/stat (after the last ')').
fn stat_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().next()?.chars().next()
}

/// Assert the pid is alive and NOT stopped or zombie.
fn assert_running_not_stopped(pid: u32) {
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    assert_eq!(r, 0, "pid {pid} not alive");
    let st = stat_state(pid).expect("stat state");
    assert!(
        !matches!(st, 'T' | 't' | 'Z'),
        "pid {pid} in bad state {st:?}"
    );
}

/// Test-only teardown for a deliberately detached child (production
/// leaves it running; the test binary is still its parent and must
/// reap it to avoid a test-process zombie).
fn kill_and_reap(pid: u32) -> Option<i32> {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if r > 0 {
            return Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
        if r < 0 {
            return None;
        }
        assert!(Instant::now() < end, "pid {pid} would not die");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn spawn_rejects_empty_and_nul_argv() {
    assert!(OwnedTarget::spawn_stopped(&[], WorkloadDest::Null).is_err());
    assert!(OwnedTarget::spawn_stopped(&["/bin/true\0".to_string()], WorkloadDest::Null).is_err());
}

#[test]
fn pre_release_failure_cleanup_leaves_no_zombie() {
    let mut t = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    // Setup failed before release: the never-released child is
    // terminated and reaped (SIGKILL -> 128+9).
    t.resolve_setup_failure().unwrap();
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_eq!(t.exit_code(), Some(128 + libc::SIGKILL));
    assert_eq!(t.poll_exit().unwrap(), Some(128 + libc::SIGKILL));
    assert_reaped_no_zombie(pid);
    // Idempotent.
    t.resolve_setup_failure().unwrap();
}

#[test]
fn exit_status_preserved_exit7() {
    let mut t = OwnedTarget::spawn_stopped(
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 7".to_string(),
        ],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    t.release().unwrap();
    assert_eq!(t.state(), CustodyState::Released);
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(7));
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_eq!(t.exit_code(), Some(7));
    assert_reaped_no_zombie(pid);
}

#[test]
fn failed_exec_reports_127() {
    let mut t = OwnedTarget::spawn_stopped(
        &["/nonexistent-osslscope-probe-xyz".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(127));
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_reaped_no_zombie(pid);
}

#[test]
fn no_query_fast_exit_preserves_status() {
    // A fast command that is already gone when setup observes it
    // (the no-query early return): its status is preserved, not lost.
    let mut t = OwnedTarget::spawn_stopped(&["/bin/true".to_string()], WorkloadDest::Null).unwrap();
    let pid = t.pid();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_eq!(
        t.finish_observation().unwrap(),
        TargetDisposition::Exited { code: 0 }
    );
    assert_reaped_no_zombie(pid);
}

#[test]
fn resolve_after_release_reaps_an_exited_child() {
    // Setup fails after release but the child already exited: its
    // status is preserved (Reaped), not relabeled Detached.
    let mut t = OwnedTarget::spawn_stopped(&["/bin/true".to_string()], WorkloadDest::Null).unwrap();
    let pid = t.pid();
    t.release().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if stat_state(pid) == Some('Z') {
            break;
        }
        assert!(Instant::now() < end, "child never became a zombie");
        std::thread::sleep(Duration::from_millis(5));
    }
    t.resolve_setup_failure().unwrap();
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_eq!(t.exit_code(), Some(0));
    assert_reaped_no_zombie(pid);
}

#[test]
fn signal_before_release_still_cleans_up() {
    let mut t = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    // A signal arrives during setup (pending on the stopped child);
    // setup-failure resolution must still leave no stopped/zombie child.
    let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    assert_eq!(r, 0);
    t.resolve_setup_failure().unwrap();
    assert_eq!(t.state(), CustodyState::Reaped);
    assert!(t.exit_code().is_some());
    assert_reaped_no_zombie(pid);
}

#[test]
fn normal_expiry_detaches_a_running_child() {
    let mut t = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    t.release().unwrap();
    // Detaching transfers ownership explicitly and cannot leave a
    // stopped child: the target keeps running.
    assert_eq!(
        t.finish_observation().unwrap(),
        TargetDisposition::Detached { pid }
    );
    assert_eq!(t.state(), CustodyState::Detached);
    assert_running_not_stopped(pid);
    // Idempotent; polling a detached target is an ownership error.
    assert_eq!(
        t.finish_observation().unwrap(),
        TargetDisposition::Detached { pid }
    );
    assert!(t.poll_exit().is_err());
    assert_running_not_stopped(pid);
    kill_and_reap(pid);
    assert_reaped_no_zombie(pid);
}

#[test]
fn drop_guard_never_leaves_a_stopped_child() {
    let pid = {
        let t = OwnedTarget::spawn_stopped(
            &["/bin/sleep".to_string(), "30".to_string()],
            WorkloadDest::Null,
        )
        .unwrap();
        let pid = t.pid();
        assert_eq!(t.state(), CustodyState::Stopped);
        pid // `t` drops here without release or resolve.
    };
    assert_reaped_no_zombie(pid);
}

#[test]
fn release_is_strictly_once() {
    let mut t = OwnedTarget::spawn_stopped(&["/bin/true".to_string()], WorkloadDest::Null).unwrap();
    t.release().unwrap();
    assert!(t.release().is_err(), "double release must fail");
    assert_eq!(t.state(), CustodyState::Released);
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert!(t.release().is_err(), "release after reap must fail");
}

#[test]
fn stopped_child_maps_readable_for_setup_baseline() {
    // F-CAPS-1 setup shape: while the child is stopped pre-exec,
    // the observer reads its /proc/PID/maps for the baseline. The
    // child opts itself dumpable pre-exec (target.rs), so the read
    // succeeds even when the observer runs under filecaps (the
    // filecaps transition itself is pinned by the T14 capability
    // matrix evidence + the installed/filecaps suites, not here).
    let mut t = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .expect("stopped pre-exec child maps readable");
    assert!(!maps.is_empty());
    t.resolve_setup_failure().unwrap();
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_reaped_no_zombie(pid);
}

#[test]
fn external_pid_target_is_never_signaled() {
    // An external `--pid` target (not spawned by the observer) is
    // pinned for identity only: pin + verify touch nothing, and the
    // typed wrapper offers no signaling operation at all.
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    let ext = osslscope::pin::ExternalTarget::adopt(pid).unwrap();
    assert_eq!(ext.pid(), pid);
    ext.verify().unwrap();
    ext.verify().unwrap();
    assert_running_not_stopped(pid);
    child.kill().unwrap();
    child.wait().unwrap();
}

fn sentinel_argv() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo H9-OUT-S; echo H9-ERR-S >&2".to_string(),
    ]
}

#[test]
fn h9_t1_default_null_discards_both_streams() {
    // T1 (RED): default destination sinks both workload streams
    // (exit preserved; true stderr-cleanliness pinned by the lane
    // sentinel leg — this process's stderr is not observable here).
    let mut t = OwnedTarget::spawn_stopped(&sentinel_argv(), WorkloadDest::Null).unwrap();
    let pid = t.pid();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(pid);
}

#[test]
fn h9_t2_file_captures_both_sentinels() {
    // T2 (RED): --workload-out file receives both streams
    // byte-identical (sequential echoes: deterministic order).
    let dir = std::env::temp_dir().join(format!("h9t2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("workload.log");
    let mut t =
        OwnedTarget::spawn_stopped(&sentinel_argv(), WorkloadDest::File(file.clone())).unwrap();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    let bytes = std::fs::read(&file).unwrap();
    assert_eq!(bytes, b"H9-OUT-S\nH9-ERR-S\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn h9_t3_fd_receives_both_sentinels() {
    // T3 (RED): caller-held fd receives both streams; the child
    // never closes the caller's fd (still writable after reap).
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (read, write) = (fds[0], fds[1]);
    let mut t = OwnedTarget::spawn_stopped(&sentinel_argv(), WorkloadDest::Fd(write)).unwrap();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(t.pid());
    // No EOF wait (the parent's own write end stays open by
    // design): read exactly the 18 sentinel bytes, bounded.
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    for _ in 0..100 {
        if out.len() >= 18 {
            break;
        }
        let n = unsafe { libc::read(read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        assert!(n > 0, "pipe closed early");
        out.extend_from_slice(&buf[..n as usize]);
    }
    assert_eq!(out, b"H9-OUT-S\nH9-ERR-S\n");
    // Caller fd still open (neither child nor parent setup closed
    // it): a write succeeds.
    let w = unsafe { libc::write(write, c"x".as_ptr() as *const libc::c_void, 1) };
    assert_eq!(w, 1);
    unsafe {
        libc::close(read);
        libc::close(write);
    }
}

#[test]
fn h9_t3b_invalid_fd_fails_without_spawn() {
    // T3 (RED): invalid fd is rejected pre-fork — the error names
    // the fd (never exec/127 confusion: nothing was spawned, so no
    // child status can ride along). Pre-fork ordering is structural
    // (validation precedes fork() in spawn_stopped).
    let err = OwnedTarget::spawn_stopped(&sentinel_argv(), WorkloadDest::Fd(999_999))
        .err()
        .expect("invalid fd must fail")
        .to_string();
    assert!(err.contains("999999"), "names the fd: {err}");
    assert!(!err.contains("127"), "nothing spawned: {err}");
}

#[test]
fn h9_nul_in_workload_path_fails_pre_fork() {
    // NUL bytes cannot reach the child CString: rejected pre-fork
    // like NUL in argv.
    let err = OwnedTarget::spawn_stopped(
        &sentinel_argv(),
        WorkloadDest::File("/tmp/h9-\0-nul.log".into()),
    )
    .err()
    .expect("NUL path must fail")
    .to_string();
    assert!(err.contains("NUL"), "names the cause: {err}");
}

#[test]
fn h9_t5_unwritable_path_maps_126_naming_path() {
    // T5 (RED): child-side open failure exits 126 (never 127),
    // and the parent error names the path (never silent null).
    let path = "/nonexistent-h9-dir-xyz/workload.log";
    let err = OwnedTarget::spawn_stopped(&sentinel_argv(), WorkloadDest::File(path.into()))
        .err()
        .expect("unwritable path must fail")
        .to_string();
    assert!(err.contains("126"), "126 mapping: {err}");
    assert!(!err.contains("127"), "never 127-confused: {err}");
    assert!(err.contains(path), "names the path: {err}");
}
