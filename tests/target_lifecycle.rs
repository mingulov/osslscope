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

// ---------------------------------------------------------------------------
// R06 (F07): bounded pre-stop setup with immediate child custody.
// ---------------------------------------------------------------------------

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Unique scratch dir per R06 test (parallel-safe: distinct names).
fn r06_scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("r06-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Sentinel argv: touches `sentinel`, then sleeps. The sentinel must
/// NEVER exist after a failed setup: a never-released child is killed
/// pre-exec (or never forked), so the payload cannot run.
fn r06_sentinel_argv(sentinel: &Path) -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("touch '{}'; sleep 30", sentinel.display()),
    ]
}

fn r06_mkfifo(path: &Path) {
    let c = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

/// Independent watchdog for the FIFO tests: if the spawn has not
/// returned after `timeout`, opens the fifo O_RDWR (never blocks,
/// even with no counterpart) and HOLDS it — releasing any child
/// stuck in a blocking open (the RED shape) so the test runner never
/// waits indefinitely. `finish` returns whether the rescue fired.
struct R06Rescue {
    done: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn r06_watch_fifo(fifo: PathBuf, timeout: Duration) -> R06Rescue {
    let done = Arc::new(AtomicBool::new(false));
    let fired = Arc::new(AtomicBool::new(false));
    let done_c = done.clone();
    let fired_c = fired.clone();
    let handle = std::thread::spawn(move || {
        let end = Instant::now() + timeout;
        let mut fd: libc::c_int = -1;
        loop {
            if done_c.load(Ordering::SeqCst) {
                break;
            }
            if Instant::now() >= end {
                fired_c.store(true, Ordering::SeqCst);
                if fd < 0 {
                    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
                    fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
                }
            }
            if Instant::now() >= end + Duration::from_secs(60) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    });
    R06Rescue {
        done,
        fired,
        handle: Some(handle),
    }
}

impl R06Rescue {
    fn finish(mut self) -> bool {
        self.done.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap();
        self.fired.load(Ordering::SeqCst)
    }
}

/// Cleanup for an unexpectedly spawned child on the must-fail paths:
/// retains the exact owned pid and guarantees no stopped child or
/// zombie survives, then fails with the RED shape.
fn r06_unexpected_child(mut t: OwnedTarget, what: &str) -> ! {
    let pid = t.pid();
    t.resolve_setup_failure().unwrap();
    assert_reaped_no_zombie(pid);
    panic!("{what}, but spawned pid {pid}");
}

#[test]
fn fifo_setup_cancel_reaps_child() {
    // R06/F07 core: a FIFO workload destination with no reader, plus
    // a SIGINT/SIGTERM-like cancellation arriving mid-setup. Setup
    // must fail fast with no surviving child; the sentinel must never
    // execute. The watchdog only fires on a regressed (blocking)
    // implementation, releasing the stuck child so the runner never
    // hangs; GREEN never needs the rescue.
    let dir = r06_scratch("fifo-cancel");
    let fifo = dir.join("sink.fifo");
    r06_mkfifo(&fifo);
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = Arc::new(AtomicBool::new(false));
    // Signal-like cancellation from another thread (the same store
    // the SIGINT/SIGTERM handler performs on capture's live flag).
    let cancel_c = cancel.clone();
    let signaller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        cancel_c.store(true, Ordering::SeqCst);
    });
    let watchdog = r06_watch_fifo(fifo.clone(), Duration::from_secs(5));
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(fifo.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    let elapsed = t0.elapsed();
    let fired = watchdog.finish();
    signaller.join().unwrap();
    match result {
        Err(e) => {
            let msg = e.to_string();
            // No-reader FIFO: the pre-fork open fails fast (ENXIO),
            // naming the path, the fifo kind and the 126 marker. (A
            // wildly descheduled entry could observe the pending
            // cancel first instead — also a childless fast failure.)
            assert!(msg.contains("sink.fifo"), "names the path: {msg}");
            assert!(msg.contains("126"), "126 marker: {msg}");
            assert!(
                msg.contains("fifo") || msg.contains("cancel"),
                "fifo or cancel cause: {msg}"
            );
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert!(!fired, "watchdog rescue must not be needed");
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "FIFO setup must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn prestop_deadline_reaps_child() {
    // R06: an already-exceeded pre-stop deadline fails WITHOUT
    // forking: no child exists to stop, the sentinel never executes,
    // and the error names the deadline.
    let dir = r06_scratch("prestop-deadline");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    // Zero-timeout-shaped deadline, sampled before the call, so the
    // `now >= deadline` check inside is deterministically true.
    let deadline = osslscope::args::deadline_at(Instant::now(), Duration::ZERO).unwrap();
    let t0 = Instant::now();
    let result =
        OwnedTarget::spawn_stopped_with_control(&argv, WorkloadDest::Null, deadline, &cancel);
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("deadline"), "names the deadline: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "expired deadline must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn setup_cancel_before_fork_spawns_nothing() {
    // R06: cancellation already pending (SIGINT/SIGTERM delivered
    // before setup) fails without forking; the sentinel never runs.
    let dir = r06_scratch("cancel-prefix");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(true);
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("cancel"), "names cancellation: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "pending cancel must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn zero_timeout_admission_fails_fast_without_child() {
    // `--timeout 0` is ADMITTED (range [0,120]) and means "no setup
    // time": capture's checked setup deadline is already exceeded, so
    // the spawn fails before ANY side effect — the child is never
    // forked AND the file sink is never opened/truncated.
    assert_eq!(
        osslscope::args::parse_seconds("--timeout", "0").unwrap(),
        Duration::ZERO
    );
    let dir = r06_scratch("zero-timeout");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"precious\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let deadline = osslscope::args::deadline_at(Instant::now(), Duration::ZERO).unwrap();
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        deadline,
        &cancel,
    );
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("deadline"), "names the deadline: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert_eq!(
                std::fs::read(&log).unwrap(),
                b"precious\n",
                "no truncation on dead setup"
            );
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "zero timeout must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn file_open_failure_names_path_with_126() {
    // R06 keeps the H9 126 taxonomy on the new entrypoint: a file
    // sink that cannot be opened fails pre-fork, naming the path with
    // the 126 setup marker (never 127, never silent null).
    let path = "/nonexistent-r06-dir-xyz/workload.log";
    let cancel = AtomicBool::new(false);
    let err = OwnedTarget::spawn_stopped_with_control(
        &sentinel_argv(),
        WorkloadDest::File(path.into()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    )
    .err()
    .expect("unwritable path must fail")
    .to_string();
    assert!(err.contains("126"), "126 mapping: {err}");
    assert!(!err.contains("127"), "never 127-confused: {err}");
    assert!(err.contains(path), "names the path: {err}");
}

#[test]
fn fifo_dest_rejected_without_spawn() {
    // FIFO rejection via the fstat gate (no cancellation): the test
    // itself holds a reader, so even a regressed blocking open could
    // not hang — yet the sink is still refused as a non-regular
    // file, pre-fork, naming the path. Nothing forked, sentinel
    // never executes.
    let dir = r06_scratch("fifo-plain");
    let fifo = dir.join("sink.fifo");
    r06_mkfifo(&fifo);
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let fc = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    let reader = unsafe { libc::open(fc.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    assert!(reader >= 0, "test holds a fifo reader");
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(fifo.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    let elapsed = t0.elapsed();
    unsafe {
        libc::close(reader);
    }
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not a regular file") && msg.contains("fifo"),
                "regular-file cause: {msg}"
            );
            assert!(msg.contains("sink.fifo"), "names the path: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "FIFO dest must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn device_dest_rejected_without_spawn() {
    // Non-regular sinks are rejected even when openable: /dev/null
    // (a character device) is not a pinned regular file — the Null
    // default and caller-held fds cover those uses.
    let dir = r06_scratch("device-sink");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File("/dev/null".into()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("regular file"), "regular-file cause: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "device dest must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn symlink_dest_rejected_without_truncation() {
    // A symlinked sink is refused WITHOUT following it: the classic
    // truncation surprise (open+truncate through a link the operator
    // did not pin) cannot happen.
    let dir = r06_scratch("symlink-sink");
    let victim = dir.join("victim.log");
    std::fs::write(&victim, b"precious\n").unwrap();
    let link = dir.join("sink.log");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(link.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("sink.log"), "names the path: {msg}");
            assert_eq!(
                std::fs::read(&victim).unwrap(),
                b"precious\n",
                "link target never truncated"
            );
            assert!(!sentinel.exists(), "sentinel must never execute");
        }
        Ok(t) => r06_unexpected_child(t, "symlink dest must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pinned_sink_survives_path_replacement() {
    // The file sink is PINNED (an open fd, not a path): replacing the
    // path after a successful spawn cannot redirect the child's
    // output — the original inode keeps the bytes, the replacement
    // stays untouched. (Preserved-behavior pin: the pinning moves
    // parent-side under R06.)
    let dir = r06_scratch("replacement");
    let path = dir.join("workload.log");
    std::fs::write(&path, b"stale\n").unwrap();
    let cancel = AtomicBool::new(false);
    let mut t = OwnedTarget::spawn_stopped_with_control(
        &sentinel_argv(),
        WorkloadDest::File(path.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    )
    .unwrap();
    let pid = t.pid();
    let aside = dir.join("original.log");
    std::fs::rename(&path, &aside).unwrap();
    std::fs::write(&path, b"replacement\n").unwrap();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(pid);
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        b"H9-OUT-S\nH9-ERR-S\n",
        "original inode keeps the bytes"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"replacement\n",
        "replacement untouched"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn with_control_happy_path_releases_and_reaps() {
    // The new entrypoint preserves the happy path: spawn stopped,
    // release, exit status preserved, reaped exactly once.
    let cancel = AtomicBool::new(false);
    let mut t = OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".to_string()],
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(30),
        &cancel,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(pid);
}
