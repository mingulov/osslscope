//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 owned-target custody lifecycle (R05): explicit stopped /
//! released / reaped / detached states on every return; no owned
//! stopped child or zombie after cleanup; external `--pid` targets
//! are never signaled. No BPF or privileges needed — except the
//! R20 F1 live lane (`ordinary_production_run_…`, `#[ignore]` +
//! env-gated, root-only), which runs production `capture::run`.

use osslscope::target::{
    __test_set_control_worker_counter, __test_set_fail_fork, __test_set_prestop_pid_sink,
    __test_set_prestop_stall_ms, __test_set_publish_gate, __test_set_rename_hold_ms,
    __test_set_rename_hold_ready, __test_set_setup_delay_ms, __test_set_truncate_delay_ms,
    CustodyState, OwnedTarget, TargetDisposition, WorkloadDest,
};
use std::time::{Duration, Instant};

/// Connector facility gate (R20-fix rounds 2-4 MINOR — mirrored
/// in capture_controller.rs): two tiers, probed once per process
/// (subscribing runs the initial watermark burst, so probing per
/// test would spam). Tier 1 (`require_connector`) needs a working
/// subscription; tier 2 (`require_clean_connector`) additionally
/// needs the socket Drops row readable AND a clean watermark
/// burst (every online CPU pinned — restricted-affinity hosts
/// record pinning loss by design). COMPLETE/zero-loss tests use
/// tier 2, so supported PARTIAL (drops-blind or pin-limited)
/// environments skip them instead of failing. Either tier skips
/// (pass) unless `OSSLSCOPE_REQUIRE_CONNECTOR=1` forces a hard
/// failure. `OSSLSCOPE_CONNECTOR_TEST=force-absent` simulates
/// absence; `=force-no-drops` simulates a drops-blind
/// environment; `=force-no-watermark` simulates restricted
/// affinity (pin-limited) environments.
fn connector_facility_cached() -> (bool, bool, bool) {
    use std::sync::OnceLock;
    static PROBE: OnceLock<(bool, bool, bool)> = OnceLock::new();
    *PROBE.get_or_init(|| {
        let hook = std::env::var("OSSLSCOPE_CONNECTOR_TEST").unwrap_or_default();
        if hook == "force-absent" {
            return (false, false, false);
        }
        let f = osslscope::capture::connector_facility();
        if hook == "force-no-drops" {
            return (f.subscribes, false, f.watermark_clean);
        }
        if hook == "force-no-watermark" {
            return (f.subscribes, f.drops_readable, false);
        }
        (f.subscribes, f.drops_readable, f.watermark_clean)
    })
}

fn connector_present() -> bool {
    connector_facility_cached().0
}

fn connector_clean() -> bool {
    connector_facility_cached() == (true, true, true)
}

fn require_connector(test: &str) -> bool {
    if connector_present() {
        return true;
    }
    assert!(
        std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() != Ok("1"),
        "{test} requires a working proc connector (OSSLSCOPE_REQUIRE_CONNECTOR=1)"
    );
    eprintln!("SKIP {test}: proc connector unavailable (fallback/PARTIAL shape unsupported here)");
    false
}

fn require_clean_connector(test: &str) -> bool {
    if connector_clean() {
        return true;
    }
    assert!(
        std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() != Ok("1"),
        "{test} requires a working proc connector with readable Drops and clean watermark pinning (OSSLSCOPE_REQUIRE_CONNECTOR=1)"
    );
    let (_, drops, _) = connector_facility_cached();
    if !drops {
        eprintln!("SKIP {test}: connector drops-blind here (supported PARTIAL, not zero-loss)");
    } else {
        eprintln!(
            "SKIP {test}: watermark pinning limited here (restricted affinity records loss by design; supported PARTIAL, not zero-loss)"
        );
    }
    false
}

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
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;

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

/// Cancel source for a supervised spawn: a shared flag (direct
/// store) or the process signal flag (wired to a real SIGINT/SIGTERM
/// handler by the signal tests below).
#[derive(Clone)]
enum R06Cancel {
    Shared(Arc<AtomicBool>),
    Signalled(&'static AtomicBool),
}

impl R06Cancel {
    fn flag(&self) -> &AtomicBool {
        match self {
            R06Cancel::Shared(a) => a,
            R06Cancel::Signalled(s) => s,
        }
    }
}

/// Spawn on a worker thread with the pre-stop test hook armed (fix round
/// 1): the worker reports the forked pid out-of-band into the returned
/// sink (0 = not forked yet) and the pre-stop stall keeps the parent's
/// wait loop provably mid-spin, so cancellation/deadline land post-fork.
/// The caller enforces its own join bound plus exact-pid rescue — fully
/// independent of the code under test (a hung worker fails the test, it
/// never hangs the runner, and no child leaks on any path).
fn r06_spawn_async(
    argv: Vec<String>,
    dest: WorkloadDest,
    deadline: Instant,
    cancel: R06Cancel,
    stall_ms: u64,
) -> (
    std::thread::JoinHandle<()>,
    Arc<AtomicU32>,
    mpsc::Receiver<anyhow::Result<OwnedTarget>>,
) {
    let sink = Arc::new(AtomicU32::new(0));
    let sink_c = sink.clone();
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        __test_set_prestop_stall_ms(stall_ms);
        __test_set_prestop_pid_sink(Some(sink_c));
        let r = OwnedTarget::spawn_stopped_with_control(&argv, dest, deadline, cancel.flag());
        __test_set_prestop_pid_sink(None);
        __test_set_prestop_stall_ms(0);
        let _ = tx.send(r);
    });
    (worker, sink, rx)
}

/// Setup-hook bundle for a supervised spawn (fix round 5): the setup
/// hooks are thread-local to the thread calling `spawn_stopped_with_control`,
/// so a supervised (async) spawn must arm them on its worker thread, not the
/// test thread. All armed before the call, all reset after (every path).
#[derive(Default)]
struct R06SetupHooks {
    setup_delay_ms: u64,
    truncate_delay_ms: u64,
    publish_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
    rename_hold_ms: u64,
    rename_hold_ready: Option<Arc<AtomicBool>>,
    worker_counter: Option<Arc<AtomicU32>>,
}

/// Supervised spawn with setup hooks armed on the worker thread (fix round
/// 5): same independence guarantees as [`r06_spawn_async`] (own join bound,
/// exact-pid discipline, never hangs the runner), plus worker-side setup
/// instrumentation for tests that must act mid-setup (retry during a poised
/// worker, cancel during a post-check hold).
fn r06_spawn_async_setup(
    argv: Vec<String>,
    dest: WorkloadDest,
    deadline: Instant,
    cancel: R06Cancel,
    stall_ms: u64,
    setup: R06SetupHooks,
) -> (
    std::thread::JoinHandle<()>,
    Arc<AtomicU32>,
    mpsc::Receiver<anyhow::Result<OwnedTarget>>,
) {
    let sink = Arc::new(AtomicU32::new(0));
    let sink_c = sink.clone();
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        __test_set_prestop_stall_ms(stall_ms);
        __test_set_prestop_pid_sink(Some(sink_c));
        __test_set_setup_delay_ms(setup.setup_delay_ms);
        __test_set_truncate_delay_ms(setup.truncate_delay_ms);
        __test_set_publish_gate(setup.publish_gate);
        __test_set_rename_hold_ms(setup.rename_hold_ms);
        __test_set_rename_hold_ready(setup.rename_hold_ready);
        __test_set_control_worker_counter(setup.worker_counter);
        let r = OwnedTarget::spawn_stopped_with_control(&argv, dest, deadline, cancel.flag());
        __test_set_control_worker_counter(None);
        __test_set_rename_hold_ready(None);
        __test_set_rename_hold_ms(0);
        __test_set_publish_gate(None);
        __test_set_truncate_delay_ms(0);
        __test_set_setup_delay_ms(0);
        __test_set_prestop_pid_sink(None);
        __test_set_prestop_stall_ms(0);
        let _ = tx.send(r);
    });
    (worker, sink, rx)
}

/// Wait until the pid sink reports a fork (or the bound expires).
fn r06_wait_forked(sink: &AtomicU32, bound: Duration) -> Option<u32> {
    let end = Instant::now() + bound;
    loop {
        let pid = sink.load(Ordering::SeqCst);
        if pid != 0 {
            return Some(pid);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Independent PID custody: SIGKILL + reap one exact pid, tolerating the
/// race where the spawn worker reaped it first (ECHILD). Bounded (5s),
/// and never touches any other pid (no global child scans — unsafe under
/// parallel test threads).
fn r06_rescue_pid(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if r > 0 {
            return;
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // ECHILD: the worker reaped it — custody resolved either way.
            return;
        }
        assert!(Instant::now() < end, "rescue: pid {pid} would not die");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Independent exact-PID teardown (fix round 2 / F4): RAII rescue of one
/// observed pid. Armed the moment a fork is observed, disarmed only after
/// the test verifies the reap. `Drop` is best-effort SIGKILL + bounded
/// reap of the exact pid only (ECHILD-tolerant, never panics), so
/// assertion failures and unwinding still rescue the child — confinement
/// never depends on production cleanup succeeding.
struct R06PidGuard {
    pid: u32,
    armed: bool,
}

impl R06PidGuard {
    fn arm(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for R06PidGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            let mut status = 0;
            let r = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if r > 0 {
                return;
            }
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // ECHILD: someone else reaped it — resolved either way.
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Bounded effort exhausted: Drop must never panic, so an
        // unkillable child is left for the explicit asserts (which fail
        // loudly) rather than panicking from unwinding.
    }
}

/// Join a supervised spawn with a hard bound: on timeout, rescue the
/// exact observed pid, verify no zombie, then fail — a regressed hang
/// fails the test, never the runner. (The still-blocked worker is
/// detached: dropping its handle; it owns no child after the rescue.)
fn r06_join_supervised(
    worker: std::thread::JoinHandle<()>,
    rx: mpsc::Receiver<anyhow::Result<OwnedTarget>>,
    pid: u32,
    bound: Duration,
) -> anyhow::Result<OwnedTarget> {
    match rx.recv_timeout(bound) {
        Ok(r) => {
            worker.join().unwrap();
            r
        }
        Err(_) => {
            r06_rescue_pid(pid);
            assert_reaped_no_zombie(pid);
            panic!("spawn hung beyond {bound:?}; rescued pid {pid}");
        }
    }
}

/// Process-wide test signal flag (mirrors capture's INTERRUPTED: one flag
/// fed by the real handler). Reset on every arm; the two signal tests
/// serialize on [`R06_SIGNAL_LOCK`] so delivery attribution stays exact.
static R06_SIGNAL_FLAG: AtomicBool = AtomicBool::new(false);
static R06_SIGNAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

extern "C" fn r06_on_test_signal(_sig: libc::c_int) {
    R06_SIGNAL_FLAG.store(true, Ordering::SeqCst);
}

/// RAII signal disposition: installs the test handler, restores the
/// previous disposition on drop (all paths).
struct R06SigGuard {
    sig: libc::c_int,
    old: libc::sigaction,
}

fn r06_arm_signal(sig: libc::c_int) -> R06SigGuard {
    R06_SIGNAL_FLAG.store(false, Ordering::SeqCst);
    unsafe {
        let mut new: libc::sigaction = std::mem::zeroed();
        new.sa_sigaction = r06_on_test_signal as usize;
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(sig, &new, &mut old),
            0,
            "install test signal handler"
        );
        R06SigGuard { sig, old }
    }
}

impl Drop for R06SigGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(self.sig, &self.old, std::ptr::null_mut());
        }
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
    // R06/F07 fix round 1: a FIFO workload destination in its sanctioned
    // streaming form (caller-held fifo fd — `File(fifo)` rejection stays
    // pinned by `fifo_dest_rejected_without_spawn`), with a
    // SIGINT/SIGTERM-like cancellation arriving deterministically
    // post-fork (only after the fork is observed; the 10s stall keeps the
    // wait loop provably mid-spin). Setup must fail with the forked child
    // killed pre-exec and reaped (status 137); the sentinel must never
    // execute. Join bound + exact-pid rescue are independent of the code
    // under test: error, unexpected-Ok and hung-worker paths all leave no
    // child and never hang the runner.
    let dir = r06_scratch("fifo-cancel");
    let fifo = dir.join("sink.fifo");
    r06_mkfifo(&fifo);
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    // Caller-held streaming fd for the fifo (O_RDWR never blocks, even
    // with no counterpart): the documented non-File form for FIFOs.
    // OwnedFd so the descriptor closes on every path, including panics.
    let fc = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    let raw = unsafe { libc::open(fc.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(raw >= 0, "test holds the fifo fd");
    let stream = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Fd(stream.as_raw_fd()),
        Instant::now() + Duration::from_secs(30),
        R06Cancel::Shared(cancel.clone()),
        10_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    // F4: independent teardown armed before any fallible step — panics
    // below (join timeout, message asserts, reap verification) still
    // rescue the exact observed pid on unwinding.
    let mut r06_guard = R06PidGuard::arm(pid);
    cancel.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let result = r06_join_supervised(worker, rx, pid, Duration::from_secs(20));
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("cancel"), "names cancellation: {msg}");
            assert!(
                msg.contains(&format!("owned child {pid} killed and reaped")),
                "confirmed cleanup of the observed pid: {msg}"
            );
            assert!(msg.contains("(status 137)"), "SIGKILL status: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert_reaped_no_zombie(pid);
            assert!(!sentinel.exists(), "sentinel must never execute");
            r06_guard.disarm();
        }
        Ok(t) => r06_unexpected_child(t, "cancelled FIFO setup must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn prestop_deadline_reaps_child() {
    // Leg 1 (R06): an already-exceeded pre-stop deadline fails WITHOUT
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

    // Leg 2 (fix round 1): a LIVE deadline expiring deterministically
    // mid-wait (2s deadline vs 10s stall, with prep taking ~1ms): the
    // forked child is killed pre-exec and reaped (status 137), and the
    // error names both the deadline and the observed pid.
    let dir = r06_scratch("prestop-deadline-live");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let live_cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(2),
        R06Cancel::Shared(live_cancel),
        10_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    // F4: independent teardown armed before any fallible step.
    let mut r06_guard = R06PidGuard::arm(pid);
    let t0 = Instant::now();
    let result = r06_join_supervised(worker, rx, pid, Duration::from_secs(20));
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("deadline"), "names the deadline: {msg}");
            assert!(
                msg.contains(&format!("owned child {pid} killed and reaped")),
                "confirmed cleanup of the observed pid: {msg}"
            );
            assert!(msg.contains("(status 137)"), "SIGKILL status: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert_reaped_no_zombie(pid);
            assert!(!sentinel.exists(), "sentinel must never execute");
            r06_guard.disarm();
        }
        Ok(t) => r06_unexpected_child(t, "expired live deadline must fail"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Shared body for the real-signal tests: install a genuine SIGINT /
/// SIGTERM handler (the production shape — one flag fed by the handler),
/// spawn supervised with a 10s stall, deliver the actual signal only
/// after the fork is observed, and prove the child is killed pre-exec
/// and reaped. Serialized with the sibling signal test so attribution of
/// the shared process flag stays exact.
fn r06_prestop_signal_reaps_child(sig: libc::c_int, sig_name: &str, scratch: &str) {
    // Poison-tolerant: the lock only serializes the two signal tests
    // (no data protected), so a sibling's failure must not mask this
    // test's own verdict.
    let _lock = R06_SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = r06_arm_signal(sig);
    let dir = r06_scratch(scratch);
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(30),
        R06Cancel::Signalled(&R06_SIGNAL_FLAG),
        10_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    // F4: independent teardown armed before any fallible step (including
    // the raise assert itself).
    let mut r06_guard = R06PidGuard::arm(pid);
    // Actual signal delivery to this process (not a bare store): the
    // installed handler performs the production store.
    assert_eq!(unsafe { libc::raise(sig) }, 0, "raise {sig_name}");
    let t0 = Instant::now();
    let result = r06_join_supervised(worker, rx, pid, Duration::from_secs(20));
    let elapsed = t0.elapsed();
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("cancel"), "names cancellation: {msg}");
            assert!(
                msg.contains(&format!("owned child {pid} killed and reaped")),
                "confirmed cleanup of the observed pid: {msg}"
            );
            assert!(msg.contains("(status 137)"), "SIGKILL status: {msg}");
            assert!(elapsed < Duration::from_secs(5), "fail fast: {elapsed:?}");
            assert_reaped_no_zombie(pid);
            assert!(!sentinel.exists(), "sentinel must never execute");
            r06_guard.disarm();
        }
        Ok(t) => r06_unexpected_child(t, &format!("{sig_name} must cancel setup")),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn prestop_sigint_reaps_stalled_child() {
    r06_prestop_signal_reaps_child(libc::SIGINT, "SIGINT", "sigint-reap");
}

#[test]
fn prestop_sigterm_reaps_stalled_child() {
    r06_prestop_signal_reaps_child(libc::SIGTERM, "SIGTERM", "sigterm-reap");
}

#[test]
fn prestop_watchdog_rescues_blocked_setup() {
    // The join bound + exact-pid rescue are ENFORCING, not advisory: with
    // a 60s stall the spawn cannot return within the 3s join window, so
    // this test must take the timeout path, rescue the exact observed pid
    // itself, and then confirm the worker still returns (its wait loop
    // notices the reaped child) — no hung test, no leaked child, no
    // leaked worker.
    let dir = r06_scratch("watchdog-rescue");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(120),
        R06Cancel::Shared(cancel),
        60_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    // F4: independent teardown armed before any fallible step.
    let mut r06_guard = R06PidGuard::arm(pid);
    // The spawn cannot return in 3s (60s stall, no cancel, far deadline):
    // the timeout path is the assertion.
    assert!(
        rx.recv_timeout(Duration::from_secs(3)).is_err(),
        "spawn must still be blocked"
    );
    // Independent rescue of the exact observed pid (the worker never
    // participates): kill + reap, then verify no zombie.
    r06_rescue_pid(pid);
    assert_reaped_no_zombie(pid);
    r06_guard.disarm();
    // After the rescue the worker's wait must return promptly (its child
    // is gone): confirm no hung worker, then drop either outcome.
    let drained = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("worker returns after rescue");
    worker.join().unwrap();
    if let Ok(t) = drained {
        // Unexpected Ok after a rescue: resolve + verify, then fail.
        r06_unexpected_child(t, "rescued setup must not succeed");
    }
    assert!(!sentinel.exists(), "sentinel must never execute");
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

// ---------------------------------------------------------------------------
// R06 fix round 1 (F3): a pinned file sink must survive closed stdio.
// ---------------------------------------------------------------------------

/// Marker env var for the closed-stdio inner run: value is the result-file path.
const R06_CLOSED_STDIO_INNER: &str = "R06_CLOSED_STDIO_INNER";
/// This test's own name (libtest filter for the inner re-exec).
const R06_CLOSED_STDIO_TEST: &str = "pinned_sink_survives_closed_stdio";

fn r06_note(log: &mut std::fs::File, s: &str) {
    use std::io::Write as _;
    let _ = writeln!(log, "{s}");
}

/// One closed-stdio spawn: file sink must capture both sentinel streams.
/// Runs with the caller's stdio already closed; performs no printing.
/// Returns (exit status, sink bytes): content is checked before status so
/// a lost stream reports MISMATCH (the F3 shape) rather than a bare error.
fn r06_closed_stdio_one(sink: &Path, idle: &AtomicBool) -> Result<(Option<i32>, Vec<u8>), String> {
    let mut t = OwnedTarget::spawn_stopped_with_control(
        &sentinel_argv(),
        WorkloadDest::File(sink.to_path_buf()),
        Instant::now() + Duration::from_secs(30),
        idle,
    )
    .map_err(|e| format!("spawn: {e:#}"))?;
    t.release().map_err(|e| format!("release: {e:#}"))?;
    let code = wait_for_exit(&mut t, Duration::from_secs(5));
    let bytes = std::fs::read(sink).map_err(|e| format!("read sink: {e}"))?;
    Ok((code, bytes))
}

/// Check one case's (status, bytes): MISMATCH (return 1) when a stream was
/// lost, ERROR (return 2) on any other surprise, or `None` to continue.
fn r06_closed_stdio_check(
    log: &mut std::fs::File,
    case: &str,
    r: Result<(Option<i32>, Vec<u8>), String>,
) -> Option<i32> {
    match r {
        Ok((code, bytes)) if bytes == b"H9-OUT-S\nH9-ERR-S\n" && code == Some(0) => {
            r06_note(log, &format!("case {case}: PASS"));
            None
        }
        Ok((code, bytes)) => {
            r06_note(
                log,
                &format!("case {case}: MISMATCH exit={code:?} bytes={bytes:?}"),
            );
            Some(1)
        }
        Err(e) => {
            r06_note(log, &format!("case {case}: ERROR {e}"));
            Some(2)
        }
    }
}

/// Inner run (re-exec'd subprocess): closes stdio, then proves both
/// sentinel streams still land in pinned file sinks. Communicates only
/// via the result file (fd >= 3, opened before any close) and the exit
/// code. Returns the process exit code: 0 both pass, 1 content mismatch
/// (the F3 bug shape), 2 unexpected error.
fn r06_closed_stdio_inner_main(result_path: &Path) -> i32 {
    let mut log = match std::fs::File::create(result_path) {
        Ok(f) => f,
        Err(_) => return 2,
    };
    let dir = r06_scratch("closed-stdio-inner");
    let idle = AtomicBool::new(false);
    // Case B first (stderr-only closed: open returns fd 2), then case A
    // (both closed: open returns fd 1). Each case must capture both lines.
    unsafe {
        libc::close(libc::STDERR_FILENO);
    }
    let sink_b = dir.join("b.log");
    if let Some(code) = r06_closed_stdio_check(
        &mut log,
        "stderr-only-closed",
        r06_closed_stdio_one(&sink_b, &idle),
    ) {
        let _ = std::fs::remove_dir_all(&dir);
        return code;
    }
    unsafe {
        libc::close(libc::STDOUT_FILENO);
    }
    let sink_a = dir.join("a.log");
    if let Some(code) = r06_closed_stdio_check(
        &mut log,
        "both-closed",
        r06_closed_stdio_one(&sink_a, &idle),
    ) {
        let _ = std::fs::remove_dir_all(&dir);
        return code;
    }
    r06_note(&mut log, "PASS");
    let _ = std::fs::remove_dir_all(&dir);
    0
}

#[test]
fn pinned_sink_survives_closed_stdio() {
    // Inner branch: this same test binary re-exec'd with the marker env
    // set. Closing stdio happens ONLY in the subprocess, so the parallel
    // harness (which shares fds 1/2 with every in-process test) is
    // untouched. Never returns.
    if let Ok(path) = std::env::var(R06_CLOSED_STDIO_INNER) {
        std::process::exit(r06_closed_stdio_inner_main(Path::new(&path)));
    }
    // Outer: re-exec with only this test selected; the inner run closes
    // ITS copies of fds 1/2, forcing the pinned open() onto fd 1/2 — the
    // F3 shape (O_CLOEXEC + dup2 no-op loses the stream at exec).
    let dir = r06_scratch("closed-stdio");
    let result = dir.join("result.txt");
    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .args(["--exact", R06_CLOSED_STDIO_TEST, "--nocapture"])
        .env(R06_CLOSED_STDIO_INNER, &result)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // Bounded wait: the inner run is self-bounding (~seconds); kill on a
    // 60s overrun so a regression can never hang the runner.
    let end = Instant::now() + Duration::from_secs(60);
    let status = loop {
        match child.try_wait().unwrap() {
            Some(s) => break s,
            None => {
                if Instant::now() >= end {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("closed-stdio inner run hung; killed");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let detail =
        std::fs::read_to_string(&result).unwrap_or_else(|_| "<inner never wrote>".to_string());
    assert!(
        status.success(),
        "closed-stdio inner failed ({status}): {detail}"
    );
    assert!(detail.contains("PASS"), "inner result: {detail}");
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

// ---------------------------------------------------------------------------
// R06 fix round 2: discarded-result/fork-error disposal (F1), guard-based
// test teardown (F4), abandoned-worker truncation (NEW).
// ---------------------------------------------------------------------------

#[test]
fn fork_failure_disposes_sink_under_control() {
    // F1: the fork-failure path must dispose the prepared sink on a
    // control worker — never by dropping it inline on the caller (a FUSE
    // FLUSH inside that drop would hang setup). The injected fork fault
    // is deterministic; the worker counter proves a disposal worker ran
    // beyond the preparation worker(s).
    let dir = r06_scratch("fork-fail-dispose");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"stale\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let counter = Arc::new(AtomicU32::new(0));
    __test_set_control_worker_counter(Some(counter.clone()));
    __test_set_fail_fork(true);
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    );
    __test_set_control_worker_counter(None);
    __test_set_fail_fork(false);
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "injected fork failure must fail"),
    };
    assert!(msg.contains("fork"), "fork failure surfaces: {msg}");
    assert!(!sentinel.exists(), "sentinel must never execute");
    // The disposal worker runs asynchronously: bounded poll, then the
    // ownership assertion (fails on inline disposal: the counter never
    // passes the preparation worker(s)).
    let end = Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < end,
            "no disposal worker ran (counter {})",
            counter.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn abandoned_prep_worker_never_truncates_successor() {
    // NEW: a preparation worker delayed past the caller's abandonment must
    // never truncate bytes written after that abandonment. The worker is
    // deterministically delayed (2s) past a 300ms setup deadline; a
    // successor then populates the destination; the late worker must not
    // destroy it.
    let dir = r06_scratch("abandoned-prep");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"original\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let counter = Arc::new(AtomicU32::new(0));
    __test_set_control_worker_counter(Some(counter.clone()));
    __test_set_setup_delay_ms(2000);
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_millis(300),
        &cancel,
    );
    __test_set_setup_delay_ms(0);
    __test_set_control_worker_counter(None);
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "expired setup must fail"),
    };
    assert!(
        msg.contains("deadline"),
        "caller abandoned on deadline: {msg}"
    );
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"original\n",
        "worker still delayed at abandonment"
    );
    // A retry or another writer populates the destination now.
    std::fs::write(&log, b"successor-bytes\n").unwrap();
    // Wait for the late worker to finish (bounded), then prove the
    // successor bytes survived it.
    let end = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"successor-bytes\n",
        "late worker must never truncate post-abandonment bytes"
    );
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn file_truncate_runs_under_setup_control() {
    // Fix round 3 / NEW: file-sink truncation must run where
    // deadline/cancellation control applies — the caller must never block
    // in open/truncate/close on the setup path — while a worker delayed
    // past abandonment still truncates nothing.
    //
    // Leg 1 (bounded + gated): preparation is deterministically
    // stalled (3s, simulating a sink that answers slowly) between staging
    // and the atomic publish, past a 300ms setup deadline. The caller must
    // fail fast on the deadline — not block in the stall — fork nothing,
    // and the successor bytes written after abandonment must survive the
    // late worker.
    let dir = r06_scratch("truncate-control");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"original\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let counter = Arc::new(AtomicU32::new(0));
    let pid_sink = Arc::new(AtomicU32::new(0));
    __test_set_control_worker_counter(Some(counter.clone()));
    __test_set_truncate_delay_ms(3000);
    __test_set_prestop_pid_sink(Some(pid_sink.clone()));
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_millis(300),
        &cancel,
    );
    let elapsed = t0.elapsed();
    __test_set_truncate_delay_ms(0);
    __test_set_control_worker_counter(None);
    __test_set_prestop_pid_sink(None);
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "expired setup must fail"),
    };
    assert!(
        msg.contains("deadline"),
        "caller abandoned on deadline: {msg}"
    );
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert_eq!(pid_sink.load(Ordering::SeqCst), 0, "no fork may happen");
    assert!(
        elapsed < Duration::from_secs(2),
        "caller must not block in truncation (took {elapsed:?})"
    );
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"original\n",
        "staged open truncates nothing"
    );
    assert!(!sentinel.exists(), "sentinel must never execute");
    // A retry or another writer populates the destination now.
    std::fs::write(&log, b"successor-bytes\n").unwrap();
    // Wait for the late worker to finish (bounded), then prove the
    // successor bytes survived it.
    let end = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"successor-bytes\n",
        "late worker must never truncate post-abandonment bytes"
    );
    //
    // Leg 2 (live setup still truncates): pre-existing bytes — longer than
    // the workload output, so a skipped truncate would leave a detectable
    // tail — are gone after a successful spawn; the workload output lands
    // in the file byte-identical.
    let log2 = dir.join("live.log");
    std::fs::write(&log2, b"stale-stale-stale-stale-stale\n").unwrap();
    let mut t = OwnedTarget::spawn_stopped_with_control(
        &sentinel_argv(),
        WorkloadDest::File(log2.clone()),
        Instant::now() + Duration::from_secs(30),
        &cancel,
    )
    .unwrap();
    let pid = t.pid();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(pid);
    assert_eq!(
        std::fs::read(&log2).unwrap(),
        b"H9-OUT-S\nH9-ERR-S\n",
        "live setup truncates pre-existing bytes"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn abandoned_late_worker_never_truncates_successor() {
    // Fix round 4 / NO-LATE-TRUNCATE (restored post-check control): the
    // worker runs every pre-publish step (outer check passed while live,
    // destination validated, staging complete) and then pauses poised at
    // the atomic publish; the caller abandons on its deadline, a
    // successor populates the destination, and only then is the worker
    // released — the abandonment is ordered strictly before the atomic
    // check + rename, so the worker must delete its staging and publish
    // nothing, and the successor bytes must survive. (The old structure's
    // check-then-truncate gap — the RED shape of this test — no longer
    // exists: there is no post-check pause point inside the atomic
    // section, so this pauses at the last point before it.)
    let dir = r06_scratch("post-check-pause");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"original\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let counter = Arc::new(AtomicU32::new(0));
    let pid_sink = Arc::new(AtomicU32::new(0));
    let ready = Arc::new(AtomicBool::new(false));
    let proceed = Arc::new(AtomicBool::new(false));
    __test_set_control_worker_counter(Some(counter.clone()));
    __test_set_publish_gate(Some((ready.clone(), proceed.clone())));
    __test_set_prestop_pid_sink(Some(pid_sink.clone()));
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_millis(300),
        &cancel,
    );
    let elapsed = t0.elapsed();
    __test_set_publish_gate(None);
    __test_set_control_worker_counter(None);
    __test_set_prestop_pid_sink(None);
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "expired setup must fail"),
    };
    assert!(
        msg.contains("deadline"),
        "caller abandoned on deadline: {msg}"
    );
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert_eq!(pid_sink.load(Ordering::SeqCst), 0, "no fork may happen");
    assert!(
        elapsed < Duration::from_secs(2),
        "caller must not block on the poised worker (took {elapsed:?})"
    );
    // The worker is poised at the publish (bounded wait covers a
    // descheduled worker — either way it has NOT taken the publish lock
    // yet, and the abandonment above strictly precedes its decision).
    let end = Instant::now() + Duration::from_secs(10);
    while !ready.load(Ordering::SeqCst) {
        assert!(Instant::now() < end, "worker never poised at publish");
        std::thread::sleep(Duration::from_millis(1));
    }
    // A retry or another writer populates the destination now — after
    // the abandonment, before the worker's publish decision.
    std::fs::write(&log, b"successor-bytes\n").unwrap();
    assert!(!sentinel.exists(), "sentinel must never execute");
    // Release the worker, wait for it to finish (bounded), then prove
    // the successor bytes survived it.
    proceed.store(true, Ordering::SeqCst);
    let end = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"successor-bytes\n",
        "late worker must never truncate post-abandonment bytes"
    );
    // The abandoned worker deleted its staging: no litter beside the
    // destination.
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["workload.log".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn abandonment_bounded_with_stuck_worker() {
    // Fix round 5 / (i): abandonment returns within the deadline no matter
    // where the prep worker is stuck — the caller path takes no lock and
    // performs no blocking file syscalls (bounded by construction). Leg A
    // parks the worker before its first check; leg C parks it after its
    // final check (the re-reviewer's descheduled-after-check shape). The
    // pre-final-check pause stays pinned by
    // `abandoned_late_worker_never_truncates_successor` (preserved).
    //
    // Leg A (stuck pre-check): the worker is deterministically delayed
    // (2s) past a 300ms setup deadline; the caller must fail fast.
    let dir = r06_scratch("stuck-worker");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"original\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = AtomicBool::new(false);
    let counter = Arc::new(AtomicU32::new(0));
    let pid_sink = Arc::new(AtomicU32::new(0));
    __test_set_control_worker_counter(Some(counter.clone()));
    __test_set_setup_delay_ms(2000);
    __test_set_prestop_pid_sink(Some(pid_sink.clone()));
    let t0 = Instant::now();
    let result = OwnedTarget::spawn_stopped_with_control(
        &argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_millis(300),
        &cancel,
    );
    let elapsed = t0.elapsed();
    __test_set_setup_delay_ms(0);
    __test_set_control_worker_counter(None);
    __test_set_prestop_pid_sink(None);
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "expired setup must fail"),
    };
    assert!(msg.contains("deadline"), "caller abandoned: {msg}");
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert_eq!(pid_sink.load(Ordering::SeqCst), 0, "no fork may happen");
    assert!(
        elapsed < Duration::from_secs(2),
        "caller must not wait out a stuck worker (took {elapsed:?})"
    );
    std::fs::write(&log, b"successor-bytes\n").unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"successor-bytes\n",
        "late worker must never truncate post-abandonment bytes"
    );
    assert!(!sentinel.exists(), "sentinel must never execute");
    //
    // Leg C (stuck post-final-check): the worker passes every check while
    // live, then sleeps 6s between its final abandonment check and the
    // rename — the exact descheduled-after-check / blocked-inside-rename
    // shape. The caller cancels during the hold and must return within its
    // bound anyway; an OUR-setup retry during the hold must refuse (the
    // registry fences even this window). Every ordering is gate-enforced
    // except the 6s hold itself, which dwarfs the ~ms caller actions.
    let log_c = dir.join("post-check.log");
    std::fs::write(&log_c, b"original\n").unwrap();
    let argv_c = r06_sentinel_argv(&sentinel);
    let hold_ready = Arc::new(AtomicBool::new(false));
    let counter_c = Arc::new(AtomicU32::new(0));
    let cancel_c = Arc::new(AtomicBool::new(false));
    let (worker, sink_c, rx) = r06_spawn_async_setup(
        argv_c,
        WorkloadDest::File(log_c.clone()),
        Instant::now() + Duration::from_secs(60),
        R06Cancel::Shared(cancel_c.clone()),
        0,
        R06SetupHooks {
            rename_hold_ms: 6000,
            rename_hold_ready: Some(hold_ready.clone()),
            worker_counter: Some(counter_c.clone()),
            ..R06SetupHooks::default()
        },
    );
    let end = Instant::now() + Duration::from_secs(10);
    while !hold_ready.load(Ordering::SeqCst) {
        assert!(Instant::now() < end, "worker never reached post-check hold");
        std::thread::sleep(Duration::from_millis(1));
    }
    // The worker is now stuck past its final check. Cancel and prove the
    // caller stays bounded.
    let t0 = Instant::now();
    cancel_c.store(true, Ordering::SeqCst);
    let result = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("caller returns despite the stuck worker");
    let elapsed = t0.elapsed();
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "cancelled setup must fail"),
    };
    assert!(msg.contains("cancelled"), "caller abandoned: {msg}");
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert!(
        elapsed < Duration::from_secs(2),
        "caller must not wait out a post-check stuck worker (took {elapsed:?})"
    );
    // Still inside the 6s hold: an OUR-setup retry must refuse without
    // writing (registry fencing covers the post-check window too).
    let before: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let retry_cancel = AtomicBool::new(false);
    match OwnedTarget::spawn_stopped_with_control(
        &r06_sentinel_argv(&sentinel),
        WorkloadDest::File(log_c.clone()),
        Instant::now() + Duration::from_secs(5),
        &retry_cancel,
    ) {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("in flight"), "refusal names fencing: {msg}");
            assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
        }
        Ok(mut t) => {
            let pid = t.pid();
            t.resolve_setup_failure().unwrap();
            assert_reaped_no_zombie(pid);
            panic!("retry must refuse while the prior worker is live, but spawned pid {pid}");
        }
    }
    let mut after: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut before_sorted = before.clone();
    before_sorted.sort();
    after.sort();
    assert_eq!(before_sorted, after, "refused retry writes nothing");
    worker.join().unwrap();
    assert_eq!(sink_c.load(Ordering::SeqCst), 0, "no fork may happen");
    // Quiesce the stuck worker, then pin the documented residual honestly:
    // a worker descheduled after its final check still publishes on resume
    // (no userspace conditional-rename exists) — but no OUR bytes were at
    // risk in that window (the retry above refused), so only concurrent
    // EXTERNAL writers are unfenced.
    let end = Instant::now() + Duration::from_secs(15);
    while counter_c.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log_c).unwrap(),
        b"",
        "post-check hold documents the residual: the resumed worker publishes"
    );
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retry_setup_refuses_while_prior_worker_live() {
    // Fix round 5 / (ii): a process-wide per-destination setup registry —
    // a new OUR-setup for a path with a still-live prior worker REFUSES
    // instead of writing concurrently (this closes OUR-retry successor
    // races structurally). The first worker poises pre-publish; the retry
    // must refuse without writing; after the first worker quiesces, a
    // successor setup runs normally (fencing is live-worker-scoped).
    let dir = r06_scratch("registry-fence");
    let log = dir.join("workload.log");
    std::fs::write(&log, b"original\n").unwrap();
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let ready = Arc::new(AtomicBool::new(false));
    let proceed = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU32::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async_setup(
        argv,
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_secs(60),
        R06Cancel::Shared(cancel.clone()),
        0,
        R06SetupHooks {
            publish_gate: Some((ready.clone(), proceed.clone())),
            worker_counter: Some(counter.clone()),
            ..R06SetupHooks::default()
        },
    );
    let end = Instant::now() + Duration::from_secs(10);
    while !ready.load(Ordering::SeqCst) {
        assert!(Instant::now() < end, "worker never poised at publish");
        std::thread::sleep(Duration::from_millis(1));
    }
    // The prior worker is live (poised, registered). The retry must refuse
    // fast, fork nothing, and write nothing — not even staging.
    let mut before: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    before.sort();
    let retry_cancel = AtomicBool::new(false);
    let t0 = Instant::now();
    let retry = OwnedTarget::spawn_stopped_with_control(
        &r06_sentinel_argv(&sentinel),
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_secs(5),
        &retry_cancel,
    );
    let elapsed = t0.elapsed();
    match retry {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("in flight"), "refusal names fencing: {msg}");
            assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
        }
        Ok(mut t) => {
            let pid = t.pid();
            t.resolve_setup_failure().unwrap();
            assert_reaped_no_zombie(pid);
            panic!("retry must refuse while the prior worker is live, but spawned pid {pid}");
        }
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "refusal must fail fast (took {elapsed:?})"
    );
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"original\n",
        "refused retry writes nothing"
    );
    let mut after: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    after.sort();
    assert_eq!(before, after, "refused retry creates nothing");
    // Abandon the first setup BEFORE releasing its worker (strictly
    // ordered: the lock-free caller returns while the worker is still
    // gated, so the worker must observe abandonment at its final check):
    // it must publish nothing and delete only its own staging.
    cancel.store(true, Ordering::SeqCst);
    let result = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("first setup returns after abandonment");
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "cancelled setup must fail"),
    };
    assert!(msg.contains("cancelled"), "caller abandoned: {msg}");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "worker still gated at abandonment"
    );
    proceed.store(true, Ordering::SeqCst);
    worker.join().unwrap();
    assert_eq!(sink.load(Ordering::SeqCst), 0, "no fork may happen");
    let end = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < end, "worker never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"original\n",
        "abandoned worker publishes nothing"
    );
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["workload.log".to_string()], "no staging litter");
    assert!(!sentinel.exists(), "sentinel must never execute");
    // After quiescence the fence lifts: a successor OUR-setup runs the full
    // path (publish + fork + workload output).
    let idle = AtomicBool::new(false);
    let mut t = OwnedTarget::spawn_stopped_with_control(
        &sentinel_argv(),
        WorkloadDest::File(log.clone()),
        Instant::now() + Duration::from_secs(30),
        &idle,
    )
    .expect("successor setup runs after quiescence");
    let pid = t.pid();
    t.release().unwrap();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_reaped_no_zombie(pid);
    assert_eq!(
        std::fs::read(&log).unwrap(),
        b"H9-OUT-S\nH9-ERR-S\n",
        "successor output lands byte-identical"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn staging_namespace_dest_refused_before_creating() {
    // Fix round 5 / (iv): staging paths are provably distinct from the
    // destination — any destination whose file name lies in the staging
    // namespace is refused BEFORE creating anything (no staging, no
    // validation fd, no child), so abandoned cleanup can never alias it.
    let dir = r06_scratch("staging-collision");
    let sentinel = dir.join("SENTINEL");
    let idle = AtomicBool::new(false);
    let pid_sink = Arc::new(AtomicU32::new(0));
    __test_set_prestop_pid_sink(Some(pid_sink.clone()));
    // Leg 1: absent destination in the staging namespace.
    let absent = dir.join(".osslscope-staging-probe-1");
    let result = OwnedTarget::spawn_stopped_with_control(
        &r06_sentinel_argv(&sentinel),
        WorkloadDest::File(absent.clone()),
        Instant::now() + Duration::from_secs(5),
        &idle,
    );
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "staging-namespace dest must be refused"),
    };
    assert!(msg.contains("staging"), "refusal names staging: {msg}");
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert!(!absent.exists(), "refused setup creates nothing");
    // Leg 2: existing destination in the staging namespace keeps its bytes.
    let present = dir.join(".osslscope-staging-probe-2");
    std::fs::write(&present, b"precious\n").unwrap();
    let result = OwnedTarget::spawn_stopped_with_control(
        &r06_sentinel_argv(&sentinel),
        WorkloadDest::File(present.clone()),
        Instant::now() + Duration::from_secs(5),
        &idle,
    );
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(t) => r06_unexpected_child(t, "staging-namespace dest must be refused"),
    };
    assert!(msg.contains("staging"), "refusal names staging: {msg}");
    assert!(msg.contains("no child spawned"), "nothing forked: {msg}");
    assert_eq!(
        std::fs::read(&present).unwrap(),
        b"precious\n",
        "refused setup touches nothing"
    );
    __test_set_prestop_pid_sink(None);
    assert_eq!(pid_sink.load(Ordering::SeqCst), 0, "no fork may happen");
    assert!(!sentinel.exists(), "sentinel must never execute");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![".osslscope-staging-probe-2".to_string()],
        "nothing created beside the pre-existing file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn r06_pid_guard_rescues_live_child() {
    // F4 proof: the guard rescues a genuinely live child the test owns
    // only via the observed pid (production never acts: the worker is
    // blocked in its pre-stop wait with a far deadline and no cancel).
    let dir = r06_scratch("guard-rescue");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(120),
        R06Cancel::Shared(cancel),
        60_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    // Guard drop (explicit scope) kills + reaps the live child.
    {
        let _guard = R06PidGuard::arm(pid);
    }
    assert_reaped_no_zombie(pid);
    // The worker notices its reaped child and returns promptly: no hung
    // worker on any path.
    let drained = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("worker returns after rescue");
    worker.join().unwrap();
    if let Ok(t) = drained {
        r06_unexpected_child(t, "rescued setup must not succeed");
    }
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn r06_pid_guard_rescues_on_unwind() {
    // F4 proof: the guard rescues on panic paths too (a simulated
    // assertion failure inside `catch_unwind` — the unwind drops the
    // guard, which kills + reaps the live child).
    let dir = r06_scratch("guard-unwind");
    let sentinel = dir.join("SENTINEL");
    let argv = r06_sentinel_argv(&sentinel);
    let cancel = Arc::new(AtomicBool::new(false));
    let (worker, sink, rx) = r06_spawn_async(
        argv,
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(120),
        R06Cancel::Shared(cancel),
        60_000,
    );
    let Some(pid) = r06_wait_forked(&sink, Duration::from_secs(10)) else {
        let _ = rx.recv_timeout(Duration::from_secs(20));
        panic!("no fork observed within 10s");
    };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = R06PidGuard::arm(pid);
        panic!("simulated assertion failure");
    }));
    assert!(r.is_err(), "the simulated failure must unwind");
    assert_reaped_no_zombie(pid);
    let drained = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("worker returns after rescue");
    worker.join().unwrap();
    if let Ok(t) = drained {
        r06_unexpected_child(t, "rescued setup must not succeed");
    }
    assert!(!sentinel.exists(), "sentinel must never execute");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// R20 lifecycle/readiness: exec custody composition.
// ---------------------------------------------------------------------------

#[test]
fn r20_exec_replaces_image_custody_survives() {
    // R20 cleanup mapping: the owned child execs a second image
    // mid-flight (same pid, new exe link). Custody still tracks it
    // to its real exit — no lost child, no zombie, no wrong status.
    let mut t = OwnedTarget::spawn_stopped(
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exec /bin/sleep 0.3".to_string(),
        ],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    assert_eq!(t.state(), CustodyState::Stopped);
    t.release().unwrap();
    // The exe link must flip from sh to sleep while custody holds
    // (300ms sleep vs 5ms polls — no timing flake).
    let end = Instant::now() + Duration::from_secs(5);
    let mut saw_sleep = false;
    loop {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
        if exe.to_string_lossy().contains("sleep") {
            saw_sleep = true;
            break;
        }
        if t.poll_exit().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < end, "child never reached exec");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(saw_sleep, "exe link never flipped to sleep");
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(5)), Some(0));
    assert_eq!(t.state(), CustodyState::Reaped);
    assert_eq!(t.exit_code(), Some(0));
    assert_reaped_no_zombie(pid);
}

// ---------------------------------------------------------------------------
// R20-fix finding 1: kernel-observed lifecycle (proc connector).
// ---------------------------------------------------------------------------

#[test]
fn r20fix_kernel_lifecycle_witnesses_real_fork_exec_exit() {
    // Real-kernel control (no fakes, no privileges): subscribe BEFORE
    // release — the stopped child cannot act until released, so no
    // activity can precede the subscription — then release a workload
    // that execs (the target's own exec) and forks a sub-poll
    // grandchild (invisible to any snapshot poll). The adapter must
    // witness both, report zero drops/loss, and close with an empty
    // tail. The target's own exit is custody's verdict, never a
    // lifecycle event.
    use osslscope::capture::{KernelLifecycle, LifecycleKind, LifecyclePort};
    use std::collections::HashSet;

    if !require_clean_connector("r20fix_kernel_lifecycle_witnesses_real_fork_exec_exit") {
        return;
    }
    let mut t = OwnedTarget::spawn_stopped(
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "(exit 3) & wait".to_string(),
        ],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    let mut lc = match KernelLifecycle::subscribe(pid, false) {
        Ok(lc) => lc,
        Err(e) => {
            let _ = t.resolve_setup_failure();
            panic!("connector subscribe failed after gating present: {e:#}");
        }
    };
    assert!(
        !lc.fallback_partial(),
        "kernel signals must not be the PARTIAL fallback"
    );
    t.release().unwrap();
    lc.mark_released();
    assert_eq!(wait_for_exit(&mut t, Duration::from_secs(10)), Some(0));
    // Drain until both witnesses arrive (bounded): delivery into the
    // socket is kernel-queued, so this loop only waits out scheduling.
    let mut forks: HashSet<u32> = HashSet::new();
    let mut execs: HashSet<u32> = HashSet::new();
    let mut loss = 0u64;
    let mut dropped = 0u64;
    let end = Instant::now() + Duration::from_secs(10);
    while (forks.is_empty() || execs.is_empty()) && Instant::now() < end {
        let delta = lc.poll();
        loss += delta.loss;
        dropped += delta.dropped;
        assert_eq!(delta.pending, 0, "quiet test must not truncate drains");
        for e in &delta.events {
            match e.kind {
                LifecycleKind::Fork => {
                    forks.insert(e.pid);
                }
                LifecycleKind::Exec => {
                    execs.insert(e.pid);
                }
            }
        }
        if forks.is_empty() || execs.is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert_eq!(execs, HashSet::from([pid]), "target exec must witness");
    assert_eq!(forks.len(), 1, "one sub-poll grandchild fork: {forks:?}");
    let gc: u32 = *forks.iter().next().unwrap();
    assert_ne!(gc, pid, "grandchild is not the target");
    assert_eq!(loss, 0, "no scan loss on a quiet window");
    assert_eq!(dropped, 0, "no kernel drops on a quiet window");
    // Close drain: witnessed, complete, still lossless.
    let tail = lc.close_drain().expect("kernel close witness");
    assert_eq!(tail.pending, 0, "close drain must reach the tail");
    assert_eq!(tail.loss, 0);
    assert_eq!(tail.dropped, 0);
    assert!(tail.events.is_empty(), "no stragglers: {:?}", tail.events);
    assert_reaped_no_zombie(pid);
}

// ---------------------------------------------------------------------------
// R20-fix round 2: balanced registration (NEW) + namespace failure (F2).
// ---------------------------------------------------------------------------

/// Protocol constants (uapi `connector.h` / `cn_proc.h` — test-local
/// copies; production parses with its own).
const TEST_CN_IDX_PROC: u32 = 1;
const TEST_CN_VAL_PROC: u32 = 1;
const TEST_NLMSG_HDRLEN: usize = 16;
const TEST_CN_HDRLEN: usize = 20;
const TEST_PROC_EVENT_HDRLEN: usize = 16;

/// Raw group member (bound, never LISTENed — group membership alone
/// receives multicasts): observes our IGNORE ack on the wire.
fn bind_proc_group_sniffer() -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_CONNECTOR,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    use std::os::fd::AsRawFd;
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0; // autobind (several observer sockets coexist)
    addr.nl_groups = TEST_CN_IDX_PROC;
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|w| w.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Await the NONE ack echoing `our_ack` on the sniffer (other group
/// traffic is skipped): returns its err field. Positive wire proof —
/// a missing ack times out instead of passing vacuously.
fn await_none_ack(
    fd: &std::os::fd::OwnedFd,
    our_ack: u32,
    budget: Duration,
) -> anyhow::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut buf = vec![0u8; 65536];
    let end = Instant::now() + budget;
    while Instant::now() < end {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
        if pr <= 0 {
            continue;
        }
        let r = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if r <= 0 {
            continue;
        }
        let bytes = &buf[..r as usize];
        let mut off = 0usize;
        while off + TEST_NLMSG_HDRLEN <= bytes.len() {
            let (Some(len), Some(typ)) = (
                le_u32(bytes, off).map(|l| l as usize),
                le_u32(bytes, off + 4).map(|t| t as u16),
            ) else {
                break;
            };
            if len < TEST_NLMSG_HDRLEN || off + len > bytes.len() || typ == 2 {
                break;
            }
            let body = &bytes[off + TEST_NLMSG_HDRLEN..off + len];
            if body.len() >= TEST_CN_HDRLEN + TEST_PROC_EVENT_HDRLEN
                && le_u32(body, 0) == Some(TEST_CN_IDX_PROC)
                && le_u32(body, 4) == Some(TEST_CN_VAL_PROC)
                && le_u32(body, 12) == Some(our_ack)
            {
                let ev = &body[TEST_CN_HDRLEN..];
                if le_u32(ev, 0) == Some(0) {
                    if let Some(err) = le_u32(ev, TEST_PROC_EVENT_HDRLEN) {
                        return Ok(err);
                    }
                }
            }
            off += (len + 3) & !3;
        }
    }
    anyhow::bail!("IGNORE ack not observed on the wire")
}

#[test]
fn kernel_unsubscribe_is_accepted_live() {
    // NEW (balanced registration): IGNORE must be ACCEPTED by the
    // kernel (err 0 on the echoed NONE ack — a wrong op would answer
    // EINVAL and leak the listener count). A holder keeps the global
    // count ≥ 1 so the ack is emitted; a raw group sniffer bound
    // AFTER both subscribes observes the ack on the wire (positive
    // proof — silence would time out, never pass). Repeat + Drop
    // after unsubscribe are safe (kernel guards double-IGNORE), and
    // a fresh subscribe still works afterwards (no wedged state).
    use osslscope::capture::{KernelLifecycle, LifecyclePort};
    if !require_clean_connector("kernel_unsubscribe_is_accepted_live") {
        return;
    }
    let holder = KernelLifecycle::subscribe(std::process::id(), true).expect("holder subscribe");
    let mut lc = KernelLifecycle::subscribe(std::process::id(), true).expect("subscribe");
    assert_ne!(
        holder.ack_token(),
        lc.ack_token(),
        "concurrent same-process subscriptions must hold distinct tokens"
    );
    let sniff = bind_proc_group_sniffer().expect("sniffer bind");
    lc.unsubscribe().expect("unsubscribe sends");
    let our_ack = lc.ack_token().wrapping_add(1);
    let err = await_none_ack(&sniff, our_ack, Duration::from_secs(5)).expect("IGNORE ack on wire");
    assert_eq!(err, 0, "kernel must ACCEPT the IGNORE (err=EINVAL leaks)");
    // Corroboration through the adapter itself: our own socket also
    // receives the ack (err 0 → silent, never loss).
    let end = Instant::now() + Duration::from_millis(500);
    loop {
        let d = lc.poll();
        assert_eq!(d.loss, 0, "accepted IGNORE ack is silent: {d:?}");
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    lc.unsubscribe().expect("repeat unsubscribe sends");
    drop(lc);
    let resub = KernelLifecycle::subscribe(std::process::id(), true).expect("resubscribe works");
    drop(resub);
    drop(holder);
}

// ---------------------------------------------------------------------------
// R20-fix round 3, F2: per-CPU sequence watermarks — a CPU's first
// received sequence must not silently establish its baseline, and
// close needs a terminal per-CPU watermark.
// ---------------------------------------------------------------------------

#[test]
fn kernel_live_target_first_sighting_gaps_prefix() {
    // F2 RED (live): subscribing to a LIVE target — activity
    // possible throughout, so no first sighting is preceded by a
    // proven-quiet interval — must not silently baseline per-CPU
    // sequences. First sightings gap their unwitnessed prefix
    // (a fork lost before the first message is otherwise
    // invisible with zero socket Drops).
    use osslscope::capture::{KernelLifecycle, LifecyclePort};
    if !require_connector("kernel_live_target_first_sighting_gaps_prefix") {
        return;
    }
    let mut lc = KernelLifecycle::subscribe(std::process::id(), true).expect("subscribe live");
    // Deterministic traffic: our own short-lived child (FORK +
    // EXIT, kernel-queued — no scheduling race).
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork for sync traffic");
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    assert!(unsafe { libc::waitpid(child, &mut status, 0) } >= 0);
    let mut dropped = 0u64;
    let mut saw_fork = false;
    let end = Instant::now() + Duration::from_secs(10);
    while !saw_fork && Instant::now() < end {
        let d = lc.poll();
        dropped += d.dropped;
        saw_fork = d.events.iter().any(|e| {
            matches!(e.kind, osslscope::capture::LifecycleKind::Fork) && e.pid as i32 == child
        });
        if !saw_fork {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(saw_fork, "our child's fork must witness");
    assert!(
        dropped >= 1,
        "live-target first sightings must gap their prefix, not baseline silently: dropped={dropped}"
    );
}

/// Online CPU count established INDEPENDENTLY of the watermark
/// machinery (R20-fix round 4, F2c): live watermark tests must not
/// merely compare internally reported `seen` vs `sought` (`sought`
/// counts successfully created helpers — a shortfalled burst
/// would pass) — they pin the required set from the OS directly.
fn r20_online_cpu_count() -> u32 {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    assert!(n >= 1, "this host must report at least one online CPU");
    n as u32
}

#[test]
fn kernel_subscribe_watermarks_all_cpus_pre_activity() {
    // F2 (live): subscribing to a STOPPED owned child watermarks
    // every online CPU pre-activity — each CPU delivers a
    // baseline while the target provably cannot emit, so later
    // traffic is interior (holes detected) with NO prefix gaps.
    // This is what keeps connector COMPLETE reachable honestly.
    // Tier 2 (round 4, MINOR): the zero-dropped shape needs clean
    // watermark pinning (restricted affinity records loss by
    // design). The required set is established independently
    // (round 4, F2c) — `sought` counts created helpers, so
    // seen==sought alone would mask a shortfalled burst.
    use osslscope::capture::{KernelLifecycle, LifecyclePort};
    if !require_clean_connector("kernel_subscribe_watermarks_all_cpus_pre_activity") {
        return;
    }
    let online = r20_online_cpu_count();
    let mut t = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "60".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = t.pid();
    let mut lc = KernelLifecycle::subscribe(pid, false).expect("subscribe stopped");
    let (sought, seen) = lc.watermark_status().expect("initial watermark ran");
    assert_eq!(
        sought, online,
        "initial watermark must seek every online CPU (independently: {online}), not just created helpers"
    );
    assert_eq!(
        seen, online,
        "initial watermark must cover every online CPU"
    );
    let d = lc.poll();
    assert_eq!(
        d.dropped, 0,
        "pre-activity baselines must stay silent: {d:?}"
    );
    assert!(d.events.is_empty(), "stopped child emits nothing: {d:?}");
    t.resolve_setup_failure().unwrap();
    assert_reaped_no_zombie(pid);
}

#[test]
fn kernel_close_drain_establishes_terminal_watermark() {
    // F2 (live): close establishes a terminal per-CPU watermark —
    // successors on every online CPU prove the suffix (any
    // pre-close loss surfaces as an interior hole when its
    // successor ingests). In a quiet window the watermark
    // completes with no terminal loss. (Prefix gaps from the
    // live self-target land in the first poll, ignored here.)
    use osslscope::capture::{KernelLifecycle, LifecyclePort};
    if !require_clean_connector("kernel_close_drain_establishes_terminal_watermark") {
        return;
    }
    // Required set established independently (round 4, F2c) —
    // `sought` counts created helpers, so seen==sought alone
    // would mask a shortfalled terminal burst.
    let online = r20_online_cpu_count();
    let mut lc = KernelLifecycle::subscribe(std::process::id(), true).expect("subscribe");
    let _ = lc.poll();
    let tail = lc.close_drain().expect("kernel close witness");
    assert_eq!(tail.pending, 0, "close drain must reach the tail");
    let (sought, seen) = lc.watermark_status().expect("terminal watermark ran");
    assert_eq!(
        sought, online,
        "terminal watermark must seek every online CPU (independently: {online}), not just created helpers"
    );
    assert_eq!(
        seen, online,
        "terminal successors must cover every online CPU"
    );
    assert_eq!(tail.loss, 0, "quiet close must not add terminal loss");
}

// ---------------------------------------------------------------------------
// R20-fix round 4, F1: THE ordinary-supported-window qualification —
// production `capture::run` on a supported crypto target with real
// discovery, real counting, real mappings and real time. No empty
// event source, no fake count backend, no fabricated provider
// mapping, no bypassed resolution: the target is the pinned
// `openssl speed` vehicle (real libcrypto queries under uprobes),
// resolved through production resolution. The control FAILS if
// ordinary production capture cannot run free of polling fallback
// (deliberately NOT connector-gated — a fallback run reports
// `lifecycle-polling-partial` and fails the teeth assertion).
//
// Live lane (mirrors the p5d legs): `#[ignore]` + env-gated
// (`OSSL_R20_LIVE=1`, `OSSL_R20_HARVEST_OBJECT`, `OSSL_R20_COUNT_OBJECT`
// pointing at built BPF objects), pinned-vehicle checks, orphan
// backstop. Needs root (BPF load + uprobe attach) and MUST run
// single-threaded (the orphan backstop attributes new process
// children to this leg). Without the gate it skips quietly.
// ---------------------------------------------------------------------------

/// Pinned vehicle identity (Ubuntu 3.5.5-1ubuntu3.7, debian-amd64 —
/// same pins as the p5d legs; duplicated because that file is
/// outside R20's allowed list).
const R20_VEHICLE_BIN: &str = "/usr/bin/openssl";
const R20_VEHICLE_SHA256: &str = "1d72cbc5bf62be3f3dbd7626c295b63c5fdc1dd8439f323ac47998d8a062b4c9";
const R20_VEHICLE_VERSION_MARK: &str = "3.5.5";
const R20_LIBCRYPTO: &str = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const R20_LIBCRYPTO_SHA256: &str =
    "5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28";

fn r20_live_gated() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    if std::env::var("OSSL_R20_LIVE").unwrap_or_default() != "1" {
        eprintln!("r20 F1: set OSSL_R20_LIVE=1 with built BPF objects; skipping");
        return None;
    }
    let harvest: std::path::PathBuf = std::env::var("OSSL_R20_HARVEST_OBJECT")
        .expect("OSSL_R20_HARVEST_OBJECT=<harvest BPF .o>")
        .into();
    let count: std::path::PathBuf = std::env::var("OSSL_R20_COUNT_OBJECT")
        .expect("OSSL_R20_COUNT_OBJECT=<count BPF .o>")
        .into();
    assert!(harvest.is_file(), "harvest object missing: {harvest:?}");
    assert!(count.is_file(), "count object missing: {count:?}");
    Some((harvest, count))
}

fn r20_sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Assert the vehicle is the pinned build and the loader
/// environment is pristine (an `LD_LIBRARY_PATH` alternate or
/// `LD_PRELOAD` interposition would silently substitute the
/// measured library — fail closed instead).
fn r20_assert_vehicle_pinned() {
    assert!(
        std::env::var_os("LD_LIBRARY_PATH").is_none(),
        "refusing to measure under LD_LIBRARY_PATH (loader substitution risk)"
    );
    assert!(
        std::env::var_os("LD_PRELOAD").is_none(),
        "refusing to measure under LD_PRELOAD (interposition risk)"
    );
    let out = std::process::Command::new(R20_VEHICLE_BIN)
        .arg("version")
        .output()
        .expect("vehicle runs");
    assert!(out.status.success(), "vehicle `openssl version` failed");
    let v = String::from_utf8_lossy(&out.stdout);
    assert!(
        v.contains(R20_VEHICLE_VERSION_MARK),
        "vehicle version drift: {v:?}"
    );
    let bytes = std::fs::read(R20_VEHICLE_BIN).expect("read vehicle");
    assert_eq!(r20_sha256_hex(&bytes), R20_VEHICLE_SHA256, "vehicle drift");
    let lib_bytes = std::fs::read(R20_LIBCRYPTO).expect("read libcrypto");
    assert_eq!(
        r20_sha256_hex(&lib_bytes),
        R20_LIBCRYPTO_SHA256,
        "libcrypto drift"
    );
}

/// This process's children across all threads (orphan backstop —
/// minimal mirror of the p5d guard; sound only under
/// `--test-threads=1`). Returns (children, enumeration failures).
fn r20_process_children() -> (Vec<i32>, usize) {
    let mut out = Vec::new();
    let mut failures = 0;
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return (out, 1);
    };
    for entry in tasks {
        let Ok(t) = entry else {
            failures += 1;
            continue;
        };
        let Ok(s) = std::fs::read_to_string(t.path().join("children")) else {
            failures += 1;
            continue;
        };
        out.extend(s.split_whitespace().filter_map(|x| x.parse::<i32>().ok()));
    }
    out.sort_unstable();
    out.dedup();
    (out, failures)
}

/// Orphan backstop: `capture::run` owns its child internally and may
/// detach it live on salvage paths — a capture error or a failed
/// assertion after the run would otherwise leak a running workload.
/// Snapshots this process's children at arming; on drop, SIGKILLs +
/// reaps any child that appeared since. Drop never panics.
struct R20OrphanGuard {
    before: Vec<i32>,
}

impl R20OrphanGuard {
    fn arm() -> Self {
        let (before, failures) = r20_process_children();
        if failures > 0 {
            eprintln!("r20 orphan-guard: ARM DEGRADED ({failures} enumeration failures)");
        }
        Self { before }
    }
}

impl Drop for R20OrphanGuard {
    fn drop(&mut self) {
        let (current, failures) = r20_process_children();
        if failures > 0 {
            eprintln!(
                "r20 orphan-guard: drop enumeration had {failures} failures (sweep may miss)"
            );
        }
        for pid in current {
            if self.before.contains(&pid) {
                continue;
            }
            eprintln!("r20 orphan-guard: reclaiming leaked child {pid}");
            let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!("r20 orphan-guard: SIGKILL {pid} failed: {e}");
                }
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if Instant::now() >= deadline {
                    eprintln!("r20 orphan-guard: child {pid} survived SIGKILL (LEAKED)");
                    break;
                }
                let mut status = 0;
                let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if r == pid as libc::pid_t {
                    break;
                }
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::ECHILD) {
                        break;
                    }
                    if e.raw_os_error() != Some(libc::EINTR) {
                        eprintln!("r20 orphan-guard: waitpid {pid} failed: {e}");
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Guarded enrollment fixture for the pinned build (runbook rung
/// 2 — same measured fact as the p5d legs' fixture, duplicated
/// because that file is outside R20's allowed list): offsets
/// measured from the dbgsym twin (same build-id 0ebcfe...):
/// `ossl_provider_query_operation` @ 0x275390, anchor
/// `OSSL_PROVIDER_available` @ 0x275190. Production resolution
/// REQUIRES enrollment for stripped builds (it rejects unenrolled
/// stripped targets — observed live on HEAD), so this is the
/// production-faithful shape, not a bypass. Unique path per run,
/// removed on drop.
struct R20EnrollmentTable {
    path: std::path::PathBuf,
}

impl R20EnrollmentTable {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "r20-table-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let content = r#"{"table_version": 1,
    "entries": [{"build_id": "0ebcfeaee273dc860b29e067d255def704185b41",
      "openssl": "3.5.5-1ubuntu3.7",
      "query_offset": 2577296,
      "anchor": "OSSL_PROVIDER_available",
      "anchor_offset": 2576784}]}"#;
        std::fs::write(&path, content).expect("write enrollment table");
        Self { path }
    }

    fn path(&self) -> std::path::PathBuf {
        self.path.clone()
    }
}

impl Drop for R20EnrollmentTable {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn r20_doc_counter(cap: &osslscope::capture::Capture, name: &str) -> u64 {
    cap.document
        .counters
        .iter()
        .filter(|c| c.name == name)
        .map(|c| c.value)
        .sum()
}

#[test]
#[ignore = "live lane only (OSSL_R20_LIVE=1 + root + BPF objects)"]
fn ordinary_production_run_counts_real_crypto_free_of_polling_fallback() {
    // F1 (round 4): the qualified ordinary supported production
    // window. `openssl speed -seconds 1 aes-128-cbc` (real
    // libcrypto queries) runs through PRODUCTION `capture::run`:
    // production resolution accepts the target, production
    // discovery attaches uprobes over live maps, production
    // counting drains real query executions — nothing scripted,
    // nothing fabricated. The honest verdict for an exited owned
    // workload is PARTIAL via the exited-and-reaped close join
    // (`discovery-loss`); the qualification is that the window
    // runs COMPLETELY free of polling fallback with genuine
    // counted calls. NOT connector-gated by design: if the
    // connector is unavailable, production falls back and the
    // polling-partial teeth below FAIL (that is the control).
    let Some((harvest_object, count_object)) = r20_live_gated() else {
        return;
    };
    r20_assert_vehicle_pinned();
    // Arm BEFORE the run (no owned handle exists for capture's
    // child — leaks on error/assert-failure paths reclaim here).
    let _orphans = R20OrphanGuard::arm();
    // Stripped pinned build: production resolution requires
    // enrollment (observed live — unenrolled rejects).
    let table = R20EnrollmentTable::create();
    let cfg = osslscope::capture::Config {
        harvest_object: Some(harvest_object),
        count_object: Some(count_object),
        provider: Some(std::path::PathBuf::from(R20_LIBCRYPTO)),
        builtin: true,
        table: Some(table.path()),
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: Duration::from_secs(15),
        settle: Duration::from_secs(30),
        harvest_timeout: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        image_digest: String::new(),
    };
    let cap = osslscope::capture::run(
        &cfg,
        osslscope::capture::Target::Spawn {
            argv: vec![
                R20_VEHICLE_BIN.to_string(),
                "speed".to_string(),
                "-seconds".to_string(),
                "1".to_string(),
                "aes-128-cbc".to_string(),
            ],
            workload: WorkloadDest::Null,
        },
    )
    .expect("production run must accept and complete the supported target");
    let total_calls: u64 = cap.executions.iter().map(|e| e.count).sum();
    eprintln!(
        "r20 F1: outcome={:?} reasons={:?} executions={} calls={} child_exit={:?} \
         build_id={:?} counters={:?}",
        cap.outcome,
        cap.reasons,
        cap.executions.len(),
        total_calls,
        cap.child_exit,
        cap.provider_build_id,
        cap.document
            .counters
            .iter()
            .map(|c| (c.name.as_str(), c.value))
            .collect::<Vec<_>>()
    );
    // Genuineness: real queries executed and really counted.
    assert!(
        !cap.executions.is_empty(),
        "production counting must observe executions: {cap:?}"
    );
    assert!(
        total_calls > 0,
        "production counting must count real calls: {cap:?}"
    );
    assert_eq!(cap.child_exit, Some(0), "workload must exit 0: {cap:?}");
    assert_ne!(
        cap.provider_build_id, "unknown",
        "production resolution must genuinely resolve the provider: {cap:?}"
    );
    // THE teeth: free of polling fallback (fails if production
    // capture fell back — the connector-gate inversion above).
    assert!(
        !cap.reasons.iter().any(|r| r == "lifecycle-polling-partial"),
        "ordinary production capture must run free of polling fallback: {cap:?}"
    );
    // R20 lifecycle-witness pins: the kernel signal path carries
    // the whole window with zero witness loss.
    for name in [
        "lifecycle.polling_fallback",
        "lifecycle.scan_loss",
        "lifecycle.signal_dropped",
        "lifecycle.no_witness",
        "lifecycle.drain_pending",
        "lifecycle.exec_gap",
        "lifecycle.fork_exec_ignored",
    ] {
        assert_eq!(
            r20_doc_counter(&cap, name),
            0,
            "witness counter {name} must be zero: {cap:?}"
        );
    }
    // Honest verdict shape (observed live, stable 3/3): the
    // workload exits mid-window, so the exited-and-reaped close
    // join withholds COMPLETE explicitly (PARTIAL). Exact reasons,
    // each with its provenance: `discovery-loss` (the R20-owned
    // close-join skip, counter `discovery.close_join_skipped` ==
    // 1); `lowlevel-fallback-uninstrumented` (4 lowlevel syms on
    // the pinned vehicle probed-but-uninstrumented — a static
    // vehicle fact from the legacy plane, not a window loss);
    // `unattributed` (op:2 unknown denominator — discovery/count
    // synthesis planes, outside R20). Nothing lifecycle-owned.
    assert!(
        matches!(cap.outcome, osslscope::capture::Outcome::Partial),
        "exited owned workload is honestly PARTIAL: {cap:?}"
    );
    assert_eq!(
        cap.reasons,
        vec![
            "discovery-loss".to_string(),
            "lowlevel-fallback-uninstrumented".to_string(),
            "unattributed".to_string()
        ],
        "exact honest reason set: {cap:?}"
    );
    assert_eq!(
        r20_doc_counter(&cap, "discovery.close_join_skipped"),
        1,
        "the close join is skipped exactly once (exited-and-reaped): {cap:?}"
    );
}

const USERNS_PROBE_ENV: &str = "R20_USERNS_PROBE";

#[test]
fn helper_userns_subscribe_probe() {
    // Hidden probe worker for `kernel_subscribe_in_user_namespace_
    // fails_closed` (re-executed in a child test-binary process —
    // never forked in-process, so no post-fork lock hazard). No-op
    // in normal suite runs.
    if std::env::var(USERNS_PROBE_ENV).as_deref() != Ok("1") {
        return;
    }
    let code = unsafe {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EPERM || e == libc::EINVAL {
                // Namespace creation blocked by the environment
                // (unprivileged userns disabled, seccomp/apparmor
                // policy, full namespace table) — skip, claiming
                // no timeout evidence here.
                44
            } else {
                eprintln!("userns probe: unshare failed: errno {e}");
                45 // unexpected: the timeout path is unverified here
            }
        } else {
            match osslscope::capture::KernelLifecycle::subscribe(std::process::id(), true) {
                Ok(_) => 43, // namespace silence NOT observed — real failure
                Err(e) => {
                    // MINOR-B: only the TIMEOUT proves the
                    // silence mechanism — any other error is a
                    // different failure (45), never timeout
                    // evidence (42).
                    let msg = format!("{e:#}");
                    eprintln!("{msg}");
                    if msg.contains("not acknowledged") {
                        42 // expected: ignored namespace, no ack
                    } else {
                        45
                    }
                }
            }
        }
    };
    std::process::exit(code);
}

#[test]
fn kernel_subscribe_in_user_namespace_fails_closed() {
    // F2 (unsupported-namespace registration failure): the kernel
    // ignores LISTEN from non-init namespaces with SILENCE (no ack)
    // — subscribe must bail (loud fallback), never manufacture a
    // clean witness from the empty socket. The probe runs in a child
    // process (re-executed test binary — no in-process fork). The
    // positive control gates first: if the facility is broken
    // in-parent, a child failure would pass vacuously.
    if !require_connector("kernel_subscribe_in_user_namespace_fails_closed") {
        return;
    }
    let exe = std::env::current_exe().expect("test exe");
    let mut child = std::process::Command::new(exe)
        .arg("--exact")
        .arg("helper_userns_subscribe_probe")
        .arg("--nocapture")
        .env(USERNS_PROBE_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("probe spawn");
    let end = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= end {
            child.kill().ok();
            panic!("userns probe hung (30s)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        use std::io::Read as _;
        err.read_to_string(&mut stderr).ok();
    }
    match status.code() {
        // MINOR-B: 42 alone is not timeout evidence — the probe's
        // error text must name the timeout (a 42 without it fails:
        // the silence mechanism is unproven).
        Some(42) => assert!(
            stderr.contains("not acknowledged"),
            "userns 42 without timeout evidence proves nothing: {stderr:?}"
        ),
        Some(44) => eprintln!("SKIP: userns unavailable in this environment"),
        Some(43) => panic!("subscribe SUCCEEDED in a child userns (silence not observed)"),
        Some(45) => panic!("userns probe could not verify the timeout path: {stderr:?}"),
        other => panic!("userns probe unexpected status: {other:?}"),
    }
}
