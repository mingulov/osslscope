//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 owned-target custody lifecycle (R05): explicit stopped /
//! released / reaped / detached states on every return; no owned
//! stopped child or zombie after cleanup; external `--pid` targets
//! are never signaled. No BPF or privileges needed.

use osslscope::target::{
    __test_set_control_worker_counter, __test_set_fail_fork, __test_set_prestop_pid_sink,
    __test_set_prestop_stall_ms, __test_set_setup_delay_ms, CustodyState, OwnedTarget,
    TargetDisposition, WorkloadDest,
};
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
