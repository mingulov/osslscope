//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 owned spawn-target custody (R05): an owned child moves through
//! explicit stopped → released → reaped/detached states, and every
//! setup/error/signal return resolves custody. A never-released child
//! is terminated and reaped on failed setup; once released, the
//! existing leave-running policy applies and is reported. Detaching
//! transfers ownership explicitly and can never leave a stopped child.
//!
//! `--pid` targets are NOT owned: they are pinned via [`crate::pin`]
//! and never signaled or waited on here (there is deliberately no
//! constructor from a pid).
//!
//! Signal ownership assumption (same as the pre-existing capture
//! code): the observer owns the child's signals; an external SIGCONT
//! landing between fork and setup-failure resolution is out of model.
//! The kill paths below still refuse to signal a child that is not
//! observably stopped, so the residual window is microseconds, not
//! the whole setup phase.
use std::cell::RefCell;
use std::ffi::CString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Explicit custody of an owned child. Query with
/// [`OwnedTarget::state`] after any operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyState {
    /// Forked and held stopped pre-exec; not yet released.
    Stopped,
    /// Released (SIGCONT sent); running or exited, still owned.
    Released,
    /// Reaped; exit status preserved (see [`OwnedTarget::exit_code`]).
    Reaped,
    /// Ownership transferred; a live child was left running.
    Detached,
}

/// End-of-observation disposition of an owned child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDisposition {
    /// The child exited and was reaped; `code` is the exit status or
    /// 128+signal, preserved for the report.
    Exited { code: i32 },
    /// The child was still running; it was left running and ownership
    /// transferred (the observer never kills a running application).
    Detached { pid: u32 },
}

/// An owned spawn target (`run --`). The `Drop` impl is a backstop:
/// a still-stopped child is killed and reaped (bounded effort); a
/// released child is left running. Prefer the explicit
/// [`OwnedTarget::resolve_setup_failure`] /
/// [`OwnedTarget::finish_observation`] paths, which block until
/// custody is fully resolved.
pub struct OwnedTarget {
    pid: u32,
    state: CustodyState,
    /// Set when entering `Reaped`.
    exit_code: Option<i32>,
}

/// Kernel state letter from `/proc/<pid>/stat` (after the last ')').
/// Level-triggered (unlike `waitpid` stop reports, which are consumed
/// on first read): the initial stop was already consumed by
/// `spawn_stopped`, so this is the only reliable stopped check.
fn stat_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().next()?.chars().next()
}

/// Stopped vs running for a waitpid-confirmed-alive child.
enum ChildQuery {
    Stopped,
    Exited(i32),
    Running,
}

/// Query a not-yet-reaped owned child: a zombie reaps here with its
/// status; otherwise `/proc` state distinguishes a stopped child (`T`,
/// or `t` under a tracer) from a running one. A fresh stop is also
/// visible via `WUNTRACED`, which serves as the fallback when `/proc`
/// is unreadable; anything still unclassified answers `Running` (the
/// kill paths must not signal what might be running). EINTR retries.
fn query_child(pid: u32) -> anyhow::Result<ChildQuery> {
    if let Some(code) = reap_once(pid)? {
        return Ok(ChildQuery::Exited(code));
    }
    match stat_state(pid) {
        Some('T' | 't') => return Ok(ChildQuery::Stopped),
        Some(_) => return Ok(ChildQuery::Running),
        None => {}
    }
    // /proc unreadable for a live pid: fall back to the edge-triggered
    // stop report (catches a stop no waitpid has consumed yet).
    loop {
        let mut status = 0;
        let r = unsafe {
            libc::waitpid(
                pid as libc::pid_t,
                &mut status,
                libc::WNOHANG | libc::WUNTRACED,
            )
        };
        if r == 0 {
            return Ok(ChildQuery::Running);
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            anyhow::bail!("waitpid {pid}: {e}");
        }
        if libc::WIFEXITED(status) {
            return Ok(ChildQuery::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(ChildQuery::Exited(128 + libc::WTERMSIG(status)));
        }
        if libc::WIFSTOPPED(status) {
            return Ok(ChildQuery::Stopped);
        }
        return Ok(ChildQuery::Running);
    }
}

/// Reaping poll: `Ok(None)` = alive; `Ok(Some(code))` = reaped, with
/// the exit status or 128+signal. EINTR retries.
fn reap_once(pid: u32) -> anyhow::Result<Option<i32>> {
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if r == 0 {
            return Ok(None);
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            anyhow::bail!("waitpid {pid}: {e}");
        }
        if libc::WIFEXITED(status) {
            return Ok(Some(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Some(128 + libc::WTERMSIG(status)));
        }
        return Ok(None);
    }
}

/// Blocking reap for a child known to be dying (SIGKILL was sent):
/// the only owner waits until it is gone. EINTR retries.
fn reap_blocking(pid: u32) -> anyhow::Result<i32> {
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            anyhow::bail!("waitpid {pid}: {e}");
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128 + libc::WTERMSIG(status));
        }
        // No WUNTRACED: stops are not reported; anything else means
        // keep waiting for the death we caused.
    }
}

/// Workload stdio destination (H9/R07, pinned under R06): where a
/// spawned child's stdout+stderr go. Observer stderr NEVER carries
/// workload bytes: the default sinks to /dev/null and explicit
/// destinations are operator-chosen (a file per run, or a caller-held
/// fd).
///
/// File vs streaming (R06/F07): a [`WorkloadDest::File`] path is
/// validated, staged and atomically published to a fresh regular file by
/// the PARENT pre-fork; the child inherits the open fd and never opens a
/// path itself, so a FIFO/device/symlink selection — or a path replaced
/// after validation — can neither block nor redirect setup. Anything
/// that must stream (pipes, sockets, FIFOs, devices) uses
/// [`WorkloadDest::Fd`]: the caller opens and owns the fd with
/// whatever blocking behavior it chose, and the child only dup2s it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadDest {
    /// Both streams to /dev/null (default).
    Null,
    /// Both streams to this file (fresh empty inode per run,
    /// parent-side, pre-fork). Preparation runs on ONE gated worker:
    /// the destination is validated (never created, never truncated),
    /// then a uniquely-owned staging file is created beside it, then the
    /// abandonment check + atomic publish (`rename`) run under the ONE
    /// lock the caller's abandonment setter shares — a worker delayed
    /// past abandonment deletes its staging and publishes nothing, and
    /// the caller never blocks in the open/stage itself. Accepted ONLY
    /// as a regular file: missing parents, symlinks, FIFOs, directories,
    /// sockets and devices fail setup pre-fork, naming the path with the
    /// 126 setup marker. The published fd — not the path — is handed to
    /// the child, so post-publish path replacement is harmless. Notes:
    /// each run publishes a FRESH inode (hard links to a previous run's
    /// file are not preserved; permission bits are carried over), and the
    /// destination's directory must be writable (staging + rename live
    /// beside the destination).
    File(PathBuf),
    /// Both streams to a caller-held fd (harness pipe form; the
    /// child never closes the caller's fd). Validated pre-fork for
    /// openness only — flags and blocking behavior stay the caller's
    /// choice and responsibility. The only streaming form: pass a
    /// FIFO/pipe/device fd here, never as [`WorkloadDest::File`].
    Fd(RawFd),
}

/// Child-side stdio setup failure exit (H9): distinct from
/// exec-failure 127 — the parent maps 126 to a Setup error naming
/// the destination, never to silent null. Under R06 the parent
/// detects file-sink failures pre-fork and reports them with the
/// same 126 marker, so operators keep one vocabulary.
pub const WORKLOAD_SETUP_EXIT: i32 = 126;

/// Redirect a fork child's stdout+stderr onto its workload
/// destination (H9/R07 output policy, R06 custody): a spawned
/// workload must never share the observer's stdout artifact channel
/// (JSON corruption, secret capture) NOR the observer's stderr
/// (workload secrets in harness-captured diagnostics).
/// Async-signal-safe (raw syscalls only); never returns on
/// failure — `_exit(126)` (see [`WORKLOAD_SETUP_EXIT`]). Closes
/// only fds it opened itself; a caller-held [`WorkloadDest::Fd`]
/// is never closed (dup2 targets 1/2 excepted: when the caller's
/// fd IS 1 or 2 the dup is a no-op by construction). A
/// [`WorkloadDest::File`] sink arrives here as an already-open
/// parent-pinned fd — the child opens no paths (R06/F07: a
/// child-side open of a FIFO with no reader used to block before
/// SIGSTOP with no custody and no cancellation). `Null` still opens
/// /dev/null child-side: a fixed, always-present, never-blocking
/// node — no custody gap.
fn redirect_child_stdio(dest: &ChildDest) {
    unsafe {
        let sink: libc::c_int = match dest {
            ChildDest::Null => libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY),
            ChildDest::Fd(fd) => *fd,
        };
        if sink < 0 {
            libc::_exit(WORKLOAD_SETUP_EXIT);
        }
        if libc::dup2(sink, libc::STDOUT_FILENO) < 0 || libc::dup2(sink, libc::STDERR_FILENO) < 0 {
            libc::_exit(WORKLOAD_SETUP_EXIT);
        }
        // F3: dup2(n, n) is a no-op that RETAINS the close-on-exec flag,
        // so a sink that already is fd 1 or 2 (open returns the lowest
        // free descriptor when the caller started with stdio closed)
        // would vanish at exec. The workload's stdio must always survive
        // exec, whatever produced the sink — clear both flags (raw fcntl,
        // async-signal-safe; cannot fail after the dup2s above).
        libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFD, 0);
        libc::fcntl(libc::STDERR_FILENO, libc::F_SETFD, 0);
        // open() returns the lowest free fd: when a stdio fd was
        // closed the sink may BE fd 1 or 2 already — close only a
        // spare (a caller fd above stdio is the child's own copy;
        // the caller's descriptor is untouched).
        if sink != libc::STDOUT_FILENO && sink != libc::STDERR_FILENO {
            libc::close(sink);
        }
    }
}

/// Pre-fork-prepared child destination: no path opens remain — a
/// file sink is an already-open parent-pinned fd — so the child
/// allocates nothing (async-signal-safe).
enum ChildDest {
    Null,
    Fd(libc::c_int),
}

/// File-type word for an st_mode (operability: sink errors name what
/// the path/fd actually is).
fn file_kind(mode: libc::mode_t) -> &'static str {
    let masked = mode & libc::S_IFMT;
    if masked == libc::S_IFREG {
        "regular file"
    } else if masked == libc::S_IFIFO {
        "fifo"
    } else if masked == libc::S_IFDIR {
        "directory"
    } else if masked == libc::S_IFCHR {
        "character device"
    } else if masked == libc::S_IFBLK {
        "block device"
    } else if masked == libc::S_IFLNK {
        "symlink"
    } else if masked == libc::S_IFSOCK {
        "socket"
    } else {
        "special file"
    }
}

/// Best-effort kind word for a path whose sink open failed (missing
/// path, directory, symlink, fifo, ...).
fn lstat_kind(c: &std::ffi::CStr) -> &'static str {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            "missing path"
        } else {
            "unstatable path"
        };
    }
    file_kind(st.st_mode)
}

/// A validated [`WorkloadDest::File`] target (fix round 4): the
/// destination as it stands BEFORE staging. Validation opens the CURRENT
/// destination without creating or truncating it, so a worker delayed
/// past abandonment has no destructive act available until the atomic
/// publish — which it then loses (see [`prepare_and_publish_sink`]).
struct ValidatedTarget {
    /// The open destination fd when it exists (proves writability,
    /// non-symlink, regular file; closed after the publish decision —
    /// the child never sees this fd). `None` when the destination is
    /// absent (the publish creates it).
    fd: Option<OwnedFd>,
    /// Permission bits to carry onto the published inode when the
    /// destination exists (truncate-in-place preserved them; the atomic
    /// publish copies them instead). `None` when absent (staging keeps
    /// its create mode, as a fresh destination always did).
    mode: Option<u32>,
}

/// Validate a [`WorkloadDest::File`] target parent-side, pre-fork
/// (R06/F07) — WITHOUT creating or truncating anything: the open carries
/// neither `O_CREAT` nor `O_TRUNC`, so validation alone can neither
/// conjure a destination nor destroy a byte. `O_NONBLOCK` keeps a
/// FIFO-with-no-reader from hanging the open (it fails `ENXIO` instead);
/// `O_NOFOLLOW` refuses a final symlink; the `fstat` accepts ONLY a
/// regular file; `O_NONBLOCK` is then cleared. An absent destination
/// (`ENOENT`) is NOT an error here — staging + publish create it; every
/// other failure names the path with the 126 setup marker and spawns
/// nothing. Runs on a setup-control worker (see [`run_under_control`]) —
/// never call it directly on the setup path: `O_NONBLOCK` bounds neither
/// a stalled FUSE open nor a block-device open.
fn validate_sink_target(path: &Path) -> anyhow::Result<ValidatedTarget> {
    use anyhow::Context as _;
    let c = CString::new(path.as_os_str().as_bytes()).context("NUL in --workload-out path")?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(ValidatedTarget {
                fd: None,
                mode: None,
            });
        }
        anyhow::bail!(
            "workload output {}: cannot open file sink ({}): {e} (setup status 126)",
            path.display(),
            lstat_kind(&c),
        );
    }
    // open succeeded, so the fd is ours to own (closed on every
    // error return below via the OwnedFd).
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } != 0 {
        let e = std::io::Error::last_os_error();
        anyhow::bail!(
            "workload output {}: cannot fstat file sink: {e} (setup status 126)",
            path.display()
        );
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        anyhow::bail!(
            "workload output {}: not a regular file ({}); streaming destinations must use a caller-held fd (setup status 126)",
            path.display(),
            file_kind(st.st_mode),
        );
    }
    // Clear O_NONBLOCK: it only guarded the open itself.
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0
    {
        let e = std::io::Error::last_os_error();
        anyhow::bail!(
            "workload output {}: cannot clear O_NONBLOCK: {e} (setup status 126)",
            path.display()
        );
    }
    let mode = st.st_mode & 0o7777;
    Ok(ValidatedTarget {
        fd: Some(owned),
        mode: Some(mode),
    })
}

/// Per-process staging sequence: staging names are unique per (pid,
/// counter), so a worker delayed past abandonment can only ever touch
/// its own staging file — never the destination, never another
/// attempt's staging.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create the uniquely-owned staging sink for `path` (fix round 4): a
/// fresh empty regular file in the destination's directory, opened
/// `O_CREAT|O_EXCL` — born empty, so it is never truncated, and never the
/// destination inode. `mode` carries the validated destination's
/// permission bits when it exists (see [`ValidatedTarget`]). The staging
/// path returns alongside the fd so every outcome either publishes it
/// (atomic rename, exactly once) or deletes it. Every failure names the
/// destination path with the 126 setup marker and spawns nothing.
fn create_staging_sink(path: &Path, mode: Option<u32>) -> anyhow::Result<(OwnedFd, PathBuf)> {
    use anyhow::Context as _;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let pid = std::process::id();
    for _ in 0..100 {
        let n = STAGING_COUNTER.fetch_add(1, Ordering::SeqCst);
        let staging = dir.join(format!(".osslscope-staging-{pid}-{n}"));
        let c =
            CString::new(staging.as_os_str().as_bytes()).context("NUL in --workload-out path")?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NONBLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EEXIST) {
                continue; // Stale staging from a crashed run or pid reuse; next name.
            }
            anyhow::bail!(
                "workload output {}: cannot create staging file {}: {e} (setup status 126)",
                path.display(),
                staging.display(),
            );
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        {
            let _ = std::fs::remove_file(&staging);
            anyhow::bail!(
                "workload output {}: staging file is not a regular file (setup status 126)",
                path.display(),
            );
        }
        // Clear O_NONBLOCK: it only guarded the open itself; the
        // workload must inherit ordinary blocking stdio.
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) }
                != 0
        {
            let e = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&staging);
            anyhow::bail!(
                "workload output {}: cannot clear O_NONBLOCK on staging file: {e} (setup status 126)",
                path.display(),
            );
        }
        if let Some(mode) = mode {
            if unsafe { libc::fchmod(owned.as_raw_fd(), mode) } != 0 {
                let e = std::io::Error::last_os_error();
                let _ = std::fs::remove_file(&staging);
                anyhow::bail!(
                    "workload output {}: cannot set staging file mode: {e} (setup status 126)",
                    path.display(),
                );
            }
        }
        return Ok((owned, staging));
    }
    anyhow::bail!(
        "workload output {}: cannot pick a staging name after 100 attempts (setup status 126)",
        path.display(),
    );
}

/// Read the abandonment gate (fix round 4): poison-tolerant — a lock
/// failure still yields the guarded value instead of panicking setup
/// (no panicking operation runs under this lock, so poisoning should
/// never occur).
fn abandonment_get(gate: &Mutex<bool>) -> bool {
    *gate.lock().unwrap_or_else(|e| e.into_inner())
}

/// Set the abandonment gate (fix round 4): same poison tolerance.
fn abandonment_set(gate: &Mutex<bool>) {
    *gate.lock().unwrap_or_else(|e| e.into_inner()) = true;
}

/// Prepare + publish a [`WorkloadDest::File`] sink, worker-side (fix
/// round 4): the gated setup op. Staging first — [`validate_sink_target`]
/// (never creates, never truncates) then [`create_staging_sink`] (a fresh
/// empty file the worker uniquely owns) — then the ATOMIC publish: the
/// abandonment check and the `rename` run under ONE mutual-exclusion lock
/// shared with the caller's abandonment setter, so a late worker is
/// physically incapable of touching the destination: if the caller
/// abandoned first, the worker deletes its staging and publishes nothing;
/// if the worker publishes first, the caller's abandonment lands after —
/// and the rendezvous only delivers the published fd to a live receiver.
/// After the caller abandons, no worker path truncates, writes, or
/// renames onto the destination inode. `test_delay_ms` is a moved-in test
/// copy (see `SETUP_TEST_HOOK`): a stall between staging and the publish
/// decision, simulating a sink that answers preparation slowly. Inert
/// (`0`) unless a test armed it. `publish_gate` is the moved-in poised
/// rendezvous (see `SETUP_TEST_HOOK`): when armed, the worker signals
/// readiness and waits (bounded) BEFORE taking the publish lock, so a
/// test can order the caller's abandonment strictly before the atomic
/// decision. Residual: the caller takes the publish lock to record
/// abandonment, so it waits out an in-flight `rename` — microseconds on a
/// local filesystem; a FUSE server withholding rename would stall
/// abandonment past the deadline (strictly narrower than a caller-side
/// truncate, which stalls on every slow SETATTR — and the price of an
/// atomic publish, since there is no conditional-rename primitive).
fn prepare_and_publish_sink(
    path: &Path,
    gate: &Mutex<bool>,
    test_delay_ms: u64,
    publish_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
) -> anyhow::Result<OwnedFd> {
    if abandonment_get(gate) {
        anyhow::bail!("pre-stop setup abandoned before file-sink preparation (no child spawned)");
    }
    let validated = validate_sink_target(path)?;
    let (staging_fd, staging_path) = create_staging_sink(path, validated.mode)?;
    if test_delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(test_delay_ms));
    }
    if let Some((ready, proceed)) = publish_gate.as_ref() {
        ready.store(true, Ordering::SeqCst);
        let end = Instant::now() + Duration::from_secs(10);
        while !proceed.load(Ordering::SeqCst) {
            if Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // The atomic publish: abandonment check + rename under the ONE lock
    // shared with the caller's abandonment setter. NOTHING else runs
    // under this lock — every fd close and staging delete below is
    // worker-owned (a FUSE stall there hangs only the detached worker,
    // never the caller's abandonment).
    enum Decision {
        Published,
        Abandoned,
        Failed(anyhow::Error),
    }
    let decision = {
        let guard = gate.lock().unwrap_or_else(|e| e.into_inner());
        if *guard {
            Decision::Abandoned
        } else {
            match std::fs::rename(&staging_path, path) {
                Ok(()) => Decision::Published,
                Err(e) => Decision::Failed(anyhow::anyhow!(
                    "workload output {}: cannot publish file sink: {e} (setup status 126)",
                    path.display(),
                )),
            }
        }
    };
    match decision {
        Decision::Published => {
            // The validation fd refers to the REPLACED inode (or nothing,
            // when the destination was absent): drop it — the staging fd
            // is the published sink the child inherits.
            drop(validated.fd);
            Ok(staging_fd)
        }
        Decision::Abandoned => {
            let _ = std::fs::remove_file(&staging_path);
            drop(validated.fd);
            drop(staging_fd);
            anyhow::bail!(
                "pre-stop setup abandoned during file-sink preparation (no child spawned)"
            );
        }
        Decision::Failed(e) => {
            let _ = std::fs::remove_file(&staging_path);
            drop(validated.fd);
            drop(staging_fd);
            Err(e)
        }
    }
}

/// Outcome of running one blocking setup op under deadline +
/// cancellation control (fix round 1 / F1): a stalled sink open or
/// close (FUSE, block device — `O_NONBLOCK` bounds neither) must fail
/// the setup instead of hanging it.
enum Control<T> {
    /// The op finished; carries its value.
    Done(T),
    /// Cancellation was pending (checked before running, then while
    /// waiting); the abandonment gate is set, so a worker that has not
    /// started its op skips it — a started worker keeps running detached
    /// and owns its captures.
    Cancelled,
    /// The deadline passed while waiting; the abandonment gate is set
    /// (as above) and a started worker keeps running detached and owns
    /// its captures.
    Expired,
    /// The worker died (panic) before reporting.
    Lost,
}

/// Run a potentially-blocking setup op on a worker thread, bounded by
/// the setup deadline and cancel flag (polled at 1ms). An already-dead
/// setup never starts the op, and a worker that has not started its op
/// when the caller abandons setup skips it (fix round 2: the abandonment
/// gate — a late worker must not perform setup work after the caller
/// gave up). The op receives the gate so a multi-phase op can decide its
/// destructive half atomically with the caller's abandonment (fix round
/// 4: staging, then check + publish under the ONE lock the abandonment
/// setter shares — no check-then-act gap survives). The result channel is
/// a rendezvous (fix round 2 / F1): a value is delivered only to a live
/// receiver, so a discarded result is always dropped on the worker, never
/// inline on the caller. On expiry the worker is detached — its ownership
/// moves with it, so a stuck open's fd closes whenever the sink answers —
/// and the caller fails WITHOUT forking (pre-fork) or resolves the
/// guard-held child under custody (post-fork). `Err` = the worker thread
/// itself could not start (fail-closed at the call site).
fn run_under_control<T, F>(
    deadline: Instant,
    cancel: &AtomicBool,
    op: F,
) -> anyhow::Result<Control<T>>
where
    T: Send + 'static,
    F: FnOnce(&Mutex<bool>) -> T + Send + 'static,
{
    if cancel.load(Ordering::SeqCst) {
        return Ok(Control::Cancelled);
    }
    if Instant::now() >= deadline {
        return Ok(Control::Expired);
    }
    // Abandonment gate: set by the caller (under the lock) when it stops
    // waiting, read by the worker before running the op — and locked by
    // the op itself around its atomic publish decision.
    let abandoned = Arc::new(Mutex::new(false));
    let abandoned_c = abandoned.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let (test_delay_ms, test_counter) = read_setup_test_hook();
    std::thread::Builder::new()
        .name("osslscope-setup-op".to_string())
        .spawn(move || {
            if test_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(test_delay_ms));
            }
            if !abandonment_get(&abandoned_c) {
                let _ = tx.send(op(abandoned_c.as_ref()));
            }
            if let Some(c) = test_counter.as_ref() {
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
        .map_err(|e| anyhow::anyhow!("setup worker thread: {e}"))?;
    poll_controlled(deadline, cancel, rx, Some(abandoned.as_ref()))
}

/// Spawn the control worker and poll it. Close disposal calls this
/// directly: a close must run (possibly late, on the detached worker)
/// even on an already-dead setup — otherwise its fd would leak. There is
/// deliberately NO abandonment gate here (unlike
/// [`run_under_control`]): disposal is never skipped. The result channel
/// is a rendezvous (fix round 2 / F1), as above.
fn spawn_controlled<T, F>(
    deadline: Instant,
    cancel: &AtomicBool,
    op: F,
) -> anyhow::Result<Control<T>>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let (test_delay_ms, test_counter) = read_setup_test_hook();
    std::thread::Builder::new()
        .name("osslscope-setup-op".to_string())
        .spawn(move || {
            if test_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(test_delay_ms));
            }
            let _ = tx.send(op());
            if let Some(c) = test_counter.as_ref() {
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
        .map_err(|e| anyhow::anyhow!("setup worker thread: {e}"))?;
    poll_controlled(deadline, cancel, rx, None)
}

/// Poll one control worker (the waiting half of [`run_under_control`] /
/// [`spawn_controlled`]). When `abandoned` is present (gated ops), it is
/// set — under the ONE lock the worker's atomic publish shares — before
/// returning `Cancelled` / `Expired`, so a worker that has not started
/// its op skips it, and a worker poised at publish loses the decision,
/// instead of running setup work after the caller gave up. When the
/// test-only poll gate is armed, the caller waits on it (bounded) before
/// its first check, so a test can order abandonment strictly after a
/// result completed (fix round 3 / F1-PROOF).
fn poll_controlled<T>(
    deadline: Instant,
    cancel: &AtomicBool,
    rx: std::sync::mpsc::Receiver<T>,
    abandoned: Option<&Mutex<bool>>,
) -> anyhow::Result<Control<T>> {
    if let Some(gate) = SETUP_TEST_HOOK.with(|h| h.borrow().poll_gate.clone()) {
        let end = Instant::now() + Duration::from_secs(10);
        while !gate.load(Ordering::SeqCst) {
            if Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    loop {
        if cancel.load(Ordering::SeqCst) {
            if let Some(a) = abandoned {
                abandonment_set(a);
            }
            return Ok(Control::Cancelled);
        }
        if Instant::now() >= deadline {
            if let Some(a) = abandoned {
                abandonment_set(a);
            }
            return Ok(Control::Expired);
        }
        match rx.recv_timeout(Duration::from_millis(1)) {
            Ok(v) => return Ok(Control::Done(v)),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return Ok(Control::Lost),
        }
    }
}

/// Read the test-only setup copies on the spawning thread (see
/// `SETUP_TEST_HOOK`): the worker-startup delay and the completion
/// counter. Inert (`0` / `None`) unless a test armed them.
fn read_setup_test_hook() -> (u64, Option<Arc<AtomicU32>>) {
    SETUP_TEST_HOOK.with(|h| {
        let h = h.borrow();
        (h.setup_delay_ms, h.worker_counter.clone())
    })
}

/// Close a parent-held sink fd under setup control (F1): the actual
/// close runs on a worker, so a FUSE FLUSH cannot hang setup. The full
/// [`Control`] outcome returns: on expiry the fd stays owned by the
/// worker (closed whenever the sink answers); only a worker-thread
/// spawn failure leaks it process-lifetime (fail-closed thread
/// exhaustion — setup still never blocks, custody still never breaks).
fn close_under_control(
    fd: OwnedFd,
    deadline: Instant,
    cancel: &AtomicBool,
) -> anyhow::Result<Control<()>> {
    // Pass the fd BY NUMBER so a thread-spawn failure leaks it instead
    // of closing it inline: dropping the closure must never run the
    // close on this thread.
    let raw = fd.into_raw_fd();
    // No dead-setup pre-check (see `spawn_controlled`): the close runs
    // even when the deadline already won — late, on the worker.
    spawn_controlled(deadline, cancel, move || {
        // SAFETY: `raw` is the live sink fd, moved here by number; this
        // closure runs at most once (the worker calls it once, or never
        // on spawn failure — a leaked number, never closed twice).
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
    })
}

/// Test-only pre-stop instrumentation (fix round 1 / F4), thread-local
/// so parallel tests never interact:
/// - `stall_ms`: the forked child sleeps this long before SIGSTOP, so
///   the parent's pre-stop wait is provably mid-spin when cancellation
///   or the deadline lands (a deterministic post-fork race — no timing
///   luck, no ambient scheduling dependence).
/// - `pid_sink`: the parent stores each forked pid here the instant fork
///   returns, giving tests exact-PID custody independent of the call's
///   own return (blocked calls and error returns included).
///
/// The parent copies both values to the stack BEFORE forking; the child
/// uses only its stack copy (a plain integer + nanosleep — no
/// allocation, no TLS access post-fork). Production callers must never
/// arm this.
struct PrestopTestHook {
    stall_ms: u64,
    pid_sink: Option<Arc<AtomicU32>>,
}

thread_local! {
    static PRESTOP_TEST_HOOK: RefCell<PrestopTestHook> =
        const { RefCell::new(PrestopTestHook { stall_ms: 0, pid_sink: None }) };
}

/// Test-only: arm the pre-stop stall (see the `PRESTOP_TEST_HOOK` static).
#[doc(hidden)]
pub fn __test_set_prestop_stall_ms(ms: u64) {
    PRESTOP_TEST_HOOK.with(|h| h.borrow_mut().stall_ms = ms);
}

/// Test-only: arm the forked-pid report (see the `PRESTOP_TEST_HOOK` static).
#[doc(hidden)]
pub fn __test_set_prestop_pid_sink(sink: Option<Arc<AtomicU32>>) {
    PRESTOP_TEST_HOOK.with(|h| h.borrow_mut().pid_sink = sink);
}

/// Test-only setup instrumentation (fix round 2), thread-local so parallel
/// tests never interact. The spawning thread copies these values BEFORE
/// creating a control worker; the worker uses only its moved copies — the
/// worker thread never touches this thread-local:
/// - `setup_delay_ms`: the worker sleeps this long before running its op,
///   so the caller deterministically abandons setup first (proves a late
///   worker cannot harm a successor).
/// - `worker_counter`: the worker increments this exactly once when it
///   finishes (all non-panic exits), proving disposal ran on a worker.
/// - `fail_fork`: the next spawn on this thread skips `fork()` and takes
///   the fork-failure path (consumed on read).
/// - `truncate_delay_ms` (fix round 3): file-sink preparation stalls
///   this long between staging and the publish decision, simulating a
///   sink that answers preparation slowly — the caller must stay bounded
///   regardless. The spawning thread copies it BEFORE creating the
///   worker; the worker uses only its moved copy.
/// - `poll_gate` (fix round 3): when armed, the control caller waits on
///   this flag (bounded) before its first poll check, so a test can order
///   abandonment strictly after a result completed.
/// - `publish_gate` (fix round 4): when armed as `(ready, proceed)`,
///   file-sink preparation sets `ready` and waits (bounded) on `proceed`
///   AFTER staging and BEFORE the atomic publish, so a test can order
///   the caller's abandonment strictly before the publish decision. The
///   spawning thread clones it BEFORE creating the worker; the worker
///   uses only its moved clone. Production callers must never arm any of
///   these.
struct SetupTestHook {
    setup_delay_ms: u64,
    worker_counter: Option<Arc<AtomicU32>>,
    fail_fork: bool,
    truncate_delay_ms: u64,
    poll_gate: Option<Arc<AtomicBool>>,
    publish_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
}

thread_local! {
    static SETUP_TEST_HOOK: RefCell<SetupTestHook> = const {
        RefCell::new(SetupTestHook {
            setup_delay_ms: 0,
            worker_counter: None,
            fail_fork: false,
            truncate_delay_ms: 0,
            poll_gate: None,
            publish_gate: None,
        })
    };
}

/// Test-only: arm the control-worker startup delay (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_setup_delay_ms(ms: u64) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().setup_delay_ms = ms);
}

/// Test-only: arm the control-worker completion counter (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_control_worker_counter(counter: Option<Arc<AtomicU32>>) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().worker_counter = counter);
}

/// Test-only: fail the next fork on this thread (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_fail_fork(fail: bool) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().fail_fork = fail);
}

/// Test-only: arm the truncate-half stall (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_truncate_delay_ms(ms: u64) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().truncate_delay_ms = ms);
}

/// Test-only: arm the control-poll gate (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_poll_gate(gate: Option<Arc<AtomicBool>>) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().poll_gate = gate);
}

/// Test-only: arm the publish poised-gate (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_publish_gate(gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().publish_gate = gate);
}

/// Post-fork pre-stop custody (R06/F07): owns the just-forked pid
/// from the fork return until the SIGSTOP is observed (then an
/// `OwnedTarget` takes over) or the wait fails (kill + reap here).
/// Armed at construction; every return disarms or resolves — Drop is
/// only the unwind backstop and mirrors `OwnedTarget::drop` (a SIGKILL
/// with bounded reap: never a hang, never a stopped child left
/// behind). Only ever holds a never-released owned child.
struct PrestopGuard {
    pid: u32,
    armed: bool,
}

/// How long the pre-stop guard waits to reap a SIGKILLed child before
/// reporting cleanup failure (a kill is normally reaped in
/// microseconds; only an unkillable/D-state child exhausts this).
const PRESTOP_REAP_GRACE: Duration = Duration::from_secs(5);

/// Confirmed outcome of pre-stop failure cleanup (fix round 1 / F2).
/// Only [`GuardCleanup::KilledAndReaped`] confirms BOTH the kill and the
/// reap — every other outcome says exactly what was (and was not)
/// established, so callers never report "killed and reaped" on a guess.
enum GuardCleanup {
    /// SIGKILL was delivered and this guard collected the status.
    KilledAndReaped(i32),
    /// Resolved without a confirmed kill: the status when observed
    /// (`Some`), or unknown when another waiter collected it (`None`).
    ReapedElsewhere(Option<i32>),
    /// Kill found no process and no status remained (ESRCH + ECHILD):
    /// nothing existed to kill or reap.
    AlreadyGone,
}

impl GuardCleanup {
    /// Factual report fragment ("owned child {pid} {this}").
    fn report(&self) -> String {
        match self {
            GuardCleanup::KilledAndReaped(code) => format!("killed and reaped (status {code})"),
            GuardCleanup::ReapedElsewhere(Some(code)) => {
                format!("reaped without confirmed kill (status {code})")
            }
            GuardCleanup::ReapedElsewhere(None) => {
                "reaped by a concurrent waiter (status unknown)".to_string()
            }
            GuardCleanup::AlreadyGone => "already gone (nothing to kill or reap)".to_string(),
        }
    }
}

/// Run guard cleanup and render its confirmed outcome (or failure) as a
/// report fragment. Cleanup failures propagate instead of dissolving
/// into a "killed and reaped" claim.
fn guard_cleanup_report(guard: &mut PrestopGuard) -> String {
    match guard.kill_and_reap() {
        Ok(outcome) => outcome.report(),
        Err(e) => format!("cleanup failed: {e:#}"),
    }
}

impl PrestopGuard {
    /// Failure path: SIGKILL, then a bounded reap (fix round 1 / F2).
    /// Custody stays explicit (armed) until resolution is CONFIRMED —
    /// only the success returns disarm; every failure propagates with
    /// the guard still armed, so `Drop` gets a bounded backstop retry.
    /// The kill result is honored (ESRCH is distinguished from a real
    /// kill failure) and reap errors propagate — nothing dissolves into
    /// `None`.
    fn kill_and_reap(&mut self) -> anyhow::Result<GuardCleanup> {
        let killed = unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) } == 0;
        if !killed {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                anyhow::bail!("SIGKILL to owned child {} failed: {e}", self.pid);
            }
        }
        let end = Instant::now() + PRESTOP_REAP_GRACE;
        loop {
            let mut status = 0;
            let r = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if r > 0 {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    let code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        128 + libc::WTERMSIG(status)
                    };
                    self.disarm();
                    return Ok(if killed {
                        GuardCleanup::KilledAndReaped(code)
                    } else {
                        GuardCleanup::ReapedElsewhere(Some(code))
                    });
                }
                // No WUNTRACED was requested, so a stop report cannot
                // occur; anything else is not our death — keep waiting
                // (bounded, below).
            } else if r < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    // EINTR falls through to the bounded wait below.
                    Some(libc::EINTR) => {}
                    // Someone else collected our child (a concurrent
                    // rescue): resolved, status unknown — or already
                    // gone, if the kill itself found nothing.
                    Some(libc::ECHILD) => {
                        self.disarm();
                        return Ok(if killed {
                            GuardCleanup::ReapedElsewhere(None)
                        } else {
                            GuardCleanup::AlreadyGone
                        });
                    }
                    _ => anyhow::bail!("reap of owned child {} failed: {e}", self.pid),
                }
            }
            if Instant::now() >= end {
                if killed {
                    anyhow::bail!(
                        "reap of owned child {} timed out after {:?} (SIGKILL sent, still unreaped)",
                        self.pid,
                        PRESTOP_REAP_GRACE
                    );
                }
                anyhow::bail!(
                    "reap of owned child {} timed out after {:?} (kill found no process, yet still unreaped)",
                    self.pid,
                    PRESTOP_REAP_GRACE
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PrestopGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_millis(200);
        while Instant::now() < end {
            match reap_once(self.pid) {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

impl OwnedTarget {
    /// Fork a child held stopped pre-exec, with a pre-stop setup
    /// deadline and a cancellation flag (R06/F07: a FIFO/device
    /// workload destination must not hang setup before child
    /// custody exists). Capture calls this with its checked setup
    /// deadline and the live SIGINT/SIGTERM flag.
    ///
    /// Ordering: argv validation, then the cancel/deadline checks
    /// (a dead setup forks nothing and publishes nothing), then
    /// destination preparation — file sinks are validated, staged and
    /// atomically published to a fresh regular file by the PARENT
    /// pre-fork (see [`WorkloadDest::File`]), on ONE gated worker under
    /// the same deadline + cancel (a stalled sink fails the setup; it
    /// never hangs it; the abandonment check + publish run under the ONE
    /// lock the abandonment setter shares, so a worker delayed past
    /// abandonment publishes nothing) — then a final cancel/deadline
    /// re-check, then fork. The caller performs no file syscalls itself
    /// on this path: validate, stage, publish and close all run on
    /// control workers (abandonment takes the publish lock only to set
    /// the flag). Custody starts
    /// at the fork return, BEFORE the parent's sink copy is disposed
    /// (also under control) and before waiting for SIGSTOP; the wait
    /// polls with the checked deadline and the cancel flag, and every
    /// failure kills + reaps only this never-released owned child,
    /// reporting the confirmed outcome (cleanup failures propagate —
    /// "killed and reaped" is claimed only when both are confirmed). A
    /// child that exits before stopping is already reaped, and its
    /// status rides in the error (126 keeps the H9 stdio-setup
    /// mapping). The child allocates nothing post-fork
    /// (async-signal-safe): it dup2s inherited fds only and opens no
    /// paths.
    pub fn spawn_stopped_with_control(
        argv: &[String],
        dest: WorkloadDest,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        if argv.is_empty() {
            anyhow::bail!("run -- needs a command");
        }
        if cancel.load(Ordering::SeqCst) {
            anyhow::bail!("pre-stop setup cancelled before fork");
        }
        if Instant::now() >= deadline {
            anyhow::bail!("pre-stop setup deadline already exceeded (no child spawned)");
        }
        let cs: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<Result<_, _>>()
            .context("NUL in argv")?;
        let mut ptrs: Vec<*const libc::c_char> = cs.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        // Test-only hook values, copied to the stack BEFORE forking
        // (the child uses only its stack copy — no TLS access, no
        // allocation post-fork).
        let (prestop_stall_ms, prestop_pid_sink) = PRESTOP_TEST_HOOK.with(|h| {
            let h = h.borrow();
            (h.stall_ms, h.pid_sink.clone())
        });
        // Destination validated + prepared pre-fork (the child
        // allocates nothing). A file sink is opened + pinned HERE
        // (never by the child), on a worker under the setup deadline +
        // cancel; an invalid fd fails HERE — no spawn.
        let mut owned_sink: Option<OwnedFd> = None;
        let child_dest = match &dest {
            WorkloadDest::Null => ChildDest::Null,
            WorkloadDest::File(path) => {
                // Staging + atomic publish inside ONE gated worker (fix
                // round 4): validation never creates or truncates, the
                // staging file is uniquely owned (a worker delayed past
                // abandonment can only touch its own staging), and the
                // abandonment check + rename run under the ONE lock the
                // caller's abandonment setter shares — a late worker is
                // physically incapable of touching the destination. The
                // caller only polls the rendezvous (it takes the publish
                // lock solely to record abandonment). (Fix round 3 ran a
                // fenced ftruncate on the worker: bounded, but the fence
                // load and the truncate could not be atomic — a worker
                // descheduled between them erased successor bytes.)
                let owned_path = path.clone();
                let truncate_delay_ms = SETUP_TEST_HOOK.with(|h| h.borrow().truncate_delay_ms);
                let publish_gate = SETUP_TEST_HOOK.with(|h| h.borrow().publish_gate.clone());
                let prep = run_under_control(deadline, cancel, move |gate| {
                    prepare_and_publish_sink(&owned_path, gate, truncate_delay_ms, publish_gate)
                })
                .map_err(|e| anyhow::anyhow!("{e:#} (no child spawned)"))?;
                let published = match prep {
                    Control::Done(r) => r?,
                    Control::Cancelled => {
                        anyhow::bail!(
                            "pre-stop setup cancelled during file-sink preparation (no child spawned)"
                        );
                    }
                    Control::Expired => {
                        anyhow::bail!(
                            "pre-stop setup deadline exceeded during file-sink preparation (no child spawned)"
                        );
                    }
                    Control::Lost => {
                        anyhow::bail!(
                            "pre-stop setup worker lost during file-sink preparation (no child spawned)"
                        );
                    }
                };
                let raw = published.as_raw_fd();
                owned_sink = Some(published);
                ChildDest::Fd(raw)
            }
            WorkloadDest::Fd(fd) => {
                let r = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
                if r < 0 {
                    anyhow::bail!(
                        "workload output fd {fd}: not a valid open fd ({})",
                        std::io::Error::last_os_error()
                    );
                }
                ChildDest::Fd(*fd)
            }
        };
        // The setup may have died while preparation ran: re-check BEFORE
        // forking so a dead setup forks nothing. A prepared sink
        // disposes under the same control (a FUSE close must not hang
        // this path either); there is no child yet, so the outcome needs
        // no custody.
        if cancel.load(Ordering::SeqCst) {
            if let Some(sink) = owned_sink.take() {
                let _ = close_under_control(sink, deadline, cancel);
            }
            anyhow::bail!(
                "pre-stop setup cancelled after destination preparation (no child spawned)"
            );
        }
        if Instant::now() >= deadline {
            if let Some(sink) = owned_sink.take() {
                let _ = close_under_control(sink, deadline, cancel);
            }
            anyhow::bail!(
                "pre-stop setup deadline exceeded after destination preparation (no child spawned)"
            );
        }
        // Test-only fork fault (see `SETUP_TEST_HOOK`): consumed on read,
        // inert (`false`) for every production caller.
        let fail_fork =
            SETUP_TEST_HOOK.with(|h| std::mem::replace(&mut h.borrow_mut().fail_fork, false));
        let pid = if fail_fork {
            -1
        } else {
            unsafe { libc::fork() }
        };
        if pid < 0 {
            // F1: a prepared sink disposes under control here too — never
            // by dropping it inline (a FUSE FLUSH in that drop would hang
            // setup on the caller). No child exists, so the outcome needs
            // no custody.
            if let Some(sink) = owned_sink.take() {
                let _ = close_under_control(sink, deadline, cancel);
            }
            if fail_fork {
                anyhow::bail!("fork: test-injected fork failure");
            }
            anyhow::bail!("fork: {}", std::io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                // F-CAPS-1: a filecaps observer (cap_bpf+cap_perfmon)
                // is born non-dumpable, and the forked child inherits
                // that — same-uid /proc/PID/maps reads then fail with
                // EACCES while the child is stopped pre-exec, which
                // breaks the setup baseline read. The child opts
                // itself back to dumpable pre-exec (unprivileged
                // self-set; async-signal-safe: prctl is a raw
                // syscall). Post-exec the child is dumpable regardless
                // (plain binaries reset it — measured), so this only
                // covers the stopped pre-exec window and changes no
                // post-exec posture. A prctl failure is non-fatal (an
                // exotic kernel keeps the old behavior; the maps read
                // then fails loud, never silent).
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
                // H9/R07: explicit output policy — the workload's
                // stdio follows its destination (never the stdout
                // artifact channel, never observer stderr), before
                // the pre-exec stop so the fds are final while
                // setup observes us.
                redirect_child_stdio(&child_dest);
                // Test-only pre-stop stall (see the hook static): a
                // plain stack integer + nanosleep — no allocation, no
                // TLS access (async-signal-safe). EINTR resumes the
                // remainder so the stall is never cut short.
                if prestop_stall_ms > 0 {
                    let mut rem = libc::timespec {
                        tv_sec: (prestop_stall_ms / 1000) as libc::time_t,
                        tv_nsec: ((prestop_stall_ms % 1000) * 1_000_000) as libc::c_long,
                    };
                    loop {
                        let mut out: libc::timespec = std::mem::zeroed();
                        if libc::nanosleep(&rem, &mut out) == 0 {
                            break;
                        }
                        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                            rem = out;
                            continue;
                        }
                        break;
                    }
                }
                libc::raise(libc::SIGSTOP);
                libc::execvp(ptrs[0], ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        // Parent only from here (the child never falls through).
        let pid = pid as u32;
        // Out-of-band fork report for the test hook (an atomic store:
        // never blocks).
        if let Some(sink) = prestop_pid_sink.as_ref() {
            sink.store(pid, Ordering::SeqCst);
        }
        // Custody starts IMMEDIATELY at the fork return — before the
        // parent's sink copy is disposed (a FUSE close can block) and
        // before the wait.
        let mut guard = PrestopGuard { pid, armed: true };
        // The parent's copy of a pinned sink closes NOW (the child
        // inherited its own) — under setup control, with the guard
        // already armed. If disposal itself outlives the setup, the
        // guard-held child resolves under custody.
        if let Some(sink) = owned_sink.take() {
            match close_under_control(sink, deadline, cancel) {
                Ok(Control::Done(()) | Control::Lost) => {}
                Ok(Control::Cancelled) => {
                    let report = guard_cleanup_report(&mut guard);
                    anyhow::bail!(
                        "pre-stop setup cancelled while disposing parent sink; owned child {pid} {report}"
                    );
                }
                Ok(Control::Expired) => {
                    let report = guard_cleanup_report(&mut guard);
                    anyhow::bail!(
                        "pre-stop setup deadline exceeded while disposing parent sink; owned child {pid} {report}"
                    );
                }
                Err(_) => {
                    // Thread exhaustion: the fd leaked (never closed
                    // inline — see `close_under_control`); custody is
                    // intact, so continue into the wait rather than
                    // killing a healthy child over a local shortage.
                }
            }
        }
        loop {
            if cancel.load(Ordering::SeqCst) {
                let report = guard_cleanup_report(&mut guard);
                anyhow::bail!("pre-stop setup cancelled; owned child {pid} {report}");
            }
            if Instant::now() >= deadline {
                let report = guard_cleanup_report(&mut guard);
                anyhow::bail!("pre-stop setup deadline exceeded; owned child {pid} {report}");
            }
            let mut status = 0;
            let r = unsafe {
                libc::waitpid(
                    pid as libc::pid_t,
                    &mut status,
                    libc::WNOHANG | libc::WUNTRACED,
                )
            };
            if r == 0 {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            if r < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                let e = std::io::Error::last_os_error();
                let report = guard_cleanup_report(&mut guard);
                anyhow::bail!("waitpid {pid}: {e}; owned child {pid} {report}");
            }
            if libc::WIFSTOPPED(status) {
                guard.disarm();
                return Ok(OwnedTarget {
                    pid,
                    state: CustodyState::Stopped,
                    exit_code: None,
                });
            }
            // Reaped by this waitpid: disarm (nothing left to kill)
            // and report the status.
            guard.disarm();
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                status
            };
            // H9: 126 is ours alone (stdio setup failure — nothing
            // else exits pre-stop with it). Name the destination:
            // never silent null when the operator asked for the log.
            if code == WORKLOAD_SETUP_EXIT {
                let what = match &dest {
                    WorkloadDest::Null => "/dev/null".to_string(),
                    WorkloadDest::File(path) => path.display().to_string(),
                    WorkloadDest::Fd(fd) => format!("fd {fd}"),
                };
                anyhow::bail!("workload output {what}: child stdio setup failed (status 126)");
            }
            anyhow::bail!("child exited before stop (status {code})");
        }
    }

    /// Fork a child held stopped pre-exec. Bounded convenience
    /// over [`OwnedTarget::spawn_stopped_with_control`] for test
    /// callers: a 60s pre-stop bound, never cancelled. Production
    /// capture uses the control entrypoint with its checked setup
    /// deadline and the live SIGINT/SIGTERM flag. CStrings are built
    /// before the fork so the child allocates nothing
    /// (async-signal-safe). Exec failure in the child exits 127.
    /// The parent observes the stop before returning; a child that
    /// exits before stopping is already reaped, and its status
    /// rides in the error.
    pub fn spawn_stopped(argv: &[String], dest: WorkloadDest) -> anyhow::Result<Self> {
        let idle = AtomicBool::new(false);
        // Fail closed on overflow (unreachable: 60s past now).
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);
        Self::spawn_stopped_with_control(argv, dest, deadline, &idle)
    }

    /// Owned pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Current explicit custody state.
    pub fn state(&self) -> CustodyState {
        self.state
    }

    /// Preserved exit status once reaped (`Some` in `Reaped` only).
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Release a stopped child (SIGCONT): `Stopped` → `Released`.
    /// Strictly once: any other state is an error. A failed SIGCONT
    /// reaps when the child is already dead (recording `Reaped`) and
    /// still errors, so the caller never assumes a running child.
    pub fn release(&mut self) -> anyhow::Result<()> {
        if self.state != CustodyState::Stopped {
            anyhow::bail!("release: not stopped (state {:?})", self.state);
        }
        let r = unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGCONT) };
        if r == 0 {
            self.state = CustodyState::Released;
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if let Ok(Some(code)) = reap_once(self.pid) {
            self.exit_code = Some(code);
            self.state = CustodyState::Reaped;
        }
        anyhow::bail!("SIGCONT to {}: {e}", self.pid);
    }

    /// Non-blocking exit poll: `Ok(None)` = still owned and alive;
    /// `Ok(Some(code))` = reaped (state `Reaped`, idempotent — the
    /// stored status is returned again). Polling a detached target is
    /// an ownership error (it is no longer ours to wait on).
    pub fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        match self.state {
            CustodyState::Reaped => Ok(self.exit_code),
            CustodyState::Detached => anyhow::bail!("poll: target {} detached", self.pid),
            CustodyState::Stopped | CustodyState::Released => {
                if let Some(code) = reap_once(self.pid)? {
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                    Ok(Some(code))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Resolve custody after a setup failure: a never-released child
    /// is terminated and reaped (`Stopped` → `Reaped`); a released
    /// child is reaped when already exited, else detached and left
    /// running (the observer never kills a running application because
    /// its own setup failed). Terminal states are a no-op. A stopped
    /// child that is no longer observably stopped (externally
    /// continued) is detached, never killed.
    pub fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        match self.state {
            CustodyState::Reaped | CustodyState::Detached => Ok(()),
            CustodyState::Released => {
                // Reap first: an already-exited child keeps its status
                // instead of lingering as a zombie under a detached label.
                if let Some(code) = reap_once(self.pid)? {
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                } else {
                    self.state = CustodyState::Detached;
                }
                Ok(())
            }
            CustodyState::Stopped => match query_child(self.pid)? {
                ChildQuery::Stopped => {
                    unsafe {
                        libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                    }
                    let code = reap_blocking(self.pid)?;
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                    Ok(())
                }
                ChildQuery::Exited(code) => {
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                    Ok(())
                }
                // Alive but not stopped: leave it running.
                ChildQuery::Running => {
                    self.state = CustodyState::Detached;
                    Ok(())
                }
            },
        }
    }

    /// End-of-observation disposition: a stopped child is terminated
    /// and reaped; an exited child reports its preserved status; a
    /// running child is detached and left running. Idempotent on
    /// terminal states.
    pub fn finish_observation(&mut self) -> anyhow::Result<TargetDisposition> {
        match self.state {
            CustodyState::Reaped => Ok(TargetDisposition::Exited {
                code: self.exit_code.unwrap_or(0),
            }),
            CustodyState::Detached => Ok(TargetDisposition::Detached { pid: self.pid }),
            CustodyState::Stopped => {
                self.resolve_setup_failure()?;
                // Invariant: Reaped always carries a code; resolve can
                // otherwise only detach a live-but-unstopped child.
                match self.state {
                    CustodyState::Reaped => Ok(TargetDisposition::Exited {
                        code: self.exit_code.unwrap_or(0),
                    }),
                    _ => Ok(TargetDisposition::Detached { pid: self.pid }),
                }
            }
            CustodyState::Released => {
                if let Some(code) = reap_once(self.pid)? {
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                    Ok(TargetDisposition::Exited { code })
                } else {
                    self.state = CustodyState::Detached;
                    Ok(TargetDisposition::Detached { pid: self.pid })
                }
            }
        }
    }
}

#[cfg(test)]
mod control_tests {
    //! F1 mechanism pins: blocking setup ops run under deadline +
    //! cancellation control (see [`super::run_under_control`]).
    use super::{
        __test_set_control_worker_counter, __test_set_poll_gate, __test_set_setup_delay_ms,
        Control, close_under_control, prepare_and_publish_sink, run_under_control,
    };
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn control_expired_deadline_does_not_run() {
        let cancel = AtomicBool::new(false);
        let ran = std::sync::Arc::new(AtomicBool::new(false));
        let ran_c = ran.clone();
        let out = run_under_control(Instant::now(), &cancel, move |_| {
            ran_c.store(true, Ordering::SeqCst);
            42
        })
        .unwrap();
        assert!(matches!(out, Control::Expired));
        assert!(!ran.load(Ordering::SeqCst), "dead op must not run");
    }

    #[test]
    fn control_pending_cancel_does_not_run() {
        let cancel = AtomicBool::new(true);
        let ran = std::sync::Arc::new(AtomicBool::new(false));
        let ran_c = ran.clone();
        let out = run_under_control(
            Instant::now() + Duration::from_secs(30),
            &cancel,
            move |_| {
                ran_c.store(true, Ordering::SeqCst);
                42
            },
        )
        .unwrap();
        assert!(matches!(out, Control::Cancelled));
        assert!(!ran.load(Ordering::SeqCst), "dead op must not run");
    }

    #[test]
    fn control_returns_value() {
        let cancel = AtomicBool::new(false);
        let out =
            run_under_control(Instant::now() + Duration::from_secs(30), &cancel, |_| 42).unwrap();
        assert!(matches!(out, Control::Done(42)));
    }

    #[test]
    fn control_slow_op_cancelled_mid_run() {
        let cancel = AtomicBool::new(false);
        // Signal-like cancellation from another thread (the same store
        // the SIGINT/SIGTERM handler performs on capture's live flag).
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                cancel.store(true, Ordering::SeqCst);
            });
            let t0 = Instant::now();
            // The op simulates an uninterruptible stall (a FUSE sink
            // that never answers): it sleeps past the test and is
            // abandoned, never awaited.
            let out = run_under_control(Instant::now() + Duration::from_secs(30), &cancel, |_| {
                std::thread::sleep(Duration::from_secs(30))
            })
            .unwrap();
            assert!(matches!(out, Control::Cancelled));
            assert!(t0.elapsed() < Duration::from_secs(5), "fail fast");
        });
    }

    #[test]
    fn control_slow_op_deadline_mid_run() {
        let cancel = AtomicBool::new(false);
        let t0 = Instant::now();
        let out = run_under_control(Instant::now() + Duration::from_millis(100), &cancel, |_| {
            std::thread::sleep(Duration::from_secs(30))
        })
        .unwrap();
        assert!(matches!(out, Control::Expired));
        assert!(t0.elapsed() < Duration::from_secs(5), "fail fast");
    }

    #[test]
    fn control_close_confirms_on_live_setup() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let cancel = AtomicBool::new(false);
        let fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let out =
            close_under_control(fd, Instant::now() + Duration::from_secs(30), &cancel).unwrap();
        assert!(matches!(out, Control::Done(())));
        let r = unsafe { libc::fcntl(fds[1], libc::F_GETFD) };
        assert!(r < 0, "fd must be closed");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        unsafe {
            libc::close(fds[0]);
        }
    }

    #[test]
    fn control_close_runs_even_on_dead_setup() {
        // F1 leak pin: disposal on an already-dead setup still closes
        // (late, on the worker) instead of leaking the fd.
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let cancel = AtomicBool::new(true);
        let fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let out =
            close_under_control(fd, Instant::now() + Duration::from_secs(30), &cancel).unwrap();
        assert!(matches!(out, Control::Cancelled));
        // The worker closes late: poll for EBADF, bounded.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let r = unsafe { libc::fcntl(fds[1], libc::F_GETFD) };
            if r < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
                break;
            }
            assert!(Instant::now() < end, "worker never closed");
            std::thread::sleep(Duration::from_millis(1));
        }
        unsafe {
            libc::close(fds[0]);
        }
    }

    #[test]
    fn control_panicking_worker_reports_lost() {
        let cancel = AtomicBool::new(false);
        let out = run_under_control(Instant::now() + Duration::from_secs(30), &cancel, |_| {
            panic!("r06 control probe panic")
        })
        .unwrap();
        assert!(matches!(out, Control::Lost));
    }

    #[test]
    fn control_abandoned_setup_skips_op() {
        // Fix round 2: a worker that has not started its op when the
        // caller abandons setup must skip the op (a late destructive
        // open must never run). The delay deterministically orders the
        // abandonment before the worker's first step.
        let cancel = AtomicBool::new(false);
        let ran = std::sync::Arc::new(AtomicBool::new(false));
        let ran_c = ran.clone();
        let counter = std::sync::Arc::new(AtomicU32::new(0));
        __test_set_setup_delay_ms(500);
        __test_set_control_worker_counter(Some(counter.clone()));
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                cancel.store(true, Ordering::SeqCst);
            });
            let out = run_under_control(
                Instant::now() + Duration::from_secs(30),
                &cancel,
                move |_| {
                    ran_c.store(true, Ordering::SeqCst);
                    42
                },
            )
            .unwrap();
            assert!(matches!(out, Control::Cancelled));
        });
        // Bounded wait for the worker to finish, then reset hooks before
        // asserting (thread-local; this thread dies with the test anyway).
        let end = Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) < 1 {
            assert!(Instant::now() < end, "worker never finished");
            std::thread::sleep(Duration::from_millis(5));
        }
        __test_set_setup_delay_ms(0);
        __test_set_control_worker_counter(None);
        assert!(!ran.load(Ordering::SeqCst), "abandoned op must not run");
    }

    #[test]
    fn control_discarded_result_destroys_on_worker() {
        // Fix round 3 / F1-PROOF: abandonment with a completed, unreceived
        // result must destroy that result ON THE WORKER — never inline on
        // the caller (a FUSE FLUSH inside that drop would hang setup). The
        // interleaving is forced deterministically: the op reports
        // completion, a helper orders cancel-before-proceed, and the caller
        // waits on the poll gate before its first check — so the caller
        // abandons with the result completed but unreceived, on every run.
        // A drop probe records the destroying thread: on the former
        // buffered channel this fails (drop on caller); with the rendezvous
        // it passes (drop on worker).
        use std::sync::Mutex;
        use std::thread::ThreadId;

        struct DropProbe {
            dropper: std::sync::Arc<Mutex<Option<ThreadId>>>,
        }
        impl Drop for DropProbe {
            fn drop(&mut self) {
                *self.dropper.lock().unwrap() = Some(std::thread::current().id());
            }
        }

        let cancel = AtomicBool::new(false);
        let caller = std::thread::current().id();
        let op_done = std::sync::Arc::new(AtomicBool::new(false));
        let proceed = std::sync::Arc::new(AtomicBool::new(false));
        let worker_id = std::sync::Arc::new(Mutex::new(None));
        let dropper = std::sync::Arc::new(Mutex::new(None));
        let counter = std::sync::Arc::new(AtomicU32::new(0));
        __test_set_poll_gate(Some(proceed.clone()));
        __test_set_control_worker_counter(Some(counter.clone()));
        let op_done_h = op_done.clone();
        let proceed_h = proceed.clone();
        let op_done_c = op_done.clone();
        let worker_id_c = worker_id.clone();
        let dropper_c = dropper.clone();
        let out = std::thread::scope(|s| {
            // Helper: order the abandonment strictly after the op
            // completed. On a buffered channel the counter only advances
            // past the send, so waiting for it proves the result queued
            // before the caller abandoned. A rendezvous send stays blocked
            // behind the gated caller instead, so this wait expires there
            // (2s) — the assertions below stay deterministic either way:
            // abandonment always precedes the receiver's destruction, and a
            // rendezvous send can only fail once the receiver is gone.
            s.spawn(|| {
                let end = Instant::now() + Duration::from_secs(10);
                while !op_done_h.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end, "worker op never completed");
                    std::thread::sleep(Duration::from_millis(1));
                }
                let end = Instant::now() + Duration::from_secs(2);
                while counter.load(Ordering::SeqCst) < 1 {
                    if Instant::now() >= end {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                cancel.store(true, Ordering::SeqCst);
                proceed_h.store(true, Ordering::SeqCst);
            });
            run_under_control(
                Instant::now() + Duration::from_secs(30),
                &cancel,
                move |_| {
                    *worker_id_c.lock().unwrap() = Some(std::thread::current().id());
                    let probe = DropProbe { dropper: dropper_c };
                    op_done_c.store(true, Ordering::SeqCst);
                    probe
                },
            )
            .unwrap()
        });
        __test_set_poll_gate(None);
        __test_set_control_worker_counter(None);
        assert!(
            matches!(out, Control::Cancelled),
            "caller must abandon with the result unreceived"
        );
        // Bounded wait for the worker to finish (its drop precedes the
        // count), then for the drop record itself.
        let end = Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) < 1 {
            assert!(Instant::now() < end, "worker never finished");
            std::thread::sleep(Duration::from_millis(1));
        }
        let end = Instant::now() + Duration::from_secs(10);
        while dropper.lock().unwrap().is_none() {
            assert!(Instant::now() < end, "discarded result never destroyed");
            std::thread::sleep(Duration::from_millis(1));
        }
        let worker = worker_id.lock().unwrap().expect("op ran on a worker");
        assert_ne!(worker, caller, "sanity: op ran off the caller");
        assert_eq!(
            dropper.lock().unwrap().expect("drop recorded"),
            worker,
            "discarded result must be destroyed on the worker, not the caller"
        );
    }

    #[test]
    fn staged_sink_publishes_when_live_skips_when_abandoned() {
        // Fix round 4, direct pin: the worker-side preparation op
        // publishes a fresh empty inode over the destination when live
        // (carrying the prior permission bits over), and publishes
        // nothing — deleting its staging — once the abandonment gate is
        // set.
        let dir = std::env::temp_dir().join(format!("osslscope-trunc-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("live.log");
        let dead = dir.join("dead.log");
        std::fs::write(&live, b"stale\n").unwrap();
        std::fs::write(&dead, b"stale\n").unwrap();
        // A distinctive mode on the live target: the publish must carry
        // it onto the fresh inode (truncate-in-place preserved it).
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Mutex::new(false);
        let fd = prepare_and_publish_sink(&live, &gate, 0, None).unwrap();
        drop(fd);
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"",
            "live setup publishes an empty sink"
        );
        assert_eq!(
            std::fs::metadata(&live).unwrap().permissions().mode() & 0o777,
            0o600,
            "publish carries the prior mode bits over"
        );
        *gate.lock().unwrap() = true;
        let err = prepare_and_publish_sink(&dead, &gate, 0, None).unwrap_err();
        assert!(
            err.to_string().contains("abandoned"),
            "abandonment surfaces: {err:#}"
        );
        assert_eq!(
            std::fs::read(&dead).unwrap(),
            b"stale\n",
            "abandoned setup publishes nothing"
        );
        // No staging litter in either case.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, vec!["dead.log".to_string(), "live.log".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

impl Drop for OwnedTarget {
    /// Backstop: a still-stopped child is signaled and reaped with
    /// bounded effort (never left stopped); a released child is left
    /// running; terminal states are untouched. Explicit
    /// `resolve_setup_failure` / `finish_observation` remain the
    /// primary paths — they block until custody is fully resolved.
    fn drop(&mut self) {
        match self.state {
            CustodyState::Released => {
                // Best effort: reap an already-exited child; a running
                // one is left running.
                if let Ok(Some(code)) = reap_once(self.pid) {
                    self.exit_code = Some(code);
                    self.state = CustodyState::Reaped;
                }
            }
            CustodyState::Stopped => {
                // Only a kernel-confirmed stopped child is signaled; a
                // running child is left alone, an error (ECHILD: reaped
                // elsewhere) has nothing left to do.
                match query_child(self.pid) {
                    Ok(ChildQuery::Exited(code)) => {
                        self.exit_code = Some(code);
                        self.state = CustodyState::Reaped;
                    }
                    Ok(ChildQuery::Stopped) => {
                        unsafe {
                            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                        }
                        let end = Instant::now() + Duration::from_millis(200);
                        while Instant::now() < end {
                            match reap_once(self.pid) {
                                Ok(Some(code)) => {
                                    self.exit_code = Some(code);
                                    self.state = CustodyState::Reaped;
                                    return;
                                }
                                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                                Err(_) => return,
                            }
                        }
                    }
                    _ => {}
                }
            }
            CustodyState::Reaped | CustodyState::Detached => {}
        }
    }
}
