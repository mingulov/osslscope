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
use std::collections::HashMap;
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
    /// parent-side, pre-fork). Preparation runs on ONE worker: the
    /// destination is validated (never created, never truncated), then a
    /// provably-distinct staging file is created beside it, then the
    /// worker re-checks the lock-free abandonment flag immediately before
    /// the atomic publish (`rename`) — a worker that observes abandonment
    /// deletes only its own staging and performs NO destination mutation.
    /// The caller's abandonment path takes NO lock and performs NO file
    /// syscalls (bounded by construction, however stuck the worker is).
    /// A process-wide per-destination registry refuses a new OUR-setup
    /// while a prior worker for that path is still live, so OUR-retry
    /// successors never race a stale worker. Accepted ONLY as a regular
    /// file: missing parents, symlinks, FIFOs, directories, sockets and
    /// devices fail setup pre-fork, naming the path with the 126 setup
    /// marker. The published fd — not the path — is handed to the child,
    /// so post-publish path replacement is harmless. Notes: each run
    /// publishes a FRESH inode (hard links to a previous run's file are
    /// not preserved; permission bits are carried over); the
    /// destination's directory must be writable (staging + rename live
    /// beside the destination); destinations whose file name lies in the
    /// staging namespace (`.osslscope-staging-*`) are refused before
    /// anything is created. Residual: arbitrary EXTERNAL writers racing a
    /// stale worker cannot be fenced by any userspace design — the
    /// guarantee covers setups coordinated through this setup path.
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

/// Staging file-name namespace (fix round 5): every generated staging
/// name carries this prefix, and any REQUESTED destination whose file name
/// carries it is refused before anything is created (see
/// [`dest_in_staging_namespace`]) — a destination can therefore never equal
/// a would-be staging name.
const STAGING_PREFIX: &str = ".osslscope-staging-";

/// Per-process staging sequence: staging names are unique per (pid,
/// counter, random), so a worker delayed past abandonment can only ever
/// touch its own staging file — never the destination, never another
/// attempt's staging.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One random suffix for a staging name (fix round 5): `getrandom`, with a
/// time/pid/counter mix as the fallback (uniqueness is still carried by the
/// counter; the random component additionally separates stale files across
/// pid reuse and crashed runs). Runs worker-side only.
fn random_suffix() -> u64 {
    let mut buf = [0u8; 8];
    let r = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if r == buf.len() as libc::ssize_t {
        return u64::from_ne_bytes(buf);
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() ^ (d.subsec_nanos() as u64))
        .unwrap_or(0);
    t ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ STAGING_COUNTER
            .load(Ordering::Relaxed)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9)
}

/// Collision control, first layer (fix round 5): a destination whose file
/// name lies in the staging namespace could equal a generated staging name,
/// so the setup is refused BEFORE creating anything (no staging, no
/// validation fd, no worker, no child). Pure path inspection — no syscalls.
fn dest_in_staging_namespace(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.as_bytes().starts_with(STAGING_PREFIX.as_bytes()))
        .unwrap_or(false)
}

/// A staging sink the worker created itself (fix round 5): the fd, the path,
/// and the device/inode identity recorded at creation. Cleanup unlinks the
/// path ONLY while it still resolves to that recorded identity (see
/// [`remove_own_staging`]) — a stale worker touches only what it created.
/// Deliberately NO `Drop` impl: after a successful publish the path names
/// the DESTINATION and must never be unlinked — every cleanup call is
/// explicit, on failure paths only.
struct StagingFile {
    fd: OwnedFd,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

/// Delete a staging file the worker created itself (fix round 5): the path
/// is unlinked only if it still resolves (via `lstat`, so a swapped-in
/// symlink never matches) to the device/inode recorded at creation.
/// Anything else — renamed away, replaced, unstatable, or never ours — is
/// left untouched. Never called with the destination path.
fn remove_own_staging(staging: &StagingFile) {
    let Ok(c) = CString::new(staging.path.as_os_str().as_bytes()) else {
        return;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } == 0
        && st.st_dev == staging.dev
        && st.st_ino == staging.ino
    {
        let _ = std::fs::remove_file(&staging.path);
    }
}

/// Create the uniquely-owned staging sink for `path` (fix round 5): a
/// fresh empty regular file in the destination's directory, opened
/// `O_CREAT|O_EXCL` — born empty, so it is never truncated. `mode` carries
/// the validated destination's permission bits when it exists (see
/// [`ValidatedTarget`]). Provably distinct from the destination in three
/// layers: (1) the staging namespace is refused at the entrypoint before
/// anything is created; (2) a generated candidate equal to the destination
/// path is skipped without creating it; (3) after creation the staging
/// identity (device/inode) is compared against the destination path — a
/// same-file match (only reachable via symlinked-parent aliasing) deletes
/// the just-created inode (new by `O_EXCL`, so nothing pre-existing is
/// lost) and fails closed. Every failure names the destination path with
/// the 126 setup marker and spawns nothing.
fn create_staging_sink(path: &Path, mode: Option<u32>) -> anyhow::Result<StagingFile> {
    use anyhow::Context as _;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let pid = std::process::id();
    for _ in 0..100 {
        let n = STAGING_COUNTER.fetch_add(1, Ordering::SeqCst);
        let staging = dir.join(format!(
            "{STAGING_PREFIX}{pid}-{n}-{:016x}",
            random_suffix()
        ));
        if staging == path {
            continue; // Layer 2: never create onto the destination spelling.
        }
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
        let (dev, ino) = (st.st_dev, st.st_ino);
        // Layer 3: same-file comparison against the destination. An absent
        // destination (or any other stat failure) cannot alias our new
        // inode, so only a positive identity match fails closed.
        let mut dst: libc::stat = unsafe { std::mem::zeroed() };
        if let Ok(dc) = CString::new(path.as_os_str().as_bytes()) {
            if unsafe { libc::stat(dc.as_ptr(), &mut dst) } == 0
                && dst.st_dev == dev
                && dst.st_ino == ino
            {
                let _ = std::fs::remove_file(&staging);
                anyhow::bail!(
                    "workload output {}: staging file aliases the destination (setup status 126)",
                    path.display(),
                );
            }
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
        return Ok(StagingFile {
            fd: owned,
            path: staging,
            dev,
            ino,
        });
    }
    anyhow::bail!(
        "workload output {}: cannot pick a staging name after 100 attempts (setup status 126)",
        path.display(),
    );
}

/// Process-wide per-destination setup registry (fix round 5): maps a
/// lexically-normalized destination to the id of the setup whose prep
/// worker is still live. A new OUR-setup for a path with a still-live
/// prior worker REFUSES (fail fast — no bounded fence wait) instead of
/// writing concurrently; once the prior worker finishes and unregisters, a
/// successor setup runs normally. This closes OUR-retry successor races
/// structurally: at most one OUR worker per destination is ever mutating
/// it. The lock is held only for single map operations — never across file
/// syscalls, sleeps, or joins — and NEVER on the caller's
/// deadline/cancel (abandonment) path: an abandoning caller leaves its
/// entry for its still-running worker to remove.
fn setup_registry() -> &'static Mutex<HashMap<PathBuf, u64>> {
    static REGISTRY: std::sync::OnceLock<Mutex<HashMap<PathBuf, u64>>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Unique setup-attempt ids for [`setup_registry`] ownership (an entry is
/// removed only by the attempt that inserted it).
static SETUP_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Lexically normalize a destination for registry keying (fix round 5,
/// R06-a): absolutize relative spellings against the process cwd, then
/// collapse `.`, resolve `..` against normal components, drop duplicate
/// separators — so `a`, `./a`, `sub/../a`, and `$CWD/a` fence each other.
/// A `..` with no normal component to pop resolves against the root on
/// absolute paths (the root's parent is the root — the kernel's own
/// rule, still purely lexical, so `/../tmp/x` and `/tmp/x` fence each
/// other); on relative paths (getcwd-failure fallback only) it persists
/// lexically. Only `current_dir` (one bounded getcwd, no destination
/// I/O — never `canonicalize`, whose blocking file I/O the setup path
/// forbids); a getcwd failure falls back to the lexical key (today's
/// behavior, never an error). Residual: distinct spellings through
/// symlinked parents key separately (unresolvable without syscalls —
/// documented; same class as external writers).
fn normalize_setup_key(path: &Path) -> PathBuf {
    use std::path::Component;
    let absolute;
    let effective = if path.is_absolute() {
        path
    } else {
        match std::env::current_dir() {
            Ok(cwd) => {
                absolute = cwd.join(path);
                &absolute
            }
            Err(_) => path,
        }
    };
    let absolute_effective = effective.is_absolute();
    let mut out = PathBuf::new();
    for c in effective.components() {
        match c {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // Root's parent is the root (absolute paths only —
                // relative `..` stays meaningful); dropping is the
                // kernel's rule, no syscalls involved.
                _ if absolute_effective => {}
                _ => out.push(".."),
            },
            Component::Normal(n) => out.push(n),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Try to register a new OUR-setup for `key` (fix round 5): `Some(id)` when
/// no prior worker is live for it (the caller owns the entry until its
/// worker finishes or the synchronous paths below reclaim it), `None` when
/// a prior worker is still live (the setup must refuse without writing).
/// Brief map operation only. Poison-tolerant (a poisoned registry still
/// fences: the map is trusted, never the panic).
fn registry_try_insert(key: &Path) -> Option<u64> {
    let mut reg = setup_registry().lock().unwrap_or_else(|e| e.into_inner());
    if reg.contains_key(key) {
        return None;
    }
    let id = SETUP_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    reg.insert(key.to_path_buf(), id);
    Some(id)
}

/// Remove the registry entry for `key` ONLY if it still belongs to `id`
/// (fix round 5): idempotent, so the synchronous caller paths and the
/// finishing worker can both call it — exactly one removes. Brief map
/// operation only. Never called on the abandonment path.
fn registry_remove_if(key: &Path, id: u64) {
    let mut reg = setup_registry().lock().unwrap_or_else(|e| e.into_inner());
    if reg.get(key) == Some(&id) {
        reg.remove(key);
    }
}

/// Prepare + publish a [`WorkloadDest::File`] sink, worker-side (fix
/// round 5): staging first — [`validate_sink_target`] (never creates, never
/// truncates) then [`create_staging_sink`] (a fresh empty file provably
/// distinct from the destination) — then the publish. The worker re-checks
/// the lock-free abandonment flag immediately before EVERY destination
/// step, and the final check sits immediately before the ONE destination
/// mutation (`rename`): a worker that observes abandonment deletes ONLY its
/// own staging (see [`remove_own_staging`]) and performs NO destination
/// mutation — no truncate, write, rename, or unlink of the destination.
/// OUR-retry successors never race this worker: the per-destination
/// registry refused them while it was live, and the rendezvous only
/// delivers the published fd to a live receiver. `test_delay_ms` is a
/// moved-in test copy (see `SETUP_TEST_HOOK`): a stall between staging and
/// the publish decision, simulating a sink that answers preparation
/// slowly. Inert (`0`) unless a test armed it. `publish_gate` is the
/// moved-in poised rendezvous (see `SETUP_TEST_HOOK`): when armed, the
/// worker signals readiness and waits (bounded) BEFORE its final
/// abandonment check, so a test can order the caller's abandonment strictly
/// before the publish decision. `rename_hold_ms` / `rename_hold_ready`
/// (see `SETUP_TEST_HOOK`): when armed, the worker signals readiness and
/// sleeps AFTER its final check and BEFORE the rename trap — simulating a
/// worker descheduled after the check (or blocked inside rename). There is
/// deliberately NO re-check after that hold: it pins the documented
/// residual (a post-check-descheduled worker still publishes; OUR
/// successors were fenced by the registry, so only concurrent EXTERNAL
/// writers are unfenced) while proving the caller stays bounded regardless.
fn prepare_and_publish_sink(
    path: &Path,
    abandoned: &AtomicBool,
    test_delay_ms: u64,
    publish_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
    rename_hold_ms: u64,
    rename_hold_ready: Option<Arc<AtomicBool>>,
) -> anyhow::Result<OwnedFd> {
    if abandoned.load(Ordering::SeqCst) {
        anyhow::bail!("pre-stop setup abandoned before file-sink preparation (no child spawned)");
    }
    let validated = validate_sink_target(path)?;
    if abandoned.load(Ordering::SeqCst) {
        drop(validated.fd);
        anyhow::bail!("pre-stop setup abandoned during file-sink preparation (no child spawned)");
    }
    let staging = create_staging_sink(path, validated.mode)?;
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
    // The publish decision: the final abandonment check immediately before
    // the ONE destination mutation. After abandonment this worker performs
    // NO destination mutation — it deletes only its own staging.
    if abandoned.load(Ordering::SeqCst) {
        remove_own_staging(&staging);
        drop(validated.fd);
        drop(staging.fd);
        anyhow::bail!("pre-stop setup abandoned during file-sink preparation (no child spawned)");
    }
    if rename_hold_ms > 0 {
        if let Some(ready) = rename_hold_ready.as_ref() {
            ready.store(true, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(rename_hold_ms));
    }
    match std::fs::rename(&staging.path, path) {
        Ok(()) => {
            // The validation fd refers to the REPLACED inode (or nothing,
            // when the destination was absent): drop it — the staging fd
            // is the published sink the child inherits. The staging path
            // now names the DESTINATION: it is never unlinked (there is
            // deliberately no `Drop` cleanup on `StagingFile`).
            drop(validated.fd);
            Ok(staging.fd)
        }
        Err(e) => {
            remove_own_staging(&staging);
            drop(validated.fd);
            drop(staging.fd);
            Err(anyhow::anyhow!(
                "workload output {}: cannot publish file sink: {e} (setup status 126)",
                path.display(),
            ))
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
    /// waiting); the abandonment flag is stored, so a worker that has not
    /// started its op skips it — a started worker keeps running detached
    /// and owns its captures.
    Cancelled,
    /// The deadline passed while waiting; the abandonment flag is stored
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
/// flag — a late worker must not perform setup work after the caller
/// gave up). The op receives the flag so a multi-phase op can re-check it
/// immediately before every destination step (fix round 5: staging, then
/// check, then publish — no lock anywhere on this path). The result
/// channel is a rendezvous (fix round 2 / F1): a value is delivered only
/// to a live receiver, so a discarded result is always dropped on the
/// worker, never inline on the caller. `on_exit` runs on the worker on
/// every non-panic exit (op completed or op skipped — always BEFORE the
/// completion counter advances); a panicking op skips it (the `Lost`
/// caller path reclaims instead). R06-b: the two EARLY returns below
/// (already-cancelled / already-expired — the worker never spawns) run
/// `on_exit` inline on the caller instead: registration precedes this
/// call, so skipping cleanup there would orphan the entry (the caller's
/// post-spawn Cancelled/Expired arms deliberately do NOT clean — the
/// still-live worker owns the entry and removes it at exit). On expiry
/// the worker is detached — its ownership moves with it, so a stuck
/// open's fd closes whenever the sink answers — and the caller fails
/// WITHOUT forking (pre-fork) or resolves the guard-held child under
/// custody (post-fork). `Err` = the worker thread itself could not start
/// (fail-closed at the call site).
fn run_under_control<T, F>(
    deadline: Instant,
    cancel: &AtomicBool,
    op: F,
    on_exit: Option<Box<dyn FnOnce() + Send + 'static>>,
) -> anyhow::Result<Control<T>>
where
    T: Send + 'static,
    F: FnOnce(&AtomicBool) -> T + Send + 'static,
{
    // R06-b: the early returns run `on_exit` inline (the worker
    // never spawns, so the caller owns cleanup — see the doc
    // comment above). Precedence unchanged: cancel first, then
    // deadline.
    let cancelled = cancel.load(Ordering::SeqCst);
    let expired = Instant::now() >= deadline;
    if cancelled || expired {
        if let Some(f) = on_exit {
            f();
        }
        return Ok(if cancelled {
            Control::Cancelled
        } else {
            Control::Expired
        });
    }
    // Abandonment flag (fix round 5): lock-free — stored by the caller
    // when it stops waiting, loaded by the worker before running the op
    // and re-checked by the op itself before every destination step. The
    // caller's abandonment path takes NO lock and performs NO blocking
    // file syscalls (bounded by construction, however stuck the worker
    // is — the round-4 lock-across-rename is rejected for exactly this).
    let abandoned = Arc::new(AtomicBool::new(false));
    let abandoned_c = abandoned.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let (test_delay_ms, test_counter) = read_setup_test_hook();
    std::thread::Builder::new()
        .name("osslscope-setup-op".to_string())
        .spawn(move || {
            if test_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(test_delay_ms));
            }
            if !abandoned_c.load(Ordering::SeqCst) {
                let _ = tx.send(op(abandoned_c.as_ref()));
            }
            if let Some(f) = on_exit {
                f();
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
/// deliberately NO abandonment flag here (unlike
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
/// [`spawn_controlled`]). When `abandoned` is present, it is STORED (one
/// lock-free atomic store — no mutex, no file syscalls) before returning
/// `Cancelled` / `Expired`, so a worker that has not started its op skips
/// it, and a worker poised at publish observes it at its final check,
/// instead of running setup work after the caller gave up. The registry
/// entry (if any) is deliberately NOT touched here: the still-running
/// worker removes it when it finishes. When the test-only poll gate is
/// armed, the caller waits on it (bounded) before its first check, so a
/// test can order abandonment strictly after a result completed (fix
/// round 3 / F1-PROOF).
fn poll_controlled<T>(
    deadline: Instant,
    cancel: &AtomicBool,
    rx: std::sync::mpsc::Receiver<T>,
    abandoned: Option<&AtomicBool>,
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
                a.store(true, Ordering::SeqCst);
            }
            return Ok(Control::Cancelled);
        }
        if Instant::now() >= deadline {
            if let Some(a) = abandoned {
                a.store(true, Ordering::SeqCst);
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
///   AFTER staging and BEFORE its final abandonment check, so a test can
///   order the caller's abandonment strictly before the publish decision.
///   The spawning thread clones it BEFORE creating the worker; the worker
///   uses only its moved clone.
/// - `rename_hold_ms` / `rename_hold_ready` (fix round 5): when armed,
///   file-sink preparation sets `ready` and sleeps `rename_hold_ms` AFTER
///   its final abandonment check and BEFORE the rename trap — simulating
///   a worker descheduled after the check (or blocked inside rename), so
///   a test can prove the caller stays bounded in exactly that window.
///   The spawning thread copies them BEFORE creating the worker; the
///   worker uses only its moved copies. Production callers must never arm
///   any of these.
struct SetupTestHook {
    setup_delay_ms: u64,
    worker_counter: Option<Arc<AtomicU32>>,
    fail_fork: bool,
    truncate_delay_ms: u64,
    poll_gate: Option<Arc<AtomicBool>>,
    publish_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
    rename_hold_ms: u64,
    rename_hold_ready: Option<Arc<AtomicBool>>,
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
            rename_hold_ms: 0,
            rename_hold_ready: None,
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

/// Test-only: arm the post-check hold duration (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_rename_hold_ms(ms: u64) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().rename_hold_ms = ms);
}

/// Test-only: arm the post-check hold readiness flag (see `SETUP_TEST_HOOK`).
#[doc(hidden)]
pub fn __test_set_rename_hold_ready(ready: Option<Arc<AtomicBool>>) {
    SETUP_TEST_HOOK.with(|h| h.borrow_mut().rename_hold_ready = ready);
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
    /// (a dead setup forks nothing and publishes nothing), then staging
    /// collision control (a destination in the staging namespace is
    /// refused before anything is created), then the per-destination
    /// registry (a new setup refuses while a prior worker for that path
    /// is still live), then destination preparation — file sinks are
    /// validated, staged and atomically published to a fresh regular file
    /// by the PARENT pre-fork (see [`WorkloadDest::File`]), on ONE worker
    /// under the same deadline + cancel (a stalled sink fails the setup;
    /// it never hangs it; the worker re-checks the lock-free abandonment
    /// flag before every destination step, so a worker that observes
    /// abandonment publishes nothing) — then a final cancel/deadline
    /// re-check, then fork. The caller performs no file syscalls itself
    /// on this path (validate, stage, publish and close all run on
    /// control workers) and its abandonment path takes NO lock: it stores
    /// one atomic flag and returns, leaving the registry entry for its
    /// still-running worker to remove. Custody starts
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
                // Staging + atomic publish inside ONE worker (fix round
                // 5): the destination is refused first when it lies in the
                // staging namespace (collision control — before anything
                // is created) and when a prior OUR worker for it is still
                // live (registry fencing — without writing); then
                // validation never creates or truncates, the staging file
                // is provably distinct from the destination, and the
                // worker re-checks the lock-free abandonment flag before
                // every destination step — a worker that observes
                // abandonment deletes only its own staging and performs NO
                // destination mutation. The caller only polls the
                // rendezvous; its abandonment path stores one atomic flag
                // and returns (no lock, no file syscalls). (Fix round 4
                // ran check + rename under ONE lock the abandonment setter
                // shared: bounded publish, but the caller waited out a
                // worker stuck holding that lock — unbounded abandonment.)
                if dest_in_staging_namespace(path) {
                    anyhow::bail!(
                        "workload output {}: destination lies in the staging namespace (setup status 126) (no child spawned)",
                        path.display(),
                    );
                }
                let reg_key = normalize_setup_key(path);
                let Some(reg_id) = registry_try_insert(&reg_key) else {
                    anyhow::bail!(
                        "workload output {}: another setup for this destination is still in flight (no child spawned)",
                        path.display(),
                    );
                };
                let owned_path = path.clone();
                let truncate_delay_ms = SETUP_TEST_HOOK.with(|h| h.borrow().truncate_delay_ms);
                let publish_gate = SETUP_TEST_HOOK.with(|h| h.borrow().publish_gate.clone());
                let rename_hold_ms = SETUP_TEST_HOOK.with(|h| h.borrow().rename_hold_ms);
                let rename_hold_ready =
                    SETUP_TEST_HOOK.with(|h| h.borrow().rename_hold_ready.clone());
                // The finishing worker removes the registry entry on every
                // non-panic exit (before the completion counter advances);
                // the synchronous caller paths below reclaim it
                // idempotently. The post-spawn abandonment paths
                // (Cancelled/Expired) deliberately touch NOTHING here —
                // no lock, lock-free by construction (the still-live
                // worker owns the entry); only the pre-spawn early
                // returns clean inline via on_exit (R06-b — the worker
                // never spawns there, so the caller owns cleanup).
                let reg_key_w = reg_key.clone();
                let prep = run_under_control(
                    deadline,
                    cancel,
                    move |abandoned| {
                        prepare_and_publish_sink(
                            &owned_path,
                            abandoned,
                            truncate_delay_ms,
                            publish_gate,
                            rename_hold_ms,
                            rename_hold_ready,
                        )
                    },
                    Some(Box::new(move || registry_remove_if(&reg_key_w, reg_id))),
                )
                .map_err(|e| {
                    registry_remove_if(&reg_key, reg_id);
                    anyhow::anyhow!("{e:#} (no child spawned)")
                })?;
                let published = match prep {
                    Control::Done(r) => {
                        registry_remove_if(&reg_key, reg_id);
                        r?
                    }
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
                        registry_remove_if(&reg_key, reg_id);
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
        let fork_errno = std::io::Error::last_os_error();
        if pid < 0 {
            // F1: a prepared sink disposes under control here too — never
            // by dropping it inline (a FUSE FLUSH in that drop would hang
            // setup on the caller). No child exists, so the outcome needs
            // no custody. fork_errno was captured BEFORE this disposal:
            // thread creation and timed waits inside can overwrite errno
            // (R06 fork-errno minor).
            if let Some(sink) = owned_sink.take() {
                let _ = close_under_control(sink, deadline, cancel);
            }
            if fail_fork {
                anyhow::bail!("fork: test-injected fork failure");
            }
            anyhow::bail!("fork: {fork_errno}");
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
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn control_expired_deadline_does_not_run() {
        let cancel = AtomicBool::new(false);
        let ran = std::sync::Arc::new(AtomicBool::new(false));
        let ran_c = ran.clone();
        let out = run_under_control(
            Instant::now(),
            &cancel,
            move |_| {
                ran_c.store(true, Ordering::SeqCst);
                42
            },
            None,
        )
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
            None,
        )
        .unwrap();
        assert!(matches!(out, Control::Cancelled));
        assert!(!ran.load(Ordering::SeqCst), "dead op must not run");
    }

    #[test]
    fn control_returns_value() {
        let cancel = AtomicBool::new(false);
        let out = run_under_control(
            Instant::now() + Duration::from_secs(30),
            &cancel,
            |_| 42,
            None,
        )
        .unwrap();
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
            let out = run_under_control(
                Instant::now() + Duration::from_secs(30),
                &cancel,
                |_| std::thread::sleep(Duration::from_secs(30)),
                None,
            )
            .unwrap();
            assert!(matches!(out, Control::Cancelled));
            assert!(t0.elapsed() < Duration::from_secs(5), "fail fast");
        });
    }

    #[test]
    fn control_slow_op_deadline_mid_run() {
        let cancel = AtomicBool::new(false);
        let t0 = Instant::now();
        let out = run_under_control(
            Instant::now() + Duration::from_millis(100),
            &cancel,
            |_| std::thread::sleep(Duration::from_secs(30)),
            None,
        )
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
        let out = run_under_control(
            Instant::now() + Duration::from_secs(30),
            &cancel,
            |_| panic!("r06 control probe panic"),
            None,
        )
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
                None,
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
                None,
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
        // Fix round 4 (kept under round 5 with the lock-free flag), direct
        // pin: the worker-side preparation op publishes a fresh empty
        // inode over the destination when live (carrying the prior
        // permission bits over), and publishes nothing — deleting only
        // its own staging — once the abandonment flag is stored.
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
        let abandoned = AtomicBool::new(false);
        let fd = prepare_and_publish_sink(&live, &abandoned, 0, None, 0, None).unwrap();
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
        abandoned.store(true, Ordering::SeqCst);
        let err = prepare_and_publish_sink(&dead, &abandoned, 0, None, 0, None).unwrap_err();
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

    #[test]
    fn staging_namespace_collision_is_pure_path_inspection() {
        // Fix round 5, direct pin: the first collision-control layer —
        // destinations in the staging namespace are recognized without
        // touching the filesystem (the entrypoint refuses them before
        // creating anything; the behavioral refusal is pinned by the
        // `staging_namespace_dest_refused_before_creating` integration
        // test).
        use super::{STAGING_PREFIX, dest_in_staging_namespace};
        assert!(dest_in_staging_namespace(std::path::Path::new(
            ".osslscope-staging-123-4-abcdef"
        )));
        assert!(dest_in_staging_namespace(std::path::Path::new(
            "/tmp/x/.osslscope-staging-1-2-3"
        )));
        assert!(!dest_in_staging_namespace(std::path::Path::new(
            "/tmp/x/workload.log"
        )));
        assert!(!dest_in_staging_namespace(std::path::Path::new(
            "/tmp/.osslscope-staging-dir/workload.log",
        )));
        assert!(!dest_in_staging_namespace(std::path::Path::new(
            ".osslscope-staging",
        )));
        assert!(STAGING_PREFIX.starts_with('.'), "hidden-file prefix");
    }

    #[test]
    fn setup_key_normalizes_lexically_without_syscalls() {
        // Fix round 5, direct pin: registry keys collapse `.`, `..`, and
        // duplicate separators purely lexically (no `canonicalize` — the
        // caller path forbids blocking file I/O), so equivalent spellings
        // fence each other while distinct paths stay distinct.
        use super::normalize_setup_key;
        let a = normalize_setup_key(std::path::Path::new("/tmp/x/workload.log"));
        assert_eq!(
            a,
            normalize_setup_key(std::path::Path::new("/tmp/x/./workload.log"))
        );
        assert_eq!(
            a,
            normalize_setup_key(std::path::Path::new("/tmp/x/sub/../workload.log"))
        );
        assert_eq!(
            a,
            normalize_setup_key(std::path::Path::new("/tmp//x/workload.log"))
        );
        assert_eq!(
            normalize_setup_key(std::path::Path::new("a")),
            normalize_setup_key(std::path::Path::new("./a"))
        );
        assert_ne!(
            a,
            normalize_setup_key(std::path::Path::new("/tmp/x/other.log"))
        );
        assert_ne!(
            normalize_setup_key(std::path::Path::new("/tmp/x/workload.log")),
            normalize_setup_key(std::path::Path::new("/tmp/y/workload.log"))
        );
        // Leading `..` resolves against the process cwd (R06-a
        // premise change, justified: relative inputs absolutize, so
        // `..` pops the cwd's last component instead of persisting
        // lexically — never collapses onto a sibling).
        let cwd = std::env::current_dir().expect("test cwd");
        let mut parent = cwd;
        assert!(parent.pop(), "test cwd has a parent");
        assert_eq!(
            normalize_setup_key(std::path::Path::new("../a")),
            parent.join("a")
        );
    }

    #[test]
    fn setup_key_root_parent_aliases_key_identically() {
        // Round 2, residual H (R06-a lexical alias): a `..` against the
        // filesystem root resolves to the root itself (pure lexical
        // rule — the kernel does the same), so root-parent spellings
        // must fence with their collapsed forms. Needs no syscalls.
        use super::normalize_setup_key;
        use std::path::{Path, PathBuf};
        for (alias, canon) in [
            ("/../tmp/x", "/tmp/x"),
            ("/..", "/"),
            ("/../..", "/"),
            ("/a/../../b", "/b"),
            ("/a/b/../..", "/"),
            ("/tmp/x/../../y", "/y"),
            ("/tmp/./../tmp/x", "/tmp/x"),
        ] {
            assert_eq!(
                normalize_setup_key(Path::new(alias)),
                PathBuf::from(canon),
                "alias {alias:?} must key as {canon:?}"
            );
        }
        // Distinct roots stay distinct; relative `..` still resolves
        // against the cwd (never collapses onto a sibling).
        assert_ne!(
            normalize_setup_key(Path::new("/../tmp/x")),
            normalize_setup_key(Path::new("/../tmp/y"))
        );
    }

    #[test]
    fn setup_key_unifies_relative_and_absolute_spellings() {
        // R06-a: one destination spelled relative and absolute
        // must fence together (aliases must not bypass the
        // per-destination registry).
        use super::normalize_setup_key;
        let cwd = std::env::current_dir().expect("test cwd");
        assert_eq!(
            normalize_setup_key(std::path::Path::new("r06-alias-pin.log")),
            normalize_setup_key(&cwd.join("r06-alias-pin.log")),
            "relative and absolute spellings must key together"
        );
    }

    #[test]
    fn control_early_cancel_and_expiry_run_on_exit() {
        // R06-b: registration precedes run_under_control, so the
        // early Cancelled/Expired returns (worker never spawned)
        // must run the cleanup callback — otherwise the registry
        // entry orphans and the destination refuses forever.
        use super::{Control, run_under_control};
        for (deadline, cancel, tag) in [
            (Instant::now(), false, "expired"),
            (Instant::now() + Duration::from_secs(30), true, "cancelled"),
        ] {
            let flag = AtomicBool::new(cancel);
            let ran = std::sync::Arc::new(AtomicBool::new(false));
            let cleaned = std::sync::Arc::new(AtomicBool::new(false));
            let ran_c = ran.clone();
            let cleaned_c = cleaned.clone();
            let out = run_under_control(
                deadline,
                &flag,
                move |_| {
                    ran_c.store(true, Ordering::SeqCst);
                    42
                },
                Some(Box::new(move || cleaned_c.store(true, Ordering::SeqCst))),
            )
            .unwrap();
            assert!(
                matches!(out, Control::Expired | Control::Cancelled),
                "{tag}: early return expected"
            );
            assert!(!ran.load(Ordering::SeqCst), "{tag}: dead op must not run");
            assert!(
                cleaned.load(Ordering::SeqCst),
                "{tag}: on_exit must run on the early return"
            );
        }
    }

    #[test]
    fn registry_fences_distinct_ids_and_releases() {
        // Fix round 5, direct pin: the per-destination registry refuses a
        // second insert while the first is live, ignores removals from
        // non-owners, and releases for a successor once the owner removes.
        // (Uses a unique key: the registry is process-wide and lib tests
        // run in parallel.)
        use super::{normalize_setup_key, registry_remove_if, registry_try_insert};
        let key = normalize_setup_key(std::path::Path::new(
            "/tmp/osslscope-reg-pin/pin-registry-fences.log",
        ));
        let id = registry_try_insert(&key).expect("first insert wins");
        assert!(
            registry_try_insert(&key).is_none(),
            "second insert refuses while live"
        );
        registry_remove_if(&key, id.wrapping_add(1));
        assert!(
            registry_try_insert(&key).is_none(),
            "non-owner removal changes nothing"
        );
        registry_remove_if(&key, id);
        let id2 = registry_try_insert(&key).expect("successor runs after release");
        assert_ne!(id, id2, "ids are unique per attempt");
        registry_remove_if(&key, id2);
        let id3 = registry_try_insert(&key).expect("registry is empty afterwards");
        registry_remove_if(&key, id3);
    }
}
