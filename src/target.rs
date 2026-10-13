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
use std::ffi::CString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
/// opened, truncated and pinned to a regular file by the PARENT
/// pre-fork; the child inherits the open fd and never opens a path
/// itself, so a FIFO/device/symlink selection — or a path replaced
/// after validation — can neither block nor redirect setup. Anything
/// that must stream (pipes, sockets, FIFOs, devices) uses
/// [`WorkloadDest::Fd`]: the caller opens and owns the fd with
/// whatever blocking behavior it chose, and the child only dup2s it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadDest {
    /// Both streams to /dev/null (default).
    Null,
    /// Both streams to this file (created + truncated per run,
    /// parent-side, pre-fork). Accepted ONLY as a pinned regular
    /// file: missing parents, symlinks, FIFOs, directories, sockets
    /// and devices fail setup pre-fork, naming the path with the 126
    /// setup marker. The open fd — not the path — is handed to the
    /// child, so post-open path replacement is harmless.
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

/// Open + pin a [`WorkloadDest::File`] sink parent-side, pre-fork
/// (R06/F07). `O_NONBLOCK` keeps a FIFO-with-no-reader from hanging
/// the open (it fails `ENXIO` instead); `O_NOFOLLOW` refuses a final
/// symlink instead of truncating through it; the `fstat` accepts
/// ONLY a regular file; `O_NONBLOCK` is then cleared so the workload
/// inherits ordinary blocking stdio. The open fd — never the path —
/// is handed to the child, so post-open path replacement is
/// harmless. Every failure names the path with the 126 setup marker
/// and spawns nothing.
fn open_pinned_sink(path: &Path) -> anyhow::Result<OwnedFd> {
    use anyhow::Context as _;
    let c = CString::new(path.as_os_str().as_bytes()).context("NUL in --workload-out path")?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_TRUNC
                | libc::O_NONBLOCK
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
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
    // Clear O_NONBLOCK: it only guarded the open itself; the
    // workload must inherit ordinary blocking stdio.
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
    Ok(owned)
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

impl PrestopGuard {
    /// Failure path: SIGKILL (harmless if already dead) then a
    /// blocking reap; the exit code rides along when known.
    fn kill_and_reap(&mut self) -> Option<i32> {
        self.armed = false;
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
        reap_blocking(self.pid).ok()
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
    /// (a dead setup forks nothing and truncates nothing), then
    /// destination preparation — file sinks are opened + pinned to
    /// a regular file by the PARENT pre-fork (see
    /// [`WorkloadDest::File`]) — then fork. Custody starts at the
    /// fork return, BEFORE waiting for SIGSTOP; the wait polls with
    /// the checked deadline and the cancel flag, and every failure
    /// kills + reaps only this never-released owned child. A child
    /// that exits before stopping is already reaped, and its status
    /// rides in the error (126 keeps the H9 stdio-setup mapping).
    /// The child allocates nothing post-fork (async-signal-safe):
    /// it dup2s inherited fds only and opens no paths.
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
        // Destination validated + prepared pre-fork (the child
        // allocates nothing). A file sink is opened + pinned HERE
        // (never by the child); an invalid fd fails HERE — no spawn.
        let mut owned_sink: Option<OwnedFd> = None;
        let child_dest = match &dest {
            WorkloadDest::Null => ChildDest::Null,
            WorkloadDest::File(path) => {
                let sink = open_pinned_sink(path)?;
                let raw = sink.as_raw_fd();
                owned_sink = Some(sink);
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
        let pid = unsafe { libc::fork() };
        if pid < 0 {
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
                libc::raise(libc::SIGSTOP);
                libc::execvp(ptrs[0], ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        // Parent only from here (the child never falls through):
        // the parent's copy of a pinned sink closes NOW (the child
        // inherited its own), and custody starts BEFORE the wait.
        drop(owned_sink);
        let pid = pid as u32;
        let mut guard = PrestopGuard { pid, armed: true };
        loop {
            if cancel.load(Ordering::SeqCst) {
                guard.kill_and_reap();
                anyhow::bail!("pre-stop setup cancelled; owned child {pid} killed and reaped");
            }
            if Instant::now() >= deadline {
                guard.kill_and_reap();
                anyhow::bail!(
                    "pre-stop setup deadline exceeded; owned child {pid} killed and reaped"
                );
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
                guard.kill_and_reap();
                anyhow::bail!("waitpid {pid}: {e}");
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
