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

impl OwnedTarget {
    /// Fork a child held stopped pre-exec. CStrings are built before
    /// the fork so the child allocates nothing (async-signal-safe).
    /// Exec failure in the child exits 127. The parent observes the
    /// stop before returning; a child that exits before stopping is
    /// already reaped, and its status rides in the error.
    pub fn spawn_stopped(argv: &[String]) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        if argv.is_empty() {
            anyhow::bail!("run -- needs a command");
        }
        let cs: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<Result<_, _>>()
            .context("NUL in argv")?;
        let mut ptrs: Vec<*const libc::c_char> = cs.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
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
                libc::raise(libc::SIGSTOP);
                libc::execvp(ptrs[0], ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        let pid = pid as u32;
        loop {
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED) };
            if r < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                anyhow::bail!("waitpid: {}", std::io::Error::last_os_error());
            }
            if libc::WIFSTOPPED(status) {
                return Ok(OwnedTarget {
                    pid,
                    state: CustodyState::Stopped,
                    exit_code: None,
                });
            }
            // Reaped by this waitpid: nothing leaks; report the status.
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                status
            };
            anyhow::bail!("child exited before stop (status {code})");
        }
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
