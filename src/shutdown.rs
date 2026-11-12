// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared first/second-signal shutdown token (P0-8).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(1);

static CANCELLED: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicU8 = AtomicU8::new(0);
static SIGNO: AtomicU8 = AtomicU8::new(0);

extern "C" fn on_signal(signo: libc::c_int) {
    if COUNT.fetch_add(1, Ordering::SeqCst) >= 1 {
        unsafe { libc::_exit(128 + signo) };
    }
    SIGNO.store(signo as u8, Ordering::SeqCst);
    CANCELLED.store(true, Ordering::SeqCst);
}

pub struct Shutdown {
    acked: AtomicBool,
    first_signal_at: std::sync::Mutex<Option<Instant>>,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Shutdown {
    pub fn install() -> io::Result<Self> {
        CANCELLED.store(false, Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
        let mut previous = Vec::new();
        for signo in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = on_signal as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signo, &action, &mut old) } != 0 {
                return Err(io::Error::last_os_error());
            }
            previous.push((signo, old));
        }
        Ok(Self {
            acked: AtomicBool::new(false),
            first_signal_at: std::sync::Mutex::new(None),
            previous,
        })
    }

    pub fn cancel_flag(&self) -> &'static AtomicBool {
        &CANCELLED
    }

    /// Process-wide cancel state without an instance (v0.6.0 signals
    /// Task 4): the live capture loops take `&dyn Fn() -> bool`, not
    /// `&Shutdown`, so `capture::interrupted()` delegates here. A
    /// single atomic load like the flag it replaces; it never stamps
    /// `first_signal_at` (deadline accounting stays instance-side).
    pub fn cancelled_global() -> bool {
        CANCELLED.load(Ordering::SeqCst)
    }

    pub fn cancelled(&self) -> bool {
        if CANCELLED.load(Ordering::SeqCst) {
            let mut slot = self.first_signal_at.lock().unwrap();
            if slot.is_none() {
                *slot = Some(Instant::now());
            }
            true
        } else {
            false
        }
    }

    pub fn ack(&self) -> Option<String> {
        if !self.cancelled() || self.acked.swap(true, Ordering::SeqCst) {
            return None;
        }
        let name = match SIGNO.load(Ordering::SeqCst) as libc::c_int {
            libc::SIGINT => "SIGINT",
            libc::SIGTERM => "SIGTERM",
            _ => "signal",
        };
        Some(format!("osslscope: received {name}, shutting down…\n"))
    }

    pub fn expired(&self) -> bool {
        self.cancelled()
            && self
                .first_signal_at
                .lock()
                .unwrap()
                .is_some_and(|t| t.elapsed() >= SHUTDOWN_DEADLINE)
    }

    /// Cancel check with first-observation ack (v0.6.0 signals Task
    /// 3): returns `cancelled()`, writing `ack()` to stderr exactly
    /// once — on the first call that observes cancel. Every
    /// watch/observation loop calls this at each sample, poll-window,
    /// and teardown boundary instead of `cancelled()`.
    pub fn cancelled_and_acked(&self) -> bool {
        if !self.cancelled() {
            return false;
        }
        if let Some(ack) = self.ack() {
            write_ack(&ack);
        }
        true
    }
}

/// Ack-on-scope-exit backstop (v0.6.0 signals codex F1): the
/// capture paths exit through many setup/acquisition/teardown
/// error returns that never poll a loop boundary, so each arms
/// this guard right after `install()` — dropping it acks the
/// first observed signal exactly once, on every exit path, ok or
/// err. A no-op when the loops already acked or no signal
/// arrived. Must drop before its `Shutdown` (declare it after).
pub(crate) struct AckOnExit<'a> {
    shutdown: &'a Shutdown,
}

impl<'a> AckOnExit<'a> {
    pub(crate) fn arm(shutdown: &'a Shutdown) -> Self {
        Self { shutdown }
    }
}

impl Drop for AckOnExit<'_> {
    fn drop(&mut self) {
        self.shutdown.cancelled_and_acked();
    }
}

/// Prompt first-signal ack to locked stderr, panic-free like
/// [`crate::report::err_line`] (a broken stderr degrades to silence,
/// never to exit 101) but byte-exact: the ack already ends in
/// newline, so no extra line is added. Verbosity-independent.
pub(crate) fn write_ack(ack: &str) {
    use std::io::Write as _;
    let stderr = io::stderr();
    let mut locked = stderr.lock();
    let _ = locked.write_all(ack.as_bytes());
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        for (signo, old) in self.previous.iter().rev() {
            unsafe { libc::sigaction(*signo, old, std::ptr::null_mut()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn v060_first_signal_cancels_and_acks_once() {
        let shutdown = Shutdown::install().unwrap();
        assert!(!shutdown.cancelled());
        unsafe { libc::raise(libc::SIGINT) };
        assert!(shutdown.cancelled());
        let first = shutdown.ack();
        assert!(first.unwrap().contains("shutting down"));
        assert!(shutdown.ack().is_none());
    }

    #[test]
    fn v060_deadline_expires_after_one_second() {
        let shutdown = Shutdown::install().unwrap();
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(!shutdown.expired());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(shutdown.expired());
    }

    #[test]
    fn v060_first_signal_ack_names_sigint_and_sigterm() {
        // Codex F1 wording pin: each signal's ack names that signal.
        let shutdown = Shutdown::install().unwrap();
        unsafe { libc::raise(libc::SIGINT) };
        assert!(
            shutdown.ack().unwrap().contains("SIGINT"),
            "SIGINT ack must name SIGINT"
        );
        let shutdown = Shutdown::install().unwrap();
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(
            shutdown.ack().unwrap().contains("SIGTERM"),
            "SIGTERM ack must name SIGTERM"
        );
    }

    #[test]
    fn v060_ack_on_exit_consumes_first_signal_ack_once() {
        // Codex F1: the capture backstop guard acks through drop —
        // the one ack is consumed exactly once, a second guard (or
        // a later ack()) stays silent.
        let shutdown = Shutdown::install().unwrap();
        unsafe { libc::raise(libc::SIGINT) };
        {
            let _guard = AckOnExit::arm(&shutdown);
        }
        assert!(shutdown.ack().is_none(), "guard must consume the one ack");
        {
            let _guard = AckOnExit::arm(&shutdown);
        }
        assert!(shutdown.ack().is_none(), "second guard must stay silent");
    }

    #[test]
    fn v060_ack_on_exit_silent_without_signal() {
        // Codex F1: no signal, no ack — the guard is a pure backstop.
        let shutdown = Shutdown::install().unwrap();
        {
            let _guard = AckOnExit::arm(&shutdown);
        }
        assert!(shutdown.ack().is_none());
        assert!(!shutdown.cancelled());
    }
}
