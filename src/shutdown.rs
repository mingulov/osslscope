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
}
