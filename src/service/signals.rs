//! SPDX-License-Identifier: GPL-3.0-or-later
//! Synchronous signal handling (§§3/7): signals are blocked
//! process-wide and consumed on the coordinator's normal path via
//! signalfd — never async-handler I/O. SIGHUP sets the reload flag
//! the coordinator consumes at the next boundary (admission and
//! window-open are one critical section); SIGTERM/SIGINT stop after
//! the current window; a second SIGTERM/SIGINT stops immediately.
//!
//! Relationship to the CLI shutdown token (v0.6.0 signals): the
//! service keeps this signalfd design while the CLI watch and
//! observation routes (`scan --watch`, `--observe-providers`,
//! `--observe-crypto`) share `crate::shutdown::Shutdown` — an
//! async-handler token with a stderr ack and a 1s teardown bound.
//! One-shot `scan`/`inspect` routes stay deliberately
//! uninstrumented (no `Shutdown`: SIGINT/SIGTERM kill with
//! 128+signo as before), since graceful cancel there is unrequested
//! behavior and would change exit codes.

use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

/// Consumed signals (coordinator clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Hup,
}

/// Owned signalfd + blocked mask. Closing restores nothing (the
/// process exits; masks die with it).
pub struct SignalFd {
    fd: RawFd,
}

impl SignalFd {
    /// Block SIGTERM/SIGINT/SIGHUP process-wide (workers spawned
    /// later inherit the mask) and open a CLOEXEC signalfd.
    pub fn install() -> std::io::Result<Self> {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGHUP);
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { fd })
        }
    }

    /// Drain pending signals (non-blocking). Standard signals
    /// coalesce in the kernel pending set BEFORE any userspace
    /// mechanism can observe them (verified: two rapid SIGTERMs
    /// read back as ONE entry — no handler/counter/signalfd design
    /// can distinguish them): a same-signo rapid pair is observed
    /// once and handled as a single stop. Two `Term`s from one
    /// drain happen for mixed-signo pairs (SIGTERM + SIGINT do not
    /// merge) or pairs separated by a consume.
    pub fn drain(&self) -> Vec<Signal> {
        let mut out = Vec::new();
        loop {
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::read(
                    self.fd,
                    &mut info as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                )
            };
            if rc != std::mem::size_of::<libc::signalfd_siginfo>() as isize {
                break;
            }
            match info.ssi_signo as libc::c_int {
                libc::SIGTERM | libc::SIGINT => out.push(Signal::Term),
                libc::SIGHUP => out.push(Signal::Hup),
                _ => {}
            }
        }
        out
    }

    /// Wait up to `timeout` for a signal (poll + drain). Returns the
    /// drained batch (possibly empty on timeout).
    pub fn wait(&self, timeout: Duration) -> Vec<Signal> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // The poll IS the wait (a readiness sleep); the drain after
        // is non-blocking either way (empty when nothing arrived).
        let _ = unsafe { libc::poll(&mut pfd, 1, ms) };
        let _ = pfd.revents;
        self.drain()
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Unblock the service signals again (test hygiene: the lib-test
/// process outlives any one test).
#[cfg(test)]
pub fn restore_test_mask() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hup_and_term_are_consumed_synchronously() {
        // NOTE: installs the process-wide mask (serial suite).
        let sig = SignalFd::install().unwrap();
        unsafe { libc::raise(libc::SIGHUP) };
        unsafe { libc::raise(libc::SIGTERM) };
        let batch = sig.wait(Duration::from_secs(2));
        assert!(batch.contains(&Signal::Hup), "hup consumed: {batch:?}");
        assert!(batch.contains(&Signal::Term), "term consumed: {batch:?}");
        // Drained: nothing left.
        assert!(sig.drain().is_empty());
        restore_test_mask();
    }
}
