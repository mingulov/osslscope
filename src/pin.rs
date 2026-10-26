//! SPDX-License-Identifier: GPL-3.0-or-later
//! `--pid` target pinning (P1 exit-6): pidfd + starttime identity.
//!
//! Evidence paths (`inspect`/harvest) must not attribute one
//! process's dispatch rows to another after pid recycle. The pin is
//! taken at run start and re-verified before attach points and
//! before emission; a mismatch discards everything (rows AND
//! tripwires — both are pid-scoped observations) and surfaces as
//! `PARTIAL(pid-recycled)` + exit 4, never misattributed rows.
//! `doctor` deliberately does NOT pin (diagnostic, not evidence);
//! `run --` (P2) is immune (own child, no pid lookup).
use crate::capture_setup::{SetupControl, SetupFailure, SetupLinks, SetupOrigin};
use anyhow::Context as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

// Only the already successful owned-child acquisition enters this graph.
// No Clone/raw-fd constructor is exposed by either ownership wrapper.
pub(crate) struct OriginalGroupAcquisition {
    file: Arc<OriginalGroupFile>,
    origin: Option<SetupOrigin>,
}
struct OriginalGroupFile {
    pid: u32,
    fd: Option<OwnedFd>,
    #[cfg(test)]
    close_probe: Option<std::sync::Weak<OriginalCloseProbe>>,
}
impl Drop for OriginalGroupFile {
    fn drop(&mut self) {
        #[cfg(test)]
        let probe = self.close_probe.as_ref().and_then(std::sync::Weak::upgrade);
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe
                .entered
                .store(true, std::sync::atomic::Ordering::Release);
            while probe.held.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        // Last physical owner, outside native/barrier locks. Record only after Drop returns.
        drop(self.fd.take());
        #[cfg(test)]
        if let Some(probe) = probe {
            probe
                .closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}
#[cfg(test)]
pub(crate) struct OriginalCloseProbe {
    held: std::sync::atomic::AtomicBool,
    pub(crate) entered: std::sync::atomic::AtomicBool,
    pub(crate) closed: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl OriginalCloseProbe {
    pub(crate) fn release(&self) {
        self.held.store(false, std::sync::atomic::Ordering::Release);
    }
}
pub(crate) struct OriginalGroupHandoff {
    file: Arc<OriginalGroupFile>,
    origin: SetupOrigin,
}
impl OriginalGroupAcquisition {
    pub(crate) fn acquired_child(acquired: crate::target::AcquiredChildPidfd) -> Self {
        let (pid, fd) = acquired.into_parts();
        Self {
            file: Arc::new(OriginalGroupFile {
                pid,
                fd: Some(fd),
                #[cfg(test)]
                close_probe: None,
            }),
            origin: None,
        }
    }
    pub(crate) fn handoff(&mut self, origin: SetupOrigin) -> anyhow::Result<OriginalGroupHandoff> {
        if self.origin.is_some() {
            anyhow::bail!("original group handoff already issued");
        }
        self.origin = Some(origin.clone());
        Ok(OriginalGroupHandoff {
            file: self.file.clone(),
            origin,
        })
    }
    #[cfg(test)]
    pub(crate) fn hold_close(&mut self) -> Arc<OriginalCloseProbe> {
        let probe = Arc::new(OriginalCloseProbe {
            held: std::sync::atomic::AtomicBool::new(true),
            entered: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        Arc::get_mut(&mut self.file)
            .expect("install before handoff")
            .close_probe = Some(Arc::downgrade(&probe));
        probe
    }
    #[cfg(test)]
    pub(crate) fn test_identity(&self) -> (usize, i32) {
        (Arc::as_ptr(&self.file) as usize, self.as_raw_fd())
    }
}
impl AsRawFd for OriginalGroupAcquisition {
    fn as_raw_fd(&self) -> i32 {
        self.file
            .fd
            .as_ref()
            .expect("live acquired file")
            .as_raw_fd()
    }
}
impl OriginalGroupHandoff {
    pub(crate) fn pid(&self) -> u32 {
        self.file.pid
    }
    pub(crate) fn validate(
        &self,
        links: &SetupLinks,
        control: &SetupControl,
    ) -> Result<(), SetupFailure> {
        links.validate_origin(&self.origin, control)
    }
}
#[cfg(test)]
std::thread_local! {
    static PIN_OPEN_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn test_pin_open_attempts() -> usize {
    PIN_OPEN_ATTEMPTS.get()
}

/// Pinned target identity: the pidfd keeps the ORIGINAL task
/// referenced (operations fail once it exits); the starttime catches
/// `/proc/<pid>` resolving to a DIFFERENT task after recycle.
pub struct TargetPin {
    pid: u32,
    starttime: u64,
    _pidfd: TargetPinFd,
}
enum TargetPinFd {
    External { _fd: OwnedFd },
    Original { _file: Arc<OriginalGroupFile> },
}

/// Pid recycle detected mid-run: the evidence is tainted and must be
/// discarded (callers emit PARTIAL + exit 4, never rows).
#[derive(Debug)]
pub struct PinError {
    pub pid: u32,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "target {} recycled mid-run (starttime changed — evidence discarded)",
            self.pid
        )
    }
}

impl std::error::Error for PinError {}

/// Parse field 22 (starttime) out of a `/proc/<pid>/stat` line:
/// comm may contain spaces and ')' — fields start after the LAST ')'.
fn parse_starttime(stat: &str, pid: u32) -> anyhow::Result<u64> {
    let after = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| anyhow::anyhow!("malformed /proc/{pid}/stat"))?;
    let starttime = after
        .split_whitespace()
        .nth(19) // field 22 overall (post-comm token k = field k+3)
        .ok_or_else(|| anyhow::anyhow!("short /proc/{pid}/stat"))?;
    starttime
        .parse()
        .map_err(|_| anyhow::anyhow!("bad starttime in /proc/{pid}/stat"))
}

/// Process starttime (clock ticks since boot): unique per boot per
/// task, unlike the pid.
pub fn starttime_of(pid: u32) -> anyhow::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_starttime(&stat, pid)
}

/// Pin a live target. Fails (plain error — caller exits 1, same as
/// today's dead-target reads) when the pid is already gone; needs no
/// privileges (pidfd_open is caps-free for live tasks).
pub fn pin(pid: u32) -> anyhow::Result<TargetPin> {
    pin_with(pid, None, starttime_of)
}

pub(crate) fn pin_controlled(
    pid: u32,
    links: &crate::capture_setup::SetupLinks,
) -> anyhow::Result<TargetPin> {
    pin_with(pid, Some(links), starttime_of)
}
fn pin_with(
    pid: u32,
    links: Option<&crate::capture_setup::SetupLinks>,
    mut read_starttime: impl FnMut(u32) -> anyhow::Result<u64>,
) -> anyhow::Result<TargetPin> {
    crate::lifecycle_producer::note_acquisition()?;
    let stage = crate::capture::BoundaryStage::Discovery;
    let starttime = read_starttime(pid).with_context(|| format!("target {pid} gone"))?;
    // SAFETY: successful pidfd_open returns a new owned descriptor.
    #[cfg(test)]
    PIN_OPEN_ATTEMPTS.set(PIN_OPEN_ATTEMPTS.get() + 1);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) as libc::c_int };
    if fd < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())
            .context(format!("target {pid} gone (pidfd_open)")));
    }
    let value = TargetPin {
        pid,
        starttime,
        _pidfd: TargetPinFd::External {
            _fd: unsafe { OwnedFd::from_raw_fd(fd) },
        },
    };
    #[cfg(test)]
    if let Some(links) = links {
        links.test_retained_fd(fd);
    }
    // Own the actual descriptor before the second fallible identity observation.
    let pin = match links {
        Some(links) => crate::capture_setup::SetupResource::guarded(value, links, stage),
        None => crate::capture_setup::SetupResource::local(value),
    };
    let result = (|| {
        let again = read_starttime(pid)?;
        if again != starttime {
            anyhow::bail!("target {pid} recycled during pin");
        }
        Ok(())
    })();
    if let Some(links) = links {
        links.retain_result(result, stage)?;
        links.check_owned(stage)?;
    } else {
        result?;
    }
    Ok(pin.into_inner())
}
#[cfg(test)]
pub(crate) fn pin_controlled_fault(
    pid: u32,
    links: &crate::capture_setup::SetupLinks,
) -> anyhow::Result<TargetPin> {
    let mut calls = 0;
    pin_with(pid, Some(links), |pid| {
        calls += 1;
        if calls == 2 {
            Err(std::io::Error::from_raw_os_error(libc::EIO).into())
        } else {
            starttime_of(pid)
        }
    })
}

impl TargetPin {
    pub(crate) fn from_original_controlled(
        handoff: OriginalGroupHandoff,
        control: &SetupControl,
        links: &SetupLinks,
    ) -> anyhow::Result<Self> {
        handoff.validate(links, control)?;
        let stage = crate::capture::BoundaryStage::Discovery;
        let pid = handoff.pid();
        let starttime = links.retain_result(
            starttime_of(pid).with_context(|| format!("target {pid} gone")),
            stage,
        )?;
        let pin = crate::capture_setup::SetupResource::guarded(
            Self {
                pid,
                starttime,
                _pidfd: TargetPinFd::Original {
                    _file: handoff.file,
                },
            },
            links,
            stage,
        );
        links.retain_result(
            (|| {
                if starttime_of(pid)? != starttime {
                    anyhow::bail!("target {pid} recycled during pin");
                }
                Ok(())
            })(),
            stage,
        )?;
        links.check_owned(stage)?;
        Ok(pin.into_inner())
    }
    #[cfg(test)]
    pub(crate) fn test_identity(&self) -> (usize, i32) {
        match &self._pidfd {
            TargetPinFd::External { _fd } => (0, _fd.as_raw_fd()),
            TargetPinFd::Original { _file } => (
                Arc::as_ptr(_file) as usize,
                _file.fd.as_ref().expect("live acquired file").as_raw_fd(),
            ),
        }
    }

    /// Re-verify identity. `Ok` = same task; `Err(PinError)` =
    /// recycled (caller discards all evidence).
    pub fn verify(&self) -> Result<(), PinError> {
        match starttime_of(self.pid) {
            Ok(t) if t == self.starttime => Ok(()),
            _ => Err(PinError { pid: self.pid }),
        }
    }

    // T04 (coordinator review): pid accessor for the external-target wrapper below.
    /// Pinned pid (identity only — never a signal target).
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

// T04 (coordinator review): `--pid` targets are external processes the
// observer must never signal or wait on (R05). This wrapper owns a pin
// and deliberately exposes no kill/wait operation, so `--pid` custody
// cannot be confused with `OwnedTarget` custody at the type level.
/// An external (`--pid`) target: pinned for identity, never signaled.
pub struct ExternalTarget {
    pin: TargetPin,
}

impl ExternalTarget {
    /// Adopt a live external pid (pin it; send nothing).
    pub fn adopt(pid: u32) -> anyhow::Result<Self> {
        Ok(ExternalTarget { pin: pin(pid)? })
    }

    /// Adopted pid (identity only — never a signal target).
    pub fn pid(&self) -> u32 {
        self.pin.pid()
    }

    /// Re-verify identity (pidfd + starttime; sends nothing).
    pub fn verify(&self) -> Result<(), PinError> {
        self.pin.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_self_verifies() {
        let me = std::process::id();
        let p = pin(me).unwrap();
        assert!(p.verify().is_ok(), "self re-read: {:?}", starttime_of(me));
        assert!(starttime_of(me).unwrap() > 0);
    }

    // T04 (coordinator review): the wrapper pins without signaling.
    #[test]
    fn external_target_adopts_without_signaling() {
        let me = std::process::id();
        let ext = ExternalTarget::adopt(me).unwrap();
        assert_eq!(ext.pid(), me);
        assert!(ext.verify().is_ok());
        assert!(starttime_of(me).is_ok(), "self still alive, untouched");
    }

    #[test]
    fn dead_pid_fails_to_pin() {
        // Implausibly large pid: stat fails → plain error, not PinError.
        let r = pin(u32::MAX - 7);
        assert!(r.is_err());
    }

    #[test]
    fn stat_parse_tolerates_tricky_comm() {
        // Field 22 must be found after the LAST ')' (post-comm
        // token 19; token 20 is vsize — the off-by-one this guards).
        let stat = "123 (a)b (c) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 20";
        assert_eq!(parse_starttime(stat, 123).unwrap(), 777);
        assert!(parse_starttime("123 broken", 123).is_err());
        assert!(parse_starttime("123 (x) R", 123).is_err());
    }
}
