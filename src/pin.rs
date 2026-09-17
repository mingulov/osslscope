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
use anyhow::Context as _;
use std::os::fd::{FromRawFd, OwnedFd};

/// Pinned target identity: the pidfd keeps the ORIGINAL task
/// referenced (operations fail once it exits); the starttime catches
/// `/proc/<pid>` resolving to a DIFFERENT task after recycle.
pub struct TargetPin {
    pid: u32,
    starttime: u64,
    _pidfd: OwnedFd,
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
    let starttime = starttime_of(pid).with_context(|| format!("target {pid} gone"))?;
    // SAFETY: raw pidfd_open(2) returns an owned fd on success,
    // -1 with errno on error (libc has no pidfd_open wrapper).
    let pidfd = unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) as libc::c_int;
        if fd < 0 {
            anyhow::bail!(
                "target {pid} gone (pidfd_open: {})",
                std::io::Error::last_os_error()
            );
        }
        OwnedFd::from_raw_fd(fd)
    };
    // Re-read under the pin: the task seen by stat may have exited
    // between the stat and pidfd_open (pidfd then refers to nothing
    // usable — fail rather than pin a ghost).
    let again = starttime_of(pid)?;
    if again != starttime {
        anyhow::bail!("target {pid} recycled during pin");
    }
    Ok(TargetPin {
        pid,
        starttime,
        _pidfd: pidfd,
    })
}

impl TargetPin {
    /// Re-verify identity. `Ok` = same task; `Err(PinError)` =
    /// recycled (caller discards all evidence).
    pub fn verify(&self) -> Result<(), PinError> {
        match starttime_of(self.pid) {
            Ok(t) if t == self.starttime => Ok(()),
            _ => Err(PinError { pid: self.pid }),
        }
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
