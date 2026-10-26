// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordinary owned-child controls for the count-only preview. No BPF or root.

use osslscope::target::{CustodyState, OwnedTarget, TargetDisposition, WorkloadDest};
use std::time::{Duration, Instant};

struct ChildCleanup(u32);
impl Drop for ChildCleanup {
    fn drop(&mut self) {
        // This test owns this child; cleanup is required even after an assertion.
        unsafe { libc::kill(self.0 as libc::pid_t, libc::SIGKILL) };
        let mut status = 0;
        while unsafe { libc::waitpid(self.0 as libc::pid_t, &mut status, 0) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
    }
}

#[test]
fn owned_exit_peek_is_non_consuming() {
    let mut target = OwnedTarget::spawn_stopped(
        &["/bin/sh".into(), "-c".into(), "exit 7".into()],
        WorkloadDest::Null,
    )
    .unwrap();
    let cleanup = ChildCleanup(target.pid());
    assert_eq!(target.peek_exit().unwrap(), None);
    target.release().unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    let code = loop {
        if let Some(code) = target.peek_exit().unwrap() {
            break code;
        }
        assert!(Instant::now() < end, "child exit was not observed");
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(code, 7);
    assert_eq!(target.peek_exit().unwrap(), Some(7));
    assert_eq!(target.state(), CustodyState::Released);
    assert_eq!(target.exit_code(), None);
    assert!(std::fs::metadata(format!("/proc/{}", target.pid())).is_ok());
    assert_eq!(
        target.finish_observation().unwrap(),
        TargetDisposition::Exited { code: 7 }
    );
    assert_eq!(target.peek_exit().unwrap(), Some(7));
    std::mem::forget(cleanup); // Consuming wait proved this test no longer owns a PID.
}

#[test]
fn setup_failure_resolves_stopped_child() {
    let mut target = OwnedTarget::spawn_stopped(&["/bin/true".into()], WorkloadDest::Null).unwrap();
    let pid = target.pid();
    target.resolve_setup_failure().unwrap();
    assert_eq!(target.state(), CustodyState::Reaped);
    assert!(std::fs::metadata(format!("/proc/{pid}")).is_err());
}

#[test]
fn released_child_survives_observation_end() {
    let mut target =
        OwnedTarget::spawn_stopped(&["/bin/sleep".into(), "30".into()], WorkloadDest::Null)
            .unwrap();
    let pid = target.pid();
    let _cleanup = ChildCleanup(pid);
    target.release().unwrap();
    assert_eq!(
        target.finish_observation().unwrap(),
        TargetDisposition::Detached { pid }
    );
    drop(target);
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
}
