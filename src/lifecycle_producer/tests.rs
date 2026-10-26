// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[test]
fn lifecycle_producer_codec_rejects_reserved_and_short() {
    let f = Frame {
        kind: SPAWN,
        session: 1,
        request: 2,
        deadline: 3,
        floor: 1,
        arg0: 0,
        arg1: 1,
    };
    let b = f.encode();
    assert_eq!(Frame::decode(&b), Some(f));
    assert!(Frame::decode(&b[..63]).is_none());
    let mut forged = b;
    forged[12] = 1;
    assert!(Frame::decode(&forged).is_none());
}

pub(crate) fn host_main() {
    if let Some(case) = std::env::args().nth(1).filter(|a| a.starts_with("host-")) {
        host_case(&case);
        return;
    }
    host_signal_and_parent_death();
    for case in [
        "host-reuse",
        "host-consumer",
        "host-closed-stdin",
        "host-closed-stdout",
        "host-workload-stdout",
        "host-invalid-workload",
        "host-normalize-failure",
        "host-protected-original",
        "host-filter",
        "host-history",
        "host-deadline",
        "host-target-close",
        "host-invalid-help",
        "host-starting-gates",
        "host-foreign-child",
        "host-eof",
        "host-echild",
        "host-mask",
        "host-drop-publication",
        "host-supervisor-unwind",
        "host-proc-fd-extra",
        "host-proc-fd-original",
        "host-audit-target-race",
        "host-stop-before-close",
        "host-child-unreported",
        "host-restore-failure",
        "host-helper-control-eof",
        "host-supervisor-control-eof-passive",
        "host-supervisor-buffered-reaped-hup",
        "host-supervisor-buffered-done-hup",
        "host-supervisor-buffered-child-reaped-hup",
        "host-supervisor-empty-receive-reaped-hup",
        "host-failed-ready-target",
        "host-failed-construction-target",
        "host-domain-rechecks",
        "host-seal-before-observed",
        "host-seal-queued-observed",
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(case)
            .spawn()
            .unwrap();
        let case_start = Instant::now();
        eprintln!("HOST case={case} pid={} pgid={}", child.id(), unsafe {
            libc::getpgid(child.id() as i32)
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                eprintln!(
                    "HOST case={case} pid={} status={status} milliseconds={}",
                    child.id(),
                    case_start.elapsed().as_millis()
                );
                assert!(status.success(), "{case}: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("{case} exceeded failsafe: {status}")
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn host_case(case: &str) {
    let t0 = Instant::now();
    match case {
        "host-supervisor-control-eof-passive" => return host_supervisor_eof_passive(),
        "host-supervisor-buffered-reaped-hup"
        | "host-supervisor-buffered-done-hup"
        | "host-supervisor-buffered-child-reaped-hup"
        | "host-supervisor-empty-receive-reaped-hup" => {
            return host_supervisor_buffered_hup(case);
        }
        "host-audit-target-race" => return host_audit_target_race(),
        "host-stop-before-close" => return host_stop_before_close(),
        "host-child-unreported" | "host-restore-failure" | "host-helper-control-eof" => {
            return host_child_custody(case);
        }
        "host-failed-ready-target" => return host_failed_ready_target(),
        "host-failed-construction-target" => return host_failed_construction_target(),
        "host-domain-rechecks" => return host_domain_rechecks(),
        _ => {}
    }
    if matches!(case, "host-proc-fd-extra" | "host-proc-fd-original") {
        use std::os::fd::AsFd;
        let directory = std::fs::File::open("/proc/self/fd").unwrap();
        let original = case == "host-proc-fd-original";
        let result = unsafe {
            LifecycleRuntime::bootstrap_early(
                t0 + Duration::from_secs(2),
                original.then(|| directory.as_fd()),
            )
        };
        let refused = match result {
            Err(error) => {
                eprintln!("HOST proc directory original={original} refusal={error}");
                assert!(!error.cleanup_pending);
                true
            }
            Ok(runtime) => {
                assert_eq!(
                    runtime
                        .shutdown(Instant::now() + Duration::from_secs(2))
                        .state,
                    ProducerShutdownState::Complete
                );
                false
            }
        };
        assert!(unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(refused, "caller proc-fd directory bypassed bootstrap audit");
        return;
    }
    if matches!(
        case,
        "host-seal-before-observed" | "host-seal-queued-observed"
    ) {
        host_shutdown_observation(case);
        return;
    }

    if case == "host-close-pause" {
        extern "C" fn inherited(_: i32) {
            let marker = b"INHERITED-HANDLER";
            unsafe {
                libc::write(1, marker.as_ptr().cast(), marker.len());
            }
        }
        let mut a: libc::sigaction = unsafe { std::mem::zeroed() };
        a.sa_sigaction = inherited as usize;
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGINT, &a, std::ptr::null_mut()) },
            0
        );
        launcher::HOST_CLOSE_PAUSE.store(true, Ordering::Relaxed);
    }

    if case == "host-filter" {
        launcher::HOST_FORBIDDEN_SYSCALL.store(true, Ordering::Release);
        assert!(
            unsafe { LifecycleRuntime::bootstrap_early(t0 + Duration::from_millis(100), None) }
                .is_err()
        );
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let status = HOST_LAUNCHER_WAIT.load(Ordering::Acquire);
            if status >= 0 {
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
                assert!(!libc::WCOREDUMP(status));
                break;
            }
            assert!(
                Instant::now() < end,
                "actual launcher wait missing after filter kill"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        return;
    }
    if case == "host-protected-original" {
        use std::os::fd::AsFd;
        let ns = std::fs::File::open("/proc/self/ns/user").unwrap();
        match unsafe {
            LifecycleRuntime::bootstrap_early(t0 + Duration::from_millis(100), Some(ns.as_fd()))
        } {
            Err(error) => assert_eq!(error.reason, "protected original descriptor"),
            Ok(runtime) => {
                assert_eq!(
                    runtime
                        .shutdown(Instant::now() + Duration::from_secs(2))
                        .state,
                    ProducerShutdownState::Complete
                );
                panic!("namespace descriptor was accepted as workload output")
            }
        }
        assert!(
            unsafe { libc::fcntl(ns.as_raw_fd(), libc::F_GETFD) } >= 0,
            "rejected caller descriptor must remain borrowed"
        );
        return;
    }
    if case == "host-normalize-failure" {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur = 4;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        assert_eq!(unsafe { libc::close(0) }, 0);
        let error = match unsafe {
            LifecycleRuntime::bootstrap_early(t0 + Duration::from_millis(100), None)
        } {
            Err(e) => e,
            Ok(_) => panic!("normalization must fail with no duplication slot"),
        };
        assert_eq!(error.errno, Some(libc::EMFILE));
        assert_eq!(
            unsafe { libc::fcntl(0, libc::F_GETFD) },
            -1,
            "originally closed stdin must be restored on allocation failure"
        );
        assert_eq!(
            unsafe { libc::fcntl(3, libc::F_GETFD) },
            -1,
            "the unnormalized peer must retain an owner on partial construction failure"
        );
        return;
    }
    if case == "host-invalid-workload" {
        assert_eq!(unsafe { libc::close(0) }, 0);
        assert!(crate::target::validate_workload_fd(&crate::target::WorkloadDest::Fd(0)).is_err());
        return;
    }
    if case == "host-starting-gates" {
        host_starting_gates();
        return;
    }
    if case == "host-history" {
        crate::loader::host_acquisition_history(false);
        assert!(
            unsafe { LifecycleRuntime::bootstrap_early(t0 + Duration::from_millis(100), None) }
                .is_err()
        );
        return;
    }
    if case == "host-invalid-help" {
        for (args, want) in [
            (vec!["help"], 0),
            (vec!["--version"], 0),
            (vec!["report", "--duration", "NaN", "--pid", "1"], 2),
            (
                vec![
                    "report",
                    "--libcrypto",
                    "/nonexistent-libcrypto.so",
                    "--count-object",
                    "/nonexistent-count.o",
                    "run",
                    "--",
                    "/bin/true",
                ],
                4,
            ),
        ] {
            match crate::cli::prepare(args.into_iter().map(str::to_owned)) {
                crate::cli::PreparedCommand::Immediate(code) => {
                    assert_eq!(code, std::process::ExitCode::from(want))
                }
                _ => panic!("invalid/help command was executable"),
            }
        }
        assert!(
            REGISTRY.lock().unwrap().history == History::Empty,
            "invalid/help/admission errors must not bootstrap or acquire"
        );
    }
    let mask_bit = 1u64 << ((libc::SIGUSR2 - 1) as u32);
    if case == "host-mask" {
        assert_eq!(
            unsafe {
                launcher::raw(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_BLOCK as usize,
                    &mask_bit as *const _ as usize,
                    0,
                    8,
                    0,
                    0,
                )
            },
            0
        );
    }
    let closed = match case {
        "host-closed-stdin" => Some(0),
        "host-closed-stdout" => Some(1),
        _ => None,
    };
    if let Some(fd) = closed {
        assert_eq!(unsafe { libc::close(fd) }, 0)
    }
    let workload = (case == "host-workload-stdout").then(|| unsafe { BorrowedFd::borrow_raw(1) });
    launcher::HOST_HELPER_HOLD.store(true, Ordering::Relaxed);
    let runtime =
        unsafe { LifecycleRuntime::bootstrap_early(t0 + Duration::from_secs(2), workload) }
            .expect("early HOST bootstrap must succeed");
    if let Some(fd) = closed {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    if case == "host-mask" {
        let mut actual = 0u64;
        assert_eq!(
            unsafe {
                launcher::raw(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK as usize,
                    0,
                    &mut actual as *mut _ as usize,
                    8,
                    0,
                    0,
                )
            },
            0
        );
        assert_eq!(
            actual, mask_bit,
            "bootstrap must restore the exact observer mask"
        );
    }
    let handle = runtime.handle();
    let guard = runtime.install().unwrap();
    if case == "host-supervisor-unwind" {
        HOST_SUPERVISOR_PANIC.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_millis(100);
        let receipt = runtime.shutdown(deadline);
        assert_eq!(receipt.state, ProducerShutdownState::Unknown, "{receipt:?}");
        // The deliberate fault occurred with no helper. The HOST actor owns this
        // launcher and explicitly disposes its retained exact pair after a true
        // parent wait; the returned Unknown receipt remains unchanged.
        assert_eq!(unsafe { libc::kill(handle.0.launcher, libc::SIGKILL) }, 0);
        let mut status = 0;
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let r = unsafe { libc::waitpid(handle.0.launcher, &mut status, libc::WNOHANG) };
            if r == handle.0.launcher {
                break;
            }
            assert_eq!(r, 0);
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        let retained = loop {
            if let Some(r) = RETAINED_SUPERVISOR.lock().unwrap().take() {
                break r;
            }
            assert!(Instant::now() < end);
            std::thread::yield_now();
        };
        let (endpoint, pidfd) = retained._descriptors.unwrap();
        assert!(close_owned(endpoint));
        assert!(close_owned(pidfd));
        assert_eq!(runtime.shutdown(end).state, ProducerShutdownState::Unknown);
        drop(guard);
        return;
    }
    if case == "host-drop-publication" {
        let lease = handle
            .begin(
                BurstPhase::Initial,
                Instant::now() + Duration::from_secs(2),
                launcher::monotonic(),
            )
            .unwrap();
        let shared = handle.0.clone();
        let (sent, entered) = std::sync::mpsc::sync_channel(1);
        let holder = std::thread::spawn(move || {
            let _slot = shared.slot.lock().unwrap();
            sent.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let begin = Instant::now();
        drop(lease);
        drop(guard);
        let ticket = runtime.request_shutdown(begin + Duration::from_millis(10));
        drop(runtime);
        assert!(
            begin.elapsed() < Duration::from_millis(50),
            "Drop/request publication blocked behind an owner"
        );
        assert_eq!(ticket.wait().state, ProducerShutdownState::Pending);
        assert!(
            begin.elapsed() < Duration::from_millis(50),
            "deadline wait blocked behind an owner"
        );
        holder.join().unwrap();
        let finish = Instant::now() + Duration::from_secs(2);
        while !handle.0.host_disposed.load(Ordering::Acquire) {
            assert!(Instant::now() < finish);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(ticket.wait().state, ProducerShutdownState::Pending);
        return;
    }
    let mut foreign = if case == "host-foreign-child" {
        Some(
            std::process::Command::new("/bin/sleep")
                .arg("0.1")
                .spawn()
                .unwrap(),
        )
    } else {
        None
    };
    if case == "host-reuse" {
        let mut subs = Vec::new();
        for _ in 0..4 {
            subs.push(handle.subscribe().unwrap())
        }
        assert!(handle.subscribe().is_err());
        drop(subs);
    }

    if case == "host-consumer" {
        for _ in 0..2 {
            crate::capture::tests::host_producer_consumer(&handle)
        }
    } else if case == "host-eof" || case == "host-echild" {
        if case == "host-echild" {
            HOST_SUPERVISOR_WAIT_HOLD.store(true, Ordering::Release);
        }
        assert_eq!(unsafe { libc::kill(handle.0.launcher, libc::SIGKILL) }, 0);
        if case == "host-echild" {
            let mut status = 0;
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let r = unsafe { libc::waitpid(handle.0.launcher, &mut status, libc::WNOHANG) };
                if r == handle.0.launcher {
                    break;
                }
                assert_eq!(r, 0);
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            HOST_SUPERVISOR_WAIT_HOLD.store(false, Ordering::Release);
        }
    } else if case == "host-target-close" {
        let mut target = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        for fd in handle.child_close_set().unwrap().0 {
            assert!(
                std::fs::read_link(format!("/proc/{}/fd/{fd}", target.pid())).is_err(),
                "target must close producer references before SIGSTOP"
            );
        }
        target.resolve_setup_failure().unwrap();
    } else if case == "host-deadline" {
        let mut lease = handle
            .begin(
                BurstPhase::Terminal,
                Instant::now() + Duration::from_millis(100),
                launcher::monotonic(),
            )
            .unwrap();
        lease.spawn(first_cpu()).unwrap();
        let sticky = runtime.request_shutdown(Instant::now() + Duration::from_millis(100));
        let late = runtime.request_shutdown(Instant::now() + Duration::from_secs(2));
        assert_eq!(sticky.deadline, late.deadline);
        assert_eq!(sticky.wait().state, ProducerShutdownState::Pending);
        drop(lease);
    } else {
        for _ in 0..2 {
            let mut pipe = [-1; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
                0
            );
            let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
            let mut writer = Some(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut lease = handle
                .begin(BurstPhase::Initial, deadline, launcher::monotonic())
                .unwrap();
            lease.spawn(first_cpu()).unwrap();
            let mut pid = 0;
            let mut reaped = false;
            while Instant::now() < deadline {
                match lease.poll().unwrap() {
                    Some(ProducerReply::Child {
                        pid: child,
                        cpu,
                        birth_floor_ns,
                    }) => {
                        pid = child;
                        assert!(birth_floor_ns > 0);
                        let stat = std::fs::read_to_string(format!("/proc/{child}/stat"))
                            .expect("held helper state is required for the HOST oracle");
                        let state = stat[stat.rfind(')').unwrap() + 2..].as_bytes()[0];
                        assert!(
                            matches!(state, b'R' | b'S'),
                            "HOST hold elapsed before inheritance observation; fixture timing is unresolved: state={state}"
                        );
                        drop(writer.take());
                        let mut byte = 0u8;
                        let observed = unsafe {
                            libc::read(
                                read.as_raw_fd(),
                                &mut byte as *mut _ as *mut libc::c_void,
                                1,
                            )
                        };
                        assert_eq!(
                            observed, 0,
                            "pipe EOF while the actual helper remains alive independently proves no copied writer reference"
                        );
                        let after = std::fs::read_to_string(format!("/proc/{child}/stat"))
                            .expect("held helper state after EOF");
                        let state = after[after.rfind(')').unwrap() + 2..].as_bytes()[0];
                        assert!(
                            matches!(state, b'R' | b'S'),
                            "HOST hold elapsed during EOF observation; fixture timing is unresolved: state={state}"
                        );
                        lease.observed(cpu, WitnessKind::Fork).unwrap();
                    }
                    Some(ProducerReply::Reaped { pid: child, status }) => {
                        assert_eq!(child, pid);
                        assert_eq!(status, 0);
                        reaped = true;
                        break;
                    }
                    Some(ProducerReply::Failed(e)) => panic!("{e}"),
                    None => {}
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(reaped, "positive true-parent reap required");
        }
    }
    if let Some(child) = foreign.as_mut() {
        assert!(
            child.wait().unwrap().success(),
            "producer must never consume a foreign wait"
        );
    }
    drop(guard);
    if !matches!(case, "host-deadline" | "host-eof" | "host-echild") {
        assert!(
            !handle.0.sealed.load(Ordering::Acquire),
            "guard Drop only unregisters"
        );
    }
    let receipt = runtime.shutdown(Instant::now() + Duration::from_secs(2));
    if matches!(case, "host-eof" | "host-echild") {
        assert_eq!(receipt.state, ProducerShutdownState::Unknown, "{receipt:?}");
        if case == "host-echild" {
            assert_eq!(receipt.launcher_status, None)
        } else {
            assert_eq!(receipt.launcher_status, Some(libc::SIGKILL))
        }
    } else if case != "host-deadline" {
        assert_eq!(
            receipt.state,
            ProducerShutdownState::Complete,
            "{receipt:?}"
        );
        assert_eq!(receipt.launcher_status, Some(0));
    }
    if case == "host-deadline" {
        let finish = Instant::now() + Duration::from_secs(2);
        while !handle.0.host_disposed.load(Ordering::Acquire) {
            assert!(
                Instant::now() < finish,
                "actual producer disposal did not settle after the retained Pending receipt"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            runtime
                .shutdown(Instant::now() + Duration::from_secs(2))
                .state,
            ProducerShutdownState::Pending,
            "late disposal must not rewrite the returned receipt"
        );
    }
    assert!(t0.elapsed() < Duration::from_secs(5));
}

fn host_wait_until(deadline: Instant, mut ready: impl FnMut() -> bool) {
    while !ready() {
        assert!(Instant::now() < deadline, "HOST owning seam did not settle");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn host_audit_target_race() {
    let end = Instant::now() + Duration::from_secs(2);
    let runtime = unsafe { LifecycleRuntime::bootstrap_early(end, None) }.unwrap();
    let handle = runtime.handle();
    HOST_DOMAIN_HOLD.store(true, Ordering::Release);
    let worker_handle = handle.clone();
    let worker = std::thread::spawn(move || {
        worker_handle.begin(BurstPhase::Initial, end, launcher::monotonic())
    });
    host_wait_until(end, || HOST_DOMAIN_FD.load(Ordering::Acquire) > 0);
    let audit_fd = HOST_DOMAIN_FD.load(Ordering::Acquire) - 1;
    let directory = format!("/proc/self/fd/{audit_fd}");
    let audited = std::fs::read_link(directory).unwrap();
    let attempted = crate::target::OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
        end,
        &AtomicBool::new(false),
    );
    let mut inherited = false;
    let admitted = attempted.is_ok();
    if let Ok(mut target) = attempted {
        inherited = std::fs::read_link(format!("/proc/{}/fd/{audit_fd}", target.pid()))
            .is_ok_and(|link| link == audited);
        eprintln!(
            "HOST actual target={} inherited open namespace audit={inherited}",
            target.pid()
        );
        target.resolve_setup_failure().unwrap();
    }
    HOST_DOMAIN_HOLD.store(false, Ordering::Release);
    let burst = worker.join().unwrap().unwrap();
    drop(burst);
    let mut positive = crate::target::OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
        end,
        &AtomicBool::new(false),
    )
    .unwrap();
    let absent_after_audit =
        std::fs::read_link(format!("/proc/{}/fd/{audit_fd}", positive.pid())).is_err();
    positive.resolve_setup_failure().unwrap();
    assert_eq!(
        runtime
            .shutdown(Instant::now() + Duration::from_secs(2))
            .state,
        ProducerShutdownState::Complete
    );
    assert!(
        !admitted,
        "target fork admitted while namespace audit descriptor was open (inherited={inherited})"
    );
    assert!(absent_after_audit);
}

fn host_stop_before_close() {
    let end = Instant::now() + Duration::from_secs(2);
    let runtime = unsafe { LifecycleRuntime::bootstrap_early(end, None) }.unwrap();
    let handle = runtime.handle();
    crate::target::HOST_BEFORE_PRODUCER_CLOSE_STOP.store(true, Ordering::Release);
    crate::target::HOST_PRODUCER_STOP_HOLD.store(true, Ordering::Release);
    let worker = std::thread::spawn(move || {
        crate::target::OwnedTarget::spawn_stopped_with_control(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
            end,
            &AtomicBool::new(false),
        )
    });
    host_wait_until(end, || {
        crate::target::HOST_PRODUCER_STOP_PID.load(Ordering::Acquire) > 0
    });
    let pid = crate::target::HOST_PRODUCER_STOP_PID.load(Ordering::Acquire);
    let still_copied = handle.child_close_set().unwrap().0.into_iter().all(|fd| {
        std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap()
            == std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap()
    });
    let charged = handle.0.slot.lock().unwrap().target_active;
    let burst_refused = handle
        .begin(BurstPhase::Initial, end, launcher::monotonic())
        .is_err();
    crate::target::HOST_PRODUCER_STOP_HOLD.store(false, Ordering::Release);
    let result = worker.join().unwrap();
    let admitted = result.is_ok();
    if let Ok(mut target) = result {
        target.resolve_setup_failure().unwrap();
    }
    crate::target::HOST_BEFORE_PRODUCER_CLOSE_STOP.store(false, Ordering::Release);
    let mut positive = crate::target::OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
        end,
        &AtomicBool::new(false),
    )
    .unwrap();
    let positive_closed = handle
        .child_close_set()
        .unwrap()
        .0
        .into_iter()
        .all(|fd| std::fs::read_link(format!("/proc/{}/fd/{fd}", positive.pid())).is_err());
    positive.resolve_setup_failure().unwrap();
    assert_eq!(
        runtime
            .shutdown(Instant::now() + Duration::from_secs(2))
            .state,
        ProducerShutdownState::Complete
    );
    assert!(still_copied && charged && burst_refused);
    assert!(
        !admitted,
        "an unrelated pre-close SIGSTOP discharged copied producer references"
    );
    assert!(positive_closed);
}

fn host_child_custody(case: &str) {
    // This HOST actor is an explicit subreaper only to settle the deliberately
    // orphaned fault child. Production supervisor never reaps that helper.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let word = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(word, libc::MAP_FAILED);
    let word = word.cast::<std::sync::atomic::AtomicU32>();
    unsafe {
        word.write(std::sync::atomic::AtomicU32::new(0));
    }
    launcher::HOST_CHILD_PID_WORD.store(word as usize, Ordering::Release);
    launcher::HOST_BEFORE_CHILD_EXIT.store(case == "host-child-unreported", Ordering::Release);
    launcher::HOST_RESTORE_FAILURE.store(case == "host-restore-failure", Ordering::Release);
    launcher::HOST_HELPER_HOLD.store(true, Ordering::Release);
    let end = Instant::now() + Duration::from_secs(2);
    let runtime = unsafe { LifecycleRuntime::bootstrap_early(end, None) }.unwrap();
    let handle = runtime.handle();
    let mut burst = handle
        .begin(BurstPhase::Initial, end, launcher::monotonic())
        .unwrap();
    burst.spawn(first_cpu()).unwrap();
    if case == "host-helper-control-eof" {
        host_wait_until(end, || handle.host_child().is_some());
        let pid = handle.host_child().unwrap().0;
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        assert!(matches!(
            state[state.rfind(')').unwrap() + 2..].as_bytes()[0],
            b'R' | b'S'
        ));
        assert_eq!(
            unsafe { libc::shutdown(handle.0.endpoint, libc::SHUT_RDWR) },
            0
        );
    }
    host_wait_until(end, || HOST_LAUNCHER_WAIT.load(Ordering::Acquire) >= 0);
    let child = unsafe { (*word).load(Ordering::Acquire) };
    assert!(child > 0);
    let mut actor_adopted = false;
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(child as i32, &mut status, libc::WNOHANG) };
        if result == child as i32 {
            actor_adopted = true;
            break;
        }
        if result < 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    let reaped_reply = handle
        .0
        .slot
        .lock()
        .unwrap()
        .reply
        .filter(|f| f.kind == REAPED);
    drop(burst);
    host_wait_until(end, || handle.0.slot.lock().unwrap().receipt.is_some());
    let retained = !handle.0.host_disposed.load(Ordering::Acquire)
        && handle.0.slot.lock().unwrap().busy
        && unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } >= 0
        && unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } >= 0;
    let receipt = runtime.shutdown(end);
    assert_eq!(unsafe { libc::munmap(word.cast(), 4096) }, 0);
    eprintln!(
        "HOST custody case={case} helper={child} actor-adopted={actor_adopted} actual-status={status} launcher-status={} retained={retained}",
        HOST_LAUNCHER_WAIT.load(Ordering::Acquire)
    );
    assert_eq!(receipt.state, ProducerShutdownState::Unknown);
    if case == "host-restore-failure" {
        assert!(
            reaped_reply.is_some_and(|f| f.arg0 == child as u64),
            "post-clone restoration failure lost positive helper REAPED"
        );
        assert!(!actor_adopted, "launcher abandoned its own helper wait");
        assert!(handle.0.host_disposed.load(Ordering::Acquire));
    } else {
        assert!(
            retained,
            "dispatched SPAWN obligation disappeared without bound FAILED/REAPED"
        );
        assert_eq!(actor_adopted, case == "host-child-unreported");
    }
}

fn host_failed_ready_target() {
    launcher::HOST_READY_DELAY.store(true, Ordering::Release);
    HOST_SUPERVISOR_WAIT_HOLD.store(true, Ordering::Release);
    let result = unsafe {
        LifecycleRuntime::bootstrap_early(Instant::now() + Duration::from_millis(20), None)
    };
    assert!(result.is_err());
    let shared = HOST_BOOT_SHARED.lock().unwrap().as_ref().unwrap().clone();
    let handle = ProducerHandle(shared.clone());
    let attempted = crate::target::OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    let admitted = attempted.is_ok();
    if let Ok(mut target) = attempted {
        let inherited = [shared.endpoint, shared.pidfd]
            .into_iter()
            .all(|fd| std::fs::read_link(format!("/proc/{}/fd/{fd}", target.pid())).is_ok());
        eprintln!(
            "HOST failed Ready target={} copied hidden pair={inherited}",
            target.pid()
        );
        target.resolve_setup_failure().unwrap();
    }
    HOST_SUPERVISOR_WAIT_HOLD.store(false, Ordering::Release);
    shared.wake.notify_all();
    host_wait_until(Instant::now() + Duration::from_secs(2), || {
        shared.host_disposed.load(Ordering::Acquire)
    });
    assert!(HOST_LAUNCHER_WAIT.load(Ordering::Acquire) >= 0);
    drop(handle);
    HOST_BOOT_SHARED.lock().unwrap().take();
    assert!(
        !admitted,
        "failed bootstrap hid its retained producer pair from ordinary target admission"
    );
}
fn first_cpu() -> u32 {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    (0..1024)
        .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .unwrap() as u32
}

fn host_signal_and_parent_death() {
    use std::io::Read;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    for kill_parent in [false, true] {
        let mut parent = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("host-close-pause")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let launcher = loop {
            let text = std::fs::read_to_string(format!(
                "/proc/{}/task/{}/children",
                parent.id(),
                parent.id()
            ))
            .unwrap_or_default();
            if let Some(pid) = text
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i32>().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "launcher never appeared");
            std::thread::sleep(Duration::from_millis(1));
        };
        eprintln!(
            "HOST close-seam parent={} launcher={launcher} kill-parent={kill_parent}",
            parent.id()
        );
        // The actual launcher is held after death protection/handler reset, before
        // inherited closes. No signal changes the observer's security state.
        std::thread::sleep(Duration::from_millis(50));
        if kill_parent {
            parent.kill().unwrap();
            assert!(!parent.wait().unwrap().success());
            let mut status = 0;
            loop {
                let r = unsafe { libc::waitpid(launcher, &mut status, libc::WNOHANG) };
                if r == launcher {
                    assert!(libc::WIFSIGNALED(status));
                    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                    eprintln!(
                        "HOST adopted launcher positive-wait pid={launcher} raw-status={status}"
                    );
                    break;
                }
                assert!(r == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EINTR));
                assert!(
                    Instant::now() < deadline,
                    "death-protected launcher not reaped"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        } else {
            assert_eq!(unsafe { libc::kill(launcher, libc::SIGINT) }, 0);
            loop {
                if let Some(status) = parent.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "signal control exceeded bound");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let mut output = Vec::new();
        parent
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        assert!(
            !output.windows(17).any(|w| w == b"INHERITED-HANDLER"),
            "inherited handler ran in launcher"
        );
    }
}

#[path = "../../tests/support/lifecycle_driver.rs"]
mod lifecycle_driver;
pub(crate) use lifecycle_driver::run_connector_driver;

#[test]
fn lifecycle_producer_shutdown_receipt_preserves_precedence_and_artifacts() {
    use crate::report::*;
    for state in [
        ProducerShutdownState::Pending,
        ProducerShutdownState::Unknown,
    ] {
        for (original, want) in [(0, 1), (3, 1), (11, 1), (2, 2), (4, 4), (10, 10), (1, 1)] {
            let delivery = DeliveryResult {
                primary: ArtifactOutcome {
                    dest: "host".into(),
                    ok: true,
                    bytes: 42,
                    error: None,
                },
                cbom: None,
                diagnostics: vec!["delivery".into()],
            };
            let mut result = CaptureCommandResult {
                document: setup_failure_document(crate::evidence::FatalKind::Environment(
                    "host".into(),
                )),
                child_exit: Some(7),
                disposition: None,
                delivery: delivery.clone(),
                exit_code: original,
                diagnostics: vec!["existing".into(); 8],
                failure_context: None,
            };
            let document = serde_json::to_value(&result.document).unwrap();
            let receipt = ProducerShutdownReceipt {
                state,
                launcher_status: Some(9),
                failure: Some(failure("HOST uncertain wait")),
            };
            let mut output = Vec::new();
            apply_producer_shutdown(&mut result, &receipt, &mut output);
            assert_eq!(result.exit_code, want);
            assert_eq!(result.delivery, delivery);
            assert_eq!(result.child_exit, Some(7));
            assert_eq!(serde_json::to_value(&result.document).unwrap(), document);
            assert_eq!(result.diagnostics.len(), 9);
            assert!(result.diagnostics[8].chars().count() <= 200);
            assert_eq!(output.iter().filter(|&&b| b == b'\n').count(), 1);
        }
    }
}

fn host_starting_gates() {
    use crate::count_owner::*;
    // This poisoned subprocess models the in-progress gate only. It never mints
    // a Ready/construction certificate or resumes eligibility for bootstrap.
    REGISTRY.lock().unwrap().history = History::Starting;
    crate::loader::host_acquisition_history(true);
    assert!(crate::pin::pin(std::process::id()).is_err());
    let error =
        crate::plan::attach_group(-1, std::process::id(), "/not-entered", &[], &[]).unwrap_err();
    assert!(error.raw_os_error().is_none());
    let error = crate::doctor::probe_ringbuf_query().unwrap_err();
    assert_eq!(error.stage, "bootstrap");
    assert_eq!(error.errno, -1);
    let barrier = Arc::new(CountForkBarrier::new());
    let lease = barrier.reserve_setup().unwrap();
    let deadline = Instant::now() + Duration::from_millis(100);
    drop(lease.prefix_permit(deadline).unwrap());
    lease.close_prefix();
    let admission = lease.reserve_count().unwrap();
    let input = CountInput {
        object_bytes: Arc::from([]),
        object_sha256: [0; 32],
        target_tgid: std::process::id(),
        fork_barrier: barrier,
    };
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let journal = CountSetupJournal::new();
    let error = match CountEngine::prepare_controlled(
        input,
        CountOwnerLimits::from_allowance(18, 1).unwrap(),
        deadline,
        admission,
        &control,
        &journal,
    ) {
        Err(e) => e,
        Ok(_) => panic!("Starting entered controlled Count"),
    };
    assert_eq!(error.failure.class, FailureClass::InvalidInput);
    assert!(error.cleanup_ticket.is_none());
    let progress = journal.watch().progress().unwrap();
    assert!(progress.owner_epoch.is_none());
    assert!(!progress.owner_cleanup_acknowledged);
    assert!(
        !progress.owner_task_disposed,
        "no owner was started or falsely acknowledged"
    );
}

fn host_shutdown_observation(case: &str) {
    let started = Instant::now();
    launcher::HOST_HELPER_HOLD.store(true, Ordering::Release);
    let runtime =
        unsafe { LifecycleRuntime::bootstrap_early(started + Duration::from_secs(2), None) }
            .unwrap();
    let handle = runtime.handle();
    let guard = runtime.install().unwrap();
    let burst_deadline = Instant::now() + Duration::from_secs(2);
    let mut lease = handle
        .begin(BurstPhase::Terminal, burst_deadline, launcher::monotonic())
        .unwrap();
    let cpu = first_cpu();
    lease.spawn(cpu).unwrap();
    let (pid, birth) = loop {
        match lease.poll().unwrap() {
            Some(ProducerReply::Child {
                pid,
                cpu: received,
                birth_floor_ns,
            }) => {
                assert_eq!(received, cpu);
                break (pid, birth_floor_ns);
            }
            Some(_) => panic!("unexpected reply before Child"),
            None => {}
        }
        assert!(Instant::now() < burst_deadline);
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(birth > 0);
    // Hold the actual outbound command seam; ABORT and actual reply/reap
    // processing remain live. No transport/Ready/reap record is fabricated.
    HOST_COMMAND_HOLD.store(true, Ordering::Release);
    let queued = case == "host-seal-queued-observed";
    if queued {
        lease.observed(cpu, WitnessKind::Fork).unwrap();
        assert_eq!(
            handle.0.slot.lock().unwrap().command.unwrap().kind,
            OBSERVED
        );
    }
    let shutdown_deadline = Instant::now() + Duration::from_millis(100);
    let ticket = runtime.request_shutdown(shutdown_deadline);
    let accepted_after_seal = if queued {
        false
    } else {
        lease.observed(cpu, WitnessKind::Fork).is_ok()
    };
    // Observe real owning-state receipt before asking the sealed lease for data.
    let reaped = loop {
        let state = handle.0.slot.lock().unwrap();
        let result = state.reply.filter(|f| f.kind == REAPED);
        drop(state);
        if let Some(reply) = result {
            break reply;
        }
        assert!(Instant::now() < burst_deadline);
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(reaped.arg0, pid as u64);
    assert_eq!(reaped.request, lease.request.unwrap().request);
    eprintln!(
        "HOST shutdown schedule={case} helper={pid} positive-reaped-status={}",
        reaped.arg1
    );
    let exposed_after_seal = matches!(lease.poll(), Ok(Some(ProducerReply::Reaped { .. })));
    let receipt = ticket.wait();
    assert_eq!(receipt.state, ProducerShutdownState::Pending);
    let retained_while_held = !handle.0.host_disposed.load(Ordering::Acquire)
        && handle.0.slot.lock().unwrap().active
        && unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } >= 0
        && unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } >= 0;
    let original_budget = lease.deadline == burst_deadline && ticket.deadline <= shutdown_deadline;
    HOST_COMMAND_HOLD.store(false, Ordering::Release);
    handle.0.wake.notify_all();
    drop(lease);
    let finish = Instant::now() + Duration::from_secs(2);
    while !handle.0.host_disposed.load(Ordering::Acquire) {
        assert!(
            Instant::now() < finish,
            "actual supervisor disposal did not settle"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let launcher_status = HOST_LAUNCHER_WAIT.load(Ordering::Acquire);
    let observed_sent = HOST_OBSERVED_SENT.load(Ordering::Acquire);
    let abort_sent = HOST_ABORT_SENT.load(Ordering::Acquire);
    let unchanged = runtime
        .shutdown(Instant::now() + Duration::from_secs(2))
        .state
        == ProducerShutdownState::Pending;
    drop(guard);
    // Assertions come after actual actor settlement, including on semantic RED.
    assert!(
        !accepted_after_seal,
        "sealed lease accepted a new OBSERVED publication"
    );
    assert_eq!(
        observed_sent, 0,
        "queued OBSERVED crossed shutdown revocation before ABORT"
    );
    assert!(
        !exposed_after_seal,
        "sealed lease exposed a new completion receipt"
    );
    assert_eq!(
        abort_sent, 1,
        "the original exact child needs one successful ABORT"
    );
    assert_eq!(
        launcher_status, 0,
        "genuine late disposal needs clean launcher exit"
    );
    assert!(retained_while_held);
    assert!(original_budget);
    assert!(unchanged);
    assert!(started.elapsed() < Duration::from_secs(5));
}

fn host_failed_construction_target() {
    HOST_PIDFD_FAILURE.store(true, Ordering::Release);
    HOST_BOOTSTRAP_SETTLE_HOLD.store(true, Ordering::Release);
    let error = match unsafe {
        LifecycleRuntime::bootstrap_early(Instant::now() + Duration::from_secs(1), None)
    } {
        Err(error) => error,
        Ok(_) => panic!("actual invalid pidfd flags unexpectedly accepted"),
    };
    assert!(error.cleanup_pending);
    let fd = QUARANTINED_BOOTSTRAP
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .endpoint
        .as_raw_fd();
    let attempted = crate::target::OwnedTarget::spawn_stopped_with_control(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    let admitted = attempted.is_ok();
    if let Ok(mut target) = attempted {
        eprintln!(
            "HOST construction target={} inherited quarantined endpoint={}",
            target.pid(),
            std::fs::read_link(format!("/proc/{}/fd/{fd}", target.pid())).is_ok()
        );
        target.resolve_setup_failure().unwrap();
    }
    HOST_BOOTSTRAP_SETTLE_HOLD.store(false, Ordering::Release);
    let owner = QUARANTINED_BOOTSTRAP.lock().unwrap().take().unwrap();
    assert!(settle_bootstrap(
        owner,
        Instant::now() + Duration::from_secs(1)
    ));
    assert!(
        !admitted,
        "pre-Shared quarantine was hidden from ordinary target admission"
    );
}

fn host_domain_rechecks() {
    let end = Instant::now() + Duration::from_secs(2);
    let runtime = unsafe { LifecycleRuntime::bootstrap_early(end, None) }.unwrap();
    let handle = runtime.handle();
    let barrier = Arc::new(crate::count_owner::CountForkBarrier::new());
    let setup = barrier.reserve_setup().unwrap();
    let prefix = setup.prefix_permit(end).unwrap();
    // Unavailable-domain fixture must stop the real pre-socket path; no
    // connector socket, privileged experiment or changed namespace is used.
    HOST_DOMAIN_REJECT.store(true, Ordering::Release);
    let rejected = crate::capture::KernelLifecycle::subscribe_with_producer(
        std::process::id(),
        false,
        &prefix,
        &handle,
    )
    .err()
    .expect("domain refusal before connector socket");
    assert!(format!("{rejected:#}").contains("HOST domain read refusal"));
    assert_eq!(handle.0.subscriptions.load(Ordering::Acquire), 0);
    assert!(
        handle
            .begin(BurstPhase::Initial, end, launcher::monotonic())
            .is_err()
    );
    HOST_DOMAIN_REJECT.store(false, Ordering::Release);
    let mut burst = handle
        .begin(BurstPhase::Initial, end, launcher::monotonic())
        .unwrap();
    let reads = HOST_DOMAIN_READS.load(Ordering::Acquire);
    HOST_DOMAIN_REJECT.store(true, Ordering::Release);
    assert!(burst.spawn(first_cpu()).is_err());
    assert!(burst.request.is_none() && !handle.0.slot.lock().unwrap().busy);
    assert_eq!(burst.deadline, end);
    HOST_DOMAIN_REJECT.store(false, Ordering::Release);
    for _ in 0..2 {
        burst.spawn(first_cpu()).unwrap();
        let mut reaped = false;
        while Instant::now() < end {
            match burst.poll().unwrap() {
                Some(ProducerReply::Child { cpu, .. }) => {
                    burst.observed(cpu, WitnessKind::Fork).unwrap()
                }
                Some(ProducerReply::Reaped { .. }) => {
                    reaped = true;
                    break;
                }
                Some(ProducerReply::Failed(error)) => panic!("{error}"),
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert!(reaped);
    }
    assert_eq!(HOST_DOMAIN_READS.load(Ordering::Acquire) - reads, 3);
    assert!(!handle.0.audit_active.load(Ordering::Acquire));
    drop(burst);
    drop(prefix);
    setup.close_prefix();
    assert_eq!(
        runtime
            .shutdown(Instant::now() + Duration::from_secs(2))
            .state,
        ProducerShutdownState::Complete
    );
}

fn host_supervisor_eof_passive() {
    let started = Instant::now();
    let runtime =
        unsafe { LifecycleRuntime::bootstrap_early(started + Duration::from_secs(2), None) }
            .unwrap();
    let handle = runtime.handle();
    // Signal and observe the original pidfd without consuming launcher wait ownership.
    let stopped_signal = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.0.pidfd,
            libc::SIGSTOP,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let end = Instant::now() + Duration::from_secs(1);
    let mut stopped = false;
    while Instant::now() < end {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                handle.0.pidfd as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if r == 0
            && unsafe { info.si_pid() } == handle.0.launcher
            && info.si_code == libc::CLD_STOPPED
        {
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let read_shutdown = unsafe { libc::shutdown(handle.0.endpoint, libc::SHUT_RD) };
    let end = Instant::now() + Duration::from_secs(1);
    while HOST_SUPERVISOR_EOF.load(Ordering::Acquire) == 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    let eof_observed = HOST_SUPERVISOR_EOF.load(Ordering::Acquire) > 0;
    let snapshot = || {
        [
            HOST_SUPERVISOR_RECEIVES.load(Ordering::Acquire),
            HOST_SUPERVISOR_POLLS.load(Ordering::Acquire),
            HOST_SUPERVISOR_LOOPS.load(Ordering::Acquire),
        ]
    };
    let deadline = Instant::now() + Duration::from_millis(100);
    let ticket = runtime.request_shutdown(deadline);
    let before = snapshot();
    std::thread::sleep(Duration::from_millis(100));
    let after = snapshot();
    let delta = std::array::from_fn::<_, 3, _>(|i| after[i] - before[i]);
    let pending = ticket.wait().state;
    let original_deadline = ticket.deadline == deadline
        && runtime
            .request_shutdown(Instant::now() + Duration::from_secs(2))
            .deadline
            == deadline;
    let retained = !handle.0.host_disposed.load(Ordering::Acquire)
        && unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } >= 0
        && unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } >= 0;
    // Always settle the stopped launcher before asserting the semantic oracle.
    let killed = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.0.pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    host_wait_until(Instant::now() + Duration::from_secs(2), || {
        handle.0.host_disposed.load(Ordering::Acquire)
    });
    let waited = HOST_LAUNCHER_WAIT.load(Ordering::Acquire);
    let endpoint_closed = unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    let pidfd_closed = unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    let sticky = runtime
        .shutdown(Instant::now() + Duration::from_secs(2))
        .state;
    eprintln!(
        "HOST supervisor EOF stopped={stopped} actual-eof={eof_observed} delta-recv-poll-loop={delta:?} pending={pending:?} original-deadline={original_deadline} retained={retained} positive-wait={waited} endpoint-closed={endpoint_closed} pidfd-closed={pidfd_closed} sticky={sticky:?}"
    );
    assert_eq!(stopped_signal, 0);
    assert!(stopped);
    assert_eq!(read_shutdown, 0);
    assert!(eof_observed);
    assert_eq!(killed, 0);
    assert_eq!(waited, libc::SIGKILL);
    assert!(endpoint_closed && pidfd_closed);
    assert_eq!(pending, ProducerShutdownState::Pending);
    assert_eq!(sticky, ProducerShutdownState::Pending);
    assert!(original_deadline && retained);
    assert_eq!(handle.0.slot.lock().unwrap().shutdown, Some(deadline));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        delta.iter().all(|n| *n <= 2),
        "terminal EOF must passively await the launcher: recv/poll/loop delta={delta:?}"
    );
}

fn host_supervisor_buffered_hup(case: &str) {
    let started = Instant::now();
    let end = started + Duration::from_secs(3);
    let queued_child = case == "host-supervisor-buffered-child-reaped-hup";
    let late_reaped = case == "host-supervisor-empty-receive-reaped-hup";
    let reaped = case == "host-supervisor-buffered-reaped-hup" || queued_child || late_reaped;
    launcher::HOST_RESTORE_FAILURE.store(queued_child, Ordering::Release);
    HOST_RECEIVE_BEFORE_CHILD.store(queued_child, Ordering::Release);
    launcher::HOST_HELPER_HOLD.store(reaped, Ordering::Release);
    let runtime = unsafe { LifecycleRuntime::bootstrap_early(end, None) }.unwrap();
    let handle = runtime.handle();
    let guard = runtime.install().unwrap();
    HOST_RECEIVE_HOLD.store(!late_reaped, Ordering::Release);
    HOST_EMPTY_RECEIVE_HOLD.store(late_reaped, Ordering::Release);
    let mut lease = if reaped {
        let mut lease = handle
            .begin(BurstPhase::Initial, end, launcher::monotonic())
            .unwrap();
        lease.spawn(first_cpu()).unwrap();
        Some(lease)
    } else {
        None
    };
    // The queued-child case gates immediately after actual SPAWN delivery,
    // before the first CHILD receive. Other cases gate after CHILD/SHUTDOWN.
    // All packets and helper/launcher settlement still come from the real launcher.
    let ticket = if reaped {
        None
    } else {
        Some(runtime.request_shutdown(end))
    };
    host_wait_until(end, || {
        if late_reaped {
            HOST_EMPTY_RECEIVE_HELD.load(Ordering::Acquire)
        } else {
            HOST_RECEIVE_HELD.load(Ordering::Acquire)
        }
    });
    let empty_before_shutdown = late_reaped
        && HOST_RECEIVE_WOULD_BLOCK.load(Ordering::Acquire)
        && HOST_EMPTY_RECEIVE_HELD.load(Ordering::Acquire);
    let waits_before = HOST_LAUNCHER_WAIT_CALLS.load(Ordering::Acquire);
    let child_before_receive = handle.0.host_child.lock().unwrap().map(|f| f.arg0);
    let helper_held = child_before_receive
        .and_then(|pid| std::fs::read_to_string(format!("/proc/{pid}/stat")).ok())
        .is_some_and(|state| {
            matches!(
                state[state.rfind(')').unwrap() + 2..].as_bytes()[0],
                b'R' | b'S'
            )
        });
    let write_shutdown = if reaped && !queued_child {
        unsafe { libc::shutdown(handle.0.endpoint, libc::SHUT_WR) }
    } else {
        0
    };
    let ticket = if late_reaped {
        None
    } else {
        Some(ticket.unwrap_or_else(|| runtime.request_shutdown(end)))
    };
    let mut observed = [
        libc::pollfd {
            fd: handle.0.endpoint,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: handle.0.pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut buffered_hup = false;
    while Instant::now() < end {
        unsafe {
            libc::poll(observed.as_mut_ptr(), 2, 0);
        }
        if observed[0].revents & (libc::POLLIN | libc::POLLHUP) == libc::POLLIN | libc::POLLHUP
            && observed[1].revents & libc::POLLIN != 0
        {
            buffered_hup = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Leave the actual buffered cleanup packet available to the supervisor.
    // Peek verifies its kind without consuming any protocol or wait ownership.
    let mut bytes = [0u8; 65];
    let length = unsafe {
        libc::recv(
            handle.0.endpoint,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    let buffered = (length == 64)
        .then(|| Frame::decode(&bytes[..64]))
        .flatten();
    let child = if queued_child {
        buffered.filter(|f| f.kind == CHILD).map(|f| f.arg0)
    } else {
        child_before_receive
    };
    let retained = !handle.0.host_disposed.load(Ordering::Acquire)
        && unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } >= 0
        && unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } >= 0;
    // For the late-REAPED schedule the real empty receive precedes helper
    // settlement/launcher exit; only now seal and release the caller lease.
    let ticket = ticket.unwrap_or_else(|| runtime.request_shutdown(end));
    drop(lease.take());
    HOST_RECEIVE_HOLD.store(false, Ordering::Release);
    HOST_EMPTY_RECEIVE_HOLD.store(false, Ordering::Release);
    host_wait_until(Instant::now() + Duration::from_secs(2), || {
        handle.0.host_disposed.load(Ordering::Acquire)
            || ((queued_child || late_reaped) && handle.0.slot.lock().unwrap().receipt.is_some())
    });
    let receipt = ticket.wait();
    let actual_wait = HOST_LAUNCHER_WAIT.load(Ordering::Acquire);
    let actual_reaped = handle
        .0
        .slot
        .lock()
        .unwrap()
        .reply
        .filter(|f| f.kind == REAPED);
    let endpoint_closed = unsafe { libc::fcntl(handle.0.endpoint, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    let pidfd_closed = unsafe { libc::fcntl(handle.0.pidfd, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    // In semantic RED the true launcher wait happened, but the owning loop
    // parked with REAPED still queued. Peeking diagnoses it without replacing
    // the missing production receipt or manually closing supervisor FDs.
    let leftover_length =
        if (queued_child || late_reaped) && !handle.0.host_disposed.load(Ordering::Acquire) {
            unsafe {
                libc::recv(
                    handle.0.endpoint,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            }
        } else {
            -1
        };
    let leftover = (leftover_length == 64)
        .then(|| Frame::decode(&bytes[..64]))
        .flatten();
    drop(guard);
    eprintln!(
        "HOST buffered case={case} HUP-and-pidfd-ready={buffered_hup} packet={buffered:?} child={child:?} actual-reaped={actual_reaped:?} actual-wait={actual_wait} retained={retained} endpoint-closed={endpoint_closed} pidfd-closed={pidfd_closed} receipt={receipt:?} child-before-receive={child_before_receive:?} leftover={leftover:?} actual-empty-before-shutdown={empty_before_shutdown} helper-held={helper_held} wait-calls-before={waits_before} wait-calls-after={}",
        HOST_LAUNCHER_WAIT_CALLS.load(Ordering::Acquire)
    );
    // GREEN requires production receipt/wait/disposal. On queued-child RED,
    // actor process exit settles the retained FDs; no successful disposal is claimed.
    assert_eq!(write_shutdown, 0);
    assert!(buffered_hup && retained);
    assert_eq!(
        buffered.unwrap().kind,
        if queued_child {
            CHILD
        } else if reaped {
            REAPED
        } else {
            DONE
        }
    );
    if queued_child {
        assert!(child_before_receive.is_none());
    }
    if late_reaped {
        assert!(empty_before_shutdown && helper_held);
        assert_eq!(waits_before, 0);
        assert_eq!(HOST_LAUNCHER_WAIT_CALLS.load(Ordering::Acquire), 1);
    }
    assert!(endpoint_closed && pidfd_closed);
    assert_eq!(receipt.launcher_status, Some(actual_wait));
    if reaped {
        assert_eq!(actual_reaped.unwrap().arg0, child.unwrap());
        assert!(libc::WIFSIGNALED(actual_reaped.unwrap().arg1 as i32));
        assert_eq!(
            libc::WTERMSIG(actual_reaped.unwrap().arg1 as i32),
            libc::SIGKILL
        );
        assert_eq!(actual_wait, (if queued_child { 133 } else { 138 }) << 8);
        assert_eq!(receipt.state, ProducerShutdownState::Unknown);
        assert!(receipt.failure.is_some());
    } else {
        assert_eq!(actual_wait, 0);
        assert_eq!(receipt.state, ProducerShutdownState::Complete);
        assert!(receipt.failure.is_none());
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}
