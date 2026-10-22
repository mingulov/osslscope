//! SPDX-License-Identifier: GPL-3.0-or-later
use super::io::CountIoDriver;
use super::protocol::*;
use super::registry::{CountLoadSink, Registry, RegistryEvent, ResourceKind};
use super::*;
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
enum Event {
    Started,
    Registry(RegistryEvent),
    EnterAcquire(usize),
    Acquired(usize),
    EnterClose,
    Closed(Option<i32>),
    LogBuffer(usize),
}
struct InvocationLog {
    events: Vec<(ThreadId, Event)>,
    // Independent write-end witnesses, never aliases of owner-managed read FDs.
    witnesses: Vec<OwnedFd>,
}
struct Probe {
    log: Mutex<InvocationLog>,
    changed: Condvar,
    released: Mutex<bool>,
    release: Condvar,
}
impl Probe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::new(InvocationLog {
                events: Vec::with_capacity(256),
                witnesses: Vec::with_capacity(16),
            }),
            changed: Condvar::new(),
            released: Mutex::new(false),
            release: Condvar::new(),
        })
    }
    fn event(&self, event: Event) {
        self.log
            .lock()
            .unwrap()
            .events
            .push((std::thread::current().id(), event));
        self.changed.notify_all();
    }
    fn wait(&self, predicate: impl Fn(&[(ThreadId, Event)]) -> bool) {
        let cutoff = Instant::now() + Duration::from_secs(3);
        let mut log = self.log.lock().unwrap();
        while !predicate(&log.events) {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "owner did not advance: {:?}",
                log.events
            );
            log = self.changed.wait_timeout(log, remaining).unwrap().0;
        }
    }
    fn hold(&self) {
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
    fn acquire(&self, ordinal: usize) -> OwnedFd {
        let mut pair = [-1; 2];
        // SAFETY: pipe2 initializes this live output array with two fresh FDs.
        assert_eq!(
            unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: these distinct pipe endpoints were just returned by pipe2.
        let (read, write) =
            unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        self.log.lock().unwrap().witnesses.push(write);
        self.event(Event::Acquired(ordinal));
        read
    }
    fn assert_cleanup(&self, expected: usize, controller: ThreadId) {
        self.wait(|events| {
            events
                .iter()
                .filter(|(_, e)| matches!(e, Event::Closed(_)))
                .count()
                == expected
        });
        let log = self.log.lock().unwrap();
        assert_eq!(
            log.events
                .iter()
                .filter(|(_, e)| matches!(e, Event::Acquired(_)))
                .count(),
            expected
        );
        assert_eq!(
            log.events
                .iter()
                .filter(
                    |(t, e)| *t == controller && matches!(e, Event::EnterClose | Event::Closed(_))
                )
                .count(),
            0,
            "coordinator_close_calls"
        );
        assert!(
            log.events.iter().all(|(t, _)| *t != controller),
            "count I/O escaped the owner"
        );
        if let Some((owner, _)) = log
            .events
            .iter()
            .find(|(_, event)| matches!(event, Event::Started))
        {
            assert!(
                log.events.iter().all(|(thread, _)| thread == owner),
                "count I/O moved to another worker"
            );
        }
        for (_, event) in &log.events {
            if let Event::Registry(event) = event {
                assert_ne!(event.resource(), ResourceId::Engine);
            }
        }
        for witness in &log.witnesses {
            let mut poll = libc::pollfd {
                fd: witness.as_raw_fd(),
                // Other host tests fork raw helpers in this same process. An
                // inherited test read endpoint can outlive our exact parent
                // close. Wait only for the independent fixture to settle; this
                // is never a writer acknowledgment or a fork-permit condition.
                events: 0,
                revents: 0,
            };
            let cutoff = Instant::now() + Duration::from_secs(3);
            loop {
                let remaining = cutoff.saturating_duration_since(Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "test pipe reader remains after bounded fixture cleanup"
                );
                let timeout = i32::try_from(remaining.as_millis())
                    .unwrap_or(i32::MAX)
                    .max(1);
                // SAFETY: poll refers to one live initialized pollfd.
                let result = unsafe { libc::poll(&mut poll, 1, timeout) };
                if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                assert_eq!(
                    result, 1,
                    "test pipe reader remains after bounded fixture cleanup"
                );
                break;
            }
            assert_ne!(
                poll.revents & libc::POLLERR,
                0,
                "a pipe still has an owner-managed reader after recorded cleanup"
            );
        }
    }
}
#[derive(Clone, Default)]
struct Faults {
    fail_acquire_from: Option<usize>,
    expire_after: Option<usize>,
    hold_acquire: Option<usize>,
    hold_close: Option<usize>,
    fail_close: Option<usize>,
    quiet_failure: bool,
}
struct PipeDriver {
    probe: Arc<Probe>,
    faults: Faults,
    deadline: Instant,
    attempts: usize,
    acquired: usize,
    closes: usize,
}
impl PipeDriver {
    fn acquire(&mut self) -> io::Result<OwnedFd> {
        self.attempts += 1;
        self.probe.event(Event::EnterAcquire(self.attempts));
        if self.faults.hold_acquire == Some(self.attempts) {
            self.probe.hold();
        }
        // Injection depends only on the independent invocation counter.
        if self
            .faults
            .fail_acquire_from
            .is_some_and(|n| self.attempts >= n)
        {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        self.acquired += 1;
        Ok(self.probe.acquire(self.acquired))
    }
}
impl CountIoDriver for PipeDriver {
    fn map_create(&mut self, _: &crate::loader::MapSpecLite) -> io::Result<OwnedFd> {
        self.acquire()
    }
    fn load_program(&mut self, _: &[u8], _: &str, log: Option<&mut [u8]>) -> io::Result<OwnedFd> {
        if let Some(log) = log {
            self.probe.event(Event::LogBuffer(log.len()));
            log[..4].copy_from_slice(b"test");
        } else if self.faults.quiet_failure {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.acquire()
    }
    fn open_pin(&mut self, _: &CStr) -> io::Result<OwnedFd> {
        self.acquire()
    }
    fn pin_identity(&mut self, _: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        Ok(BackingIdentity {
            device: 1,
            inode: 2,
        })
    }
    fn attach(
        &mut self,
        _: BorrowedFd<'_>,
        _: &CStr,
        _: &[u64],
        _: &[u64],
        _: u32,
    ) -> io::Result<OwnedFd> {
        self.acquire()
    }
    unsafe fn update(&mut self, _: BorrowedFd<'_>, _: &[u8], _: &[u8]) -> io::Result<()> {
        unreachable!("Task 2 does not program maps")
    }
    unsafe fn lookup(&mut self, _: BorrowedFd<'_>, _: &[u8], _: &mut [u8]) -> io::Result<()> {
        unreachable!("Task 2 does not read maps")
    }
    unsafe fn next_key(
        &mut self,
        _: BorrowedFd<'_>,
        _: Option<&[u8]>,
        _: &mut [u8],
    ) -> io::Result<()> {
        unreachable!("Task 2 does not enumerate maps")
    }
    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        // Consume before a test hold can discard ordinary OwnedFd RAII.
        let fd = std::mem::ManuallyDrop::new(fd);
        self.closes += 1;
        self.probe.event(Event::EnterClose);
        if self.faults.hold_close == Some(self.closes) {
            self.probe.hold();
        }
        let result = ossl_bpf_sys::close_owned(std::mem::ManuallyDrop::into_inner(fd));
        let result = if self.faults.fail_close == Some(self.closes) {
            result.unwrap();
            Err(io::Error::from_raw_os_error(libc::EINTR))
        } else {
            result
        };
        self.probe.event(Event::Closed(
            result.as_ref().err().and_then(io::Error::raw_os_error),
        ));
        result
    }
    fn now(&self) -> Instant {
        if self.faults.expire_after.is_some_and(|n| self.acquired >= n) {
            self.deadline + Duration::from_nanos(1)
        } else {
            Instant::now()
        }
    }
    fn monotonic_ns(&self) -> Option<u64> {
        Some(1)
    }
}
fn input(barrier: Arc<CountForkBarrier>) -> CountInput {
    use sha2::Digest as _;
    let bytes: Arc<[u8]> = count_elf().into();
    CountInput {
        object_sha256: sha2::Sha256::digest(&bytes).into(),
        object_bytes: bytes,
        target_tgid: 1,
        fork_barrier: barrier,
    }
}
fn injected(
    probe: Arc<Probe>,
    faults: Faults,
    barrier: Arc<CountForkBarrier>,
    deadline: Instant,
    mut hooks: PrepareHooks,
) -> Result<CountEngine, CountPrepareFailure> {
    let observed = Arc::clone(&probe);
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event))
    }));
    CountEngine::prepare_with(
        input(barrier),
        CountOwnerLimits::from_allowance(18, 2).unwrap(),
        deadline,
        hooks,
        move || {
            probe.event(Event::Started);
            PipeDriver {
                probe,
                faults,
                deadline,
                attempts: 0,
                acquired: 0,
                closes: 0,
            }
        },
        spawn_owner,
    )
}
#[test]
fn g1_prepare_before_first_fd() {
    let probe = Probe::new();
    let controller = std::thread::current().id();
    let engine = injected(
        Arc::clone(&probe),
        Faults::default(),
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(2),
        PrepareHooks::host(),
    )
    .unwrap();
    assert_eq!(engine.ready().evidence_domain, EvidenceDomain::HostModel);
    assert_eq!(engine.ready().dimensions.maps.len(), 7);
    assert_eq!(engine.ready().dimensions.root, "count_entry");
    {
        let log = probe.log.lock().unwrap();
        let started = log
            .events
            .iter()
            .position(|(_, e)| matches!(e, Event::Started))
            .unwrap();
        let first = log
            .events
            .iter()
            .position(|(_, e)| matches!(e, Event::EnterAcquire(_)));
        assert!(first.is_none_or(|i| started < i));
        assert!(
            log.events.iter().all(|(thread, _)| *thread != controller),
            "all count acquisition must run on the already-started owner, never the controller"
        );
        let entered: Vec<_> = log
            .events
            .iter()
            .filter_map(|(_, event)| {
                if let Event::EnterAcquire(n) = event {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(entered, (1..=8).collect::<Vec<_>>());
        for ordinal in 1..=8 {
            let acquire = log
                .events
                .iter()
                .position(|(_, e)| matches!(e, Event::Acquired(n) if *n == ordinal))
                .unwrap();
            assert!(matches!(
                log.events[acquire - 2].1,
                Event::Registry(RegistryEvent::Creating(_))
            ));
            assert!(matches!(
                log.events[acquire + 1].1,
                Event::Registry(RegistryEvent::Installed(_))
            ));
        }
    }
    drop(engine);
    probe.assert_cleanup(8, controller);
}
#[test]
fn g1_prepare_failure_custody() {
    let controller = std::thread::current().id();
    for acquired in 1..=8 {
        let probe = Probe::new();
        let failure = injected(
            Arc::clone(&probe),
            Faults {
                expire_after: Some(acquired),
                ..Faults::default()
            },
            Arc::new(CountForkBarrier::new()),
            Instant::now() + Duration::from_secs(2),
            PrepareHooks::host(),
        )
        .err()
        .unwrap();
        assert_eq!(failure.failure.class, FailureClass::Deadline);
        assert!(
            failure.cleanup_ticket.is_some(),
            "post-acquisition failure erased custody at {acquired}"
        );
        probe.assert_cleanup(acquired, controller);
    }
    for failure_at in 1..=8 {
        let probe = Probe::new();
        let failure = injected(
            Arc::clone(&probe),
            Faults {
                fail_acquire_from: Some(failure_at),
                ..Faults::default()
            },
            Arc::new(CountForkBarrier::new()),
            Instant::now() + Duration::from_secs(2),
            PrepareHooks::host(),
        )
        .err()
        .unwrap();
        assert_eq!(failure.failure.errno, Some(libc::EMFILE));
        assert!(failure.cleanup_ticket.is_some());
        probe.assert_cleanup(failure_at - 1, controller);
    }
    let probe = Probe::new();
    let mut hooks = PrepareHooks::host();
    hooks.fail_ready_publication = true;
    let failure = injected(
        Arc::clone(&probe),
        Faults::default(),
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(2),
        hooks,
    )
    .err()
    .unwrap();
    assert_eq!(failure.failure.class, FailureClass::Publication);
    assert!(failure.cleanup_ticket.is_some());
    probe.assert_cleanup(8, controller);
}
#[test]
fn g1_owner_limits_and_ids() {
    let limits_for = |a| CountOwnerLimits::from_allowance(a, 1);
    assert_eq!(limits_for(18).unwrap().link_slots, 1);
    assert_eq!(limits_for(16_400).unwrap().link_slots, 8192);
    assert!(limits_for(17).is_err());
    assert_eq!(limits_for(u64::MAX).unwrap().fd_reservation, 16_400);
    assert!(CountOwnerLimits::from_allowance(18, 0).is_err());
    assert!(CountOwnerLimits::from_allowance(18, usize::MAX).is_err());
    assert!(CountOwnerLimits::from_allowance(18, isize::MAX as usize / 24 + 1).is_err());
    assert_eq!(
        CountOwnerLimits::from_allowance(18, 3)
            .unwrap()
            .cpu_scratch_bytes,
        72
    );
    let mut ids = IdCounter::with_last(u64::MAX - 1);
    assert_eq!(ids.next().unwrap(), u64::MAX);
    assert_eq!(ids.next().unwrap_err().class, FailureClass::IdExhausted);
    assert!(ids.next().is_err(), "an exhausted ID must never be reused");
    let mut registry = Registry::allocate(limits_for(18).unwrap()).unwrap();
    for _ in 0..8 {
        registry.reserve(ResourceKind::Transient).unwrap();
    }
    assert_eq!(
        registry.reserve(ResourceKind::Transient).unwrap_err().class,
        FailureClass::Capacity
    );
    assert_eq!(registry.summary().resources.len(), 18);
}
#[test]
fn g1_prepare_pre_spawn_failure_opens_nothing() {
    for allocation in [true, false] {
        let probe = Probe::new();
        let factory_log = Arc::clone(&probe);
        let barrier = Arc::new(CountForkBarrier::new());
        let mut hooks = PrepareHooks::host();
        hooks.fail_allocation = allocation;
        let failure = CountEngine::prepare_with(
            input(Arc::clone(&barrier)),
            CountOwnerLimits::from_allowance(18, 1).unwrap(),
            Instant::now() + Duration::from_secs(1),
            hooks,
            move || {
                factory_log.event(Event::Started);
                PipeDriver {
                    probe: factory_log,
                    faults: Faults::default(),
                    deadline: Instant::now(),
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                }
            },
            |_| Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        )
        .err()
        .unwrap();
        assert_eq!(
            failure.failure.class,
            if allocation {
                FailureClass::Allocation
            } else {
                FailureClass::Io
            }
        );
        assert_eq!(failure.cleanup_ticket, None);
        assert!(probe.log.lock().unwrap().events.is_empty());
        assert!(barrier.prefix_permit(Instant::now()).is_ok());
    }
}
#[test]
fn g1_prepare_blocked_cancellation_keeps_one_ticket() {
    let probe = Probe::new();
    let barrier = Arc::new(CountForkBarrier::new());
    let failure = injected(
        Arc::clone(&probe),
        Faults {
            hold_acquire: Some(1),
            ..Faults::default()
        },
        Arc::clone(&barrier),
        Instant::now() + Duration::from_millis(80),
        PrepareHooks::host(),
    )
    .err()
    .unwrap();
    let ticket = failure
        .cleanup_ticket
        .expect("blocked create must retain its owner ticket");
    assert_eq!(failure.failure.class, FailureClass::Deadline);
    assert!(barrier.prefix_permit(Instant::now()).is_err());
    assert!(
        barrier
            .terminal_permit(ticket.owner_epoch, Instant::now())
            .is_err()
    );
    let second = Probe::new();
    assert!(
        injected(
            Arc::clone(&second),
            Faults::default(),
            Arc::clone(&barrier),
            Instant::now() + Duration::from_millis(10),
            PrepareHooks::host()
        )
        .is_err()
    );
    assert!(
        second.log.lock().unwrap().events.is_empty(),
        "unresolved epoch admitted another owner"
    );
    probe.release();
    probe.assert_cleanup(1, std::thread::current().id());
    assert!(
        barrier
            .terminal_permit(ticket.owner_epoch, Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}
#[test]
fn g1_prepare_fork_permits_exclude_acquisition() {
    let barrier = Arc::new(CountForkBarrier::new());
    let permit = barrier.prefix_permit(Instant::now()).unwrap();
    let probe = Probe::new();
    assert!(
        injected(
            Arc::clone(&probe),
            Faults::default(),
            Arc::clone(&barrier),
            Instant::now() + Duration::from_millis(20),
            PrepareHooks::host()
        )
        .is_err()
    );
    assert!(probe.log.lock().unwrap().events.is_empty());
    drop(permit);
    let engine = injected(
        Arc::clone(&probe),
        Faults::default(),
        Arc::clone(&barrier),
        Instant::now() + Duration::from_secs(2),
        PrepareHooks::host(),
    )
    .unwrap();
    assert!(barrier.prefix_permit(Instant::now()).is_err());
    assert!(engine.fork_permit(Instant::now()).is_err());
    engine.abandon();
    let permit = engine
        .fork_permit(Instant::now() + Duration::from_secs(2))
        .unwrap();
    let second = Probe::new();
    assert!(
        injected(
            Arc::clone(&second),
            Faults::default(),
            Arc::clone(&barrier),
            Instant::now() + Duration::from_millis(20),
            PrepareHooks::host()
        )
        .is_err()
    );
    assert!(second.log.lock().unwrap().events.is_empty());
    drop(permit);
    probe.assert_cleanup(8, std::thread::current().id());
}
#[test]
fn g1_prepare_drop_does_not_join_blocked_cleanup() {
    let probe = Probe::new();
    let engine = injected(
        Arc::clone(&probe),
        Faults {
            hold_close: Some(1),
            ..Faults::default()
        },
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(2),
        PrepareHooks::host(),
    )
    .unwrap();
    engine.abandon();
    probe.wait(|events| events.iter().any(|(_, e)| matches!(e, Event::EnterClose)));
    assert!(engine.fork_permit(Instant::now()).is_err());
    let before = Instant::now();
    drop(engine);
    assert!(
        before.elapsed() < Duration::from_millis(100),
        "coordinator Drop joined cleanup"
    );
    probe.release();
    probe.assert_cleanup(8, std::thread::current().id());
}
#[test]
fn g1_prepare_consumed_close_error_blocks_forks() {
    let probe = Probe::new();
    let engine = injected(
        Arc::clone(&probe),
        Faults {
            fail_close: Some(1),
            ..Faults::default()
        },
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(2),
        PrepareHooks::host(),
    )
    .unwrap();
    engine.abandon();
    probe.assert_cleanup(8, std::thread::current().id());
    assert!(engine.fork_permit(Instant::now()).is_err());
    let summary = engine.resource_summary();
    assert_eq!(
        summary
            .resources
            .iter()
            .filter(|r| r.errno == Some(libc::EINTR))
            .count(),
        1
    );
    assert!(
        !summary.cleanup_complete,
        "FD-count/pipe evidence cannot resolve a consumed-error outcome"
    );
    assert_eq!(
        locked(&engine.shared.state).phase,
        OwnerPhase::Cleaning,
        "an unresolved registry cannot report an idle/retired worker"
    );
    assert_eq!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Closed(Some(libc::EINTR))))
            .count(),
        1
    );
}
#[test]
fn g1_prepare_blocked_cleanup_publishes_exact_progress() {
    let probe = Probe::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    let engine = injected(
        Arc::clone(&probe),
        Faults {
            fail_close: Some(1),
            hold_close: Some(2),
            ..Faults::default()
        },
        Arc::new(CountForkBarrier::new()),
        deadline,
        PrepareHooks::host(),
    )
    .unwrap();
    engine.abandon();
    probe.wait(|events| {
        events
            .iter()
            .filter(|(_, e)| matches!(e, Event::EnterClose))
            .count()
            == 2
    });
    // Capture first, release the hold before any assertion can unwind the test.
    let summary = engine.resource_summary();
    let ticket = engine.shared.seal(deadline + Duration::from_secs(1));
    let actual_deadline = locked(&engine.shared.state).terminal.unwrap().deadline;
    probe.release();
    probe.assert_cleanup(8, std::thread::current().id());
    assert_eq!(
        summary
            .resources
            .iter()
            .filter(|r| r.state == ResourceState::ConsumedError && r.errno == Some(libc::EINTR))
            .count(),
        1,
        "a later blocked close erased the earlier consumed-error outcome from progress"
    );
    assert_eq!(
        summary
            .resources
            .iter()
            .filter(|r| r.state == ResourceState::CloseIssued)
            .count(),
        1,
        "progress must identify the actual currently blocked close"
    );
    assert!(summary.sealed);
    assert!(!summary.cleanup_complete);
    assert_eq!(ticket.owner_epoch, engine.ready().owner_epoch);
    assert_eq!(
        actual_deadline, deadline,
        "a repeated seal extended the canonical deadline"
    );
}

#[test]
fn g1_prepare_unwind_retains_installed_fds() {
    let probe = Probe::new();
    let observed = Arc::clone(&probe);
    let mut hooks = PrepareHooks::host();
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event));
        if matches!(event, RegistryEvent::Installed(_)) {
            panic!("installed-FD unwind control");
        }
    }));
    let factory_log = Arc::clone(&probe);
    let deadline = Instant::now() + Duration::from_secs(2);
    let failure = CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance(18, 1).unwrap(),
        deadline,
        hooks,
        move || {
            factory_log.event(Event::Started);
            PipeDriver {
                probe: factory_log,
                faults: Faults::default(),
                deadline,
                attempts: 0,
                acquired: 0,
                closes: 0,
            }
        },
        spawn_owner,
    )
    .err()
    .unwrap();
    assert_eq!(failure.failure.class, FailureClass::Panic);
    assert!(failure.cleanup_ticket.is_some());
    probe.assert_cleanup(1, std::thread::current().id());
}
#[test]
fn g1_prepare_bounded_verifier_retry_and_shape_rejection() {
    let probe = Probe::new();
    let engine = injected(
        Arc::clone(&probe),
        Faults {
            quiet_failure: true,
            ..Faults::default()
        },
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(2),
        PrepareHooks::host(),
    )
    .unwrap();
    assert!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::LogBuffer(n) if *n == 4 << 20))
    );
    drop(engine);
    probe.assert_cleanup(8, std::thread::current().id());
    for drift in 0..5 {
        let mut prep = crate::loader::prepare(
            &count_elf(),
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
        )
        .unwrap();
        match drift {
            0 => prep.maps[0].value_size += 1,
            1 => prep.progs[0].is_return = true,
            2 => prep.progs[0].subprogs[0].is_callback = true,
            3 => prep.progs[0].insns[..8].copy_from_slice(&[0x85, 0, 0, 0, 12, 0, 0, 0]),
            _ => prep.progs[0].name = "extra_writer".into(),
        }
        assert!(crate::loader::validate_count_prepared(&prep).is_err());
    }
}
// Exact seven-map, one-root relocatable object, parsed by the real pure loader.
fn count_elf() -> Vec<u8> {
    fn p16(b: &mut [u8], o: usize, n: u16) {
        b[o..o + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn p32(b: &mut [u8], o: usize, n: u32) {
        b[o..o + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn p64(b: &mut [u8], o: usize, n: u64) {
        b[o..o + 8].copy_from_slice(&n.to_le_bytes());
    }
    let mut shstr = Vec::new();
    let mut names = Vec::new();
    for n in [
        "",
        ".shstrtab",
        ".strtab",
        ".symtab",
        "maps",
        "uprobe",
        ".reluprobe",
    ] {
        names.push(shstr.len());
        shstr.extend_from_slice(n.as_bytes());
        shstr.push(0);
    }
    let mut strings = b"\0count_entry\0".to_vec();
    let mut map_names = Vec::new();
    let mut maps = Vec::new();
    for m in crate::loader::COUNT_MAPS {
        map_names.push(strings.len());
        strings.extend_from_slice(m.name.as_bytes());
        strings.push(0);
        for n in [
            m.map_type,
            m.key_size,
            m.value_size,
            m.max_entries,
            m.flags,
            0,
            0,
        ] {
            maps.extend_from_slice(&n.to_le_bytes());
        }
    }
    let mut insns = vec![0u8; 7 * 16];
    for i in 0..7 {
        insns[i * 16] = 0x18;
        insns[i * 16 + 1] = 1;
    }
    insns.extend_from_slice(&[0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]);
    let mut syms = vec![0u8; 9 * 24];
    p32(&mut syms, 24, 1);
    syms[28] = 0x12;
    p16(&mut syms, 30, 5);
    p64(&mut syms, 40, insns.len() as u64);
    let mut relocs = vec![0u8; 7 * 16];
    for (i, n) in map_names.into_iter().enumerate() {
        let o = (i + 2) * 24;
        p32(&mut syms, o, n as u32);
        syms[o + 4] = 0x11;
        p16(&mut syms, o + 6, 4);
        p64(&mut syms, o + 8, (i * 28) as u64);
        p64(&mut syms, o + 16, 28);
        p64(&mut relocs, i * 16, (i * 16) as u64);
        p64(&mut relocs, i * 16 + 8, ((i as u64 + 2) << 32) | 1);
    }
    let sections = [Vec::new(), shstr, strings, syms, maps, insns, relocs];
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    p16(&mut elf, 16, 1);
    p16(&mut elf, 18, 247);
    p32(&mut elf, 20, 1);
    p16(&mut elf, 52, 64);
    p16(&mut elf, 58, 64);
    p16(&mut elf, 60, 7);
    p16(&mut elf, 62, 1);
    let mut offsets = Vec::new();
    for sec in &sections {
        while elf.len() % 8 != 0 {
            elf.push(0);
        }
        offsets.push(elf.len());
        elf.extend_from_slice(sec);
    }
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let shoff = elf.len();
    p64(&mut elf, 40, shoff as u64);
    elf.resize(shoff + 7 * 64, 0);
    for i in 1..7 {
        let o = shoff + i * 64;
        p32(&mut elf, o, names[i] as u32);
        p32(
            &mut elf,
            o + 4,
            match i {
                1 | 2 => 3,
                3 => 2,
                6 => 9,
                _ => 1,
            },
        );
        p64(&mut elf, o + 8, if i == 5 { 6 } else { 0 });
        p64(&mut elf, o + 24, offsets[i] as u64);
        p64(&mut elf, o + 32, sections[i].len() as u64);
        p64(&mut elf, o + 48, 8);
        if i == 3 {
            p32(&mut elf, o + 40, 2);
            p32(&mut elf, o + 44, 1);
            p64(&mut elf, o + 56, 24);
        }
        if i == 6 {
            p32(&mut elf, o + 40, 3);
            p32(&mut elf, o + 44, 5);
            p64(&mut elf, o + 56, 16);
        }
    }
    elf
}
