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
    Mailbox(MailboxEvent),
    EnterAcquire(usize),
    Acquired(usize),
    EnterClose,
    Closed(Option<i32>),
    LogBuffer(usize),
    PinOpen,
    PinOpened(i32),
    PinIdentity(i32),
    AttachEntered(usize, Vec<u64>, Vec<u64>, String),
    AttachCreated(usize),
    PinClose,
    PinCloseResult(Option<i32>),
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
            log.events
                .iter()
                .filter(|(_, e)| !matches!(e, Event::Mailbox(_)))
                .all(|(t, _)| *t != controller),
            "count I/O escaped the owner"
        );
        if let Some((owner, _)) = log
            .events
            .iter()
            .find(|(_, event)| matches!(event, Event::Started))
        {
            assert!(
                log.events
                    .iter()
                    .filter(|(_, e)| !matches!(e, Event::Mailbox(_)))
                    .all(|(thread, _)| thread == owner),
                "count I/O moved to another worker"
            );
        }
        for (_, event) in &log.events {
            if let Event::Registry(event) = event {
                assert_ne!(event.resource(), ResourceId::Engine);
            }
        }
        // One probe can include a pre-epoch admission refusal followed by the
        // real FD-owning attempt. Inspect the cells of that actual attempt.
        let first_acquire = log
            .events
            .iter()
            .position(|(_, e)| matches!(e, Event::EnterAcquire(_)))
            .unwrap_or(log.events.len());
        if let Some((constructed_at, (request_cell, reply_cell))) = log.events[..first_acquire]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, (_, e))| {
                if let Event::Mailbox(MailboxEvent::Constructed { request, reply }) = e {
                    Some((i, (*request, *reply)))
                } else {
                    None
                }
            })
        {
            assert_ne!(request_cell, 0);
            assert_ne!(reply_cell, 0);
            assert_ne!(request_cell, reply_cell);
            let mut published = None;
            let mut taken = None;
            let mut replies = 0;
            let mut received = 0;
            for (i, (thread, event)) in log.events.iter().enumerate().skip(constructed_at) {
                match event {
                    Event::Mailbox(MailboxEvent::RequestPublished(cell)) => {
                        assert_eq!(*cell, request_cell);
                        assert_eq!(*thread, controller);
                        assert!(
                            published.replace(i).is_none(),
                            "another preparation request was admitted"
                        );
                    }
                    Event::Mailbox(MailboxEvent::RequestTaken(cell)) => {
                        assert_eq!(*cell, request_cell);
                        assert_ne!(*thread, controller);
                        assert!(
                            taken.replace(i).is_none(),
                            "request payload was consumed twice"
                        );
                    }
                    Event::Mailbox(MailboxEvent::ReplyPublished(cell)) => {
                        assert_eq!(*cell, reply_cell);
                        assert_ne!(*thread, controller);
                        replies += 1;
                    }
                    Event::Mailbox(MailboxEvent::ReplyTaken(cell)) => {
                        assert_eq!(*cell, reply_cell);
                        assert_eq!(*thread, controller);
                        received += 1;
                    }
                    _ => {}
                }
            }
            assert!(
                replies <= 1 && received <= 1,
                "setup reply cell was overwritten or consumed twice"
            );
            if let Some(first_acquire) = log
                .events
                .iter()
                .position(|(_, e)| matches!(e, Event::EnterAcquire(_)))
            {
                assert!(
                    constructed_at < published.unwrap()
                        && published.unwrap() < taken.unwrap()
                        && taken.unwrap() < first_acquire,
                    "actual request ownership did not precede acquisition"
                );
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
    let observed = Arc::clone(&probe);
    hooks.mailbox_observer = Some(Arc::new(move |event| observed.event(Event::Mailbox(event))));
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
fn g1_prepare_mailbox_before_first_fd() {
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
    drop(engine);
    probe.assert_cleanup(8, controller);
    let events = probe.log.lock().unwrap().events.clone();
    let first_acquire = events
        .iter()
        .position(|(_, e)| matches!(e, Event::EnterAcquire(_)))
        .unwrap();
    let constructed = events
        .iter()
        .position(|(_, e)| matches!(e, Event::Mailbox(MailboxEvent::Constructed { .. })));
    assert!(
        constructed.is_some_and(|i| i < first_acquire),
        "real preparation acquired eight FDs without the preallocated request/reply cells before acquisition: constructed={constructed:?}, first_acquire={first_acquire}"
    );
    let submitted = events
        .iter()
        .position(|(_, e)| matches!(e, Event::Mailbox(MailboxEvent::RequestPublished(_))))
        .unwrap();
    let taken = events
        .iter()
        .position(|(_, e)| matches!(e, Event::Mailbox(MailboxEvent::RequestTaken(_))))
        .unwrap();
    let replied = events
        .iter()
        .position(|(_, e)| matches!(e, Event::Mailbox(MailboxEvent::ReplyPublished(_))))
        .unwrap();
    let received = events
        .iter()
        .position(|(_, e)| matches!(e, Event::Mailbox(MailboxEvent::ReplyTaken(_))))
        .unwrap();
    assert!(
        constructed.unwrap() < submitted
            && submitted < taken
            && taken < first_acquire
            && first_acquire < replied
            && replied < received
    );
}

#[test]
fn g1_prepare_mailbox_capacity_and_ownership() {
    #[derive(Debug)]
    struct Payload {
        id: u8,
        drops: Arc<Mutex<Vec<u8>>>,
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.drops.lock().unwrap().push(self.id);
        }
    }
    let drops = Arc::new(Mutex::new(Vec::with_capacity(7)));
    let payload = |id| Payload {
        id,
        drops: Arc::clone(&drops),
    };
    let mut cells = OrdinaryCells::<Payload, Payload>::new();
    let request_address = &cells.request as *const _ as usize;
    let reply_address = &cells.reply as *const _ as usize;
    assert_ne!(request_address, reply_address);
    let unsolicited = cells.publish_reply(payload(0)).unwrap_err();
    assert!(drops.lock().unwrap().is_empty());
    drop(unsolicited);
    cells.publish_request(payload(1)).unwrap();
    let rejected_request = cells.publish_request(payload(2)).unwrap_err();
    assert_eq!(rejected_request.id, 2);
    let owned_request = cells.take_request().unwrap();
    assert_eq!(owned_request.id, 1);
    assert!(cells.take_request().is_none());
    let while_executing = cells.publish_request(payload(3)).unwrap_err();
    assert_eq!(
        while_executing.id, 3,
        "taking the request freed the in-flight command allowance"
    );
    cells.publish_reply(payload(4)).unwrap();
    let rejected_reply = cells.publish_reply(payload(5)).unwrap_err();
    assert_eq!(rejected_reply.id, 5);
    let while_reply_pending = cells.publish_request(payload(6)).unwrap_err();
    assert_eq!(
        while_reply_pending.id, 6,
        "a pending reply admitted another request"
    );
    assert_eq!(
        *drops.lock().unwrap(),
        vec![0],
        "refused or moved payloads were silently dropped"
    );
    let received = cells.take_reply().unwrap();
    assert_eq!(
        received.id, 4,
        "the duplicate reply replaced the original payload"
    );
    assert!(cells.take_reply().is_none());
    cells.publish_request(while_reply_pending).unwrap();
    assert_eq!(&cells.request as *const _ as usize, request_address);
    assert_eq!(&cells.reply as *const _ as usize, reply_address);
    drop((
        cells,
        owned_request,
        received,
        rejected_request,
        while_executing,
        rejected_reply,
    ));
    let mut actual = drops.lock().unwrap().clone();
    actual.sort_unstable();
    assert_eq!(
        actual,
        (0..=6).collect::<Vec<_>>(),
        "mailbox payload ownership was duplicated or lost"
    );
}

#[test]
fn g1_prepare_mailbox_pre_spawn_abort_releases_input() {
    for allocation_failure in [true, false] {
        let probe = Probe::new();
        let barrier = Arc::new(CountForkBarrier::new());
        let input = input(Arc::clone(&barrier));
        let source = Arc::downgrade(&input.object_bytes);
        let during_spawn = source.clone();
        let observed = Arc::clone(&probe);
        let mut hooks = PrepareHooks::host();
        hooks.fail_allocation = allocation_failure;
        hooks.mailbox_observer = Some(Arc::new(move |event| observed.event(Event::Mailbox(event))));
        let at_spawn = Arc::clone(&probe);
        let failure = CountEngine::prepare_with(
            input,
            CountOwnerLimits::from_allowance(18, 1).unwrap(),
            Instant::now() + Duration::from_secs(2),
            hooks,
            || -> PipeDriver {
                panic!("failed preparation must not construct a driver");
            },
            move |task| {
                assert!(
                    during_spawn.upgrade().is_some(),
                    "the request lost its owned source bytes before spawn"
                );
                {
                    let log = at_spawn.log.lock().unwrap();
                    assert_eq!(
                        log.events
                            .iter()
                            .filter(|(_, e)| matches!(
                                e,
                                Event::Mailbox(MailboxEvent::Constructed { .. })
                            ))
                            .count(),
                        1
                    );
                    assert_eq!(
                        log.events
                            .iter()
                            .filter(|(_, e)| matches!(
                                e,
                                Event::Mailbox(MailboxEvent::RequestPublished(_))
                            ))
                            .count(),
                        1
                    );
                }
                drop(task);
                assert!(
                    during_spawn.upgrade().is_some(),
                    "dropping the unstarted task erased the shared request cell's ownership"
                );
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            },
        )
        .err()
        .unwrap();
        assert_eq!(failure.cleanup_ticket, None);
        assert_eq!(
            failure.failure.class,
            if allocation_failure {
                FailureClass::Allocation
            } else {
                FailureClass::Io
            }
        );
        assert!(
            source.upgrade().is_none(),
            "an aborted, unstarted request retained its source bytes"
        );
        let log = probe.log.lock().unwrap();
        assert!(
            log.events
                .iter()
                .all(|(_, e)| matches!(e, Event::Mailbox(_))),
            "pre-spawn abort entered count I/O"
        );
        assert_eq!(log.events.len(), if allocation_failure { 0 } else { 2 });
        assert!(barrier.prefix_permit(Instant::now()).is_ok());
    }
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
            log.events
                .iter()
                .filter(|(_, e)| !matches!(e, Event::Mailbox(_)))
                .all(|(thread, _)| *thread != controller),
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
        second
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .all(|(_, e)| matches!(e, Event::Mailbox(_))),
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
    assert!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .all(|(_, e)| matches!(e, Event::Mailbox(_)))
    );
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
    assert!(
        second
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .all(|(_, e)| matches!(e, Event::Mailbox(_)))
    );
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

// Task 3 tests use real pipe descriptors and an invocation log independent of
// the registry. A syscall attempt ordinal is the expected never-reused serial.
#[derive(Clone, Copy, Default)]
enum IdentityFault {
    #[default]
    None,
    Io,
    Replaced,
    Panic,
    Hold,
}
#[derive(Default)]
struct AttachFaults {
    open_error: bool,
    open_errno: Option<i32>,
    attach_errno: Option<i32>,
    attach_errno_from: usize,
    identity: IdentityFault,
    bad_offset: Option<u64>,
    all_bad: bool,
    hold_attempt: Option<usize>,
    hold_pin_close: bool,
    pin_close_errno: Option<i32>,
    real_pin: bool,
    post_handler_clock_panic: bool,
}
struct AttachDriver {
    base: PipeDriver,
    faults: AttachFaults,
    pin: Option<i32>,
    attaches: usize,
    clock_after_create: std::cell::Cell<usize>,
}
impl CountIoDriver for AttachDriver {
    fn map_create(&mut self, s: &crate::loader::MapSpecLite) -> io::Result<OwnedFd> {
        self.base.map_create(s)
    }
    fn load_program(&mut self, i: &[u8], n: &str, l: Option<&mut [u8]>) -> io::Result<OwnedFd> {
        self.base.load_program(i, n, l)
    }
    fn open_pin(&mut self, locator: &CStr) -> io::Result<OwnedFd> {
        self.base.probe.event(Event::PinOpen);
        if let Some(errno) = self.faults.open_errno {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if self.faults.open_error {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let pin = if self.faults.real_pin {
            self.base.attempts += 1;
            self.base
                .probe
                .event(Event::EnterAcquire(self.base.attempts));
            let pin = LiveCountIoDriver.open_pin(locator)?;
            self.base.acquired += 1;
            self.base.probe.event(Event::Acquired(self.base.acquired));
            pin
        } else {
            self.base.acquire()?
        };
        self.pin = Some(pin.as_raw_fd());
        self.base.probe.event(Event::PinOpened(pin.as_raw_fd()));
        Ok(pin)
    }
    fn pin_identity(&mut self, pin: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        assert_eq!(Some(pin.as_raw_fd()), self.pin);
        self.base.probe.event(Event::PinIdentity(pin.as_raw_fd()));
        if self.faults.real_pin {
            return LiveCountIoDriver.pin_identity(pin);
        }
        match self.faults.identity {
            IdentityFault::Io => return Err(io::Error::from_raw_os_error(libc::EIO)),
            IdentityFault::Replaced => {
                return Ok(BackingIdentity {
                    device: 1,
                    inode: 3,
                });
            }
            IdentityFault::Panic => panic!("installed-pin fstat unwind control"),
            IdentityFault::Hold => self.base.probe.hold(),
            IdentityFault::None => {}
        }
        Ok(BackingIdentity {
            device: 1,
            inode: 2,
        })
    }
    fn attach(
        &mut self,
        _: BorrowedFd<'_>,
        path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        tgid: u32,
    ) -> io::Result<OwnedFd> {
        self.attaches += 1;
        assert_eq!(tgid, 1);
        let path = path.to_str().unwrap().to_owned();
        assert_eq!(path, format!("/proc/self/fd/{}", self.pin.unwrap()));
        self.base.probe.event(Event::AttachEntered(
            self.attaches,
            offsets.to_vec(),
            cookies.to_vec(),
            path,
        ));
        if self.faults.hold_attempt == Some(self.attaches) {
            self.base.probe.hold();
        }
        if let Some(errno) = self
            .faults
            .attach_errno
            .filter(|_| self.attaches >= self.faults.attach_errno_from)
        {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if self.faults.all_bad
            || self
                .faults
                .bad_offset
                .is_some_and(|bad| offsets.contains(&bad))
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let fd = self.base.acquire()?;
        self.base.probe.event(Event::AttachCreated(self.attaches));
        Ok(fd)
    }
    unsafe fn update(&mut self, _: BorrowedFd<'_>, _: &[u8], _: &[u8]) -> io::Result<()> {
        unreachable!()
    }
    unsafe fn lookup(&mut self, _: BorrowedFd<'_>, _: &[u8], _: &mut [u8]) -> io::Result<()> {
        unreachable!()
    }
    unsafe fn next_key(
        &mut self,
        _: BorrowedFd<'_>,
        _: Option<&[u8]>,
        _: &mut [u8],
    ) -> io::Result<()> {
        unreachable!()
    }
    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        if self.pin == Some(fd.as_raw_fd()) {
            let fd = std::mem::ManuallyDrop::new(fd);
            self.base.probe.event(Event::PinClose);
            if self.faults.hold_pin_close {
                self.base.probe.hold();
            }
            let result = self.base.close(std::mem::ManuallyDrop::into_inner(fd));
            if let Some(errno) = self.faults.pin_close_errno {
                result.unwrap();
                self.base.probe.event(Event::PinCloseResult(Some(errno)));
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.base.probe.event(Event::PinCloseResult(
                result.as_ref().err().and_then(io::Error::raw_os_error),
            ));
            return result;
        }
        self.base.close(fd)
    }
    fn now(&self) -> Instant {
        if self.faults.post_handler_clock_panic && self.attaches > 0 {
            let n = self.clock_after_create.get() + 1;
            self.clock_after_create.set(n);
            assert_ne!(n, 2, "post-attach clock unwind control");
        }
        Instant::now()
    }
    fn monotonic_ns(&self) -> Option<u64> {
        Some(1)
    }
}
fn attach_engine(
    probe: &Arc<Probe>,
    faults: AttachFaults,
    links: usize,
    fail_publication: bool,
) -> CountEngine {
    let observed = Arc::clone(probe);
    let mut hooks = PrepareHooks::host();
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event))
    }));
    hooks.fail_attach_publication = fail_publication;
    let probe = Arc::clone(probe);
    CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance((links as u64) * 2 + 16, 2).unwrap(),
        Instant::now() + Duration::from_secs(5),
        hooks,
        move || {
            probe.event(Event::Started);
            AttachDriver {
                base: PipeDriver {
                    probe,
                    faults: Faults::default(),
                    deadline: Instant::now(),
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                },
                faults,
                pin: None,
                attaches: 0,
                clock_after_create: std::cell::Cell::new(0),
            }
        },
        spawn_owner,
    )
    .unwrap()
}
fn attach_request(seq: u64, n: usize) -> AttachRequest {
    AttachRequest {
        seq: CommandSeq::checked(seq).unwrap(),
        deadline: Instant::now() + Duration::from_secs(10),
        expected_backing: BackingIdentity {
            device: 1,
            inode: 2,
        },
        locator: "/provider".into(),
        offsets: (0..n as u64).collect(),
        cookies: (100..100 + n as u64).collect(),
    }
}
fn task3_inventory(engine: &CountEngine) -> Result<SealedInventory, InventoryFailure> {
    let cutoff = Instant::now() + Duration::from_secs(5);
    let mut state = locked(&engine.shared.state);
    loop {
        if let Some(inventory) = &state.inventory {
            return inventory.clone();
        }
        let remaining = cutoff.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "owner did not seal inventory");
        state = engine
            .shared
            .changed
            .wait_timeout(state, remaining)
            .unwrap()
            .0;
    }
}
fn task3_cleanup(probe: &Probe, expected: usize) {
    probe.wait(|events| {
        events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Closed(_)))
            .count()
            == expected
            && events
                .iter()
                .filter(|(_, e)| matches!(e, Event::Registry(RegistryEvent::CloseReturned(_))))
                .count()
                == expected
    });
    let log = probe.log.lock().unwrap();
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
            .filter(|(_, e)| matches!(e, Event::EnterClose))
            .count(),
        expected
    );
    let owner = log
        .events
        .iter()
        .find(|(_, e)| matches!(e, Event::Started))
        .unwrap()
        .0;
    assert_ne!(owner, std::thread::current().id());
    assert!(
        log.events
            .iter()
            .filter(|(_, e)| !matches!(e, Event::Mailbox(_)))
            .all(|(thread, _)| *thread == owner),
        "count I/O or registry work escaped the prepared owner"
    );
    assert_eq!(
        log.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Registry(RegistryEvent::CloseIssued(_))))
            .count(),
        expected
    );
    assert_eq!(
        log.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Registry(RegistryEvent::CloseReturned(_))))
            .count(),
        expected
    );
    // This bounded pipe oracle accounts for the existing raw-fork CLOEXEC
    // fixture, and grants no writer-completion or fork-permit credit.
    for witness in &log.witnesses {
        let mut p = libc::pollfd {
            fd: witness.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        let cutoff = Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "independent pipe still has a reader");
            // SAFETY: p is a live initialized one-element poll array.
            let result = unsafe { libc::poll(&mut p, 1, remaining.as_millis().max(1) as i32) };
            if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(result, 1);
            assert_ne!(p.revents & libc::POLLERR, 0);
            break;
        }
    }
}
fn independent_successes(probe: &Probe) -> Vec<u64> {
    probe
        .log
        .lock()
        .unwrap()
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::AttachCreated(n) = e {
                Some(*n as u64)
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn g1_unpublished_bisection_survivor() {
    // Dropping a successful-but-unpublished survivor or its pin must fail this
    // independent syscall/journal equality and exact owner cleanup control.
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            bad_offset: Some(1),
            ..Default::default()
        },
        3,
        true,
    );
    let failure = engine.attach(attach_request(1, 3)).unwrap_err();
    assert_eq!(failure.failure.class, FailureClass::Publication);
    assert_eq!(failure.completion, CommandCompletion::Completed);
    assert!(failure.cleanup_ticket.is_some());
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(independent_successes(&probe), vec![2, 5]);
    assert_eq!(
        inventory
            .records
            .iter()
            .map(|r| r.id.serial.value())
            .collect::<Vec<_>>(),
        vec![2, 5]
    );
    assert_eq!(inventory.unpublished_links.len(), 2);
    assert!(inventory.acknowledged_links.is_empty());
    assert_eq!(
        inventory
            .memberships
            .iter()
            .map(|m| (m.offset, m.cookie))
            .collect::<Vec<_>>(),
        vec![(0, 100), (2, 102)]
    );
    assert!(
        inventory
            .records
            .iter()
            .all(|r| r.publication == PublicationState::Unpublished)
    );
    task3_cleanup(&probe, 11);
}

#[test]
fn g1_attach_stops_after_sealed_create() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            bad_offset: Some(1),
            hold_attempt: Some(2),
            ..Default::default()
        },
        3,
        false,
    );
    std::thread::scope(|scope| {
        let caller = scope.spawn(|| engine.attach(attach_request(1, 3)));
        probe.wait(|events| {
            events
                .iter()
                .any(|(_, e)| matches!(e, Event::AttachEntered(2, ..)))
        });
        let deadline = Instant::now();
        let ticket = engine.shared.seal(deadline);
        assert!(engine.fork_permit(Instant::now()).is_err());
        probe.release();
        let failure = caller.join().unwrap().unwrap_err();
        assert_eq!(failure.cleanup_ticket, Some(ticket));
        assert_eq!(failure.failure.class, FailureClass::Disconnected);
        assert_eq!(
            engine.shared.seal(Instant::now() + Duration::from_secs(5)),
            ticket
        );
        assert_eq!(
            locked(&engine.shared.state).terminal.unwrap().deadline,
            deadline
        );
    });
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.unpublished_links.len(), 1);
    assert_eq!(independent_successes(&probe), vec![2]);
    assert_eq!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::AttachEntered(..)))
            .count(),
        2,
        "a bisection create followed sealing"
    );
    task3_cleanup(&probe, 10);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn g1_attach_boundaries() {
    let probe = Probe::new();
    let engine = attach_engine(&probe, AttachFaults::default(), 2, false);
    for (i, mut request) in [
        {
            let mut r = attach_request(1, 1);
            r.locator = "x".repeat(4096);
            r
        },
        {
            let mut r = attach_request(1, 1);
            r.locator = "bad\0path".into();
            r
        },
        {
            let mut r = attach_request(1, 1);
            r.cookies.clear();
            r
        },
        attach_request(1, 8193),
        attach_request(1, 0),
    ]
    .into_iter()
    .enumerate()
    {
        request.seq = CommandSeq::checked(i as u64 + 1).unwrap();
        let failure = engine.attach(request).unwrap_err();
        assert_eq!(failure.failure.class, FailureClass::InvalidInput);
        assert_eq!(failure.completion, CommandCompletion::NotEntered);
    }
    assert!(
        !probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::PinOpen | Event::AttachEntered(..)))
    );
    let mut request = attach_request(6, 1);
    request.locator = "x".repeat(4095);
    assert_eq!(engine.attach(request).unwrap().value.links.len(), 1);
    engine.abandon();
    task3_cleanup(&probe, 10);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );

    // The actual driver must see 16,383 attempts for the all-bad 8192-position
    // batch. An accidental 8192-attempt ceiling cannot satisfy this control.
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            all_bad: true,
            ..Default::default()
        },
        1,
        false,
    );
    let ack = engine.attach(attach_request(1, 8192)).unwrap().value;
    assert_eq!(ack.refused.len(), 8192);
    assert_eq!(
        ack.refused.iter().map(|r| r.position).collect::<Vec<_>>(),
        (0..8192).collect::<Vec<_>>()
    );
    assert!(ack.links.is_empty());
    assert_eq!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::AttachEntered(..)))
            .count(),
        16383
    );
    engine.abandon();
    assert!(task3_inventory(&engine).unwrap().records.is_empty());
    task3_cleanup(&probe, 9);
}

#[test]
fn g1_attach_identity_is_owner_verified() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            identity: IdentityFault::Replaced,
            ..Default::default()
        },
        1,
        false,
    );
    let ack = engine.attach(attach_request(1, 1)).unwrap().value;
    assert!(ack.links.is_empty());
    assert_eq!(
        ack.refused,
        vec![AttachRefusal {
            position: 0,
            reason: AttachRefusalReason::Replaced
        }]
    );
    assert!(independent_successes(&probe).is_empty());
    engine.abandon();
    task3_cleanup(&probe, 9);

    let probe = Probe::new();
    let engine = attach_engine(&probe, AttachFaults::default(), 1, false);
    let first = engine
        .attach(attach_request(1, 1))
        .unwrap()
        .value
        .links
        .pop()
        .unwrap()
        .id();
    let second = engine
        .attach(attach_request(2, 1))
        .unwrap()
        .value
        .links
        .pop()
        .unwrap()
        .id();
    assert_eq!(first, second);
    assert_eq!(independent_successes(&probe), vec![1]);
    engine.abandon();
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.memberships.len(), 1);
    task3_cleanup(&probe, 10);
}

#[test]
fn g1_pin_open_install_before_identity() {
    for fault in [
        IdentityFault::Io,
        IdentityFault::Replaced,
        IdentityFault::Panic,
        IdentityFault::None,
    ] {
        let probe = Probe::new();
        let engine = attach_engine(
            &probe,
            AttachFaults {
                identity: fault,
                ..Default::default()
            },
            1,
            false,
        );
        let result = engine.attach(attach_request(1, 1));
        let acquired = !matches!(fault, IdentityFault::None);
        if acquired {
            if matches!(fault, IdentityFault::Replaced) {
                assert!(result.unwrap().value.links.is_empty());
            } else {
                assert!(result.is_err());
            }
        } else {
            assert_eq!(result.unwrap().value.links.len(), 1);
        }
        engine.abandon();
        let event_snapshot = probe.log.lock().unwrap().events.clone();
        let events = &event_snapshot;
        assert_eq!(
            events
                .iter()
                .filter(|(_, e)| matches!(e, Event::PinOpened(_)))
                .count(),
            1,
            "the fault control must first acquire a real pin"
        );
        assert!(
            events
                .iter()
                .any(|(_, e)| matches!(e, Event::PinIdentity(_))),
            "the injected identity operation must actually run"
        );
        let installed = events
            .iter()
            .position(|(_, e)| {
                matches!(
                    e,
                    Event::Registry(RegistryEvent::Installed(ResourceId::Pin(_)))
                )
            })
            .expect("acquired pin absent from registry");
        let identity = events
            .iter()
            .position(|(_, e)| matches!(e, Event::PinIdentity(_)))
            .unwrap();
        assert!(
            installed < identity,
            "fallible fstat ran before pin custody was installed"
        );
        if acquired {
            assert!(
                !events
                    .iter()
                    .any(|(_, e)| matches!(e, Event::AttachEntered(..)))
            );
        }
        task3_cleanup(&probe, if acquired { 9 } else { 10 });
        assert_eq!(
            probe
                .log
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|(_, e)| matches!(e, Event::PinClose))
                .count(),
            1
        );
    }
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            open_error: true,
            ..Default::default()
        },
        1,
        false,
    );
    let ack = engine.attach(attach_request(1, 1)).unwrap().value;
    assert_eq!(ack.refused[0].reason, AttachRefusalReason::Unreadable);
    engine.abandon();
    task3_cleanup(&probe, 8);
    assert!(
        !probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(
                e,
                Event::PinOpened(_)
                    | Event::PinIdentity(_)
                    | Event::PinClose
                    | Event::Registry(RegistryEvent::Installed(ResourceId::Pin(_)))
            ))
    );
}

#[test]
fn g1_pin_identity_cutoff_and_close_outcomes() {
    for close_errno in [None, Some(libc::EINTR), Some(libc::EIO)] {
        let probe = Probe::new();
        let engine = attach_engine(
            &probe,
            AttachFaults {
                identity: IdentityFault::Hold,
                pin_close_errno: close_errno,
                ..Default::default()
            },
            1,
            false,
        );
        std::thread::scope(|scope| {
            let caller = scope.spawn(|| {
                let mut r = attach_request(1, 1);
                r.deadline = Instant::now() + Duration::from_millis(60);
                engine.attach(r)
            });
            probe.wait(|events| {
                events
                    .iter()
                    .any(|(_, e)| matches!(e, Event::PinIdentity(_)))
            });
            let failure = caller.join().unwrap().unwrap_err();
            assert_eq!(failure.failure.class, FailureClass::Deadline);
            assert_eq!(failure.completion, CommandCompletion::Unknown);
            assert_eq!(
                locked(&engine.shared.state).active_operation,
                Some(CountOperation::PinIdentity)
            );
            assert!(engine.fork_permit(Instant::now()).is_err());
            let ticket = engine.shared.seal(Instant::now() + Duration::from_secs(5));
            assert_eq!(failure.cleanup_ticket, Some(ticket));
            probe.release();
        });
        task3_cleanup(&probe, 9);
        let events = &probe.log.lock().unwrap().events;
        assert_eq!(
            events
                .iter()
                .filter(|(_, e)| matches!(e, Event::PinClose))
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|(_, e)| matches!(e, Event::AttachEntered(..)))
        );
        if close_errno.is_some() {
            assert!(
                events
                    .iter()
                    .any(|(_, e)| matches!(e,Event::PinCloseResult(errno) if *errno==close_errno))
            );
            assert!(engine.fork_permit(Instant::now()).is_err());
            assert!(engine.resource_summary().resources.iter().any(|r| matches!(
                r.resource,
                ResourceId::Pin(_)
            ) && r.state
                == ResourceState::ConsumedError
                && r.errno == close_errno));
        } else {
            assert!(
                engine
                    .fork_permit(Instant::now() + Duration::from_secs(1))
                    .is_ok()
            );
        }
    }
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            hold_pin_close: true,
            ..Default::default()
        },
        1,
        false,
    );
    assert!(engine.attach(attach_request(1, 1)).is_ok());
    engine.abandon();
    probe.wait(|events| events.iter().any(|(_, e)| matches!(e, Event::PinClose)));
    assert!(engine.fork_permit(Instant::now()).is_err());
    assert!(engine.resource_summary().resources.iter().any(|r| matches!(
        r.resource,
        ResourceId::Pin(_)
    ) && r.state
        == ResourceState::CloseIssued));
    probe.release();
    task3_cleanup(&probe, 10);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn g1_inventory_exact_set() {
    let probe = Probe::new();
    let engine = attach_engine(&probe, AttachFaults::default(), 3, false);
    let first = engine
        .attach(attach_request(1, 1))
        .unwrap()
        .value
        .links
        .pop()
        .unwrap()
        .id();
    let mut request = attach_request(2, 1);
    request.offsets[0] = 9;
    request.cookies[0] = 109;
    let second = engine
        .attach(request)
        .unwrap()
        .value
        .links
        .pop()
        .unwrap()
        .id();
    engine.abandon();
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.acknowledged_links, vec![first, second]);
    assert!(inventory.unpublished_links.is_empty());
    assert_eq!(
        inventory.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(independent_successes(&probe), vec![1, 2]);
    assert_eq!(
        inventory
            .records
            .iter()
            .map(|r| r.command.value())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    for record in &inventory.records {
        assert_eq!(record.writer.owner_epoch, engine.ready().owner_epoch);
        assert_eq!(
            record.writer.object_sha256,
            engine.ready().writer_object_identity
        );
        assert_eq!(
            record.backing,
            BackingIdentity {
                device: 1,
                inode: 2
            }
        );
        assert_eq!(record.outcome, CreateOutcome::Succeeded);
        assert!(record.memberships.end <= inventory.memberships.len());
    }
    let frontier = ControllerFrontier {
        last_acked: Some(CommandSeq::checked(2).unwrap()),
        acknowledged_links: vec![first, second],
        pending: None,
    };
    assert!(inventory.validate(&frontier).is_ok());
    let mut duplicate = frontier.clone();
    duplicate.acknowledged_links.push(first);
    assert!(inventory.validate(&duplicate).is_err());
    let mut missing = frontier.clone();
    missing.acknowledged_links.pop();
    assert!(inventory.validate(&missing).is_err());
    let mut duplicate_manifest = inventory.clone();
    duplicate_manifest
        .records
        .push(inventory.records[0].clone());
    assert!(duplicate_manifest.validate(&frontier).is_err());
    let mut missing_manifest = inventory.clone();
    missing_manifest.records.pop();
    assert!(missing_manifest.validate(&frontier).is_err());
    let mut wrong_writer = inventory.clone();
    wrong_writer.records[0].writer.object_sha256[0] ^= 1;
    assert!(wrong_writer.validate(&frontier).is_err());
    task3_cleanup(&probe, 11);
}

#[test]
fn g1_attach_capacity_is_loss_and_runtime_failure() {
    for membership_capacity in [false, true] {
        let probe = Probe::new();
        let engine = attach_engine(
            &probe,
            AttachFaults::default(),
            if membership_capacity { 2 } else { 1 },
            false,
        );
        let n = if membership_capacity { 8192 } else { 1 };
        assert!(engine.attach(attach_request(1, n)).is_ok());
        let mut request = attach_request(2, 1);
        request.offsets[0] = 9000;
        request.cookies[0] = 9100;
        let failure = engine.attach(request).unwrap_err();
        assert_eq!(failure.failure.class, FailureClass::Capacity);
        let loss = failure
            .capacity_loss()
            .expect("owner capacity must be explicit loss");
        assert_eq!(loss.name, "count.owner_capacity");
        assert_eq!(loss.kind, crate::evidence::CounterKind::Loss);
        assert_eq!(loss.units, crate::evidence::CounterUnits::Events);
        assert_eq!(loss.source, crate::evidence::CounterSource::Attach);
        assert_eq!(loss.value, 1);
        assert_eq!(
            task3_inventory(&engine).unwrap().records.len(),
            1,
            "capacity erased prior facts"
        );
        assert_eq!(independent_successes(&probe), vec![1]);
        task3_cleanup(&probe, 10);
    }
}

#[test]
fn g1_attach_failed_attempt_storage_is_bounded() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            all_bad: true,
            ..Default::default()
        },
        1,
        false,
    );
    for seq in 1..=64 {
        let ack = engine.attach(attach_request(seq, 3)).unwrap().value;
        assert!(ack.links.is_empty());
        assert_eq!(ack.refused.len(), 3);
        assert!(
            ack.refused
                .iter()
                .all(|r| r.reason == AttachRefusalReason::KernelRefused)
        );
    }
    engine.abandon();
    assert!(task3_inventory(&engine).unwrap().records.is_empty());
    task3_cleanup(&probe, 72);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
    let log = probe.log.lock().unwrap();
    assert_eq!(
        log.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::AttachEntered(..)))
            .count(),
        320
    );
    let snapshots = log
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::Registry(RegistryEvent::AttachStorage {
                attempts,
                attempt_capacity,
                attempt_address,
                records,
                memberships,
                refusals,
                refusal_capacity,
                refusal_address,
            }) = e
            {
                assert_eq!((*attempts, *records, *memberships, *refusals), (5, 0, 0, 3));
                assert_eq!((*attempt_capacity, *refusal_capacity), (16383, 8192));
                Some((*attempt_address, *refusal_address))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(snapshots.len(), 64);
    assert!(
        snapshots.iter().all(|addresses| *addresses == snapshots[0]),
        "failed retries grew or replaced safety storage"
    );
    assert!(independent_successes_unlocked(&log).is_empty());
}
fn independent_successes_unlocked(log: &InvocationLog) -> Vec<u64> {
    log.events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::AttachCreated(n) = e {
                Some(*n as u64)
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn g1_pin_real_locator_swap_is_replaced() {
    use std::os::unix::fs::MetadataExt as _;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let directory = std::env::temp_dir().join(format!(
        "osslscope-owner-pin-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    let locator = directory.join("provider");
    let replacement = directory.join("replacement");
    std::fs::write(&locator, b"old host fixture").unwrap();
    std::fs::write(&replacement, b"replacement host fixture").unwrap();
    let old = std::fs::metadata(&locator).unwrap();
    let expected = BackingIdentity {
        device: crate::plan::encode_device(libc::major(old.dev()), libc::minor(old.dev())),
        inode: old.ino(),
    };
    std::fs::rename(&replacement, &locator).unwrap();
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            real_pin: true,
            ..Default::default()
        },
        1,
        false,
    );
    let mut request = attach_request(1, 1);
    request.locator = locator.to_str().unwrap().into();
    request.expected_backing = expected;
    let ack = engine.attach(request).unwrap().value;
    assert!(ack.links.is_empty());
    assert_eq!(
        ack.refused,
        vec![AttachRefusal {
            position: 0,
            reason: AttachRefusalReason::Replaced
        }]
    );
    assert!(independent_successes(&probe).is_empty());
    engine.abandon();
    task3_cleanup(&probe, 9);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
    let current = std::fs::metadata(&locator).unwrap();
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            real_pin: true,
            ..Default::default()
        },
        1,
        false,
    );
    let mut request = attach_request(1, 1);
    request.locator = locator.to_str().unwrap().into();
    request.expected_backing = BackingIdentity {
        device: crate::plan::encode_device(libc::major(current.dev()), libc::minor(current.dev())),
        inode: current.ino(),
    };
    assert_eq!(
        engine.attach(request).unwrap().value.links.len(),
        1,
        "matching real fstat must use the planned device encoding"
    );
    engine.abandon();
    task3_cleanup(&probe, 10);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn g1_attach_sealed_queued_request_never_enters_io() {
    let probe = Probe::new();
    let engine = attach_engine(&probe, AttachFaults::default(), 1, false);
    let request = attach_request(1, 3);
    let seq = request.seq;
    let ack = AttachAck {
        links: registry::preallocated(1).unwrap(),
        refused: registry::preallocated(3).unwrap(),
    };
    let ticket = {
        // Submit and seal atomically, so this discriminates the queued case
        // from the separate held-create test without timing a scheduler race.
        let mut state = locked(&engine.shared.state);
        state.last_command_seq = Some(seq);
        state.frontier.pending = Some(PendingCommandId {
            seq,
            operation: CountOperation::Attach,
        });
        assert!(
            state
                .ordinary
                .publish_request(OwnerRequest::Attach { request, ack })
                .is_ok()
        );
        engine.shared.seal_locked(&mut state, Instant::now())
    };
    engine.shared.worker.get().unwrap().unpark();
    let inventory = task3_inventory(&engine).unwrap();
    assert!(inventory.records.is_empty());
    assert_eq!(
        inventory.pending,
        Some(PendingCommandId {
            seq,
            operation: CountOperation::Attach
        })
    );
    let Some(OwnerReply::Attached(result)) = locked(&engine.shared.state).ordinary.take_reply()
    else {
        panic!("queued request was not explicitly resolved")
    };
    let failure = result.unwrap_err();
    assert_eq!(failure.cleanup_ticket, Some(ticket));
    assert_eq!(failure.completion, CommandCompletion::NotEntered);
    assert!(
        !probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::PinOpen | Event::AttachEntered(..)))
    );
    task3_cleanup(&probe, 8);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn g1_attach_one_in_flight_and_nonwrapping_sequence() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            identity: IdentityFault::Hold,
            ..Default::default()
        },
        1,
        false,
    );
    std::thread::scope(|scope| {
        let first = scope.spawn(|| engine.attach(attach_request(1, 1)));
        probe.wait(|events| {
            events
                .iter()
                .any(|(_, e)| matches!(e, Event::PinIdentity(_)))
        });
        let overlapping = engine.attach(attach_request(2, 1)).unwrap_err();
        assert_eq!(overlapping.failure.class, FailureClass::Capacity);
        assert_eq!(overlapping.completion, CommandCompletion::NotEntered);
        assert_eq!(
            probe
                .log
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|(_, e)| matches!(e, Event::PinOpen))
                .count(),
            1
        );
        probe.release();
        assert!(first.join().unwrap().is_ok());
    });
    assert_eq!(
        engine
            .attach(attach_request(1, 1))
            .unwrap_err()
            .failure
            .class,
        FailureClass::InvalidInput
    );
    assert!(engine.attach(attach_request(u64::MAX, 1)).is_ok());
    assert_eq!(
        engine
            .attach(attach_request(2, 1))
            .unwrap_err()
            .failure
            .class,
        FailureClass::InvalidInput
    );
    assert_eq!(independent_successes(&probe), vec![1]);
    engine.abandon();
    assert_eq!(task3_inventory(&engine).unwrap().records.len(), 1);
    task3_cleanup(&probe, 10);
}

#[test]
fn g1_attach_pin_capacity_preserves_prior_fact() {
    let probe = Probe::new();
    let worker_probe = Arc::clone(&probe);
    // One prestarted host owner exercises the registry's independent pin guard.
    // The extra provider pin is tracked and closed; it is never a link alias.
    let (failure, inventory, summary) = std::thread::spawn(move || {
        worker_probe.event(Event::Started);
        let limits = CountOwnerLimits::from_allowance(20, 2).unwrap();
        let mut registry = Registry::allocate(limits).unwrap();
        let observed = Arc::clone(&worker_probe);
        registry.observer = Some(Arc::new(move |e| observed.event(Event::Registry(e))));
        let source = input(Arc::new(CountForkBarrier::new()));
        let prepared = crate::loader::prepare(
            &source.object_bytes,
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
        )
        .unwrap();
        let mut driver = AttachDriver {
            base: PipeDriver {
                probe: worker_probe,
                faults: Faults::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                attempts: 0,
                acquired: 0,
                closes: 0,
            },
            faults: AttachFaults::default(),
            pin: None,
            attaches: 0,
            clock_after_create: std::cell::Cell::new(0),
        };
        let loaded = crate::loader::load_count_tracked(
            &prepared,
            &mut registry,
            &mut driver,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|f| f.failure)
        .unwrap();
        registry
            .journal
            .bind(OwnerEpoch::checked(1).unwrap(), source.object_sha256);
        let request = attach_request(1, 1);
        registry.journal.begin(request.seq);
        let ack = registry
            .attach(
                &mut driver,
                loaded.program,
                1,
                &request,
                AttachAck {
                    links: registry::preallocated(2).unwrap(),
                    refused: registry::preallocated(1).unwrap(),
                },
            )
            .unwrap();
        let id = ack.links[0].id();
        registry.journal.published(request.seq);
        registry.journal.acknowledged(Some(request.seq));
        let spare = registry.reserve(ResourceKind::Pin).unwrap();
        let fd = driver.open_pin(c"/tracked-spare-provider-pin").unwrap();
        registry.install(spare, fd);
        driver.pin_identity(registry.borrow(spare)).unwrap();
        let mut request = attach_request(2, 1);
        request.expected_backing.inode = 99;
        registry.journal.begin(request.seq);
        let failure = registry
            .attach(
                &mut driver,
                loaded.program,
                1,
                &request,
                AttachAck {
                    links: registry::preallocated(2).unwrap(),
                    refused: registry::preallocated(1).unwrap(),
                },
            )
            .unwrap_err();
        assert_eq!(failure.operation, CountOperation::PinOpen);
        let inventory = registry
            .journal
            .seal(&ControllerFrontier {
                last_acked: Some(CommandSeq::checked(1).unwrap()),
                acknowledged_links: vec![id],
                pending: Some(PendingCommandId {
                    seq: request.seq,
                    operation: CountOperation::Attach,
                }),
            })
            .unwrap();
        registry.cleanup(&mut driver);
        (failure, inventory, registry.summary())
    })
    .join()
    .unwrap();
    assert_eq!(failure.class, FailureClass::Capacity);
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(independent_successes(&probe), vec![1]);
    task3_cleanup(&probe, 11);
    assert!(summary.cleanup_complete);
    assert_eq!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::PinOpen))
            .count(),
        2,
        "capacity refusal acquired another pin"
    );
}

#[test]
fn g1_attach_duplicate_physical_membership_is_reused() {
    let probe = Probe::new();
    let engine = attach_engine(&probe, AttachFaults::default(), 1, false);
    let mut request = attach_request(1, 3);
    request.offsets = vec![7, 7, 7];
    request.cookies = vec![107, 107, 107];
    assert_eq!(engine.attach(request).unwrap().value.links.len(), 1);
    let mut request = attach_request(2, 1);
    request.offsets[0] = 7;
    request.cookies[0] = 107;
    assert_eq!(engine.attach(request).unwrap().value.links.len(), 1);
    assert_eq!(independent_successes(&probe), vec![1]);
    engine.abandon();
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(
        inventory.memberships,
        vec![AttachedMembership {
            offset: 7,
            cookie: 107
        }]
    );
    let log = probe.log.lock().unwrap();
    let supplied = log
        .events
        .iter()
        .find_map(|(_, e)| {
            if let Event::AttachEntered(_, offsets, cookies, _) = e {
                Some((offsets.clone(), cookies.clone()))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(supplied, (vec![7], vec![107]));
    drop(log);
    task3_cleanup(&probe, 10);
}

#[test]
fn g1_attach_post_handler_unwind_keeps_owner_custody() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            post_handler_clock_panic: true,
            ..Default::default()
        },
        1,
        false,
    );
    let mut request = attach_request(1, 1);
    request.deadline = Instant::now() + Duration::from_secs(2);
    let failure = engine.attach(request).unwrap_err();
    assert_eq!(failure.failure.class, FailureClass::Panic);
    assert_eq!(failure.completion, CommandCompletion::Unknown);
    assert!(failure.cleanup_ticket.is_some());
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.unpublished_links.len(), 1);
    assert_eq!(independent_successes(&probe), vec![1]);
    task3_cleanup(&probe, 10);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn g1_attach_failed_slot_reuse_never_reuses_serial() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            bad_offset: Some(0),
            ..Default::default()
        },
        1,
        false,
    );
    let refused = engine.attach(attach_request(1, 1)).unwrap().value;
    assert!(refused.links.is_empty());
    assert_eq!(
        refused.refused,
        vec![AttachRefusal {
            position: 0,
            reason: AttachRefusalReason::KernelRefused
        }]
    );
    let mut request = attach_request(2, 1);
    request.offsets[0] = 9;
    request.cookies[0] = 109;
    let id = engine.attach(request).unwrap().value.links[0].id();
    assert_eq!(
        id.serial.value(),
        2,
        "a known-failed serial was reused with its physical slot"
    );
    engine.abandon();
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(
        inventory
            .records
            .iter()
            .map(|r| r.id.serial.value())
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(
        inventory.memberships,
        vec![AttachedMembership {
            offset: 9,
            cookie: 109
        }]
    );
    assert_eq!(independent_successes(&probe), vec![2]);
    task3_cleanup(&probe, 11);
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

fn system_fd_exhaustion_is_runtime_failure(at_pin_open: bool) {
    for errno in [libc::EMFILE, libc::ENFILE] {
        let probe = Probe::new();
        let faults = if at_pin_open {
            AttachFaults {
                open_errno: Some(errno),
                ..Default::default()
            }
        } else {
            AttachFaults {
                attach_errno: Some(errno),
                ..Default::default()
            }
        };
        let engine = attach_engine(&probe, faults, 3, false);
        let failure = engine.attach(attach_request(1, 3)).unwrap_err();
        assert_eq!(failure.failure.class, FailureClass::Capacity);
        assert_eq!(
            failure.failure.operation,
            if at_pin_open {
                CountOperation::PinOpen
            } else {
                CountOperation::Attach
            }
        );
        assert_eq!(failure.failure.errno, Some(errno));
        assert!(failure.capacity_loss().unwrap().forces_partial());
        assert!(failure.cleanup_ticket.is_some());
        assert!(task3_inventory(&engine).unwrap().records.is_empty());
        assert!(independent_successes(&probe).is_empty());
        task3_cleanup(&probe, if at_pin_open { 8 } else { 9 });
        assert!(
            engine
                .fork_permit(Instant::now() + Duration::from_secs(1))
                .is_ok()
        );
        let log = probe.log.lock().unwrap();
        assert_eq!(
            log.events
                .iter()
                .filter(|(_, e)| matches!(e, Event::AttachEntered(..)))
                .count(),
            if at_pin_open { 0 } else { 1 },
            "system FD exhaustion caused futile bisection retries"
        );
    }
}
#[test]
fn g1_pin_system_fd_exhaustion_is_runtime_failure() {
    system_fd_exhaustion_is_runtime_failure(true)
}
#[test]
fn g1_attach_system_fd_exhaustion_is_runtime_failure() {
    system_fd_exhaustion_is_runtime_failure(false)
}

#[test]
fn g1_attach_system_fd_exhaustion_preserves_prior_positive() {
    let probe = Probe::new();
    let engine = attach_engine(
        &probe,
        AttachFaults {
            attach_errno: Some(libc::EMFILE),
            attach_errno_from: 2,
            ..Default::default()
        },
        3,
        false,
    );
    let id = engine.attach(attach_request(1, 1)).unwrap().value.links[0].id();
    let mut request = attach_request(2, 3);
    request.offsets = vec![9, 10, 11];
    request.cookies = vec![109, 110, 111];
    let failure = engine.attach(request).unwrap_err();
    assert_eq!(failure.failure.class, FailureClass::Capacity);
    assert_eq!(failure.failure.errno, Some(libc::EMFILE));
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(
        inventory.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id]
    );
    assert_eq!(inventory.acknowledged_links, vec![id]);
    assert!(inventory.unpublished_links.is_empty());
    assert_eq!(
        inventory.memberships,
        vec![AttachedMembership {
            offset: 0,
            cookie: 100
        }]
    );
    assert_eq!(independent_successes(&probe), vec![1]);
    task3_cleanup(&probe, 10);
    assert_eq!(
        probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::AttachEntered(..)))
            .count(),
        2,
        "systemic resource failure was bisected after a prior success"
    );
    assert!(
        engine
            .fork_permit(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}
