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

#[test]
fn g1_session_adopts_existing_canonical_terminal_budget() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    let cutoff = Instant::now();
    let ticket = engine.shared.seal(cutoff);
    let request = engine.terminal_request(
        cutoff + Duration::from_secs(5),
        engine.ready.evidence_domain,
        engine.ready.writer_object_identity,
        ControllerFrontier::default(),
    );
    assert_eq!(request.id, ticket.terminal_id);
    assert_eq!(
        request.deadline, cutoff,
        "consumer must adopt the first seal budget"
    );
}

#[test]
fn g1_session_admission_binds_first_request_before_worker() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    let request = engine.terminal_request(
        Instant::now() + Duration::from_secs(3),
        engine.ready.evidence_domain,
        engine.ready.writer_object_identity,
        ControllerFrontier::default(),
    );
    assert_eq!(
        locked(&engine.shared.state).terminal_expected.as_ref(),
        Some(&request)
    );
    let again = engine.terminal_request(
        Instant::now() + Duration::from_secs(30),
        engine.ready.evidence_domain,
        engine.ready.writer_object_identity,
        ControllerFrontier::default(),
    );
    assert_eq!(again, request);
    let receipt = engine.terminal(request.clone());
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    assert_eq!(receipt.terminal_id, again.id);
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_session_admission_adopts_operation_fault_seal() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                write_error: Some(1),
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let open = open_request(1);
    let failure = engine.open_window(open).unwrap_err();
    let seal = locked(&engine.shared.state)
        .terminal
        .expect("fault seals owner");
    assert_eq!(failure.cleanup_ticket, Some(seal.ticket));
    let frontier = locked(&engine.shared.state).frontier.clone();
    let request = engine.terminal_request(
        Instant::now() + Duration::from_secs(30),
        engine.ready.evidence_domain,
        engine.ready.writer_object_identity,
        frontier,
    );
    assert_eq!(request.id, seal.ticket.terminal_id);
    assert_eq!(request.deadline, open.deadline);
    assert_eq!(request.deadline, seal.deadline);
    let receipt = engine.terminal(request.clone());
    assert_eq!(receipt.cleanup_ticket, seal.ticket);
    assert_eq!(receipt.deadline, seal.deadline);
    assert!(
        receipt
            .failures
            .operations
            .iter()
            .flatten()
            .any(|f| f.class == FailureClass::Io)
    );
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_session_admission_refuses_forged_object_domain_and_frontier() {
    for forged in 0..3 {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
        let mut frontier = ControllerFrontier::default();
        if forged == 2 {
            frontier.last_acked = Some(CommandSeq::checked(99).unwrap());
        }
        let domain = if forged == 1 {
            EvidenceDomain::Live
        } else {
            engine.ready.evidence_domain
        };
        let object = if forged == 0 {
            [0x77; 32]
        } else {
            engine.ready.writer_object_identity
        };
        let request = engine.terminal_request(
            Instant::now() + Duration::from_secs(3),
            domain,
            object,
            frontier,
        );
        assert!(locked(&engine.shared.state).terminal_contradiction);
        let receipt = engine.terminal(request.clone());
        assert!(!matches!(
            receipt.writers,
            WriterCompletion::Finished(_) | WriterCompletion::KnownEmpty(_)
        ));
        assert!(
            receipt
                .failures
                .operations
                .iter()
                .flatten()
                .any(|f| f.class == FailureClass::Inventory)
        );
        assert!(validate_terminal(&request, &receipt).is_err());
        task3_cleanup(&probe.owner, 8);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MapAction {
    Write(CountMap, u32, Vec<u8>),
    Lookup(CountMap, u64, usize),
    Next(Option<u64>),
}
#[derive(Default)]
struct MapFaults {
    keys: Vec<u64>,
    row_error: Option<u64>,
    absent_key: Option<u64>,
    next_error_after: Option<usize>,
    component_error: Option<(CountMap, u32)>,
    component_error_once: bool,
    write_error: Option<usize>,
    hold_call: Option<usize>,
    panic_call: Option<usize>,
    expire_after_call: Option<usize>,
    saturating: bool,
}
struct MapProbe {
    owner: Arc<Probe>,
    calls: Mutex<Vec<(ThreadId, MapAction)>>,
    changed: Condvar,
    expired: AtomicBool,
    post_expiry: std::sync::atomic::AtomicUsize,
    before_open_write: AtomicBool,
}
impl MapProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            owner: Probe::new(),
            calls: Mutex::new(Vec::new()),
            changed: Condvar::new(),
            expired: AtomicBool::new(false),
            post_expiry: std::sync::atomic::AtomicUsize::new(0),
            before_open_write: AtomicBool::new(false),
        })
    }
    fn wait_calls(&self, n: usize) {
        let cutoff = Instant::now() + Duration::from_secs(3);
        let mut calls = self.calls.lock().unwrap();
        while calls.len() < n {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "map operation did not enter: {calls:?}"
            );
            calls = self.changed.wait_timeout(calls, remaining).unwrap().0;
        }
    }
    fn cleanup(&self) {
        task3_cleanup(&self.owner, 8);
        let calls = self.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .all(|(thread, _)| *thread != std::thread::current().id())
        );
        if let Some((owner, _)) = calls.first() {
            assert!(calls.iter().all(|(thread, _)| thread == owner));
        }
    }
}
struct MapDriver {
    base: PipeDriver,
    probe: Arc<MapProbe>,
    faults: MapFaults,
    maps: [i32; 7],
    map_count: usize,
    next_position: usize,
    writes: usize,
    cpus: usize,
    cutoff: Instant,
}
impl MapDriver {
    fn map(&self, fd: BorrowedFd<'_>) -> CountMap {
        CountMap::ALL[self.maps.iter().position(|f| *f == fd.as_raw_fd()).unwrap()]
    }
    fn enter(&mut self, action: MapAction) {
        if self.probe.expired.load(Ordering::Acquire) {
            self.probe.post_expiry.fetch_add(1, Ordering::Relaxed);
        }
        let n = {
            let mut calls = self.probe.calls.lock().unwrap();
            calls.push((std::thread::current().id(), action));
            calls.len()
        };
        self.probe.changed.notify_all();
        if self.faults.hold_call == Some(n) {
            self.probe.owner.hold();
        }
        assert_ne!(
            self.faults.panic_call,
            Some(n),
            "held map operation unwound before return"
        );
        if self.faults.expire_after_call == Some(n) {
            self.probe.expired.store(true, Ordering::Release);
        }
    }
}
impl CountIoDriver for MapDriver {
    fn map_create(&mut self, spec: &crate::loader::MapSpecLite) -> io::Result<OwnedFd> {
        let fd = self.base.map_create(spec)?;
        self.maps[self.map_count] = fd.as_raw_fd();
        self.map_count += 1;
        Ok(fd)
    }
    fn load_program(&mut self, i: &[u8], n: &str, l: Option<&mut [u8]>) -> io::Result<OwnedFd> {
        self.base.load_program(i, n, l)
    }
    fn open_pin(&mut self, path: &CStr) -> io::Result<OwnedFd> {
        self.base.open_pin(path)
    }
    fn pin_identity(&mut self, pin: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        self.base.pin_identity(pin)
    }
    fn attach(
        &mut self,
        prog: BorrowedFd<'_>,
        path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        tgid: u32,
    ) -> io::Result<OwnedFd> {
        self.base.attach(prog, path, offsets, cookies, tgid)
    }
    unsafe fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
        let map = self.map(fd);
        let key = u32::from_ne_bytes(key.try_into().unwrap());
        self.enter(MapAction::Write(map, key, value.to_vec()));
        self.writes += 1;
        if self.faults.write_error == Some(self.writes) {
            Err(io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    }
    unsafe fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8],
        value: &mut [u8],
    ) -> io::Result<()> {
        let map = self.map(fd);
        let key = if map == CountMap::Counts {
            u64::from_ne_bytes(key.try_into().unwrap())
        } else {
            u32::from_ne_bytes(key.try_into().unwrap()) as u64
        };
        self.enter(MapAction::Lookup(map, key, value.len()));
        if map == CountMap::Counts {
            assert_eq!(value.len(), self.cpus * 24, "CountValue per-CPU stride");
            if self.faults.row_error == Some(key) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if self.faults.absent_key == Some(key) {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            for (cpu, bytes) in value.chunks_exact_mut(24).enumerate() {
                let count = if self.faults.saturating {
                    if cpu == 0 { u64::MAX } else { 10 }
                } else {
                    key + cpu as u64
                };
                let first = if cpu == 0 { 100 + key } else { 90 + key };
                let last = if cpu == 0 { 200 + key } else { 300 + key };
                bytes[..8].copy_from_slice(&count.to_ne_bytes());
                bytes[8..16].copy_from_slice(&first.to_ne_bytes());
                bytes[16..24].copy_from_slice(&last.to_ne_bytes());
            }
        } else {
            assert_eq!(value.len(), self.cpus * 8, "u64 per-CPU stride");
            if self.faults.component_error == Some((map, key as u32)) {
                if self.faults.component_error_once {
                    self.faults.component_error = None;
                }
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            for (cpu, bytes) in value.chunks_exact_mut(8).enumerate() {
                let n: u64 = if self.faults.saturating {
                    if cpu == 0 { u64::MAX } else { 7 }
                } else {
                    match map {
                        CountMap::Admitted => {
                            if cpu == 0 {
                                7
                            } else {
                                11
                            }
                        }
                        CountMap::Dropfail => {
                            if cpu == 0 {
                                13
                            } else {
                                17
                            }
                        }
                        CountMap::Latc => key + cpu as u64 + 1,
                        _ => panic!("unexpected scalar map"),
                    }
                };
                bytes.copy_from_slice(&n.to_ne_bytes());
            }
        }
        Ok(())
    }
    unsafe fn next_key(
        &mut self,
        fd: BorrowedFd<'_>,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> io::Result<()> {
        assert_eq!(self.map(fd), CountMap::Counts);
        let key = key.map(|k| u64::from_ne_bytes(k.try_into().unwrap()));
        if key.is_none() {
            self.next_position = 0;
        }
        self.enter(MapAction::Next(key));
        if self.faults.next_error_after == Some(self.next_position) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let Some(key) = self.faults.keys.get(self.next_position) else {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        };
        self.next_position += 1;
        next.copy_from_slice(&key.to_ne_bytes());
        Ok(())
    }
    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        self.base.close(fd)
    }
    fn now(&self) -> Instant {
        if self.probe.expired.load(Ordering::Acquire) {
            self.cutoff + Duration::from_secs(1)
        } else {
            Instant::now()
        }
    }
    fn monotonic_ns(&self) -> Option<u64> {
        Some(1)
    }
}
fn map_engine(probe: &Arc<MapProbe>, faults: MapFaults) -> CountEngine {
    map_engine_with_sequence(probe, faults, 0)
}
fn map_engine_with_sequence(probe: &Arc<MapProbe>, faults: MapFaults, last: u64) -> CountEngine {
    let observed = Arc::clone(&probe.owner);
    let mut hooks = PrepareHooks::host();
    hooks.snapshot_sequence_last = last;
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event))
    }));
    let probe = Arc::clone(probe);
    let cutoff = Instant::now() + Duration::from_secs(30);
    CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance(18, 2).unwrap(),
        cutoff,
        hooks,
        move || {
            probe.owner.event(Event::Started);
            MapDriver {
                base: PipeDriver {
                    probe: Arc::clone(&probe.owner),
                    faults: Faults::default(),
                    deadline: cutoff,
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                },
                probe,
                faults,
                maps: [-1; 7],
                map_count: 0,
                next_position: 0,
                writes: 0,
                cpus: 2,
                cutoff,
            }
        },
        spawn_owner,
    )
    .unwrap()
}

#[test]
fn g1_read_next_error_and_concurrently_absent_key() {
    for (absent_key, next_error_after, want_enumeration, want_rows) in [
        (
            None,
            Some(2),
            EnumerationStatus::Unfinished,
            first_two_rows(),
        ),
        (
            Some(22),
            None,
            EnumerationStatus::Complete { unread_keys: 1 },
            vec![
                (
                    11,
                    osslscope_ebpf_common::CountValue {
                        count: 23,
                        first_ns: 101,
                        last_ns: 311,
                    },
                ),
                (
                    33,
                    osslscope_ebpf_common::CountValue {
                        count: 67,
                        first_ns: 123,
                        last_ns: 333,
                    },
                ),
            ],
        ),
        (
            Some(22),
            Some(2),
            EnumerationStatus::Unfinished,
            vec![(
                11,
                osslscope_ebpf_common::CountValue {
                    count: 23,
                    first_ns: 101,
                    last_ns: 311,
                },
            )],
        ),
    ] {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                keys: vec![11, 22, 33],
                absent_key,
                next_error_after,
                ..MapFaults::default()
            },
        );
        let snapshot = engine.drain(read_request(1)).unwrap().value;
        assert_eq!(snapshot.rows, want_rows);
        assert_eq!(snapshot.enumeration, want_enumeration);
        assert_eq!(snapshot.admitted, Component::Available(18));
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_read_key_cycles_do_not_restart_or_claim_complete() {
    for (keys, absent_key, want_count, want_next_calls) in [
        (vec![11, 11, 22], None, 1, 2),
        (vec![11, 22, 11, 33], None, 2, 3),
        (vec![11, 22, 22, 33], Some(22), 1, 3),
    ] {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                keys,
                absent_key,
                ..MapFaults::default()
            },
        );
        let snapshot = engine.drain(read_request(1)).unwrap().value;
        assert_eq!(snapshot.rows.len(), want_count);
        assert_eq!(snapshot.enumeration, EnumerationStatus::Unfinished);
        assert_eq!(
            locked(&engine.shared.state).read_failure.unwrap().class,
            FailureClass::Inventory
        );
        assert_eq!(
            probe
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, c)| matches!(c, MapAction::Next(_)))
                .count(),
            want_next_calls
        );
        assert_eq!(
            probe
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, c)| matches!(c, MapAction::Next(None)))
                .count(),
            1
        );
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_read_8192_rows_and_8193rd_key_are_bounded() {
    for n in [8192, 8193] {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                keys: (0..n).collect(),
                ..MapFaults::default()
            },
        );
        let snapshot = engine.drain(read_request(1)).unwrap().value;
        assert_eq!(snapshot.rows.len(), 8192);
        assert_eq!(
            snapshot.rows[8191],
            (
                8191,
                osslscope_ebpf_common::CountValue {
                    count: 16383,
                    first_ns: 8281,
                    last_ns: 8491
                }
            )
        );
        assert_eq!(
            snapshot.enumeration,
            if n == 8192 {
                EnumerationStatus::Complete { unread_keys: 0 }
            } else {
                EnumerationStatus::Unfinished
            }
        );
        assert_eq!(
            probe
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, c)| matches!(c, MapAction::Lookup(CountMap::Counts, _, _)))
                .count(),
            8192
        );
        if n == 8193 {
            assert_eq!(
                locked(&engine.shared.state).read_failure.unwrap().class,
                FailureClass::Capacity
            );
        }
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_read_per_cpu_stride_and_saturation() {
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11],
            saturating: true,
            ..MapFaults::default()
        },
    );
    let snapshot = engine.drain(read_request(1)).unwrap().value;
    assert_eq!(
        snapshot.rows,
        vec![(
            11,
            osslscope_ebpf_common::CountValue {
                count: u64::MAX,
                first_ns: 101,
                last_ns: 311
            }
        )]
    );
    assert_eq!(snapshot.admitted, Component::Available(u64::MAX));
    assert_eq!(snapshot.dropfail, Component::Available(u64::MAX));
    assert_eq!(snapshot.latc, [Component::Available(u64::MAX); 16]);
    for (_, call) in probe.calls.lock().unwrap().iter() {
        if let MapAction::Lookup(map, _, bytes) = call {
            assert_eq!(*bytes, if *map == CountMap::Counts { 48 } else { 16 });
        }
    }
    assert!(CountOwnerLimits::from_allowance(18, 0).is_err());
    assert!(CountOwnerLimits::from_allowance(18, usize::MAX / 24 + 1).is_err());
    assert!(CountOwnerLimits::from_allowance(18, isize::MAX as usize / 24 + 1).is_err());
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_read_rejects_a_short_kernel_cpu_vector_before_raw_io() {
    let limits = CountOwnerLimits::from_allowance(18, 2).unwrap();
    assert!(limits.validate_possible_cpus(2).is_ok());
    for actual in [0, 1, 3, usize::MAX] {
        assert_eq!(
            limits.validate_possible_cpus(actual).unwrap_err().class,
            FailureClass::InvalidInput
        );
    }
}

#[test]
fn g1_prepare_live_cpu_zero_mismatch_or_unavailable_acquires_nothing() {
    type Case = (fn() -> io::Result<usize>, FailureClass, Option<i32>);
    let cases: [Case; 5] = [
        (|| Ok(0), FailureClass::InvalidInput, None),
        (|| Ok(1), FailureClass::InvalidInput, None),
        (|| Ok(3), FailureClass::InvalidInput, None),
        (|| Ok(usize::MAX), FailureClass::InvalidInput, None),
        (
            || Err(io::Error::from_raw_os_error(libc::EIO)),
            FailureClass::Io,
            Some(libc::EIO),
        ),
    ];
    for (possible_cpu_count, class, errno) in cases {
        let probe = Probe::new();
        let hooks = PrepareHooks {
            possible_cpu_count,
            ..PrepareHooks::live()
        };
        let error = injected(
            Arc::clone(&probe),
            Faults::default(),
            Arc::new(CountForkBarrier::new()),
            Instant::now() + Duration::from_secs(5),
            hooks,
        )
        .err()
        .expect("live CPU preflight unexpectedly acquired count resources");
        assert_eq!(error.failure.class, class);
        assert_eq!(error.failure.errno, errno);
        assert_eq!(error.cleanup_ticket, None);
        assert!(probe.log.lock().unwrap().events.is_empty());
    }
}

#[test]
fn g1_read_prefix_stays_immutable_while_next_lookup_is_held() {
    let probe = MapProbe::new();
    // Calls: next11, lookup11, next22, lookup22, next33, held lookup33.
    let engine = Arc::new(map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22, 33],
            hold_call: Some(6),
            ..MapFaults::default()
        },
    ));
    let caller = Arc::clone(&engine);
    let call = std::thread::spawn(move || caller.drain(read_request(1)));
    probe.wait_calls(6);
    let prefix = engine.progress().unwrap();
    assert_eq!(prefix.snapshot.rows, first_two_rows());
    assert!(matches!(
        prefix.snapshot.admitted,
        Component::Unavailable(ComponentFailure { class: None, .. })
    ));
    let sequence = prefix.snapshot.sequence;
    let reread = engine.progress().unwrap();
    assert!(Arc::ptr_eq(&prefix.snapshot, &reread.snapshot));
    assert_eq!(
        probe.calls.lock().unwrap().len(),
        6,
        "progress performed count I/O"
    );
    probe.owner.release();
    let final_image = call.join().unwrap().unwrap().value;
    assert!(final_image.sequence > sequence);
    assert_eq!(final_image.rows.len(), 3);
    assert_eq!(
        prefix.snapshot.rows,
        first_two_rows(),
        "published image was mutated"
    );
    assert_eq!(prefix.snapshot.sequence, sequence);
    assert!(!Arc::ptr_eq(&prefix.snapshot, &final_image));
    assert!(Arc::ptr_eq(
        &engine.progress().unwrap().snapshot,
        &final_image
    ));
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_snapshot_pool_never_allocates_a_fourth_image() {
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22],
            ..MapFaults::default()
        },
    );
    let a = engine.drain(read_request(1)).unwrap().value;
    let b = engine.drain(read_request(2)).unwrap().value;
    let c = engine.drain(read_request(3)).unwrap().value;
    assert!(a.sequence < b.sequence && b.sequence < c.sequence);
    assert!(!Arc::ptr_eq(&a, &b) && !Arc::ptr_eq(&b, &c) && !Arc::ptr_eq(&a, &c));
    let calls = probe.calls.lock().unwrap().len();
    let failure = engine.drain(read_request(4)).unwrap_err();
    assert_eq!(failure.failure.class, FailureClass::Capacity);
    assert_eq!(failure.completion, CommandCompletion::NotEntered);
    assert_eq!(
        probe.calls.lock().unwrap().len(),
        calls,
        "pinned images started another read"
    );
    assert_eq!(a.rows, first_two_rows());
    assert_eq!(b.rows, first_two_rows());
    assert_eq!(c.rows, first_two_rows());
    assert!(Arc::ptr_eq(&engine.progress().unwrap().snapshot, &c));
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_snapshot_publication_contention_uses_retained_view() {
    let probe = MapProbe::new();
    let engine = Arc::new(map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22],
            ..MapFaults::default()
        },
    ));
    let first = engine.drain(read_request(1)).unwrap().value;
    assert!(Arc::ptr_eq(&engine.progress().unwrap().snapshot, &first));
    let busy = locked(&engine.shared.latest_progress);
    let caller = Arc::clone(&engine);
    let (send, receive) = std::sync::mpsc::channel();
    let observer = std::thread::spawn(move || send.send(caller.progress()).unwrap());
    let retained = receive.recv_timeout(Duration::from_millis(250));
    // Release the mutex even if a broken blocking getter misses the deadline.
    if retained.is_err() {
        drop(busy);
        observer.join().unwrap();
        panic!("progress blocked on publication");
    }
    assert!(Arc::ptr_eq(&retained.unwrap().unwrap().snapshot, &first));
    observer.join().unwrap();
    let second = engine
        .drain(ReadRequest {
            deadline: Instant::now() + Duration::from_secs(1),
            ..read_request(2)
        })
        .unwrap()
        .value;
    assert!(second.sequence > first.sequence);
    assert_eq!(second.rows, first_two_rows());
    assert_eq!(engine.progress().unwrap().snapshot.sequence, first.sequence);
    drop(busy);
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_snapshot_sequence_exhaustion_retains_last_published_prefix() {
    for last in [u64::MAX - 2, u64::MAX] {
        let probe = MapProbe::new();
        let engine = map_engine_with_sequence(
            &probe,
            MapFaults {
                keys: vec![11, 22],
                ..MapFaults::default()
            },
            last,
        );
        let failure = engine.drain(read_request(1)).unwrap_err();
        assert_eq!(failure.failure.class, FailureClass::IdExhausted);
        if last == u64::MAX {
            assert!(engine.progress().is_none());
            assert!(probe.calls.lock().unwrap().is_empty());
            assert_eq!(locked(&engine.shared.state).last_completed_seq, None);
        } else {
            let snapshot = engine.progress().unwrap().snapshot;
            assert_eq!(snapshot.sequence.value(), u64::MAX);
            assert_eq!(
                snapshot.rows,
                vec![(
                    11,
                    osslscope_ebpf_common::CountValue {
                        count: 23,
                        first_ns: 101,
                        last_ns: 311
                    }
                )]
            );
            assert_eq!(
                locked(&engine.shared.state).last_completed_seq,
                Some(CommandSeq::checked(1).unwrap())
            );
        }
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_program_held_generation_completes_its_exact_sequence() {
    let probe = MapProbe::new();
    let engine = Arc::new(map_engine(
        &probe,
        MapFaults {
            hold_call: Some(5),
            ..MapFaults::default()
        },
    ));
    engine.open_window(open_request(1)).unwrap();
    let request = GenerationRequest {
        seq: CommandSeq::checked(2).unwrap(),
        deadline: Instant::now() + Duration::from_secs(10),
        generation: 8,
    };
    let caller = Arc::clone(&engine);
    let call = std::thread::spawn(move || caller.set_generation(request));
    probe.wait_calls(5);
    {
        let state = locked(&engine.shared.state);
        assert_eq!(state.last_command_seq, Some(request.seq));
        assert_eq!(
            state.last_completed_seq,
            Some(CommandSeq::checked(1).unwrap())
        );
    }
    assert_eq!(
        engine.drain(read_request(3)).unwrap_err().failure.class,
        FailureClass::Capacity
    );
    engine.shared.seal(request.deadline);
    probe.owner.release();
    assert!(call.join().unwrap().is_err());
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(
        inventory.pending,
        Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Generation
        })
    );
    assert_eq!(
        locked(&engine.shared.state).last_completed_seq,
        Some(request.seq)
    );
    probe.cleanup();
    assert_only_terminal_tail(&probe, 5);
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_program_mixed_commands_preserve_attach_inventory_frontier() {
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22],
            ..MapFaults::default()
        },
    );
    let links = engine.attach(attach_request(1, 1)).unwrap().value.links;
    engine.open_window(open_request(2)).unwrap();
    engine
        .set_generation(GenerationRequest {
            seq: CommandSeq::checked(3).unwrap(),
            deadline: Instant::now() + Duration::from_secs(10),
            generation: 8,
        })
        .unwrap();
    engine.drain(read_request(4)).unwrap();
    let frontier = locked(&engine.shared.state).frontier.clone();
    engine.shared.seal(Instant::now());
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.last_acked, Some(CommandSeq::checked(4).unwrap()));
    assert_eq!(inventory.pending, None);
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(
        inventory.records[0].command,
        CommandSeq::checked(1).unwrap()
    );
    assert_eq!(inventory.acknowledged_links, vec![links[0].id()]);
    assert!(inventory.validate(&frontier).is_ok());
    drop(engine);
    task3_cleanup(&probe.owner, 10);
}

#[test]
fn g1_program_metadata_only_attach_is_a_completed_command() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let a = engine.attach(attach_request(1, 1)).unwrap().value.links;
    let b = engine.attach(attach_request(2, 1)).unwrap().value.links;
    assert_eq!(a[0].id(), b[0].id());
    assert_eq!(
        locked(&engine.shared.state).last_completed_seq,
        Some(CommandSeq::checked(2).unwrap())
    );
    engine.shared.seal(Instant::now());
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.last_acked, Some(CommandSeq::checked(2).unwrap()));
    drop(engine);
    task3_cleanup(&probe.owner, 10);
}

#[test]
fn g1_program_panic_and_queued_refusal_never_advance_completion() {
    for n in 1..=4 {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                panic_call: Some(n),
                ..MapFaults::default()
            },
        );
        let request = open_request(1);
        let failure = engine.open_window(request).unwrap_err();
        assert_eq!(failure.completion, CommandCompletion::Unknown);
        assert_eq!(failure.failure.class, FailureClass::Panic);
        assert_eq!(locked(&engine.shared.state).last_completed_seq, None);
        let receipt = locked(&engine.shared.state).resolved_open.unwrap();
        assert_eq!(
            receipt.completed_writes,
            [
                OpenWriteFrontier::NoWrites,
                OpenWriteFrontier::WindowStart,
                OpenWriteFrontier::WindowDeadline,
                OpenWriteFrontier::Generation
            ][n - 1]
        );
        assert_eq!(receipt.outcome, OpenOutcome::Unknown);
        assert!(
            receipt
                .programmed_admission(engine.ready.owner_epoch, &request)
                .is_err()
        );
        drop(engine);
        probe.cleanup();
    }
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let request = GenerationRequest {
        seq: CommandSeq::checked(1).unwrap(),
        deadline: Instant::now() + Duration::from_secs(10),
        generation: 8,
    };
    {
        let mut state = locked(&engine.shared.state);
        state.last_command_seq = Some(request.seq);
        state.frontier.pending = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Generation,
        });
        assert!(
            state
                .ordinary
                .publish_request(OwnerRequest::Generation(request))
                .is_ok()
        );
        engine.shared.seal_locked(&mut state, request.deadline);
    }
    engine.shared.worker.get().unwrap().unpark();
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(
        inventory.pending.unwrap().operation,
        CountOperation::Generation
    );
    assert_eq!(locked(&engine.shared.state).last_completed_seq, None);
    assert!(probe.calls.lock().unwrap().is_empty());
    let Some(OwnerReply::Generated(Err(failure))) =
        locked(&engine.shared.state).ordinary.take_reply()
    else {
        panic!("missing queued refusal");
    };
    assert_eq!(failure.completion, CommandCompletion::NotEntered);
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_read_unreturned_lookup_retains_unknown_tail_and_components() {
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22, 33],
            panic_call: Some(6),
            ..MapFaults::default()
        },
    );
    let failure = engine.drain(read_request(1)).unwrap_err();
    assert_eq!(failure.completion, CommandCompletion::Unknown);
    assert_eq!(locked(&engine.shared.state).last_completed_seq, None);
    let prefix = engine.progress().unwrap().snapshot;
    assert_eq!(prefix.rows, first_two_rows());
    assert_eq!(prefix.enumeration, EnumerationStatus::Unfinished);
    assert!(matches!(
        prefix.admitted,
        Component::Unavailable(ComponentFailure { class: None, .. })
    ));
    assert!(matches!(prefix.dropfail, Component::Unavailable(_)));
    assert!(
        prefix
            .latc
            .iter()
            .all(|c| matches!(c, Component::Unavailable(_)))
    );
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_open_lost_reply_wrong_pending_operation_is_rejected() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let request = open_request(1);
    {
        let mut state = locked(&engine.shared.state);
        state.last_command_seq = Some(request.seq);
        state.frontier.pending = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Generation,
        });
        state.pending_open = Some(request);
        state.resolved_open = Some(OpenReceipt::pending(engine.ready.owner_epoch, &request));
        assert!(
            state
                .ordinary
                .publish_request(OwnerRequest::Open(request))
                .is_ok()
        );
    }
    engine.shared.worker.get().unwrap().unpark();
    probe.wait_calls(4);
    engine.shared.seal(request.deadline);
    assert_eq!(task3_inventory(&engine), Err(InventoryFailure::Frontier));
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_snapshot_expired_before_entry_and_between_key_and_value() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let failure = engine
        .drain(ReadRequest {
            deadline: Instant::now(),
            ..read_request(1)
        })
        .unwrap_err();
    assert_eq!(failure.completion, CommandCompletion::NotEntered);
    assert!(probe.calls.lock().unwrap().is_empty());
    drop(engine);
    probe.cleanup();

    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22],
            expire_after_call: Some(3),
            ..MapFaults::default()
        },
    );
    let snapshot = engine.drain(read_request(1)).unwrap().value;
    assert_eq!(probe.calls.lock().unwrap().len(), 3);
    assert_eq!(
        snapshot.rows,
        vec![(
            11,
            osslscope_ebpf_common::CountValue {
                count: 23,
                first_ns: 101,
                last_ns: 311
            }
        )]
    );
    assert_eq!(snapshot.enumeration, EnumerationStatus::Unfinished);
    assert!(matches!(
        snapshot.admitted,
        Component::Unavailable(ComponentFailure {
            class: Some(FailureClass::Deadline),
            ..
        })
    ));
    assert_eq!(probe.post_expiry.load(Ordering::Acquire), 0);
    drop(engine);
    probe.cleanup();
}
fn read_request(seq: u64) -> ReadRequest {
    ReadRequest {
        seq: CommandSeq::checked(seq).unwrap(),
        deadline: Instant::now() + Duration::from_secs(10),
    }
}
fn open_request(seq: u64) -> OpenRequest {
    OpenRequest {
        seq: CommandSeq::checked(seq).unwrap(),
        deadline: Instant::now() + Duration::from_secs(10),
        tgid: 1,
        generation: 7,
        start_ns: 101,
        deadline_ns: 999,
    }
}
fn retained_read(engine: &CountEngine, seq: u64) -> Arc<RawSnapshot> {
    match engine.drain(read_request(seq)) {
        Ok(ack) => ack.value,
        Err(_) => {
            engine
                .progress()
                .expect("failed read must retain its prefix")
                .snapshot
        }
    }
}
fn first_two_rows() -> Vec<(u64, osslscope_ebpf_common::CountValue)> {
    use osslscope_ebpf_common::CountValue;
    vec![
        (
            11,
            CountValue {
                count: 23,
                first_ns: 101,
                last_ns: 311,
            },
        ),
        (
            22,
            CountValue {
                count: 45,
                first_ns: 112,
                last_ns: 322,
            },
        ),
    ]
}

#[test]
fn g1_read_error_after_two_rows() {
    // Losing the accumulated builder on a later EIO must lose this test.
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22, 33],
            row_error: Some(33),
            ..MapFaults::default()
        },
    );
    let snapshot = retained_read(&engine, 1);
    assert_eq!(snapshot.rows, first_two_rows());
    assert_eq!(snapshot.enumeration, EnumerationStatus::Unfinished);
    assert_eq!(snapshot.admitted, Component::Available(18));
    assert_eq!(snapshot.dropfail, Component::Available(30));
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_component_unavailable_is_not_zero() {
    // Defaulting one failed component must fail even with other useful data.
    for (map, key) in [
        (CountMap::Admitted, 0),
        (CountMap::Dropfail, 0),
        (CountMap::Latc, 9),
    ] {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                keys: vec![11, 22],
                component_error: Some((map, key)),
                ..MapFaults::default()
            },
        );
        let snapshot = retained_read(&engine, 1);
        let component = match map {
            CountMap::Admitted => snapshot.admitted,
            CountMap::Dropfail => snapshot.dropfail,
            _ => snapshot.latc[9],
        };
        assert_eq!(
            component,
            Component::Unavailable(ComponentFailure {
                map,
                key,
                operation: CountOperation::Read,
                class: Some(FailureClass::Io),
                errno: Some(libc::EIO)
            })
        );
        assert_eq!(snapshot.rows, first_two_rows());
        assert_eq!(
            snapshot.enumeration,
            EnumerationStatus::Complete { unread_keys: 0 }
        );
        assert_eq!(snapshot.latc[8], Component::Available(19));
        assert_eq!(snapshot.latc[10], Component::Available(23));
        if map != CountMap::Admitted {
            assert_eq!(snapshot.admitted, Component::Available(18));
        }
        if map != CountMap::Dropfail {
            assert_eq!(snapshot.dropfail, Component::Available(30));
        }
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_snapshot_deadline_has_no_tail_census() {
    // A keys-only census or counter read after the second lookup expires fails.
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: vec![11, 22, 33, 44],
            expire_after_call: Some(4),
            ..MapFaults::default()
        },
    );
    let snapshot = retained_read(&engine, 1);
    assert_eq!(
        probe.post_expiry.load(Ordering::Acquire),
        0,
        "post-expiry syscall was started"
    );
    assert_eq!(snapshot.rows, first_two_rows());
    assert_eq!(snapshot.enumeration, EnumerationStatus::Unfinished);
    assert!(matches!(snapshot.admitted, Component::Unavailable(_)));
    assert!(matches!(snapshot.dropfail, Component::Unavailable(_)));
    assert!(
        snapshot
            .latc
            .iter()
            .all(|c| matches!(c, Component::Unavailable(_)))
    );
    drop(engine);
    probe.cleanup();
}

#[test]
fn g1_program_order_and_frontier() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let request = open_request(1);
    let receipt = engine.open_window(request).unwrap().value;
    assert!(
        receipt
            .programmed_admission(engine.ready.owner_epoch, &request)
            .is_ok()
    );
    engine
        .set_generation(GenerationRequest {
            seq: CommandSeq::checked(2).unwrap(),
            deadline: request.deadline,
            generation: 8,
        })
        .unwrap();
    assert_eq!(
        probe
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, call)| call.clone())
            .collect::<Vec<_>>(),
        vec![
            MapAction::Write(CountMap::Window, 0, 101u64.to_ne_bytes().to_vec()),
            MapAction::Write(CountMap::Window, 1, 999u64.to_ne_bytes().to_vec()),
            MapAction::Write(CountMap::Gen, 0, 7u32.to_ne_bytes().to_vec()),
            MapAction::Write(CountMap::Target, 0, 1u64.to_ne_bytes().to_vec()),
            MapAction::Write(CountMap::Gen, 0, 8u32.to_ne_bytes().to_vec()),
        ]
    );
    assert_eq!(
        locked(&engine.shared.state).last_completed_seq,
        Some(CommandSeq::checked(2).unwrap())
    );
    drop(engine);
    probe.cleanup();

    for held in 1..=4 {
        let probe = MapProbe::new();
        let engine = Arc::new(map_engine(
            &probe,
            MapFaults {
                hold_call: Some(held),
                ..MapFaults::default()
            },
        ));
        let request = open_request(1);
        let caller = Arc::clone(&engine);
        let call = std::thread::spawn(move || caller.open_window(request));
        probe.wait_calls(held);
        assert_eq!(locked(&engine.shared.state).last_completed_seq, None);
        let frontier = [
            OpenWriteFrontier::NoWrites,
            OpenWriteFrontier::WindowStart,
            OpenWriteFrontier::WindowDeadline,
            OpenWriteFrontier::Generation,
        ][held - 1];
        assert_eq!(
            locked(&engine.shared.state)
                .resolved_open
                .unwrap()
                .completed_writes,
            frontier
        );
        let concurrent = engine
            .set_generation(GenerationRequest {
                seq: CommandSeq::checked(2).unwrap(),
                deadline: request.deadline,
                generation: 8,
            })
            .unwrap_err();
        assert_eq!(concurrent.failure.class, FailureClass::Capacity);
        engine.shared.seal(request.deadline);
        probe.owner.release();
        assert!(call.join().unwrap().is_err());
        task3_inventory(&engine).unwrap();
        probe.cleanup();
        assert_only_terminal_tail(&probe, held);
        assert_eq!(
            locked(&engine.shared.state).last_completed_seq,
            Some(request.seq)
        );
        let receipt = locked(&engine.shared.state).resolved_open.unwrap();
        assert_eq!(
            receipt.outcome,
            if held == 4 {
                OpenOutcome::Completed
            } else {
                OpenOutcome::Failed
            }
        );
        if held < 4 {
            assert!(
                receipt
                    .programmed_admission(engine.ready.owner_epoch, &request)
                    .is_err()
            );
        }
        drop(engine);
        probe.cleanup();
    }
}

#[test]
fn g1_open_receipt_binds_actual_interval() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let request = open_request(1);
    // Publish the ordinary request but deliberately never consume its reply.
    {
        let mut state = locked(&engine.shared.state);
        state.last_command_seq = Some(request.seq);
        state.frontier.pending = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Open,
        });
        state.pending_open = Some(request);
        state.resolved_open = Some(OpenReceipt::pending(engine.ready.owner_epoch, &request));
        assert!(
            state
                .ordinary
                .publish_request(OwnerRequest::Open(request))
                .is_ok()
        );
    }
    engine.shared.worker.get().unwrap().unpark();
    probe.wait_calls(4);
    {
        let cutoff = Instant::now() + Duration::from_secs(3);
        let mut state = locked(&engine.shared.state);
        while state.ordinary.reply.is_none() {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero());
            state = engine
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap()
                .0;
        }
    }
    engine.shared.seal(request.deadline);
    let inventory = task3_inventory(&engine).unwrap();
    assert_eq!(
        inventory.pending,
        Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Open
        })
    );
    let receipt = locked(&engine.shared.state).resolved_open.unwrap();
    assert_eq!(
        locked(&engine.shared.state).last_completed_seq,
        Some(request.seq)
    );
    let admission = receipt
        .programmed_admission(engine.ready.owner_epoch, &request)
        .unwrap();
    assert_eq!((admission.start_ns(), admission.deadline_ns()), (101, 999));
    for forged in [
        OpenReceipt {
            owner_epoch: OwnerEpoch::checked(receipt.owner_epoch.value() + 1).unwrap(),
            ..receipt
        },
        OpenReceipt {
            seq: CommandSeq::checked(2).unwrap(),
            ..receipt
        },
        OpenReceipt { tgid: 2, ..receipt },
        OpenReceipt {
            generation: 8,
            ..receipt
        },
        OpenReceipt {
            start_ns: 100,
            ..receipt
        },
        OpenReceipt {
            deadline_ns: 1000,
            ..receipt
        },
        OpenReceipt {
            completed_writes: OpenWriteFrontier::Generation,
            ..receipt
        },
        OpenReceipt {
            outcome: OpenOutcome::Unknown,
            ..receipt
        },
    ] {
        assert!(
            forged
                .programmed_admission(engine.ready.owner_epoch, &request)
                .is_err()
        );
    }
    drop(engine);
    probe.cleanup();

    for failed in 1..=4 {
        let probe = MapProbe::new();
        let engine = map_engine(
            &probe,
            MapFaults {
                write_error: Some(failed),
                ..MapFaults::default()
            },
        );
        let request = open_request(1);
        let failure = engine.open_window(request).unwrap_err();
        assert_eq!(failure.failure.errno, Some(libc::EIO));
        assert_eq!(failure.completion, CommandCompletion::Completed);
        assert_eq!(
            locked(&engine.shared.state).last_completed_seq,
            Some(request.seq)
        );
        task3_inventory(&engine).unwrap();
        let receipt = locked(&engine.shared.state).resolved_open.unwrap();
        assert_eq!(receipt.outcome, OpenOutcome::Failed);
        assert_eq!(
            receipt.completed_writes,
            [
                OpenWriteFrontier::NoWrites,
                OpenWriteFrontier::WindowStart,
                OpenWriteFrontier::WindowDeadline,
                OpenWriteFrontier::Generation
            ][failed - 1]
        );
        assert!(
            receipt
                .programmed_admission(engine.ready.owner_epoch, &request)
                .is_err()
        );
        probe.cleanup();
        assert_only_terminal_tail(&probe, failed);
        drop(engine);
        probe.cleanup();
    }
}

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
    BeforeOpenWrite,
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
    close_errors: Vec<(usize, i32)>,
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
        let injected_errno = self
            .faults
            .close_errors
            .iter()
            .find_map(|(ordinal, errno)| (*ordinal == self.closes).then_some(*errno))
            .or_else(|| (self.faults.fail_close == Some(self.closes)).then_some(libc::EINTR));
        let result = if let Some(errno) = injected_errno {
            result.unwrap();
            Err(io::Error::from_raw_os_error(errno))
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
    let abandonment_before = Instant::now();
    engine.abandon();
    let abandonment_after = Instant::now();
    probe.wait(|events| {
        events
            .iter()
            .filter(|(_, e)| matches!(e, Event::EnterClose))
            .count()
            == 2
    });
    // Capture first, release the hold before any assertion can unwind the test.
    let summary = engine.resource_summary();
    let first_deadline = locked(&engine.shared.state).terminal.unwrap().deadline;
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
        actual_deadline, first_deadline,
        "a repeated seal extended the canonical deadline"
    );
    assert!(abandonment_before <= first_deadline && first_deadline <= abandonment_after);
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
            return inventory
                .as_ref()
                .map(|i| i.as_ref().clone())
                .map_err(|e| *e);
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
        registry.journal.begin(request.seq, CountOperation::Attach);
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
        registry
            .journal
            .completed(request.seq, CountOperation::Attach);
        registry.journal.published(request.seq);
        registry.journal.acknowledged(Some(request.seq));
        let spare = registry.reserve(ResourceKind::Pin).unwrap();
        let fd = driver.open_pin(c"/tracked-spare-provider-pin").unwrap();
        registry.install(spare, fd);
        driver.pin_identity(registry.borrow(spare)).unwrap();
        let mut request = attach_request(2, 1);
        request.expected_backing.inode = 99;
        registry.journal.begin(request.seq, CountOperation::Attach);
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

// A returned close, rather than scan equality, must cause the terminal read.
#[test]
fn g1_terminal_brackets_actual_target_stop() {
    let probe = MapProbe::new();
    let engine = map_engine(&probe, MapFaults::default());
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    let _receipt = engine.terminal(request);
    probe.cleanup();
    let calls = probe.calls.lock().unwrap();
    assert!(
        calls.iter().any(|(_, action)| matches!(action,
            MapAction::Write(CountMap::Target, 0, bytes) if bytes == &0u64.to_ne_bytes()
        )),
        "terminal cleanup did not attempt the actual TARGET=0 write"
    );
}

// These stages model the producer's control flow. They do not load BPF and do
// not qualify a real kernel's unregister behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterStage {
    TargetRead,
    WindowPassed,
    AdmittedLedger,
    GenerationRead,
    ExistingLookup,
    FreshInsert,
    CountOrDrop,
    BeforeLatc,
    LastMutation,
    Returned,
}
#[derive(Debug, Clone, Copy)]
struct PhysicalAdmission {
    invocation_id: u64,
    site: u32,
    generation: Option<u32>,
    actual_sample_ns: u64,
}
#[derive(Default)]
struct PhysicalLedger(Mutex<Vec<PhysicalAdmission>>);
impl PhysicalLedger {
    fn admitted_calls(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }
}
#[derive(Default)]
struct WriterMaps {
    rows: std::collections::BTreeMap<u64, osslscope_ebpf_common::CountValue>,
    admitted: u64,
    dropfail: u64,
    latc: u64,
}
struct StagedWriter {
    ledger: PhysicalLedger,
    maps: Mutex<WriterMaps>,
    hold: Option<WriterStage>,
    stage: Mutex<Option<WriterStage>>,
    changed: Condvar,
    release: AtomicBool,
    returned: AtomicBool,
    generation: std::sync::atomic::AtomicU32,
}
impl StagedWriter {
    fn new(hold: Option<WriterStage>) -> Arc<Self> {
        Arc::new(Self {
            ledger: PhysicalLedger::default(),
            maps: Mutex::new(WriterMaps::default()),
            hold,
            stage: Mutex::new(None),
            changed: Condvar::new(),
            release: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            generation: std::sync::atomic::AtomicU32::new(0),
        })
    }
    fn at(&self, stage: WriterStage, hold_enabled: bool) {
        let mut current = self.stage.lock().unwrap();
        *current = Some(stage);
        self.changed.notify_all();
        while hold_enabled && self.hold == Some(stage) && !self.release.load(Ordering::Acquire) {
            current = self.changed.wait(current).unwrap();
        }
    }
    fn wait_at(&self, expected: WriterStage) {
        let cutoff = Instant::now() + Duration::from_secs(5);
        let mut current = self.stage.lock().unwrap();
        while *current != Some(expected) {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "producer did not reach {expected:?}: {current:?}"
            );
            current = self.changed.wait_timeout(current, remaining).unwrap().0;
        }
    }
    fn release(&self) {
        let _current = self.stage.lock().unwrap();
        self.release.store(true, Ordering::Release);
        self.changed.notify_all();
    }
    fn wait_returned(&self) {
        let mut current = self.stage.lock().unwrap();
        while !self.returned.load(Ordering::Acquire) {
            current = self.changed.wait(current).unwrap();
        }
    }
    fn run(self: &Arc<Self>, fresh: bool, fail_insert: bool) -> thread::JoinHandle<()> {
        self.run_invocation(fresh, fail_insert, true, 500)
    }
    fn run_baseline(self: &Arc<Self>) -> thread::JoinHandle<()> {
        self.run_invocation(true, false, false, 400)
    }
    fn run_invocation(
        self: &Arc<Self>,
        fresh: bool,
        fail_insert: bool,
        hold_enabled: bool,
        sample_ns: u64,
    ) -> thread::JoinHandle<()> {
        self.returned.store(false, Ordering::Release);
        let writer = Arc::clone(self);
        thread::spawn(move || {
            writer.at(WriterStage::TargetRead, hold_enabled);
            // Expected calls come from the producer before ADMITTED or COUNTS.
            let physical_index = {
                let mut ledger = writer.ledger.0.lock().unwrap();
                let index = ledger.len();
                ledger.push(PhysicalAdmission {
                    invocation_id: index as u64 + 1,
                    site: 100,
                    generation: None,
                    actual_sample_ns: sample_ns,
                });
                index
            };
            writer.at(WriterStage::WindowPassed, hold_enabled);
            writer.maps.lock().unwrap().admitted += 1;
            writer.at(WriterStage::AdmittedLedger, hold_enabled);
            // GEN is sampled by this producer after ADMITTED, independently of
            // both count-map lookup and the eventual controller's routing.
            let generation = writer.generation.load(Ordering::Acquire);
            writer.ledger.0.lock().unwrap()[physical_index].generation = Some(generation);
            writer.at(WriterStage::GenerationRead, hold_enabled);
            let key = osslscope_ebpf_common::make_key(100, generation);
            let existing = writer.maps.lock().unwrap().rows.get(&key).is_some();
            assert_eq!(
                existing, !fresh,
                "the existing branch requires a real successful lookup"
            );
            writer.at(WriterStage::ExistingLookup, hold_enabled);
            if fresh {
                if !fail_insert {
                    writer
                        .maps
                        .lock()
                        .unwrap()
                        .rows
                        .insert(key, Default::default());
                }
                writer.at(WriterStage::FreshInsert, hold_enabled);
            }
            {
                let mut maps = writer.maps.lock().unwrap();
                if fail_insert {
                    maps.dropfail += 1;
                } else {
                    let row = maps
                        .rows
                        .get_mut(&key)
                        .expect("existing or successful fresh relookup");
                    if row.count == 0 {
                        row.first_ns = sample_ns;
                    }
                    row.count += 1;
                    row.last_ns = sample_ns;
                }
            }
            writer.at(WriterStage::CountOrDrop, hold_enabled);
            if fresh {
                writer.at(WriterStage::BeforeLatc, hold_enabled);
                writer.maps.lock().unwrap().latc += 1;
            }
            writer.at(WriterStage::LastMutation, hold_enabled);
            writer.at(WriterStage::Returned, hold_enabled);
            let _current = writer.stage.lock().unwrap();
            writer.returned.store(true, Ordering::Release);
            writer.changed.notify_all();
        })
    }
}

#[test]
fn g1_before_admitted_equality_is_not_a_witness() {
    let writer = StagedWriter::new(Some(WriterStage::WindowPassed));
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, Some(Arc::clone(&writer)), TerminalFaults::default());
    engine.attach(attach_request(1, 1)).unwrap();
    engine.open_window(open_request(2)).unwrap();
    let producer = writer.run(true, false);
    writer.wait_at(WriterStage::WindowPassed);
    let (legacy_admitted, legacy_counts) = {
        let maps = writer.maps.lock().unwrap();
        (
            maps.admitted,
            maps.rows.values().map(|row| row.count).sum::<u64>(),
        )
    };
    let legacy_complete = legacy_admitted == legacy_counts;
    let legacy_final_calls = legacy_counts;
    assert!(legacy_complete, "the legacy negative must falsely finalize");
    assert_eq!(legacy_admitted, legacy_counts);
    assert_ne!(legacy_final_calls, writer.ledger.admitted_calls());
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    let terminal = thread::scope(|scope| {
        let joined = scope.spawn(|| engine.terminal(request.clone()));
        probe.owner.wait(|events| {
            events.iter().any(|(_, e)| {
                matches!(
                    e,
                    Event::Registry(RegistryEvent::CloseIssued(ResourceId::Link(_)))
                )
            })
        });
        assert!(locked(&engine.shared.state).terminal_result.is_none());
        writer.release();
        joined.join().unwrap()
    });
    producer.join().unwrap();
    assert!(matches!(terminal.writers, WriterCompletion::Finished(_)));
    let rows = &terminal.checkpoint.as_ref().unwrap().snapshot.rows;
    assert_eq!(
        rows.iter().map(|(_, v)| v.count).sum::<u64>(),
        writer.ledger.admitted_calls()
    );
    assert_eq!(validate_terminal(&request, &terminal), Ok(()));
    task3_cleanup(&probe.owner, 10);
}

fn terminal_request(engine: &CountEngine, deadline: Instant) -> TerminalRequest {
    TerminalRequest {
        id: TerminalId {
            owner_epoch: engine.ready.owner_epoch,
            sequence: TerminalSeq::checked(1).unwrap(),
        },
        deadline,
        evidence_domain: engine.ready.evidence_domain,
        writer_object_identity: engine.ready.writer_object_identity,
        frontier: locked(&engine.shared.state).frontier.clone(),
    }
}

struct TerminalFaults {
    map: MapFaults,
    close: Faults,
    profile: KernelApplicability,
    references: ReferenceFinality,
    family: CountDimensions,
    fail_publication: bool,
    clock_panic_after_close: bool,
    clock: Option<Arc<ControlledClock>>,
    publication_gate: Option<Arc<Probe>>,
    registry_hook: Option<Arc<dyn Fn(RegistryEvent) + Send + Sync>>,
    seal_claim_gate: Option<Arc<Probe>>,
}
impl Default for TerminalFaults {
    fn default() -> Self {
        Self {
            map: MapFaults::default(),
            close: Faults::default(),
            profile: KernelApplicability::reviewed_fixture(1),
            references: ReferenceFinality::final_owned(),
            family: CountDimensions::validated(),
            fail_publication: false,
            clock_panic_after_close: false,
            clock: None,
            publication_gate: None,
            registry_hook: None,
            seal_claim_gate: None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalEvent {
    Stop,
    StopReturned(Option<i32>),
    LinkClose,
    CloseAck,
    Snapshot,
}
struct TerminalDriver {
    map: MapDriver,
    writer: Option<Arc<StagedWriter>>,
    links: Vec<i32>,
    timeline: Arc<Mutex<Vec<(TerminalEvent, Instant)>>>,
    clock_panic_after_close: bool,
    clock: Option<Arc<ControlledClock>>,
}
impl CountIoDriver for TerminalDriver {
    fn map_create(&mut self, spec: &crate::loader::MapSpecLite) -> io::Result<OwnedFd> {
        self.map.map_create(spec)
    }
    fn load_program(&mut self, i: &[u8], n: &str, l: Option<&mut [u8]>) -> io::Result<OwnedFd> {
        self.map.load_program(i, n, l)
    }
    fn open_pin(&mut self, p: &CStr) -> io::Result<OwnedFd> {
        self.map.open_pin(p)
    }
    fn pin_identity(&mut self, p: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        self.map.pin_identity(p)
    }
    fn attach(
        &mut self,
        p: BorrowedFd<'_>,
        path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        tgid: u32,
    ) -> io::Result<OwnedFd> {
        let fd = self.map.attach(p, path, offsets, cookies, tgid)?;
        self.links.push(fd.as_raw_fd());
        Ok(fd)
    }
    unsafe fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
        if self.map.map(fd) == CountMap::Target && value == 0u64.to_ne_bytes() {
            self.timeline
                .lock()
                .unwrap()
                .push((TerminalEvent::Stop, Instant::now()));
        }
        let map = self.map.map(fd);
        // SAFETY: forwarded exact validated slices from the owner.
        let result = unsafe { self.map.update(fd, key, value) };
        if map == CountMap::Target && value == 0u64.to_ne_bytes() {
            self.timeline.lock().unwrap().push((
                TerminalEvent::StopReturned(
                    result.as_ref().err().and_then(io::Error::raw_os_error),
                ),
                Instant::now(),
            ));
        }
        result?;
        if map == CountMap::Gen {
            if let Some(writer) = &self.writer {
                writer.generation.store(
                    u32::from_ne_bytes(value.try_into().unwrap()),
                    Ordering::Release,
                );
            }
        }
        Ok(())
    }
    unsafe fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8],
        value: &mut [u8],
    ) -> io::Result<()> {
        let Some(writer) = self.writer.as_ref().map(Arc::clone) else {
            // SAFETY: forwarded exact validated slices from the owner.
            return unsafe { self.map.lookup(fd, key, value) };
        };
        let map = self.map.map(fd);
        let k = if key.len() == 8 {
            u64::from_ne_bytes(key.try_into().unwrap())
        } else {
            u32::from_ne_bytes(key.try_into().unwrap()) as u64
        };
        self.map.enter(MapAction::Lookup(map, k, value.len()));
        let maps = writer.maps.lock().unwrap();
        value.fill(0);
        if map == CountMap::Counts {
            let row = maps
                .rows
                .get(&k)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
            value[..8].copy_from_slice(&row.count.to_ne_bytes());
            value[8..16].copy_from_slice(&row.first_ns.to_ne_bytes());
            value[16..24].copy_from_slice(&row.last_ns.to_ne_bytes());
        } else {
            let n = match map {
                CountMap::Admitted => maps.admitted,
                CountMap::Dropfail => maps.dropfail,
                CountMap::Latc if k == 0 => maps.latc,
                CountMap::Latc => 0,
                _ => panic!("invalid model read"),
            };
            value[..8].copy_from_slice(&n.to_ne_bytes());
        }
        Ok(())
    }
    unsafe fn next_key(
        &mut self,
        fd: BorrowedFd<'_>,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> io::Result<()> {
        self.timeline
            .lock()
            .unwrap()
            .push((TerminalEvent::Snapshot, Instant::now()));
        let Some(writer) = self.writer.as_ref().map(Arc::clone) else {
            // SAFETY: forwarded exact validated slices from the owner.
            return unsafe { self.map.next_key(fd, key, next) };
        };
        assert_eq!(self.map.map(fd), CountMap::Counts);
        let key = key.map(|k| u64::from_ne_bytes(k.try_into().unwrap()));
        self.map.enter(MapAction::Next(key));
        let maps = writer.maps.lock().unwrap();
        let k = maps
            .rows
            .keys()
            .find(|k| key.is_none_or(|last| **k > last))
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        next.copy_from_slice(&k.to_ne_bytes());
        Ok(())
    }
    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        let fd = std::mem::ManuallyDrop::new(fd);
        let is_link = self.links.contains(&fd.as_raw_fd());
        if is_link {
            self.timeline
                .lock()
                .unwrap()
                .push((TerminalEvent::LinkClose, Instant::now()));
            // This wait models the reviewed close theorem. It is deliberately
            // independent of ADMITTED, COUNTS and the owner's completion code.
            if let Some(writer) = &self.writer {
                writer.wait_returned();
            }
        }
        let result = self.map.close(std::mem::ManuallyDrop::into_inner(fd));
        if is_link {
            self.timeline
                .lock()
                .unwrap()
                .push((TerminalEvent::CloseAck, Instant::now()));
        }
        result
    }
    fn now(&self) -> Instant {
        if self
            .map
            .probe
            .before_open_write
            .swap(false, Ordering::AcqRel)
        {
            self.map.probe.owner.event(Event::BeforeOpenWrite);
            self.map.probe.owner.hold();
        }
        assert!(
            !self.clock_panic_after_close || self.map.base.closes == 0,
            "terminal post-close clock unwind control"
        );
        self.clock
            .as_ref()
            .map_or_else(|| self.map.now(), |clock| clock.now())
    }
    fn monotonic_ns(&self) -> Option<u64> {
        self.map.monotonic_ns()
    }
}
fn terminal_engine(
    probe: &Arc<MapProbe>,
    writer: Option<Arc<StagedWriter>>,
    faults: TerminalFaults,
) -> (CountEngine, Arc<Mutex<Vec<(TerminalEvent, Instant)>>>) {
    let observed = Arc::clone(&probe.owner);
    let registry_hook = faults.registry_hook.clone();
    let mut hooks = PrepareHooks::host();
    hooks.kernel_profile = faults.profile;
    hooks.final_references = faults.references;
    hooks.writer_family = faults.family;
    hooks.fail_attach_publication = faults.fail_publication;
    hooks.clock = faults.clock.as_ref().map(|clock| {
        let clock = Arc::clone(clock);
        Arc::new(move || clock.now()) as Arc<dyn Fn() -> Instant + Send + Sync>
    });
    hooks.before_terminal_publication = faults.publication_gate.as_ref().map(|gate| {
        let gate = Arc::clone(gate);
        Arc::new(move || {
            gate.event(Event::Started);
            gate.hold();
        }) as Arc<dyn Fn() + Send + Sync>
    });
    hooks.seal_claim_observer = faults.seal_claim_gate.as_ref().map(|gate| {
        let gate = Arc::clone(gate);
        Arc::new(move || {
            gate.event(Event::Started);
            gate.hold();
        }) as Arc<dyn Fn() + Send + Sync>
    });
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event));
        if let Some(hook) = &registry_hook {
            hook(event);
        }
    }));
    let probe = Arc::clone(probe);
    let cutoff = Instant::now() + Duration::from_secs(30);
    let timeline = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&timeline);
    let engine = CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance(24, 2).unwrap(),
        cutoff,
        hooks,
        move || {
            probe.owner.event(Event::Started);
            TerminalDriver {
                map: MapDriver {
                    base: PipeDriver {
                        probe: Arc::clone(&probe.owner),
                        faults: faults.close,
                        deadline: cutoff,
                        attempts: 0,
                        acquired: 0,
                        closes: 0,
                    },
                    probe,
                    faults: faults.map,
                    maps: [-1; 7],
                    map_count: 0,
                    next_position: 0,
                    writes: 0,
                    cpus: 2,
                    cutoff,
                },
                writer,
                links: Vec::with_capacity(4),
                timeline: observed,
                clock_panic_after_close: faults.clock_panic_after_close,
                clock: faults.clock,
            }
        },
        spawn_owner,
    )
    .unwrap();
    (engine, timeline)
}

#[test]
fn g1_terminal_staged_writer_holds_and_no_hold_twins() {
    // Every held case has a genuinely unheld twin with identical producer work.
    for generation in [0, 3] {
        for (stage, fresh, failed) in [
            (WriterStage::TargetRead, true, false),
            (WriterStage::WindowPassed, true, false),
            (WriterStage::AdmittedLedger, true, false),
            (WriterStage::GenerationRead, true, false),
            (WriterStage::ExistingLookup, false, false),
            (WriterStage::FreshInsert, true, false),
            (WriterStage::FreshInsert, true, true),
            (WriterStage::CountOrDrop, true, false),
            (WriterStage::BeforeLatc, true, false),
            (WriterStage::LastMutation, true, false),
            (WriterStage::Returned, true, false),
        ] {
            for held in [true, false] {
                let writer = StagedWriter::new(held.then_some(stage));
                let probe = MapProbe::new();
                let (engine, timeline) =
                    terminal_engine(&probe, Some(Arc::clone(&writer)), TerminalFaults::default());
                engine.attach(attach_request(1, 1)).unwrap();
                let mut open = open_request(2);
                open.generation = generation;
                engine.open_window(open).unwrap();
                if !fresh {
                    // An actual unheld producer invocation supplies a separate
                    // physical baseline and primes the successful lookup.
                    writer.run_baseline().join().unwrap();
                }
                let producer = writer.run(fresh, failed);
                if held {
                    writer.wait_at(stage);
                } else {
                    writer.wait_returned();
                }
                if held && !fresh {
                    let maps = writer.maps.lock().unwrap();
                    let key = osslscope_ebpf_common::make_key(100, generation);
                    assert_eq!(maps.rows.get(&key).map(|v| v.count), Some(1));
                    assert_eq!(writer.ledger.admitted_calls(), 2);
                }
                engine
                    .set_generation(GenerationRequest {
                        seq: CommandSeq::checked(3).unwrap(),
                        deadline: Instant::now() + Duration::from_secs(5),
                        generation: 3,
                    })
                    .unwrap();
                let sampled_generation = if held
                    && matches!(
                        stage,
                        WriterStage::TargetRead
                            | WriterStage::WindowPassed
                            | WriterStage::AdmittedLedger
                    ) {
                    3
                } else {
                    generation
                };
                let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
                let terminal = thread::scope(|scope| {
                    let joined = scope.spawn(|| engine.terminal(request.clone()));
                    if held {
                        probe.owner.wait(|events| {
                            events.iter().any(|(_, e)| {
                                matches!(
                                    e,
                                    Event::Registry(RegistryEvent::CloseIssued(ResourceId::Link(
                                        _
                                    )))
                                )
                            })
                        });
                        assert!(
                            locked(&engine.shared.state).terminal_result.is_none(),
                            "Finished while {stage:?} was held"
                        );
                        assert!(!writer.returned.load(Ordering::Acquire));
                        writer.release();
                    }
                    joined.join().unwrap()
                });
                producer.join().unwrap();
                assert!(
                    matches!(terminal.writers, WriterCompletion::Finished(_)),
                    "{stage:?} {held}: {:?}",
                    terminal.writers
                );
                assert_eq!(validate_terminal(&request, &terminal), Ok(()));
                let snapshot = &terminal.checkpoint.as_ref().unwrap().snapshot;
                let current_calls = snapshot
                    .rows
                    .iter()
                    .filter(|(k, _)| osslscope_ebpf_common::split_key(*k).1 == 3)
                    .map(|(_, v)| v.count)
                    .sum::<u64>();
                let fenced_calls = snapshot
                    .rows
                    .iter()
                    .filter(|(k, _)| osslscope_ebpf_common::split_key(*k).1 != 3)
                    .map(|(_, v)| v.count)
                    .sum::<u64>();
                let Component::Available(dropfail) = snapshot.dropfail else {
                    panic!("missing dropfail")
                };
                let unattributed = 0;
                assert_eq!(
                    current_calls + fenced_calls + unattributed + dropfail,
                    writer.ledger.admitted_calls()
                );
                let baseline_current = u64::from(!fresh && generation == 3);
                let baseline_fenced = u64::from(!fresh && generation != 3);
                assert_eq!(
                    current_calls,
                    baseline_current + u64::from(sampled_generation == 3 && !failed)
                );
                assert_eq!(
                    fenced_calls,
                    baseline_fenced + u64::from(sampled_generation != 3 && !failed)
                );
                assert_eq!(dropfail, u64::from(failed));
                assert_eq!(
                    snapshot.admitted,
                    Component::Available(if fresh { 1 } else { 2 })
                );
                let physical = writer.ledger.0.lock().unwrap();
                if !fresh {
                    assert_eq!(
                        (
                            physical[0].invocation_id,
                            physical[0].generation,
                            physical[0].actual_sample_ns
                        ),
                        (1, Some(generation), 400)
                    );
                    let row = &snapshot.rows[0].1;
                    assert_eq!((row.count, row.first_ns, row.last_ns), (2, 400, 500));
                }
                let entry = physical.last().unwrap();
                assert_eq!(
                    (
                        entry.invocation_id,
                        entry.site,
                        entry.generation,
                        entry.actual_sample_ns
                    ),
                    (
                        if fresh { 1 } else { 2 },
                        100,
                        Some(sampled_generation),
                        500
                    )
                );
                let events = timeline.lock().unwrap();
                let ack = events
                    .iter()
                    .filter(|(e, _)| *e == TerminalEvent::CloseAck)
                    .map(|(_, t)| *t)
                    .max()
                    .unwrap();
                let read = events
                    .iter()
                    .find(|(e, _)| *e == TerminalEvent::Snapshot)
                    .unwrap()
                    .1;
                assert!(ack < read);
                assert!(terminal.snapshot_binding.unwrap().immutable);
                drop(events);
                task3_cleanup(&probe.owner, 10);
            }
        }
    }
}

fn mutate_terminal(
    receipt: &RawTerminal,
    change: impl FnOnce(&mut RawTerminalData),
) -> RawTerminal {
    // Test mutation only: production RawTerminal has no owned-vector Clone or
    // mutable accessor. These fixture copies cannot own a descriptor.
    let mut data = RawTerminalData {
        owner_epoch: receipt.owner_epoch,
        terminal_id: receipt.terminal_id,
        deadline: receipt.deadline,
        last_command_seq: receipt.last_command_seq,
        resolved_open: receipt.resolved_open,
        evidence_domain: receipt.evidence_domain,
        inventory: receipt.inventory.clone(),
        manifest: receipt.manifest.clone(),
        close_outcomes: receipt.close_outcomes.clone(),
        kernel_profile: receipt.kernel_profile,
        writer_object_identity: receipt.writer_object_identity,
        writer_family: receipt.writer_family,
        host_writes_sealed: receipt.host_writes_sealed,
        final_references: receipt.final_references,
        seal: receipt.seal,
        writers: receipt.writers,
        checkpoint: receipt.checkpoint.clone(),
        snapshot_binding: receipt.snapshot_binding,
        read_status: receipt.read_status,
        cleanup_ticket: receipt.cleanup_ticket,
        cleanup_state: receipt.cleanup_state.clone(),
        failures: receipt.failures,
    };
    change(&mut data);
    RawTerminal(Arc::new(data))
}
fn mutate_inventory(data: &mut RawTerminalData, change: impl FnOnce(&mut SealedInventory)) {
    let mut inventory = data.inventory.as_ref().unwrap().as_ref().clone();
    change(&mut inventory);
    data.inventory = Some(Arc::new(inventory));
}
#[test]
fn g1_terminal_receipt_rejects_false_proof() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                keys: vec![5, 7],
                ..MapFaults::default()
            },
            ..TerminalFaults::default()
        },
    );
    let first = engine.attach(attach_request(1, 1)).unwrap().value.links[0].id();
    engine.open_window(open_request(2)).unwrap();
    engine
        .set_generation(GenerationRequest {
            seq: CommandSeq::checked(3).unwrap(),
            deadline: Instant::now() + Duration::from_secs(5),
            generation: 3,
        })
        .unwrap();
    let mut second = attach_request(4, 1);
    second.offsets = vec![7];
    second.cookies = vec![107];
    let second = engine.attach(second).unwrap().value.links[0].id();
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    let receipt = engine.terminal(request.clone());
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    assert_eq!(
        receipt.manifest.iter().map(|r| r.id).collect::<Vec<_>>(),
        [first, second]
    );
    assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
    let cases: Vec<(&str, RawTerminal)> = vec![
        (
            "missing",
            mutate_terminal(&receipt, |d| {
                d.manifest.pop();
            }),
        ),
        (
            "duplicate",
            mutate_terminal(&receipt, |d| d.manifest.push(d.manifest[0].clone())),
        ),
        (
            "unpublished",
            mutate_terminal(&receipt, |d| {
                mutate_inventory(d, |i| {
                    i.unpublished_links.push(i.records[0].id);
                })
            }),
        ),
        (
            "epoch",
            mutate_terminal(&receipt, |d| {
                d.owner_epoch = OwnerEpoch::checked(u64::MAX).unwrap()
            }),
        ),
        (
            "terminal",
            mutate_terminal(&receipt, |d| {
                d.terminal_id.sequence = TerminalSeq::checked(2).unwrap()
            }),
        ),
        (
            "frontier",
            mutate_terminal(&receipt, |d| {
                d.last_command_seq = Some(CommandSeq::checked(99).unwrap())
            }),
        ),
        (
            "open",
            mutate_terminal(&receipt, |d| {
                d.resolved_open.as_mut().unwrap().generation += 1
            }),
        ),
        (
            "host writer",
            mutate_terminal(&receipt, |d| d.host_writes_sealed = false),
        ),
        (
            "file alias",
            mutate_terminal(&receipt, |d| d.final_references.file = false),
        ),
        (
            "link alias",
            mutate_terminal(&receipt, |d| d.final_references.bpf_link = false),
        ),
        (
            "object",
            mutate_terminal(&receipt, |d| d.writer_object_identity = [8; 32]),
        ),
        (
            "root",
            mutate_terminal(&receipt, |d| d.writer_family.root = "unreviewed"),
        ),
        (
            "stop",
            mutate_terminal(&receipt, |d| {
                d.seal.result =
                    StopResult::Failed(OwnerFailure::engine(CountOperation::Stop, FailureClass::Io))
            }),
        ),
        (
            "close",
            mutate_terminal(&receipt, |d| d.close_outcomes[0].errno = Some(libc::EINTR)),
        ),
        (
            "vendor",
            mutate_terminal(&receipt, |d| {
                d.kernel_profile = KernelApplicability::Unknown(ProfileFailure::UnknownVendor)
            }),
        ),
        (
            "model as Live",
            mutate_terminal(&receipt, |d| {
                d.evidence_domain = EvidenceDomain::Live;
                d.kernel_profile = KernelApplicability::ModelFixture;
            }),
        ),
        (
            "read not started",
            mutate_terminal(&receipt, |d| d.read_status = ReadStatus::NotStarted),
        ),
        (
            "checkpoint phase",
            mutate_terminal(&receipt, |d| {
                d.checkpoint.as_mut().unwrap().phase = OwnerPhase::Observing
            }),
        ),
        (
            "checkpoint publication",
            mutate_terminal(&receipt, |d| {
                d.checkpoint.as_mut().unwrap().published_at = d.snapshot_binding.unwrap().started_at
            }),
        ),
        (
            "snapshot seq",
            mutate_terminal(&receipt, |d| {
                d.snapshot_binding.as_mut().unwrap().sequence =
                    SnapshotSeq::checked(u64::MAX).unwrap()
            }),
        ),
        (
            "snapshot order",
            mutate_terminal(&receipt, |d| {
                d.snapshot_binding.as_mut().unwrap().started_at =
                    d.deadline - Duration::from_secs(30)
            }),
        ),
        (
            "cutoff",
            mutate_terminal(&receipt, |d| {
                d.snapshot_binding.as_mut().unwrap().completed_at =
                    d.deadline + Duration::from_secs(1)
            }),
        ),
        (
            "membership range",
            mutate_terminal(&receipt, |d| d.manifest[0].memberships.end += 1),
        ),
        (
            "membership alias",
            mutate_terminal(&receipt, |d| {
                mutate_inventory(d, |i| {
                    i.memberships[1].offset = i.memberships[0].offset;
                })
            }),
        ),
        (
            "lost completed",
            mutate_terminal(&receipt, |d| {
                mutate_inventory(d, |i| i.last_completed = None)
            }),
        ),
    ];
    for (name, bad) in cases {
        assert!(
            validate_terminal(&request, &bad).is_err(),
            "accepted {name}"
        );
    }
    // Hash supplied by the expected frontier is independent of the receipt's
    // self-consistency; rewriting all receipt hashes cannot substitute for it.
    let mut wrong_expected = request.clone();
    wrong_expected.writer_object_identity = [9; 32];
    assert_eq!(
        validate_terminal(&wrong_expected, &receipt),
        Err(ReceiptFailure::Identity)
    );
    let repeated = engine.terminal(request.clone());
    assert!(Arc::ptr_eq(&receipt.0, &repeated.0));
    task3_cleanup(&probe.owner, 11);
}

#[test]
fn g1_terminal_unknown_profile_stop_close_alias_and_read_keep_positive_rows() {
    for control in 0..7 {
        let probe = MapProbe::new();
        let mut faults = TerminalFaults::default();
        faults.map.keys = vec![5, 7];
        match control {
            0 => faults.profile = KernelApplicability::Unknown(ProfileFailure::UnknownVendor),
            1 => faults.map.write_error = Some(1),
            2 => faults.close.fail_close = Some(1),
            3 => faults.references.file = false,
            4 => faults.references.bpf_link = false,
            5 => faults.family.root = "different_entry",
            6 => faults.map.component_error = Some((CountMap::Admitted, 0)),
            _ => unreachable!(),
        }
        let (engine, _) = terminal_engine(&probe, None, faults);
        engine.attach(attach_request(1, 1)).unwrap();
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        let receipt = engine.terminal(request.clone());
        assert_eq!(
            receipt.checkpoint.as_ref().unwrap().snapshot.rows.len(),
            2,
            "control {control}"
        );
        assert_eq!(
            matches!(receipt.writers, WriterCompletion::Finished(_)),
            control == 6
        );
        assert_eq!(receipt.snapshot_binding.unwrap().immutable, control == 6);
        if control == 6 {
            assert!(matches!(receipt.read_status, ReadStatus::Incomplete { .. }));
            assert_eq!(
                receipt.failures.components[0].unwrap().errno,
                Some(libc::EIO)
            );
        }
        assert_eq!(
            validate_terminal(&request, &receipt),
            Ok(()),
            "control {control}"
        );
        task3_cleanup(&probe.owner, 10);
        if control == 1 {
            assert_eq!(
                receipt.failures.operations[CountOperation::Stop as usize]
                    .unwrap()
                    .errno,
                Some(libc::EIO)
            );
            assert_eq!(
                receipt.close_outcomes[0].state,
                ResourceState::CloseReturned
            );
        }
        if control == 2 {
            assert!(matches!(receipt.cleanup_state, CleanupState::Failed(_)));
            assert_eq!(receipt.close_outcomes[0].errno, Some(libc::EINTR));
            assert_eq!(
                receipt.close_outcomes[0].state,
                ResourceState::ConsumedError
            );
            assert_eq!(
                engine
                    .fork_permit(Instant::now() + Duration::from_secs(3))
                    .err(),
                Some(ForkBlocked::Unresolved)
            );
        }
    }
}

#[test]
fn g1_terminal_unpublished_survivor_is_exactly_closed() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            close: Faults {
                hold_acquire: Some(10),
                ..Faults::default()
            },
            ..TerminalFaults::default()
        },
    );
    let (request, receipt) = thread::scope(|scope| {
        let attach = scope.spawn(|| engine.attach(attach_request(1, 2)));
        probe.owner.wait(|events| {
            events
                .iter()
                .any(|(_, e)| matches!(e, Event::EnterAcquire(10)))
        });
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        let posted = request.clone();
        let owner = &engine;
        let terminal = scope.spawn(move || owner.terminal(posted));
        let cutoff = Instant::now() + Duration::from_secs(5);
        let mut state = locked(&engine.shared.state);
        while state.terminal.is_none() {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero());
            state = engine
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap()
                .0;
        }
        drop(state);
        probe.owner.release();
        assert!(attach.join().unwrap().is_err());
        let receipt = terminal.join().unwrap();
        (request, receipt)
    });
    assert_eq!(receipt.manifest.len(), 1);
    assert_eq!(receipt.close_outcomes.len(), 1);
    let inventory = receipt.inventory.as_ref().unwrap();
    assert_eq!(
        inventory.memberships,
        [
            AttachedMembership {
                offset: 0,
                cookie: 100
            },
            AttachedMembership {
                offset: 1,
                cookie: 101
            }
        ]
    );
    assert_eq!(inventory.unpublished_links, [receipt.manifest[0].id]);
    assert!(inventory.acknowledged_links.is_empty());
    assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    task3_cleanup(&probe.owner, 10);
}

#[test]
fn g1_terminal_kernel_source_tags_never_admit_live_builds() {
    for marker in 0..4 {
        let identity = KernelBuildIdentity {
            build_sha256: Some([marker; 32]),
            config_sha256: Some([1; 32]),
            vendor_source_sha256: Some([2; 32]),
        };
        assert!(matches!(
            resolve_kernel_applicability(&identity),
            KernelApplicability::Unknown(_)
        ));
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                profile: KernelApplicability::reviewed_fixture(marker as usize),
                ..TerminalFaults::default()
            },
        );
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        let receipt = engine.terminal(request.clone());
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        assert_eq!(validate_terminal(&request, &receipt), Ok(()));
        let mut expected = request.clone();
        expected.evidence_domain = EvidenceDomain::Live;
        let bad = mutate_terminal(&receipt, |d| d.evidence_domain = EvidenceDomain::Live);
        assert!(validate_terminal(&expected, &bad).is_err());
        task3_cleanup(&probe.owner, 8);
    }
}

#[test]
fn g1_terminal_finished_count_waits_for_pin_program_map_cleanup_before_fork() {
    for held_close in [2, 3, 4] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                close: Faults {
                    hold_close: Some(held_close),
                    ..Faults::default()
                },
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let receipt = engine.terminal(terminal_request(
            &engine,
            Instant::now() + Duration::from_secs(5),
        ));
        probe.owner.wait(|events| {
            events
                .iter()
                .filter(|(_, e)| matches!(e, Event::EnterClose))
                .count()
                == held_close
        });
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        assert!(matches!(receipt.cleanup_state, CleanupState::Pending(_)));
        assert!(engine.fork_permit(Instant::now()).is_err());
        assert!(engine.ready.owner_epoch == receipt.cleanup_ticket.owner_epoch);
        let summary = engine.resource_summary();
        assert!(
            summary
                .resources
                .iter()
                .any(|r| r.state == ResourceState::CloseIssued)
        );
        let other_probe = Probe::new();
        let refused = injected(
            Arc::clone(&other_probe),
            Faults::default(),
            Arc::clone(&engine.shared.barrier),
            Instant::now() + Duration::from_secs(1),
            PrepareHooks::host(),
        )
        .err()
        .unwrap();
        assert_eq!(refused.failure.class, FailureClass::Capacity);
        assert!(
            !other_probe
                .log
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|(_, e)| matches!(e, Event::Started | Event::EnterAcquire(_)))
        );
        probe.owner.release();
        task3_cleanup(&probe.owner, 10);
        let permit = engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        drop(permit);
        // Eventual cleanup closes the ticket, without changing this capture's
        // immutable earlier Pending receipt or manufacturing a new epoch.
        assert!(matches!(receipt.cleanup_state, CleanupState::Pending(_)));
    }
}

#[test]
fn g1_terminal_blocked_close_freezes_one_deadline_and_keeps_custody() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                keys: vec![5],
                ..MapFaults::default()
            },
            close: Faults {
                hold_close: Some(1),
                ..Faults::default()
            },
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let before = engine
        .drain(ReadRequest {
            seq: CommandSeq::checked(2).unwrap(),
            deadline: Instant::now() + Duration::from_secs(5),
        })
        .unwrap()
        .value;
    let calls = probe.calls.lock().unwrap().len();
    let request = terminal_request(&engine, Instant::now() + Duration::from_millis(50));
    let receipt = engine.terminal(request.clone());
    assert!(matches!(
        receipt.writers,
        WriterCompletion::Unknown(QuiescenceReason::Deadline)
    ));
    assert_eq!(receipt.manifest.len(), 1);
    assert_eq!(receipt.close_outcomes[0].state, ResourceState::CloseIssued);
    assert!(Arc::ptr_eq(
        &receipt.checkpoint.as_ref().unwrap().snapshot,
        &before
    ));
    assert!(engine.fork_permit(Instant::now()).is_err());
    assert!(
        engine
            .resource_summary()
            .resources
            .iter()
            .any(|r| r.state == ResourceState::CloseIssued)
    );
    let mut longer = request.clone();
    longer.deadline += Duration::from_secs(10);
    assert!(Arc::ptr_eq(&receipt.0, &engine.terminal(longer).0));
    probe.owner.release();
    task3_cleanup(&probe.owner, 10);
    engine
        .fork_permit(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        probe.calls.lock().unwrap().len(),
        calls + 1,
        "map I/O retried after cutoff"
    );
    assert!(Arc::ptr_eq(&receipt.0, &engine.terminal(request).0));
    assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
}

#[test]
fn g1_terminal_expired_budget_performs_no_map_io() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now());
    let receipt = engine.terminal(request.clone());
    assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
    assert_eq!(receipt.read_status, ReadStatus::NotStarted);
    task3_cleanup(&probe.owner, 10);
    assert!(probe.calls.lock().unwrap().is_empty());
    assert!(Arc::ptr_eq(&receipt.0, &engine.terminal(request).0));
}

#[test]
fn g1_terminal_active_open_returns_its_actual_partial_frontier() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                hold_call: Some(2),
                ..MapFaults::default()
            },
            ..TerminalFaults::default()
        },
    );
    let (request, receipt) = thread::scope(|scope| {
        let open = scope.spawn(|| engine.open_window(open_request(1)));
        probe.wait_calls(2);
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        let posted = request.clone();
        let owner = &engine;
        let terminal = scope.spawn(move || owner.terminal(posted));
        let mut state = locked(&engine.shared.state);
        while state.terminal.is_none() {
            state = engine.shared.changed.wait(state).unwrap();
        }
        drop(state);
        probe.owner.release();
        assert!(open.join().unwrap().is_err());
        let receipt = terminal.join().unwrap();
        (request, receipt)
    });
    assert_eq!(
        receipt.last_command_seq,
        Some(CommandSeq::checked(1).unwrap())
    );
    let open = receipt.resolved_open.unwrap();
    assert_eq!(open.completed_writes, OpenWriteFrontier::WindowDeadline);
    assert_eq!(open.outcome, OpenOutcome::Failed);
    assert_eq!(
        receipt.inventory.as_ref().unwrap().resolved_open,
        Some(open)
    );
    assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    assert_eq!(
        receipt.failures.operations[CountOperation::Open as usize]
            .unwrap()
            .class,
        FailureClass::Disconnected
    );
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_terminal_known_alias_release_cannot_repair_consumed_close() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            references: ReferenceFinality {
                file: true,
                bpf_link: false,
            },
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    let receipt = engine.terminal(request.clone());
    assert_eq!(
        receipt.writers,
        WriterCompletion::Unknown(QuiescenceReason::References)
    );
    task3_cleanup(&probe.owner, 10);
    // Releasing the modeled external alias after its owner FD was consumed
    // cannot provide a still-final normal close for the historical receipt.
    let released = mutate_terminal(&receipt, |d| d.final_references.bpf_link = true);
    assert_eq!(
        released.writers,
        WriterCompletion::Unknown(QuiescenceReason::References)
    );
    let repeated = engine.terminal(request);
    assert!(Arc::ptr_eq(&receipt.0, &repeated.0));
    assert!(!repeated.final_references.bpf_link);
}

#[test]
fn g1_terminal_finished_witness_survives_unreturned_snapshot_read() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                keys: vec![5, 7],
                hold_call: Some(6),
                ..MapFaults::default()
            },
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now() + Duration::from_millis(100));
    let receipt = engine.terminal(request.clone());
    probe.wait_calls(6);
    assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
    assert!(matches!(
        receipt.read_status,
        ReadStatus::Incomplete {
            enumeration: EnumerationStatus::Unfinished
        }
    ));
    assert_eq!(receipt.checkpoint.as_ref().unwrap().snapshot.rows.len(), 2);
    assert!(receipt.snapshot_binding.unwrap().immutable);
    assert_eq!(
        receipt.failures.operations[CountOperation::Read as usize]
            .unwrap()
            .class,
        FailureClass::Deadline
    );
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    assert!(engine.fork_permit(Instant::now()).is_err());
    probe.owner.release();
    task3_cleanup(&probe.owner, 10);
    assert_eq!(probe.calls.lock().unwrap().len(), 6);
    assert!(Arc::ptr_eq(&receipt.0, &engine.terminal(request).0));
}

fn assert_only_terminal_tail(probe: &MapProbe, ordinary_calls: usize) {
    let calls = probe.calls.lock().unwrap();
    let tail = &calls[ordinary_calls..];
    assert_eq!(
        tail.iter()
            .filter(|(_, action)| matches!(action, MapAction::Write(..)))
            .count(),
        1
    );
    assert!(
        matches!(&tail[0].1, MapAction::Write(CountMap::Target, 0, bytes) if bytes == &0u64.to_ne_bytes())
    );
    assert!(
        tail[1..]
            .iter()
            .all(|(_, action)| matches!(action, MapAction::Lookup(..) | MapAction::Next(..))),
        "ordinary host writes reentered after sealing: {tail:?}"
    );
}

#[test]
fn g1_terminal_cleanup_complete_and_failed_are_actual_registry_results() {
    for fail in [false, true] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                close: Faults {
                    fail_close: fail.then_some(1),
                    ..Faults::default()
                },
                ..TerminalFaults::default()
            },
        );
        // Known never-opened Ready follows the checked inert cleanup path.
        let deadline = Instant::now();
        engine.shared.seal(deadline);
        task3_cleanup(&probe.owner, 8);
        let mut barrier = locked(&engine.shared.barrier.state);
        while !barrier.sealed {
            barrier = engine.shared.barrier.changed.wait(barrier).unwrap();
        }
        drop(barrier);
        let receipt = engine.terminal(terminal_request(&engine, deadline));
        assert!(matches!(receipt.writers, WriterCompletion::KnownEmpty(_)));
        assert!(matches!(receipt.cleanup_state, CleanupState::Pending(_)));
        let diagnostic = engine.cleanup_progress().unwrap();
        if fail {
            let summary = engine.resource_summary();
            assert!(
                summary.resources.iter().any(
                    |r| r.state == ResourceState::ConsumedError && r.errno == Some(libc::EINTR)
                )
            );
            assert!(!summary.cleanup_complete);
            assert_eq!(diagnostic.status, CleanupStatus::Failed);
            assert_eq!(
                diagnostic.failures.operations[CountOperation::Cleanup as usize]
                    .unwrap()
                    .errno,
                Some(libc::EINTR)
            );
            assert!(engine.fork_permit(Instant::now()).is_err());
        } else {
            assert_eq!(diagnostic.status, CleanupStatus::Complete);
            engine
                .fork_permit(Instant::now() + Duration::from_secs(3))
                .unwrap();
        }
        assert_eq!(diagnostic.ticket, receipt.cleanup_ticket);
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(receipt.terminal_id).0
        ));
    }
}

#[test]
fn g1_terminal_wrong_expected_identity_still_closes_actual_registry() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    engine.attach(attach_request(1, 1)).unwrap();
    let actual_hash = engine.ready.writer_object_identity;
    let mut request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    request.writer_object_identity = [42; 32];
    let receipt = engine.terminal(request.clone());
    assert_eq!(receipt.writer_object_identity, actual_hash);
    assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
    assert_eq!(receipt.close_outcomes.len(), 1);
    assert_eq!(
        receipt.close_outcomes[0].state,
        ResourceState::CloseReturned
    );
    assert_eq!(
        validate_terminal(&request, &receipt),
        Err(ReceiptFailure::Identity)
    );
    task3_cleanup(&probe.owner, 10);
}

#[test]
fn g1_terminal_stop_read_and_post_close_panic_keep_cleanup_owner() {
    for control in 0..3 {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    keys: vec![5],
                    panic_call: [Some(1), Some(3), None][control],
                    ..MapFaults::default()
                },
                clock_panic_after_close: control == 2,
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let request = terminal_request(&engine, Instant::now() + Duration::from_millis(200));
        let receipt = engine.terminal(request);
        let operation = [
            CountOperation::Stop,
            CountOperation::Read,
            CountOperation::Close,
        ][control];
        assert_eq!(
            receipt.failures.operations[operation as usize]
                .unwrap()
                .class,
            FailureClass::Panic
        );
        if control == 1 {
            assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
            assert!(matches!(receipt.read_status, ReadStatus::Incomplete { .. }));
        } else {
            assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
        }
        task3_cleanup(&probe.owner, 10);
        engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
    }
}

#[test]
fn g1_terminal_recovered_read_preserves_original_component_errno() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                component_error: Some((CountMap::Latc, 7)),
                component_error_once: true,
                ..MapFaults::default()
            },
            ..TerminalFaults::default()
        },
    );
    let earlier = engine.drain(read_request(1)).unwrap().value;
    assert!(matches!(earlier.latc[7], Component::Unavailable(f) if f.errno == Some(libc::EIO)));
    let receipt = engine.terminal(terminal_request(
        &engine,
        Instant::now() + Duration::from_secs(5),
    ));
    assert_eq!(receipt.read_status, ReadStatus::Complete);
    assert!(matches!(
        receipt.checkpoint.as_ref().unwrap().snapshot.latc[7],
        Component::Available(_)
    ));
    assert_eq!(
        receipt.failures.components[9].map(|f| (f.map, f.key, f.errno)),
        Some((CountMap::Latc, 7, Some(libc::EIO)))
    );
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_terminal_late_cleanup_error_refuses_fork_after_finished_snapshot() {
    for (close, resource) in [
        (2, ResourceId::Pin(0)),
        (3, ResourceId::Program),
        (4, ResourceId::Map(CountMap::Counts)),
    ] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                close: Faults {
                    fail_close: Some(close),
                    // Make "late" independent of coordinator scheduling: the
                    // error cannot return until this artifact is selected.
                    hold_close: Some(close),
                    ..Faults::default()
                },
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let receipt = engine.terminal(terminal_request(
            &engine,
            Instant::now() + Duration::from_secs(5),
        ));
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        assert_eq!(receipt.read_status, ReadStatus::Complete);
        assert!(matches!(receipt.cleanup_state, CleanupState::Pending(_)));
        let selected_cleanup = receipt.cleanup_state.clone();
        probe.owner.release();
        task3_cleanup(&probe.owner, 10);
        let summary = engine.resource_summary();
        assert!(summary.resources.iter().any(|r| r.resource == resource
            && r.state == ResourceState::ConsumedError
            && r.errno == Some(libc::EINTR)));
        assert!(!summary.cleanup_complete);
        assert_eq!(
            engine
                .fork_permit(Instant::now() + Duration::from_secs(3))
                .err(),
            Some(ForkBlocked::Unresolved)
        );
        assert!(matches!(receipt.cleanup_state, CleanupState::Pending(_)));
        assert_eq!(receipt.cleanup_state, selected_cleanup);
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(receipt.terminal_id).0
        ));
    }
}

#[test]
fn g1_terminal_cleanup_error_observed_before_selection_is_fatal() {
    for (close, resource) in [
        (2, ResourceId::Pin(0)),
        (3, ResourceId::Program),
        (4, ResourceId::Map(CountMap::Counts)),
    ] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                close: Faults {
                    fail_close: Some(close),
                    ..Faults::default()
                },
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        {
            let mut state = locked(&engine.shared.state);
            engine.shared.seal_locked(&mut state, request.deadline);
            state.terminal_expected = Some(request.clone());
        }
        engine.shared.worker.get().unwrap().unpark();
        task3_cleanup(&probe.owner, 10);
        let mut barrier = locked(&engine.shared.barrier.state);
        while !barrier.sealed {
            barrier = engine.shared.barrier.changed.wait(barrier).unwrap();
        }
        drop(barrier);
        // All error acknowledgments are established before this coordinator's
        // first observation, unlike the held late-cleanup timing twin above.
        let receipt = engine.terminal(request.clone());
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        assert_eq!(receipt.read_status, ReadStatus::Complete);
        assert!(matches!(receipt.cleanup_state, CleanupState::Failed(_)));
        let CleanupState::Failed(selected) = &receipt.cleanup_state else {
            unreachable!()
        };
        let authoritative = engine.resource_summary();
        assert_eq!(
            selected, &authoritative,
            "selected Failed summary discarded later checked outcomes for {resource:?}"
        );
        let unresolved: Vec<_> = selected
            .resources
            .iter()
            .filter(|record| {
                !matches!(
                    record.state,
                    ResourceState::Unused
                        | ResourceState::CreateFailed
                        | ResourceState::CloseReturned
                )
            })
            .collect();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            (
                unresolved[0].resource,
                unresolved[0].state,
                unresolved[0].errno
            ),
            (resource, ResourceState::ConsumedError, Some(libc::EINTR))
        );
        let failure = receipt.failures.operations[CountOperation::Cleanup as usize].unwrap();
        assert_eq!(
            (failure.class, failure.errno, failure.resource),
            (FailureClass::Io, Some(libc::EINTR), resource)
        );
        assert_eq!(validate_terminal(&request, &receipt), Ok(()));
        assert_eq!(
            engine.cleanup_progress().unwrap().status,
            CleanupStatus::Failed
        );
        assert!(engine.fork_permit(Instant::now()).is_err());
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(receipt.terminal_id).0
        ));
    }
}

#[test]
fn g1_terminal_cleanup_multiple_errors_before_selection_keep_each_errno() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            close: Faults {
                close_errors: vec![(2, libc::EINTR), (3, libc::EIO), (4, libc::EBADF)],
                ..Faults::default()
            },
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    {
        let mut state = locked(&engine.shared.state);
        engine.shared.seal_locked(&mut state, request.deadline);
        state.terminal_expected = Some(request.clone());
    }
    engine.shared.worker.get().unwrap().unpark();
    task3_cleanup(&probe.owner, 10);
    let mut barrier = locked(&engine.shared.barrier.state);
    while !barrier.sealed {
        barrier = engine.shared.barrier.changed.wait(barrier).unwrap();
    }
    drop(barrier);
    let authoritative = engine.resource_summary();
    let receipt = engine.terminal(request.clone());
    let CleanupState::Failed(selected) = &receipt.cleanup_state else {
        panic!("checked errors lost their Failed status")
    };
    assert_eq!(
        selected, &authoritative,
        "same-operation errors and subsequent returns were lost"
    );
    for (resource, errno) in [
        (ResourceId::Pin(0), libc::EINTR),
        (ResourceId::Program, libc::EIO),
        (ResourceId::Map(CountMap::Counts), libc::EBADF),
    ] {
        let actual = selected
            .resources
            .iter()
            .find(|record| record.resource == resource)
            .unwrap();
        assert_eq!(
            (actual.state, actual.errno),
            (ResourceState::ConsumedError, Some(errno))
        );
    }
    assert_eq!(
        selected
            .resources
            .iter()
            .filter(|record| record.state == ResourceState::ConsumedError)
            .count(),
        3
    );
    assert!(!selected.resources.iter().any(|record| matches!(
        record.state,
        ResourceState::Reserved
            | ResourceState::Creating
            | ResourceState::Held
            | ResourceState::CloseIssued
    )));
    let first = receipt.failures.operations[CountOperation::Cleanup as usize].unwrap();
    assert_eq!(
        (first.resource, first.errno),
        (ResourceId::Pin(0), Some(libc::EINTR))
    );
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    assert!(engine.fork_permit(Instant::now()).is_err());
    assert!(Arc::ptr_eq(
        &receipt.0,
        &engine.salvage_view(receipt.terminal_id).0
    ));
}

#[test]
fn g1_terminal_manifest_refresh_has_linear_work_and_exact_states() {
    for (links, expected_visits) in [(1, 9), (64, 72), (8192, 8200)] {
        let epoch = OwnerEpoch::checked(1).unwrap();
        let writer = WriterIdentity {
            owner_epoch: epoch,
            object_sha256: [3; 32],
            program: ResourceId::Program,
            maps: CountMap::ALL.map(ResourceId::Map),
        };
        let mut resources: Vec<_> = CountMap::ALL
            .map(|map| ResourceRecord {
                resource: ResourceId::Map(map),
                state: ResourceState::Held,
                errno: None,
            })
            .into_iter()
            .collect();
        resources.push(ResourceRecord {
            resource: ResourceId::Program,
            state: ResourceState::Held,
            errno: None,
        });
        let mut manifest = Vec::with_capacity(links);
        for index in 0..links {
            // Failed attempts can leave serial gaps in otherwise ordered slots.
            let id = LinkId {
                owner_epoch: epoch,
                serial: LinkSerial::checked(index as u64 * 2 + 1).unwrap(),
            };
            manifest.push(CreationRecord {
                id,
                command: CommandSeq::checked(1).unwrap(),
                writer,
                backing: BackingIdentity {
                    device: 1,
                    inode: 2,
                },
                pin_slot: 0,
                memberships: index..index + 1,
                outcome: CreateOutcome::Succeeded,
                publication: PublicationState::Published,
                close_state: ResourceState::Held,
                close_errno: None,
            });
            resources.push(ResourceRecord {
                resource: ResourceId::Link(id),
                state: if index + 1 == links {
                    ResourceState::ConsumedError
                } else {
                    ResourceState::CloseReturned
                },
                errno: (index + 1 == links).then_some(libc::EIO),
            });
        }
        for index in 0..links {
            resources.push(ResourceRecord {
                resource: ResourceId::Pin(index),
                state: ResourceState::Unused,
                errno: None,
            });
        }
        for index in 0..8 {
            resources.push(ResourceRecord {
                resource: ResourceId::Transient(index),
                state: ResourceState::Unused,
                errno: None,
            });
        }
        let storage = (
            manifest.as_ptr(),
            manifest.capacity(),
            resources.as_ptr(),
            resources.capacity(),
        );
        let visits = refresh_manifest_close_states(&mut manifest, &resources);
        assert_eq!(
            visits, expected_visits,
            "resource search became quadratic for {links} links"
        );
        assert_eq!(
            (
                manifest.as_ptr(),
                manifest.capacity(),
                resources.as_ptr(),
                resources.capacity()
            ),
            storage
        );
        for (index, record) in manifest.iter().enumerate() {
            assert_eq!(
                (record.close_state, record.close_errno),
                if index + 1 == links {
                    (ResourceState::ConsumedError, Some(libc::EIO))
                } else {
                    (ResourceState::CloseReturned, None)
                }
            );
        }
        if links > 1 {
            let missing = manifest[1].id;
            resources.retain(|record| record.resource != ResourceId::Link(missing));
            for record in &mut manifest {
                record.close_state = ResourceState::Held;
                record.close_errno = None;
            }
            assert_eq!(
                refresh_manifest_close_states(&mut manifest, &resources),
                expected_visits
            );
            assert_eq!(
                (manifest[1].close_state, manifest[1].close_errno),
                (ResourceState::Held, None)
            );
            assert_eq!(
                (
                    manifest.last().unwrap().close_state,
                    manifest.last().unwrap().close_errno
                ),
                (ResourceState::ConsumedError, Some(libc::EIO))
            );
            assert_eq!(
                (manifest[2].close_state, manifest[2].close_errno),
                (ResourceState::CloseReturned, None)
            );
        }
    }
}

#[test]
fn g1_terminal_stop_and_close_errors_survive_a_later_blocked_close() {
    // The third schedule also preserves a completed link's EINTR when the next
    // link blocks. All blocks are in the owner-private host model seam.
    for control in 0..3 {
        let probe = MapProbe::new();
        let links = if control == 2 { 2 } else { 1 };
        let held_close = if control == 2 { 2 } else { 1 };
        let (engine, timeline) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    write_error: (control == 0).then_some(1),
                    ..MapFaults::default()
                },
                close: Faults {
                    hold_close: Some(held_close),
                    fail_close: (control == 2).then_some(1),
                    ..Faults::default()
                },
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        if links == 2 {
            let mut second = attach_request(2, 1);
            second.offsets = vec![7];
            second.cookies = vec![107];
            engine.attach(second).unwrap();
        }
        let request = terminal_request(&engine, Instant::now() + Duration::from_millis(250));
        let receipt = thread::scope(|scope| {
            let posted = request.clone();
            let owner = &engine;
            let result = scope.spawn(move || owner.terminal(posted));
            probe.owner.wait(|events| {
                events
                    .iter()
                    .filter(|(_, e)| matches!(e, Event::EnterClose))
                    .count()
                    == held_close
            });
            let stop_at = timeline
                .lock()
                .unwrap()
                .iter()
                .find_map(|(event, at)| {
                    matches!(event, TerminalEvent::StopReturned(_)).then_some(*at)
                })
                .expect("actual stop returned before close");
            assert!(stop_at < request.deadline);
            assert!(
                Instant::now() < request.deadline,
                "close did not block before cutoff"
            );
            result.join().unwrap()
        });
        assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
        assert!(
            engine
                .resource_summary()
                .resources
                .iter()
                .any(|r| r.state == ResourceState::CloseIssued)
        );
        let frozen_seal = receipt.seal;
        let frozen_failures = receipt.failures;
        probe.owner.release();
        task3_cleanup(&probe.owner, 9 + links);
        assert_eq!(receipt.seal.before_ns, Some(1));
        assert_eq!(receipt.seal.after_ns, Some(1));
        if control == 0 {
            assert!(
                matches!(receipt.seal.result, StopResult::Failed(f) if f.class == FailureClass::Io && f.errno == Some(libc::EIO))
            );
            assert_eq!(
                receipt.failures.operations[CountOperation::Stop as usize]
                    .map(|f| (f.class, f.errno)),
                Some((FailureClass::Io, Some(libc::EIO)))
            );
        } else {
            assert_eq!(receipt.seal.result, StopResult::Stopped);
        }
        assert_eq!(receipt.close_outcomes.len(), links);
        assert_eq!(
            receipt.close_outcomes[held_close - 1].state,
            ResourceState::CloseIssued
        );
        if control == 2 {
            assert_eq!(receipt.close_outcomes[0].errno, Some(libc::EINTR));
            assert_eq!(
                receipt.close_outcomes[0].state,
                ResourceState::ConsumedError
            );
            assert_eq!(
                receipt.failures.operations[CountOperation::Close as usize]
                    .map(|f| (f.class, f.errno)),
                Some((FailureClass::Io, Some(libc::EINTR)))
            );
        }
        assert_eq!(
            probe.calls.lock().unwrap().len(),
            1,
            "map I/O restarted after cutoff"
        );
        let repeated = engine.terminal(request);
        assert!(Arc::ptr_eq(&receipt.0, &repeated.0));
        assert_eq!(repeated.seal, frozen_seal);
        assert_eq!(repeated.failures, frozen_failures);
    }
}

#[test]
fn g1_terminal_open_refused_before_first_write_keeps_real_frontiers() {
    for prior_ack in [true, false] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
        if prior_ack {
            engine.attach(attach_request(1, 1)).unwrap();
        }
        probe.before_open_write.store(true, Ordering::Release);
        let open = open_request(if prior_ack { 2 } else { 1 });
        let (request, receipt) = thread::scope(|scope| {
            let command = scope.spawn(|| engine.open_window(open));
            probe.owner.wait(|events| {
                events
                    .iter()
                    .any(|(_, e)| matches!(e, Event::BeforeOpenWrite))
            });
            assert!(locked(&engine.shared.state).active_operation.is_none());
            let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
            let posted = request.clone();
            let owner = &engine;
            let terminal = scope.spawn(move || owner.terminal(posted));
            let mut state = locked(&engine.shared.state);
            while state.terminal.is_none() {
                state = engine.shared.changed.wait(state).unwrap();
            }
            drop(state);
            probe.owner.release();
            assert!(command.join().unwrap().is_err());
            let receipt = terminal.join().unwrap();
            (request, receipt)
        });
        let prior = prior_ack.then(|| CommandSeq::checked(1).unwrap());
        assert_eq!(receipt.last_command_seq, prior);
        assert_eq!(
            receipt
                .inventory
                .as_ref()
                .unwrap()
                .last_completed
                .map(|p| p.seq),
            prior
        );
        let resolved = receipt.resolved_open.unwrap();
        assert_eq!(resolved.seq, open.seq);
        assert_eq!(resolved.outcome, OpenOutcome::Failed);
        assert_eq!(resolved.completed_writes, OpenWriteFrontier::NoWrites);
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        task3_cleanup(&probe.owner, if prior_ack { 10 } else { 8 });
        assert_eq!(validate_terminal(&request, &receipt), Ok(()));
        for (outcome, writes, expected) in [
            (OpenOutcome::Unknown, OpenWriteFrontier::WindowStart, Ok(())),
            (
                OpenOutcome::Completed,
                OpenWriteFrontier::Target,
                Err(ReceiptFailure::Frontier),
            ),
            (
                OpenOutcome::Failed,
                OpenWriteFrontier::WindowStart,
                Err(ReceiptFailure::Frontier),
            ),
        ] {
            let changed = OpenReceipt {
                outcome,
                completed_writes: writes,
                ..resolved
            };
            let fixture = mutate_terminal(&receipt, |d| {
                d.resolved_open = Some(changed);
                mutate_inventory(d, |i| i.resolved_open = Some(changed));
            });
            assert_eq!(validate_terminal(&request, &fixture), expected);
        }
    }
}

#[test]
fn g1_terminal_open_requires_actual_operation_or_exact_pending_open() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
    let receipt = engine.terminal(request.clone());
    task3_cleanup(&probe.owner, 8);
    let open = OpenReceipt {
        completed_writes: OpenWriteFrontier::Target,
        outcome: OpenOutcome::Completed,
        ..OpenReceipt::pending(receipt.owner_epoch, &open_request(1))
    };
    let forged = mutate_terminal(&receipt, |d| {
        d.resolved_open = Some(open);
        mutate_inventory(d, |i| i.resolved_open = Some(open));
    });
    assert_eq!(
        forged.resolved_open,
        forged.inventory.as_ref().unwrap().resolved_open
    );
    assert_eq!(
        validate_terminal(&request, &forged),
        Err(ReceiptFailure::Frontier),
        "mutually consistent Completed Open has no actual operation"
    );
    for outcome in [OpenOutcome::Unknown, OpenOutcome::Failed] {
        let pending = PendingCommandId {
            seq: open.seq,
            operation: CountOperation::Generation,
        };
        let mut expected = request.clone();
        expected.frontier.pending = Some(pending);
        let forged = mutate_terminal(&receipt, |d| {
            let open = OpenReceipt {
                outcome,
                completed_writes: OpenWriteFrontier::NoWrites,
                ..open
            };
            d.resolved_open = Some(open);
            mutate_inventory(d, |i| {
                i.pending = Some(pending);
                i.resolved_open = Some(open);
            });
        });
        assert_eq!(
            validate_terminal(&expected, &forged),
            Err(ReceiptFailure::Frontier),
            "pending non-Open cannot explain {outcome:?}"
        );
    }
}

#[test]
fn g1_terminal_completed_open_lost_reply_keeps_actual_open_completion() {
    for prior_ack in [false, true] {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
        if prior_ack {
            engine.attach(attach_request(1, 1)).unwrap();
        }
        let open = open_request(if prior_ack { 2 } else { 1 });
        {
            let mut state = locked(&engine.shared.state);
            state.last_command_seq = Some(open.seq);
            state.frontier.pending = Some(PendingCommandId {
                seq: open.seq,
                operation: CountOperation::Open,
            });
            state.pending_open = Some(open);
            state.resolved_open = Some(OpenReceipt::pending(engine.ready.owner_epoch, &open));
            assert!(
                state
                    .ordinary
                    .publish_request(OwnerRequest::Open(open))
                    .is_ok()
            );
        }
        engine.shared.worker.get().unwrap().unpark();
        {
            let cutoff = Instant::now() + Duration::from_secs(3);
            let mut state = locked(&engine.shared.state);
            while state.ordinary.reply.is_none() {
                let remaining = cutoff.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero());
                state = engine
                    .shared
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap()
                    .0;
            }
        }
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        let receipt = engine.terminal(request.clone());
        assert_eq!(receipt.last_command_seq, Some(open.seq));
        assert_eq!(
            receipt.inventory.as_ref().unwrap().last_completed,
            Some(PendingCommandId {
                seq: open.seq,
                operation: CountOperation::Open
            })
        );
        assert_eq!(
            receipt.resolved_open.unwrap().outcome,
            OpenOutcome::Completed
        );
        assert_eq!(
            receipt.resolved_open.unwrap().completed_writes,
            OpenWriteFrontier::Target
        );
        assert_eq!(
            request.frontier.last_acked,
            prior_ack.then(|| CommandSeq::checked(1).unwrap())
        );
        assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
        assert_eq!(validate_terminal(&request, &receipt), Ok(()));
        task3_cleanup(&probe.owner, if prior_ack { 10 } else { 8 });
    }
}

#[test]
fn g1_terminal_close_progress_with_invalid_inventory_does_not_panic() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            close: Faults {
                hold_close: Some(1),
                ..Faults::default()
            },
            ..TerminalFaults::default()
        },
    );
    let id = engine.attach(attach_request(1, 1)).unwrap().value.links[0].id();
    // Contradict the actual journal without creating, aliasing or losing an FD.
    locked(&engine.shared.state).frontier.last_acked = Some(CommandSeq::checked(2).unwrap());
    let request = terminal_request(&engine, Instant::now() + Duration::from_millis(150));
    let result = thread::scope(|scope| {
        let posted = request.clone();
        let owner = &engine;
        let task = scope.spawn(move || owner.terminal(posted));
        probe
            .owner
            .wait(|events| events.iter().any(|(_, e)| matches!(e, Event::EnterClose)));
        task.join()
    });
    probe.owner.release();
    task3_cleanup(&probe.owner, 10);
    assert!(result.is_ok(), "invalid inventory made the fallback panic");
    let receipt = result.unwrap();
    assert!(receipt.inventory.is_none());
    assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
    assert_eq!(receipt.close_outcomes[0].id, id);
    assert_eq!(receipt.close_outcomes[0].state, ResourceState::CloseIssued);
    assert_eq!(
        receipt.failures.operations[CountOperation::Close as usize]
            .unwrap()
            .class,
        FailureClass::Inventory
    );
    assert!(validate_terminal(&request, &receipt).is_err());
}

// Catches treating the cutoff as an inclusive result-acceptance edge.
#[test]
fn g1_zero_grace_cutoff() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(3));
    let receipt = engine.terminal(request.clone());
    assert!(matches!(receipt.writers, WriterCompletion::Finished(_)));
    for (delta, want) in [
        (-1i32, Ok(())),
        (0, Err(ReceiptFailure::Cutoff)),
        (1, Err(ReceiptFailure::Cutoff)),
    ] {
        let instant = if delta < 0 {
            request.deadline - Duration::from_nanos(1)
        } else {
            request.deadline + Duration::from_nanos(delta as u64)
        };
        let boundary = mutate_terminal(&receipt, |data| {
            let WriterCompletion::Finished(witness) = &mut data.writers else {
                unreachable!()
            };
            witness.established_at = instant;
            let binding = data.snapshot_binding.as_mut().unwrap();
            binding.started_at = instant;
            binding.completed_at = instant;
            data.checkpoint.as_mut().unwrap().published_at = instant;
        });
        assert_eq!(
            validate_terminal(&request, &boundary),
            want,
            "cutoff delta {delta}"
        );
    }
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_zero_grace_confirmed_empty_is_not_a_queued_seal() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(&probe, None, TerminalFaults::default());
    let request = terminal_request(&engine, Instant::now());
    let receipt = engine.terminal(request.clone());
    assert!(
        matches!(receipt.writers, WriterCompletion::KnownEmpty(_)),
        "confirmed never-commanded Ready family must be distinguishable from an unproven queued seal"
    );
    assert_eq!(receipt.read_status, ReadStatus::NotStarted);
    assert!(receipt.checkpoint.is_none());
    assert!(probe.calls.lock().unwrap().is_empty());
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    for control in 0..10 {
        let forged = mutate_terminal(&receipt, |data| {
            let WriterCompletion::KnownEmpty(witness) = &mut data.writers else {
                unreachable!()
            };
            match control {
                0 => {
                    witness.owner_epoch =
                        OwnerEpoch::checked(witness.owner_epoch.value() + 1).unwrap()
                }
                1 => witness.writer_object_identity = [7; 32],
                2 => witness.ready_published_at = request.deadline,
                3 => data.last_command_seq = Some(CommandSeq::checked(1).unwrap()),
                4 => data.read_status = ReadStatus::Complete,
                5 => data.seal.result = StopResult::Stopped,
                6 => data.failures.record(OwnerFailure::engine(
                    CountOperation::Attach,
                    FailureClass::Panic,
                )),
                7..=9 => {
                    data.inventory = Some(Arc::new(SealedInventory {
                        owner_epoch: receipt.owner_epoch,
                        writer: WriterIdentity {
                            owner_epoch: if control == 8 {
                                OwnerEpoch::checked(receipt.owner_epoch.value() + 1).unwrap()
                            } else {
                                receipt.owner_epoch
                            },
                            object_sha256: receipt.writer_object_identity,
                            program: if control == 7 {
                                ResourceId::Engine
                            } else {
                                ResourceId::Program
                            },
                            maps: if control == 9 {
                                [ResourceId::Engine; 7]
                            } else {
                                CountMap::ALL.map(ResourceId::Map)
                            },
                        },
                        records: vec![],
                        memberships: vec![],
                        acknowledged_links: vec![],
                        unpublished_links: vec![],
                        last_acked: None,
                        pending: None,
                        last_completed: None,
                        resolved_open: None,
                    }));
                }
                _ => unreachable!(),
            }
        });
        assert!(
            validate_terminal(&request, &forged).is_err(),
            "forged empty proof {control}"
        );
    }
    let mut pending = request.clone();
    pending.frontier.pending = Some(PendingCommandId {
        seq: CommandSeq::checked(1).unwrap(),
        operation: CountOperation::Attach,
    });
    assert!(validate_terminal(&pending, &receipt).is_err());
    task3_cleanup(&probe.owner, 8);
}

// Catches putting terminal admission behind a full ordinary cell or waiting
// for either progress publication mutex while raw GEN remains entered.
#[test]
fn g1_terminal_bypasses_full_slot() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                hold_call: Some(1),
                ..MapFaults::default()
            },
            ..TerminalFaults::default()
        },
    );
    thread::scope(|scope| {
        let generation = scope.spawn(|| {
            engine.set_generation(GenerationRequest {
                seq: CommandSeq::checked(1).unwrap(),
                deadline: Instant::now() + Duration::from_secs(3),
                generation: 7,
            })
        });
        probe.wait_calls(1);
        assert!(locked(&engine.shared.state).ordinary.in_flight);
        let request = terminal_request(&engine, Instant::now());
        let _latest = locked(&engine.shared.latest_progress);
        let _retained = locked(&engine.shared.controller_progress);
        assert!(engine.progress().is_none());
        let receipt = engine.terminal(request.clone());
        assert_eq!(receipt.terminal_id, request.id);
        assert_eq!(receipt.deadline, request.deadline);
        assert_eq!(
            locked(&engine.shared.state).active_operation,
            Some(CountOperation::Generation)
        );
        assert_eq!(probe.calls.lock().unwrap().len(), 1);
        assert!(engine.fork_permit(Instant::now()).is_err());
        probe.owner.release();
        assert!(generation.join().unwrap().is_err());
    });
    task3_cleanup(&probe.owner, 8);
}

// Catches resetting the grace or retrying raw I/O when a caller requests
// terminal completion again after the first deadline.
#[test]
fn g1_one_deadline_all_phases() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            close: Faults {
                hold_close: Some(1),
                ..Faults::default()
            },
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now() + Duration::from_millis(50));
    let receipt = engine.terminal(request.clone());
    let mut repeated = request;
    repeated.deadline += Duration::from_secs(20);
    assert!(Arc::ptr_eq(&receipt.0, &engine.terminal(repeated).0));
    probe.owner.release();
    task3_cleanup(&probe.owner, 10);
    assert_eq!(probe.calls.lock().unwrap().len(), 1);
    assert_eq!(receipt.terminal_id, receipt.cleanup_ticket.terminal_id);
}

// Catches dropping the cleanup unwind result and falsely treating the final
// physical close as a checked cleanup acknowledgment after a panic.
#[test]
fn g1_panic_disconnect_retains_one_owner() {
    let probe = Probe::new();
    let observed = Arc::clone(&probe);
    let mut hooks = PrepareHooks::host();
    hooks.registry_observer = Some(Arc::new(move |event| {
        observed.event(Event::Registry(event));
        if matches!(
            event,
            RegistryEvent::CloseReturned(ResourceId::Map(CountMap::Dropfail))
        ) {
            panic!("cleanup acknowledgment unwind control");
        }
    }));
    let factory_probe = Arc::clone(&probe);
    let deadline = Instant::now() + Duration::from_secs(3);
    let engine = CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance(18, 2).unwrap(),
        deadline,
        hooks,
        move || {
            factory_probe.event(Event::Started);
            PipeDriver {
                probe: factory_probe,
                faults: Faults::default(),
                deadline,
                attempts: 0,
                acquired: 0,
                closes: 0,
            }
        },
        spawn_owner,
    )
    .unwrap();
    engine.abandon();
    probe.wait(|events| {
        events.iter().any(|(_, event)| {
            matches!(
                event,
                Event::Registry(RegistryEvent::CloseReturned(ResourceId::Map(
                    CountMap::Dropfail
                )))
            )
        })
    });
    // Wait for the owner to leave the protected cleanup body, never by sleep.
    let mut barrier = locked(&engine.shared.barrier.state);
    while !barrier.sealed {
        barrier = engine.shared.barrier.changed.wait(barrier).unwrap();
    }
    drop(barrier);
    let state = locked(&engine.shared.state);
    assert_eq!(
        state.failures.operations[CountOperation::Cleanup as usize].map(|f| f.class),
        Some(FailureClass::Panic)
    );
    drop(state);
    let diagnostic = engine.cleanup_progress().unwrap();
    assert_eq!(diagnostic.status, CleanupStatus::Stranded);
    assert_eq!(diagnostic.unresolved_resources, 0);
    assert_eq!(diagnostic.actual_phase, OwnerPhase::Cleaning);
    assert!(engine.fork_permit(Instant::now()).is_err());
    task3_cleanup(&probe, 8);
}

#[test]
fn g1_panic_disconnect_retains_one_owner_operation_matrix() {
    for control in 0..5 {
        let probe = MapProbe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    keys: vec![5, 7],
                    panic_call: match control {
                        3 => Some(1),
                        4 => Some(6),
                        _ => None,
                    },
                    ..MapFaults::default()
                },
                fail_publication: control == 2,
                registry_hook: (control < 2).then(|| {
                    Arc::new(move |event| {
                        if (control == 0
                            && matches!(event, RegistryEvent::Reserved(ResourceId::Link(_))))
                            || (control == 1
                                && matches!(event, RegistryEvent::Installed(ResourceId::Link(_))))
                        {
                            panic!("bounded owner-operation unwind {control}");
                        }
                    }) as Arc<dyn Fn(RegistryEvent) + Send + Sync>
                }),
                ..TerminalFaults::default()
            },
        );
        let failure = match control {
            0..=2 => engine.attach(attach_request(1, 1)).err().unwrap(),
            3 => engine
                .set_generation(GenerationRequest {
                    seq: CommandSeq::checked(1).unwrap(),
                    deadline: Instant::now() + Duration::from_secs(3),
                    generation: 2,
                })
                .err()
                .unwrap(),
            4 => engine.drain(read_request(1)).err().unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(
            failure.failure.class,
            if control == 2 {
                FailureClass::Publication
            } else {
                FailureClass::Panic
            }
        );
        let ticket = failure.cleanup_ticket.unwrap();
        let receipt = engine.salvage_view(ticket.terminal_id);
        assert_eq!(receipt.cleanup_ticket, ticket);
        if control == 4 {
            assert_eq!(receipt.checkpoint.as_ref().unwrap().snapshot.rows.len(), 2);
        }
        assert!(!matches!(receipt.writers, WriterCompletion::KnownEmpty(_)));
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(ticket.terminal_id).0
        ));
        task3_cleanup(
            &probe.owner,
            if control == 0 {
                9
            } else if control < 3 {
                10
            } else {
                8
            },
        );
        engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        let diagnostic = engine.cleanup_progress().unwrap();
        assert_eq!(diagnostic.ticket, ticket);
        assert_eq!(diagnostic.status, CleanupStatus::Complete);
        let log = probe.owner.log.lock().unwrap();
        assert_eq!(
            log.events
                .iter()
                .filter(|(_, event)| matches!(event, Event::Started))
                .count(),
            1
        );
        assert!(
            probe
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(thread, _)| *thread != std::thread::current().id())
        );
    }
}

#[test]
fn g1_one_deadline_runtime_error_at_cutoff_is_only_custody_diagnostic() {
    for delta in [-1, 0, 1] {
        let probe = MapProbe::new();
        let clock = ControlledClock::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    hold_call: Some(1),
                    write_error: Some(1),
                    ..MapFaults::default()
                },
                clock: Some(Arc::clone(&clock)),
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let request = terminal_request(&engine, clock.cutoff());
        let receipt = thread::scope(|scope| {
            let terminal = scope.spawn(|| engine.terminal(request));
            probe.wait_calls(1);
            clock.advance(delta, &engine);
            if delta < 0 {
                probe.owner.release();
                terminal.join().unwrap()
            } else {
                let receipt = terminal.join().unwrap();
                probe.owner.release();
                receipt
            }
        });
        let captured = receipt.failures.operations[CountOperation::Stop as usize].unwrap();
        assert_eq!(
            captured.class,
            if delta < 0 {
                FailureClass::Io
            } else {
                FailureClass::Deadline
            }
        );
        task3_cleanup(&probe.owner, 10);
        engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        let diagnostic = engine.cleanup_progress().unwrap();
        assert_eq!(
            diagnostic.failures.operations[CountOperation::Stop as usize]
                .unwrap()
                .errno,
            Some(libc::EIO)
        );
        assert_eq!(diagnostic.ticket, receipt.cleanup_ticket);
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(receipt.terminal_id).0
        ));
    }
}

/// Virtual time is advanced only at an acknowledged syscall/publication hold.
/// Its cutoff is the real start instant, so raw prefix timestamps created later
/// cannot accidentally become pre-cutoff authority in these model controls.
struct ControlledClock {
    origin: Instant,
    tick: AtomicU64,
}
impl ControlledClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            tick: AtomicU64::new(999_999_990),
        })
    }
    fn now(&self) -> Instant {
        self.origin + Duration::from_nanos(self.tick.load(Ordering::Acquire))
    }
    fn cutoff(&self) -> Instant {
        self.origin + Duration::from_secs(1)
    }
    fn advance(&self, delta: i32, engine: &CountEngine) {
        self.tick.store(
            (1_000_000_000i64 + i64::from(delta)) as u64,
            Ordering::Release,
        );
        engine.shared.changed.notify_all();
    }
}

#[derive(Debug, Clone, Copy)]
enum CutoffPhase {
    Submission,
    Stop,
    LastLink,
    Row,
    Publication,
}

// Catches extending one phase's budget, accepting a late result, claiming that
// an entered syscall was canceled, or replacing a selected artifact afterward.
#[test]
fn g1_one_deadline_all_phases_controllable_boundaries() {
    for phase in [
        CutoffPhase::Submission,
        CutoffPhase::Stop,
        CutoffPhase::LastLink,
        CutoffPhase::Row,
        CutoffPhase::Publication,
    ] {
        for delta in [-1, 0, 1] {
            let probe = MapProbe::new();
            let clock = ControlledClock::new();
            let publication = Probe::new();
            let (engine, _) = terminal_engine(
                &probe,
                None,
                TerminalFaults {
                    map: MapFaults {
                        keys: vec![5],
                        hold_call: match phase {
                            CutoffPhase::Stop => Some(1),
                            CutoffPhase::Row => Some(3),
                            _ => None,
                        },
                        ..MapFaults::default()
                    },
                    close: Faults {
                        hold_close: matches!(phase, CutoffPhase::LastLink).then_some(1),
                        ..Faults::default()
                    },
                    clock: Some(Arc::clone(&clock)),
                    publication_gate: matches!(phase, CutoffPhase::Publication)
                        .then(|| Arc::clone(&publication)),
                    ..TerminalFaults::default()
                },
            );
            engine.attach(attach_request(1, 1)).unwrap();
            let request = terminal_request(&engine, clock.cutoff());
            let receipt = thread::scope(|scope| {
                if matches!(phase, CutoffPhase::Submission) {
                    clock.advance(delta, &engine);
                    return engine.terminal(request.clone());
                }
                let posted = request.clone();
                let owner = &engine;
                let terminal = scope.spawn(move || owner.terminal(posted));
                match phase {
                    CutoffPhase::Stop => probe.wait_calls(1),
                    CutoffPhase::Row => probe.wait_calls(3),
                    CutoffPhase::LastLink => probe.owner.wait(|events| {
                        events
                            .iter()
                            .any(|(_, event)| matches!(event, Event::EnterClose))
                    }),
                    CutoffPhase::Publication => publication.wait(|events| {
                        events
                            .iter()
                            .any(|(_, event)| matches!(event, Event::Started))
                    }),
                    CutoffPhase::Submission => unreachable!(),
                }
                clock.advance(delta, &engine);
                if delta < 0 {
                    probe.owner.release();
                    publication.release();
                    terminal.join().unwrap()
                } else {
                    let receipt = terminal.join().unwrap();
                    let diagnostic = engine.cleanup_progress().unwrap();
                    assert_eq!(
                        diagnostic.status,
                        CleanupStatus::Pending,
                        "{phase:?} {delta}"
                    );
                    assert_eq!(diagnostic.ticket, receipt.cleanup_ticket);
                    assert!(diagnostic.coordinator_finalized);
                    assert!(engine.fork_permit(Instant::now()).is_err());
                    if !matches!(phase, CutoffPhase::Publication) {
                        assert!(
                            diagnostic.active_operation.is_some(),
                            "held raw operation was falsely canceled: {phase:?}"
                        );
                    }
                    probe.owner.release();
                    publication.release();
                    receipt
                }
            });
            assert_eq!(receipt.deadline, clock.cutoff(), "{phase:?} {delta}");
            assert_eq!(receipt.terminal_id, request.id);
            if delta < 0 {
                assert!(
                    matches!(receipt.writers, WriterCompletion::Finished(_)),
                    "{phase:?}"
                );
                assert_eq!(receipt.read_status, ReadStatus::Complete, "{phase:?}");
                assert_eq!(receipt.checkpoint.as_ref().unwrap().snapshot.rows.len(), 1);
                assert_eq!(validate_terminal(&request, &receipt), Ok(()), "{phase:?}");
            } else {
                assert_ne!(
                    receipt.read_status,
                    ReadStatus::Complete,
                    "late promotion: {phase:?} {delta}"
                );
                if matches!(
                    phase,
                    CutoffPhase::Submission | CutoffPhase::Stop | CutoffPhase::LastLink
                ) {
                    assert!(
                        matches!(receipt.writers, WriterCompletion::Unknown(_)),
                        "{phase:?}"
                    );
                }
            }
            task3_cleanup(&probe.owner, 10);
            engine
                .fork_permit(Instant::now() + Duration::from_secs(3))
                .unwrap();
            let after = engine.salvage_view(receipt.terminal_id);
            assert!(Arc::ptr_eq(&receipt.0, &after.0));
            let diagnostic = engine.cleanup_progress().unwrap();
            assert_eq!(diagnostic.ticket, receipt.cleanup_ticket);
            assert_eq!(diagnostic.status, CleanupStatus::Complete);
            if delta >= 0 && matches!(phase, CutoffPhase::Submission) {
                assert!(probe.calls.lock().unwrap().is_empty());
            }
        }
    }
}

// Catches using owner publication as if the coordinator had already observed
// that result: the first coordinator observation is independently controlled.
#[test]
fn g1_zero_grace_candidate_first_observed_at_cutoff_cannot_promote() {
    for delta in [-1, 0, 1] {
        let probe = MapProbe::new();
        let clock = ControlledClock::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                clock: Some(Arc::clone(&clock)),
                ..TerminalFaults::default()
            },
        );
        engine.attach(attach_request(1, 1)).unwrap();
        let request = terminal_request(&engine, clock.cutoff());
        {
            let mut state = locked(&engine.shared.state);
            engine.shared.seal_locked(&mut state, request.deadline);
            state.terminal_expected = Some(request.clone());
        }
        engine.shared.worker.get().unwrap().unpark();
        let mut state = locked(&engine.shared.state);
        while state.terminal_candidate.is_none() {
            state = engine.shared.changed.wait(state).unwrap();
        }
        assert!(state.terminal_result.is_none());
        drop(state);
        clock.advance(delta, &engine);
        let receipt = engine.terminal(request);
        assert_eq!(
            receipt.read_status == ReadStatus::Complete,
            delta < 0,
            "first observed at cutoff delta {delta}"
        );
        assert!(Arc::ptr_eq(
            &receipt.0,
            &engine.salvage_view(receipt.terminal_id).0
        ));
        task3_cleanup(&probe.owner, 10);
    }
}

#[test]
fn g1_panic_disconnect_retains_one_owner_first_abandonment_edge() {
    let probe = MapProbe::new();
    let clock = ControlledClock::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                hold_call: Some(1),
                ..MapFaults::default()
            },
            clock: Some(Arc::clone(&clock)),
            ..TerminalFaults::default()
        },
    );
    thread::scope(|scope| {
        let ordinary = scope.spawn(|| {
            engine.set_generation(GenerationRequest {
                seq: CommandSeq::checked(1).unwrap(),
                deadline: Instant::now() + Duration::from_secs(3),
                generation: 7,
            })
        });
        probe.wait_calls(1);
        let first_edge = clock.now();
        engine.abandon();
        clock.advance(0, &engine);
        let id = TerminalId {
            owner_epoch: engine.ready.owner_epoch,
            sequence: TerminalSeq::checked(1).unwrap(),
        };
        let receipt = engine.salvage_view(id);
        assert_eq!(
            receipt.deadline, first_edge,
            "salvage manufactured a later abandonment budget"
        );
        assert_eq!(
            engine.cleanup_progress().unwrap().active_operation,
            Some(CountOperation::Generation)
        );
        assert!(engine.fork_permit(Instant::now()).is_err());
        assert_eq!(probe.calls.lock().unwrap().len(), 1);
        probe.owner.release();
        assert_eq!(
            ordinary.join().unwrap().err().unwrap().cleanup_ticket,
            Some(receipt.cleanup_ticket)
        );
        task3_cleanup(&probe.owner, 8);
        engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            probe.calls.lock().unwrap().len(),
            1,
            "abandonment initiated new observation I/O"
        );
        assert!(Arc::ptr_eq(&receipt.0, &engine.salvage_view(id).0));
    });
}

#[test]
fn g1_one_deadline_all_phases_second_trigger_shortens_wait() {
    let probe = MapProbe::new();
    let clock = ControlledClock::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            close: Faults {
                hold_close: Some(1),
                ..Faults::default()
            },
            clock: Some(Arc::clone(&clock)),
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, clock.cutoff());
    let receipt = thread::scope(|scope| {
        let id = request.id;
        let terminal = scope.spawn(|| engine.terminal(request));
        probe.owner.wait(|events| {
            events
                .iter()
                .any(|(_, event)| matches!(event, Event::EnterClose))
        });
        let shortened = engine.salvage_view(id);
        let waited = terminal.join().unwrap();
        assert!(Arc::ptr_eq(&shortened.0, &waited.0));
        assert_eq!(shortened.deadline, clock.cutoff());
        assert_eq!(
            engine.cleanup_progress().unwrap().active_operation,
            Some(CountOperation::Close)
        );
        assert!(engine.fork_permit(Instant::now()).is_err());
        probe.owner.release();
        shortened
    });
    task3_cleanup(&probe.owner, 10);
    engine
        .fork_permit(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert!(Arc::ptr_eq(
        &receipt.0,
        &engine.salvage_view(receipt.terminal_id).0
    ));
}

#[test]
fn g1_panic_disconnect_retains_one_owner_lost_terminal_reply_and_drop() {
    let probe = MapProbe::new();
    let publication = Probe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            publication_gate: Some(Arc::clone(&publication)),
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    let request = terminal_request(&engine, Instant::now() + Duration::from_secs(3));
    {
        let mut state = locked(&engine.shared.state);
        engine.shared.seal_locked(&mut state, request.deadline);
        state.terminal_expected = Some(request.clone());
    }
    engine.shared.worker.get().unwrap().unpark();
    publication.wait(|events| {
        events
            .iter()
            .any(|(_, event)| matches!(event, Event::Started))
    });
    let shared = Arc::clone(&engine.shared);
    drop(engine);
    assert!(shared.abandoned.load(Ordering::Acquire));
    assert_eq!(
        locked(&shared.state).terminal.unwrap().deadline,
        request.deadline
    );
    publication.release();
    task3_cleanup(&probe.owner, 10);
    shared
        .barrier
        .terminal_permit(shared.epoch, Instant::now() + Duration::from_secs(3))
        .unwrap();
    let state = locked(&shared.state);
    assert!(
        state.terminal_result.is_none(),
        "worker pretended the departed coordinator selected an artifact"
    );
    let candidate = &state.terminal_candidate.as_ref().unwrap().1;
    assert_eq!(candidate.terminal_id, request.id);
    assert_eq!(candidate.cleanup_ticket.terminal_id, request.id);
    assert!(state.resources.cleanup_complete);
    assert_eq!(state.phase, OwnerPhase::Idle);
    assert_eq!(
        probe
            .owner
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, event)| matches!(event, Event::Started))
            .count(),
        1
    );
}

#[test]
fn g1_panic_disconnect_retains_one_owner_competing_first_triggers() {
    for explicit_first in [false, true] {
        let probe = MapProbe::new();
        let clock = ControlledClock::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    hold_call: Some(1),
                    ..MapFaults::default()
                },
                clock: Some(Arc::clone(&clock)),
                ..TerminalFaults::default()
            },
        );
        thread::scope(|scope| {
            let ordinary = scope.spawn(|| {
                engine.set_generation(GenerationRequest {
                    seq: CommandSeq::checked(1).unwrap(),
                    deadline: Instant::now() + Duration::from_secs(3),
                    generation: 7,
                })
            });
            probe.wait_calls(1);
            let first_edge = clock.now();
            if explicit_first {
                engine.shared.seal(clock.cutoff());
            }
            // Both calls still compete with an entered owner operation. The
            // two orders independently pin each side of the first-trigger CAS.
            engine.abandon();
            if !explicit_first {
                engine.shared.seal(clock.cutoff());
            }
            let seal = locked(&engine.shared.state).terminal.unwrap();
            assert_eq!(
                seal.deadline,
                if explicit_first {
                    clock.cutoff()
                } else {
                    first_edge
                }
            );
            clock.advance(1, &engine);
            let receipt = engine.salvage_view(seal.ticket.terminal_id);
            assert_eq!(receipt.deadline, seal.deadline);
            engine.abandon();
            assert!(Arc::ptr_eq(
                &receipt.0,
                &engine.salvage_view(seal.ticket.terminal_id).0
            ));
            probe.owner.release();
            let failure = ordinary.join().unwrap().err().unwrap();
            assert_eq!(failure.cleanup_ticket, Some(seal.ticket));
            task3_cleanup(&probe.owner, 8);
            engine
                .fork_permit(Instant::now() + Duration::from_secs(3))
                .unwrap();
            assert_eq!(probe.calls.lock().unwrap().len(), 1);
        });
    }
}

#[test]
fn g1_zero_grace_unknown_abandonment_offset_fails_closed() {
    assert_eq!(abandonment_code(None), 1);
    assert_eq!(abandonment_code(Some(Duration::MAX)), 1);
    assert_eq!(
        abandonment_code(Some(Duration::from_nanos(u64::MAX - 2))),
        1
    );
    let probe = MapProbe::new();
    let clock = ControlledClock::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            clock: Some(Arc::clone(&clock)),
            ..TerminalFaults::default()
        },
    );
    engine.attach(attach_request(1, 1)).unwrap();
    // A backwards/inconsistent clock cannot create a usable offset or grace.
    clock.advance(-11, &engine);
    engine.abandon();
    let receipt = engine.salvage_view(TerminalId {
        owner_epoch: engine.ready.owner_epoch,
        sequence: TerminalSeq::checked(1).unwrap(),
    });
    assert!(receipt.deadline <= clock.now());
    assert!(matches!(receipt.writers, WriterCompletion::Unknown(_)));
    task3_cleanup(&probe.owner, 10);
    assert!(probe.calls.lock().unwrap().is_empty());
    engine
        .fork_permit(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        engine.cleanup_progress().unwrap().ticket,
        receipt.cleanup_ticket
    );
}

#[test]
fn g1_zero_grace_known_empty_withdrawn_before_terminal_observation() {
    let probe = MapProbe::new();
    let clock = ControlledClock::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            clock: Some(Arc::clone(&clock)),
            ..TerminalFaults::default()
        },
    );
    let request = terminal_request(&engine, clock.cutoff());
    {
        let mut state = locked(&engine.shared.state);
        engine.shared.seal_locked(&mut state, request.deadline);
        state.terminal_expected = Some(request.clone());
    }
    engine.shared.worker.get().unwrap().unpark();
    let mut state = locked(&engine.shared.state);
    while state.terminal_candidate.is_none() {
        state = engine.shared.changed.wait(state).unwrap();
    }
    drop(state);
    clock.advance(0, &engine);
    let receipt = engine.terminal(request.clone());
    assert!(
        !matches!(receipt.writers, WriterCompletion::KnownEmpty(_)),
        "terminal observation I/O retained pristine Ready authority"
    );
    assert_eq!(validate_terminal(&request, &receipt), Ok(()));
    task3_cleanup(&probe.owner, 8);
}

#[test]
fn g1_panic_disconnect_retains_one_owner_claim_gap_binds_deadline() {
    for explicit_first in [false, true] {
        let probe = MapProbe::new();
        let claim = Probe::new();
        let (engine, _) = terminal_engine(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    hold_call: Some(1),
                    panic_call: Some(1),
                    ..MapFaults::default()
                },
                seal_claim_gate: Some(Arc::clone(&claim)),
                ..TerminalFaults::default()
            },
        );
        let operation_deadline = Instant::now() + Duration::from_secs(3);
        let explicit_deadline = operation_deadline + Duration::from_secs(1);
        thread::scope(|scope| {
            let ordinary = scope.spawn(|| {
                engine.set_generation(GenerationRequest {
                    seq: CommandSeq::checked(1).unwrap(),
                    deadline: operation_deadline,
                    generation: 7,
                })
            });
            probe.wait_calls(1);
            let mut explicit = None;
            if explicit_first {
                explicit = Some(scope.spawn(|| engine.shared.seal(explicit_deadline)));
            } else {
                probe.owner.release();
            }
            // The real first seal caller has claimed MAX but deliberately has
            // not installed its deadline yet, and still holds SharedState.
            claim.wait(|events| {
                events
                    .iter()
                    .any(|(_, event)| matches!(event, Event::Started))
            });
            if !explicit_first {
                explicit = Some(scope.spawn(|| engine.shared.seal(explicit_deadline)));
            } else {
                probe.owner.release();
            }
            let (sent, received) = std::sync::mpsc::channel();
            let owner = &engine;
            let abandon = scope.spawn(move || {
                owner.abandon();
                sent.send(()).unwrap();
            });
            let nonblocking_drop = received.recv_timeout(Duration::from_secs(1));
            // Always release before asserting, so the negative control remains
            // finite even if a regression makes abandonment take this mutex.
            claim.release();
            abandon.join().unwrap();
            assert!(
                nonblocking_drop.is_ok(),
                "abandonment waited for the first seal's mutex"
            );
            let ticket = explicit.unwrap().join().unwrap();
            let failure = ordinary.join().unwrap().err().unwrap();
            assert_eq!(failure.cleanup_ticket, Some(ticket));
            let seal = locked(&engine.shared.state).terminal.unwrap();
            assert_eq!(
                seal.deadline,
                if explicit_first {
                    explicit_deadline
                } else {
                    operation_deadline
                }
            );
            assert_eq!(seal.ticket, ticket);
            let receipt = engine.salvage_view(ticket.terminal_id);
            assert_eq!(receipt.deadline, seal.deadline);
            assert!(Arc::ptr_eq(
                &receipt.0,
                &engine.salvage_view(ticket.terminal_id).0
            ));
        });
        task3_cleanup(&probe.owner, 8);
        engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert_eq!(probe.calls.lock().unwrap().len(), 1);
    }
}

#[test]
fn g1_panic_disconnect_retains_one_owner_drop_never_takes_owner_lock() {
    let probe = Probe::new();
    let engine = injected(
        Arc::clone(&probe),
        Faults::default(),
        Arc::new(CountForkBarrier::new()),
        Instant::now() + Duration::from_secs(3),
        PrepareHooks::host(),
    )
    .unwrap();
    let shared = Arc::clone(&engine.shared);
    let state = locked(&shared.state);
    let (sent, received) = std::sync::mpsc::channel();
    let dropper = thread::spawn(move || {
        drop(engine);
        sent.send(()).unwrap();
    });
    let returned = received.recv_timeout(Duration::from_secs(1));
    assert!(shared.abandoned.load(Ordering::Acquire) || returned.is_err());
    drop(state);
    dropper.join().unwrap();
    assert!(
        returned.is_ok(),
        "CountEngine::drop waited for owner publication state"
    );
    task3_cleanup(&probe, 8);
    shared
        .barrier
        .terminal_permit(shared.epoch, Instant::now() + Duration::from_secs(3))
        .unwrap();
}

#[test]
fn g1_panic_disconnect_retains_one_owner_unknown_create_is_stranded() {
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine(
        &probe,
        None,
        TerminalFaults {
            registry_hook: Some(Arc::new(|event| {
                if matches!(event, RegistryEvent::Creating(ResourceId::Link(_))) {
                    panic!("unknown creation unwind control");
                }
            })),
            ..TerminalFaults::default()
        },
    );
    let failure = engine.attach(attach_request(1, 1)).err().unwrap();
    let ticket = failure.cleanup_ticket.unwrap();
    let receipt = engine.salvage_view(ticket.terminal_id);
    task3_cleanup(&probe.owner, 9);
    let mut barrier = locked(&engine.shared.barrier.state);
    while !barrier.sealed {
        barrier = engine.shared.barrier.changed.wait(barrier).unwrap();
    }
    drop(barrier);
    let diagnostic = engine.cleanup_progress().unwrap();
    assert_eq!(diagnostic.status, CleanupStatus::Stranded);
    assert_eq!(diagnostic.unresolved_resources, 1);
    assert_eq!(diagnostic.ticket, ticket);
    assert!(engine.fork_permit(Instant::now()).is_err());
    assert!(!matches!(receipt.writers, WriterCompletion::KnownEmpty(_)));
    assert!(Arc::ptr_eq(
        &receipt.0,
        &engine.salvage_view(ticket.terminal_id).0
    ));
}
