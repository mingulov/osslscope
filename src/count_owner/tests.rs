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

// These controls cross the real session/owner mailbox, sealed journal and map
// workspace. Only the underlying syscalls are modeled by the pipe FD driver.
#[derive(Clone, Copy)]
enum RefusePublication {
    Before,
    After,
}
struct SessionOwnerPort {
    engine: CountEngine,
    wait_inventory: bool,
    requests: Vec<TerminalRequest>,
    terminal_calls: usize,
    generation_refusal: Option<RefusePublication>,
    open_refusal: Option<RefusePublication>,
    refuse_published: Arc<AtomicBool>,
    last_failure: Option<CommandFailure>,
    replay: Option<RawCheckpoint>,
    late_release: Option<Arc<Probe>>,
    progress_cutoff: Option<Instant>,
}
impl SessionOwnerPort {
    fn refuse(&self, mode: Option<RefusePublication>, deadline: Instant) {
        match mode {
            Some(RefusePublication::Before) => {
                self.engine.shared.seal(deadline);
            }
            Some(RefusePublication::After) => {
                self.refuse_published.store(true, Ordering::Release);
            }
            None => {}
        }
    }
    fn observe<T>(&mut self, result: CommandResult<T>) -> CommandResult<T> {
        if let Err(failure) = result.as_ref() {
            self.last_failure = Some(*failure);
        }
        result
    }
}
impl crate::count_session::CountBackend for SessionOwnerPort {
    type Link = LinkToken;
    fn ready(&self) -> &Ready {
        &self.engine.ready
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
        let result = self.engine.attach(request);
        self.observe(result)
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        self.refuse(self.open_refusal, request.deadline);
        let result = self.engine.open_window(request);
        self.observe(result)
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        self.refuse(self.generation_refusal, request.deadline);
        let result = self.engine.set_generation(request);
        self.observe(result)
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        let result = self.engine.drain(request);
        if result.is_err() && self.progress_cutoff.is_some() {
            self.progress_cutoff = Some(request.deadline);
        }
        if result.is_err()
            && let Some(gate) = &self.late_release
        {
            gate.release();
            task3_inventory(&self.engine).unwrap();
        }
        self.observe(result)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        if self.wait_inventory {
            task3_inventory(&self.engine).unwrap();
        }
        let request = self.engine.terminal_request(
            deadline,
            self.engine.ready.evidence_domain,
            self.engine.ready.writer_object_identity,
            frontier,
        );
        self.requests.push(request.clone());
        request
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        self.terminal_calls += 1;
        self.engine.terminal(request)
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        let mut checkpoint = self.replay.clone().or_else(|| self.engine.progress())?;
        if let Some(cutoff) = self.progress_cutoff {
            checkpoint.published_at = cutoff;
        }
        Some(checkpoint)
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.engine.fork_permit(deadline)
    }
}
fn session_owner_port(
    probe: &Arc<MapProbe>,
    writer: Option<Arc<StagedWriter>>,
    mut faults: TerminalFaults,
) -> SessionOwnerPort {
    let refuse_published = Arc::new(AtomicBool::new(false));
    let armed = Arc::clone(&refuse_published);
    let owner = Arc::new(OnceLock::<std::sync::Weak<Shared>>::new());
    let published_owner = Arc::clone(&owner);
    faults.mailbox_observer = Some(Arc::new(move |event| {
        if matches!(event, MailboxEvent::RequestPublished(_)) && armed.swap(false, Ordering::AcqRel)
        {
            // The real publication already installed its identity under the
            // mailbox lock. Cancel before the first I/O, without waking the
            // caller until the handler publishes its actual NotEntered reply.
            published_owner
                .get()
                .unwrap()
                .upgrade()
                .unwrap()
                .abandoned
                .store(true, Ordering::Release);
        }
    }));
    let (engine, _) = terminal_engine(probe, writer, faults);
    owner.set(Arc::downgrade(&engine.shared)).unwrap();
    SessionOwnerPort {
        engine,
        wait_inventory: false,
        requests: Vec::new(),
        terminal_calls: 0,
        generation_refusal: None,
        open_refusal: None,
        refuse_published,
        last_failure: None,
        replay: None,
        late_release: None,
        progress_cutoff: None,
    }
}
struct SessionPlan {
    offsets: Vec<u64>,
    mappings: Vec<crate::discovery::maps::Mapping>,
    files: std::collections::HashMap<String, crate::plan::FileBytes>,
}
impl SessionPlan {
    fn new(positions: usize) -> Self {
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let executable = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == goblin::elf::program_header::PT_LOAD
                    && p.p_flags & goblin::elf::program_header::PF_X != 0
            })
            .unwrap();
        let offsets = (0..positions)
            .map(|n| executable.p_offset + 16 + 16 * n as u64)
            .collect();
        // The pipe driver independently reports backing (1,2), not a path
        // alias. File bytes/mapping/expected pin use that exact model identity.
        let path = "/model/provider.so".to_owned();
        Self {
            offsets,
            mappings: vec![crate::discovery::maps::Mapping {
                start: 0x7000_0000,
                end: 0x8000_0000,
                x: true,
                offset: 0,
                dev: crate::plan::render_device(1),
                ino: 2,
                path: path.clone(),
            }],
            files: std::collections::HashMap::from([(
                path,
                crate::plan::FileBytes {
                    bytes: bytes.into(),
                    dev: 1,
                    ino: 2,
                },
            )]),
        }
    }
    fn attach(
        &self,
        session: &mut crate::count_session::CountSession<SessionOwnerPort>,
        meaning: u32,
    ) {
        use crate::count_session::{CountDelta, DiscoveredSite};
        use crate::evidence::{CandidateCoverage, CandidateIdentity, ObjectId, SiteKey};
        let delta = CountDelta {
            discovered: self
                .offsets
                .iter()
                .map(|offset| DiscoveredSite {
                    site: SiteKey {
                        object: ObjectId("original-object".into()),
                        device: 1,
                        inode: 2,
                        offset: *offset,
                    },
                    candidates: vec![CandidateIdentity::new(
                        ObjectId("provider-object".into()),
                        "default".into(),
                        1,
                        meaning,
                        vec!["digest".into()],
                        false,
                    )],
                    candidates_coverage: CandidateCoverage::Complete,
                })
                .collect(),
            losses: Vec::new(),
        };
        session
            .attach_delta(
                &delta,
                &self.mappings,
                &self.files,
                900,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
    }
    fn cookie(
        &self,
        session: &crate::count_session::CountSession<SessionOwnerPort>,
        position: usize,
    ) -> u32 {
        session.cookie_for(1, 2, self.offsets[position]).unwrap()
    }
}
fn session_close() -> crate::count_session::CloseRequest {
    crate::count_session::CloseRequest {
        started_at: Instant::now(),
        grace: Duration::from_secs(5),
        reason: crate::count_session::CloseReason::Failure,
    }
}
fn session_counter(drain: &crate::count_session::CountDrain, name: &str) -> Option<u64> {
    drain
        .counters
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value)
}
fn no_inventory_failure(receipt: &RawTerminal) -> bool {
    receipt
        .failures
        .operations
        .iter()
        .flatten()
        .all(|f| f.class != FailureClass::Inventory)
}
#[test]
fn g1_fix1_fault_first_after_journal_keeps_original_frontier() {
    for deadline_only in [false, true] {
        let probe = MapProbe::new();
        let faults = TerminalFaults {
            map: MapFaults {
                write_error: (!deadline_only).then_some(1),
                expire_after_call: deadline_only.then_some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut session =
            crate::count_session::CountSession::new(1, session_owner_port(&probe, None, faults));
        let plan = SessionPlan::new(1);
        plan.attach(&mut session, 7);
        let links = locked(&session.backend().engine.shared.state)
            .frontier
            .acknowledged_links
            .clone();
        session.backend_mut().wait_inventory = true;
        let cutoff = Instant::now() + Duration::from_secs(5);
        assert!(session.open_window(1000, 2000, cutoff).is_err());
        let expected = ControllerFrontier {
            last_acked: Some(CommandSeq::checked(1).unwrap()),
            acknowledged_links: links,
            pending: Some(PendingCommandId {
                seq: CommandSeq::checked(2).unwrap(),
                operation: CountOperation::Open,
            }),
        };
        let request = session.backend().requests[0].clone();
        assert_eq!(request.frontier, expected);
        assert_eq!(
            task3_inventory(&session.backend().engine)
                .unwrap()
                .validate(&expected),
            Ok(())
        );
        let seal = locked(&session.backend().engine.shared.state)
            .terminal
            .unwrap();
        let contradiction = locked(&session.backend().engine.shared.state).terminal_contradiction;
        let terminal = session.terminal(session_close());
        let repeat = session.terminal(session_close());
        task3_cleanup(&probe.owner, 10);
        assert!(
            !contradiction,
            "matching original session frontier became contradictory after journal publication"
        );
        assert!(no_inventory_failure(&terminal.receipt));
        assert_eq!(request.id, seal.ticket.terminal_id);
        assert_eq!(request.deadline, cutoff);
        assert_eq!(terminal.receipt.deadline, cutoff);
        assert_eq!(terminal.retained_drain, repeat.retained_drain);
        assert!(std::ptr::eq(&*terminal.receipt, &*repeat.receipt));
        assert_eq!(session.backend().terminal_calls, 1);
        if deadline_only {
            assert!(
                terminal.runtime_failure.is_none(),
                "deadline-only refusal gained Runtime: {:?}, stop {:?}",
                terminal.runtime_failure,
                terminal.receipt.seal.result
            );
        } else {
            assert_eq!(terminal.runtime_failure.unwrap().class, FailureClass::Io);
        }
    }
}
#[test]
fn g1_fix1_fault_first_before_journal_has_no_runtime_invention() {
    let probe = MapProbe::new();
    let port = session_owner_port(
        &probe,
        None,
        TerminalFaults {
            map: MapFaults {
                hold_call: Some(1),
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let mut session = crate::count_session::CountSession::new(1, port);
    SessionPlan::new(1).attach(&mut session, 7);
    let cutoff = Instant::now() + Duration::from_millis(200);
    let call = std::thread::spawn(move || {
        assert!(session.open_window(1000, 2000, cutoff).is_err());
        session
    });
    probe.wait_calls(1);
    let mut session = call.join().unwrap();
    assert!(
        locked(&session.backend().engine.shared.state)
            .inventory
            .is_none()
    );
    let terminal = session.terminal(session_close());
    let pending = session.backend().requests[0].frontier.pending;
    probe.owner.release();
    task3_cleanup(&probe.owner, 10);
    assert_eq!(
        pending,
        Some(PendingCommandId {
            seq: CommandSeq::checked(2).unwrap(),
            operation: CountOperation::Open
        })
    );
    assert!(no_inventory_failure(&terminal.receipt));
    assert!(terminal.runtime_failure.is_none());
    assert_eq!(terminal.receipt.deadline, cutoff);
    assert_eq!(
        session
            .salvage_view(terminal.receipt.terminal_id)
            .retained_drain,
        terminal.retained_drain
    );
}
#[test]
fn g1_fix1_not_entered_generation_preserves_publication_distinction() {
    for mode in [RefusePublication::After, RefusePublication::Before] {
        let probe = MapProbe::new();
        let writer = StagedWriter::new(None);
        writer.returned.store(true, Ordering::Release);
        let mut session = crate::count_session::CountSession::new(
            1,
            session_owner_port(&probe, Some(Arc::clone(&writer)), TerminalFaults::default()),
        );
        let plan = SessionPlan::new(1);
        plan.attach(&mut session, 7);
        session
            .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
            .unwrap();
        let cookie = plan.cookie(&session, 0);
        writer.maps.lock().unwrap().rows.insert(
            osslscope_ebpf_common::make_key(cookie, 0),
            osslscope_ebpf_common::CountValue {
                count: 11,
                first_ns: 1100,
                last_ns: 1100,
            },
        );
        session
            .fence(
                crate::count_session::FenceReason::MappingsChanged,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        writer.maps.lock().unwrap().rows.insert(
            osslscope_ebpf_common::make_key(cookie, 1),
            osslscope_ebpf_common::CountValue {
                count: 7,
                first_ns: 1200,
                last_ns: 1300,
            },
        );
        plan.attach(&mut session, 9);
        session.backend_mut().generation_refusal = Some(mode);
        session.backend_mut().wait_inventory = true;
        assert!(
            session
                .fence(
                    crate::count_session::FenceReason::CandidatesChanged,
                    Instant::now() + Duration::from_secs(5)
                )
                .is_err()
        );
        let failure = session.backend().last_failure.unwrap();
        assert_eq!(failure.completion, CommandCompletion::NotEntered);
        assert_eq!(
            failure.publication,
            if matches!(mode, RefusePublication::After) {
                CommandPublication::Published
            } else {
                CommandPublication::NotPublished
            }
        );
        let want_pending = matches!(mode, RefusePublication::After).then_some(PendingCommandId {
            seq: CommandSeq::checked(6).unwrap(),
            operation: CountOperation::Generation,
        });
        let actual = session.backend().requests[0].frontier.pending;
        let terminal = session.terminal(session_close());
        task3_cleanup(&probe.owner, 10);
        assert_eq!(
            actual, want_pending,
            "NotEntered discarded the published GEN identity"
        );
        assert!(no_inventory_failure(&terminal.receipt));
        assert_eq!(terminal.retained_drain.total_calls(), 18);
        assert_eq!(
            session.generation(),
            1,
            "unperformed GEN committed a new meaning"
        );
        assert_eq!(terminal.retained_drain.current[0].candidates[0].funcid, 7);
        assert_eq!(terminal.retained_drain.current[0].installed_at, Some(900));
        assert_eq!(
            terminal.receipt.inventory.as_ref().unwrap().pending,
            want_pending
        );
        assert_eq!(
            session
                .salvage_view(terminal.receipt.terminal_id)
                .retained_drain,
            terminal.retained_drain
        );
        assert_eq!(session.backend().terminal_calls, 1);
        assert_eq!(
            failure.cleanup_ticket,
            Some(terminal.receipt.cleanup_ticket)
        );
        assert!(!probe.calls.lock().unwrap().iter().any(|(_,call)| matches!(call,MapAction::Write(CountMap::Gen,0,value) if value.as_slice()==2u32.to_ne_bytes())));
        let calls = probe.calls.lock().unwrap().len();
        for _ in 0..3 {
            assert_eq!(
                session
                    .salvage_view(terminal.receipt.terminal_id)
                    .retained_drain,
                terminal.retained_drain
            );
        }
        assert_eq!(probe.calls.lock().unwrap().len(), calls);
        assert!(
            failure.cleanup_ticket.is_some(),
            "both publication branches have a ticket"
        );
    }
}
#[test]
fn g1_fix1_not_entered_open_never_admits_a_window() {
    for mode in [RefusePublication::After, RefusePublication::Before] {
        let probe = MapProbe::new();
        let mut session = crate::count_session::CountSession::new(
            1,
            session_owner_port(&probe, None, TerminalFaults::default()),
        );
        SessionPlan::new(1).attach(&mut session, 7);
        session.backend_mut().open_refusal = Some(mode);
        session.backend_mut().wait_inventory = true;
        assert!(
            session
                .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
                .is_err()
        );
        let want = matches!(mode, RefusePublication::After).then_some(PendingCommandId {
            seq: CommandSeq::checked(2).unwrap(),
            operation: CountOperation::Open,
        });
        let actual = session.backend().requests[0].frontier.pending;
        let failure = session.backend().last_failure.unwrap();
        assert_eq!(failure.completion, CommandCompletion::NotEntered);
        assert_eq!(
            failure.publication,
            if matches!(mode, RefusePublication::After) {
                CommandPublication::Published
            } else {
                CommandPublication::NotPublished
            }
        );
        let terminal = session.terminal(session_close());
        task3_cleanup(&probe.owner, 10);
        assert_eq!(
            failure.cleanup_ticket,
            Some(terminal.receipt.cleanup_ticket)
        );
        assert_eq!(
            actual, want,
            "NotEntered discarded the published Open request"
        );
        assert!(no_inventory_failure(&terminal.receipt));
        assert!(session.programmed_admission().is_none());
        assert!(!session.window_open());
        assert_eq!(terminal.receipt.inventory.as_ref().unwrap().pending, want);
        if let Some(open) = terminal.receipt.resolved_open {
            assert_eq!(
                (
                    open.seq.value(),
                    open.tgid,
                    open.generation,
                    open.start_ns,
                    open.deadline_ns
                ),
                (2, 1, 0, 1000, 2000)
            );
            assert_eq!(open.completed_writes, OpenWriteFrontier::NoWrites);
            assert_ne!(open.outcome, OpenOutcome::Completed);
        }
        assert!(
            !probe.calls.lock().unwrap().iter().any(|(_, call)| matches!(
                call,
                MapAction::Write(CountMap::Window | CountMap::Gen, _, _)
            ))
        );
        let calls = probe.calls.lock().unwrap().len();
        for _ in 0..3 {
            assert_eq!(
                session
                    .salvage_view(terminal.receipt.terminal_id)
                    .retained_drain,
                terminal.retained_drain
            );
        }
        assert_eq!(probe.calls.lock().unwrap().len(), calls);
    }
}
#[test]
fn g1_fix1_observing_prefix_survives_blocked_ordinary_read() {
    let probe = MapProbe::new();
    let gate = Probe::new();
    let writer = StagedWriter::new(None);
    writer.returned.store(true, Ordering::Release);
    let mut session = crate::count_session::CountSession::new(
        1,
        session_owner_port(
            &probe,
            Some(Arc::clone(&writer)),
            TerminalFaults {
                lookup_gate: Some((
                    Arc::new(AtomicU64::new(osslscope_ebpf_common::make_key(2, 0))),
                    Arc::clone(&gate),
                )),
                ..Default::default()
            },
        ),
    );
    let plan = SessionPlan::new(3);
    plan.attach(&mut session, 7);
    session
        .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
        .unwrap();
    for (position, count) in [(0, 11), (1, 12), (2, 1)] {
        writer.maps.lock().unwrap().rows.insert(
            osslscope_ebpf_common::make_key(plan.cookie(&session, position), 0),
            osslscope_ebpf_common::CountValue {
                count,
                first_ns: 1100 + position as u64 * 100,
                last_ns: 1150 + position as u64 * 100,
            },
        );
    }
    let cutoff = Instant::now() + Duration::from_millis(200);
    let call = std::thread::spawn(move || {
        assert!(
            session
                .fence(crate::count_session::FenceReason::MappingsChanged, cutoff)
                .is_err()
        );
        session
    });
    gate.wait(|events| {
        events
            .iter()
            .any(|(_, event)| matches!(event, Event::Started))
    });
    let mut session = call.join().unwrap();
    let checkpoint = session.backend().engine.progress().unwrap();
    assert_eq!(checkpoint.phase, OwnerPhase::Observing);
    assert!(checkpoint.published_at < cutoff);
    assert_eq!(
        checkpoint
            .snapshot
            .rows
            .iter()
            .map(|(_, v)| v.count)
            .sum::<u64>(),
        23,
        "actual owner prefix must exist before testing consumer retention"
    );
    assert!(
        locked(&session.backend().engine.shared.state)
            .inventory
            .is_none()
    );
    let terminal = session.terminal(session_close());
    let call_count = probe.calls.lock().unwrap().len();
    for _ in 0..3 {
        assert_eq!(
            session
                .salvage_view(terminal.receipt.terminal_id)
                .retained_drain,
            terminal.retained_drain
        );
    }
    assert_eq!(probe.calls.lock().unwrap().len(), call_count);
    gate.release();
    task3_cleanup(&probe.owner, 10);
    assert_eq!(
        terminal.retained_drain.total_calls(),
        23,
        "ordinary Observing prefix was lost while the journal remained unavailable"
    );
    assert!(terminal.runtime_failure.is_none());
    assert_eq!(
        session_counter(&terminal.retained_drain, "count.ledger_delta"),
        None
    );
    assert_eq!(session.backend().terminal_calls, 1);
    for (position, site) in terminal.retained_drain.current.iter().enumerate() {
        assert_eq!(site.site.offset, plan.offsets[position]);
        assert_eq!(site.site.device, 1);
        assert_eq!(site.site.inode, 2);
        assert_eq!(site.installed_at, Some(900));
        assert_eq!(site.candidates[0].funcid, 7);
        assert_eq!(
            (site.first_ns, site.last_ns),
            (1100 + position as u64 * 100, 1150 + position as u64 * 100)
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrefixSelection {
    Latest,
    Stale,
    AtCutoff,
    AfterCutoff,
}
fn retained_prefix_fixture(selection: PrefixSelection) {
    use crate::count_session::{CountSession, FenceReason};
    let probe = MapProbe::new();
    let gate = Probe::new();
    let writer = StagedWriter::new(None);
    writer.returned.store(true, Ordering::Release);
    // Current belongs to cookie0/gen1; the next cookie is a later lookup. The
    // post-cutoff twin instead holds current, preventing pre-cutoff publication.
    let held_key = if selection != PrefixSelection::AfterCutoff {
        osslscope_ebpf_common::make_key(1, 1)
    } else {
        osslscope_ebpf_common::make_key(0, 1)
    };
    let selected_key = Arc::new(AtomicU64::new(u64::MAX));
    let mut session = CountSession::new(
        1,
        session_owner_port(
            &probe,
            Some(Arc::clone(&writer)),
            TerminalFaults {
                lookup_gate: Some((Arc::clone(&selected_key), Arc::clone(&gate))),
                ..Default::default()
            },
        ),
    );
    let plan = SessionPlan::new(2);
    plan.attach(&mut session, 7);
    session
        .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let cookie = plan.cookie(&session, 0);
    assert_eq!(
        cookie, 0,
        "fixture's literal held key must name the bound first site"
    );
    writer.maps.lock().unwrap().rows.insert(
        osslscope_ebpf_common::make_key(cookie, 0),
        osslscope_ebpf_common::CountValue {
            count: 11,
            first_ns: 1100,
            last_ns: 1100,
        },
    );
    plan.attach(&mut session, 9);
    session
        .fence(
            FenceReason::CandidatesChanged,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    writer.maps.lock().unwrap().rows.insert(
        osslscope_ebpf_common::make_key(cookie, 1),
        osslscope_ebpf_common::CountValue {
            count: 7,
            first_ns: 1200,
            last_ns: 1300,
        },
    );
    // Use the same private ordinary Read path that fence consumes, through a
    // test utility; it supplies a real owner acknowledgment and image, without
    // inventing row data/frontier/sequence or committing an unrelated GEN.
    let prior = crate::count_session::tests::read_for_fixture(
        &mut session,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(prior.current[0].calls, 7);
    assert_eq!(prior.fenced[0].sites[0].calls, 11);
    if selection == PrefixSelection::Stale {
        // This is an actual earlier acknowledged image. Keeping it deliberately
        // exercises replay under the existing bounded image retention contract.
        session.backend_mut().replay = session.backend().engine.progress();
    }
    selected_key.store(held_key, Ordering::Release);
    if selection == PrefixSelection::AtCutoff {
        // Only timestamp metadata is controlled for the strict equality edge;
        // the Arc rows and actual Observing phase still come from the owner.
        session.backend_mut().progress_cutoff = Some(Instant::now());
    }
    writer.maps.lock().unwrap().rows.insert(
        osslscope_ebpf_common::make_key(cookie, 1),
        osslscope_ebpf_common::CountValue {
            count: 12,
            first_ns: 1200,
            last_ns: 1600,
        },
    );
    writer.maps.lock().unwrap().rows.insert(
        osslscope_ebpf_common::make_key(plan.cookie(&session, 1), 1),
        osslscope_ebpf_common::CountValue {
            count: 1,
            first_ns: 1700,
            last_ns: 1700,
        },
    );
    if selection == PrefixSelection::AfterCutoff {
        session.backend_mut().late_release = Some(Arc::clone(&gate));
    }
    let cutoff = Instant::now() + Duration::from_millis(200);
    let call = std::thread::spawn(move || {
        assert!(session.fence(FenceReason::MappingsChanged, cutoff).is_err());
        session
    });
    gate.wait(|events| events.iter().any(|(_, e)| matches!(e, Event::Started)));
    let mut session = call.join().unwrap();
    let actual = session.backend().engine.progress().unwrap();
    assert_eq!(actual.phase, OwnerPhase::Observing);
    if selection == PrefixSelection::Latest || selection == PrefixSelection::AtCutoff {
        // Assert the actual producer prefix exists. Pinning a prior session
        // image must not silently consume the spare needed to publish it.
        let actual_total = actual
            .snapshot
            .rows
            .iter()
            .map(|(_, v)| v.count)
            .sum::<u64>();
        if actual_total != 23 {
            gate.release();
            task3_cleanup(&probe.owner, 10);
        }
        assert_eq!(
            actual_total, 23,
            "session retained image pinned away the owner's positive prefix"
        );
        assert!(actual.published_at < cutoff);
    } else if selection == PrefixSelection::AfterCutoff {
        assert!(
            actual.published_at >= cutoff,
            "late twin must exercise real post-cutoff owner publication"
        );
    }
    let terminal = session.terminal(session_close());
    let calls = probe.calls.lock().unwrap().len();
    let closes = probe
        .owner
        .log
        .lock()
        .unwrap()
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::EnterClose))
        .count();
    for _ in 0..3 {
        let salvage = session.salvage_view(terminal.receipt.terminal_id);
        assert_eq!(salvage.retained_drain, terminal.retained_drain);
        assert!(std::ptr::eq(&*salvage.receipt, &*terminal.receipt));
    }
    assert_eq!(probe.calls.lock().unwrap().len(), calls);
    assert_eq!(
        probe
            .owner
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::EnterClose))
            .count(),
        closes
    );
    gate.release();
    task3_cleanup(&probe.owner, 10);
    let want = if selection == PrefixSelection::Latest {
        23
    } else {
        18
    };
    assert_eq!(terminal.retained_drain.total_calls(), want);
    assert!(
        terminal.runtime_failure.is_none(),
        "{:?}",
        terminal.runtime_failure
    );
    assert_eq!(
        session_counter(&terminal.retained_drain, "count.ledger_delta"),
        None
    );
    let current = &terminal.retained_drain.current[0];
    assert_eq!(
        (
            current.calls,
            current.generation,
            current.candidates[0].funcid
        ),
        (want - 11, 1, 9)
    );
    assert_eq!(
        (current.first_ns, current.last_ns),
        (
            1200,
            if selection == PrefixSelection::Latest {
                1600
            } else {
                1300
            }
        )
    );
    assert_eq!(current.site.offset, plan.offsets[0]);
    assert_eq!((current.site.device, current.site.inode), (1, 2));
    assert_eq!(current.installed_at, Some(900));
    let retired = &terminal.retained_drain.fenced[0].sites[0];
    assert_eq!(
        (
            retired.calls,
            retired.generation,
            retired.candidates[0].funcid
        ),
        (11, 0, 7)
    );
    assert_eq!((retired.first_ns, retired.last_ns), (1100, 1100));
    assert_eq!(retired.site, current.site);
    assert_eq!(retired.installed_at, Some(900));
    assert_eq!(
        session
            .salvage_view(terminal.receipt.terminal_id)
            .retained_drain,
        terminal.retained_drain,
        "late cleanup cannot replace selected facts"
    );
    assert_eq!(session.backend().terminal_calls, 1);
}
#[test]
fn g1_fix1_current_and_fenced_prefix_uses_three_actual_images() {
    retained_prefix_fixture(PrefixSelection::Latest);
}

#[test]
fn g1_fix1_stale_ordinary_image_never_refolds_prior_calls() {
    retained_prefix_fixture(PrefixSelection::Stale);
}
#[test]
fn g1_fix1_prefix_observed_at_cutoff_grants_no_new_rows() {
    retained_prefix_fixture(PrefixSelection::AtCutoff);
}
#[test]
fn g1_fix1_actual_late_ordinary_prefix_grants_no_new_rows() {
    retained_prefix_fixture(PrefixSelection::AfterCutoff);
}
#[test]
fn g1_fix1_sealed_frontier_still_rejects_forged_identity() {
    for forged in 0..4 {
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
        let ack = engine.attach(attach_request(1, 1)).unwrap();
        let original = ControllerFrontier {
            last_acked: Some(ack.seq),
            acknowledged_links: ack.value.links.iter().map(LinkToken::id).collect(),
            pending: Some(PendingCommandId {
                seq: CommandSeq::checked(2).unwrap(),
                operation: CountOperation::Open,
            }),
        };
        let open = open_request(2);
        assert_eq!(
            engine.open_window(open).unwrap_err().failure.class,
            FailureClass::Io
        );
        assert_eq!(
            task3_inventory(&engine).unwrap().validate(&original),
            Ok(())
        );
        let seal = locked(&engine.shared.state).terminal.unwrap();
        let mut frontier = original;
        let mut domain = engine.ready.evidence_domain;
        let mut object = engine.ready.writer_object_identity;
        match forged {
            0 => object = [0x88; 32],
            1 => domain = EvidenceDomain::Live,
            2 => {
                frontier.pending = Some(PendingCommandId {
                    seq: CommandSeq::checked(99).unwrap(),
                    operation: CountOperation::Open,
                })
            }
            _ => frontier = ControllerFrontier::default(),
        }
        let request = engine.terminal_request(
            open.deadline + Duration::from_secs(30),
            domain,
            object,
            frontier,
        );
        assert!(locked(&engine.shared.state).terminal_contradiction);
        assert_eq!(request.id, seal.ticket.terminal_id);
        assert_eq!(request.deadline, open.deadline);
        let terminal = engine.terminal(request.clone());
        assert!(validate_terminal(&request, &terminal).is_err());
        assert!(!matches!(
            terminal.writers,
            WriterCompletion::Finished(_) | WriterCompletion::KnownEmpty(_)
        ));
        assert!(std::ptr::eq(&*terminal, &*engine.salvage_view(request.id)));
        task3_cleanup(&probe.owner, 10);
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
fn g1_snapshot_actual_row_buffers_keep_capacity_and_reuse_addresses() {
    let probe = MapProbe::new();
    let engine = map_engine(
        &probe,
        MapFaults {
            keys: (0..8192).collect(),
            ..MapFaults::default()
        },
    );
    let a = engine.drain(read_request(1)).unwrap().value;
    let b = engine.drain(read_request(2)).unwrap().value;
    let c = engine.drain(read_request(3)).unwrap().value;
    let buffers = [&a, &b, &c].map(|image| (image.rows.as_ptr() as usize, image.rows.capacity()));
    assert_eq!(buffers.map(|(_, capacity)| capacity), [8192; 3]);
    assert_ne!(buffers[0].0, buffers[1].0);
    assert_ne!(buffers[1].0, buffers[2].0);
    assert_ne!(buffers[0].0, buffers[2].0);
    for image in [&a, &b, &c] {
        assert_eq!(image.rows.len(), 8192);
        assert_eq!(image.rows[0].1.count, 1);
        assert_eq!(image.rows[8191].1.count, 16383);
    }
    println!("Task11 actual full row buffers before reuse: {buffers:?}");
    drop(a);
    let recycled_a = engine.drain(read_request(4)).unwrap().value;
    assert_eq!(
        (
            recycled_a.rows.as_ptr() as usize,
            recycled_a.rows.capacity()
        ),
        buffers[0]
    );
    assert_eq!(recycled_a.rows.len(), 8192);
    drop(b);
    let recycled_b = engine.drain(read_request(5)).unwrap().value;
    assert_eq!(
        (
            recycled_b.rows.as_ptr() as usize,
            recycled_b.rows.capacity()
        ),
        buffers[1]
    );
    assert_eq!(recycled_b.rows.len(), 8192);
    assert_eq!(c.rows.len(), 8192);
    assert_eq!(c.rows[8191].1.count, 16383);
    let calls = probe.calls.lock().unwrap().len();
    let failure = engine.drain(read_request(6)).unwrap_err();
    assert_eq!(failure.failure.class, FailureClass::Capacity);
    assert_eq!(failure.completion, CommandCompletion::NotEntered);
    assert_eq!(
        probe.calls.lock().unwrap().len(),
        calls,
        "all three actual buffers are pinned; a fourth read must not begin"
    );
    assert_eq!(recycled_a.rows[8191].1.count, 16383);
    assert_eq!(recycled_b.rows[8191].1.count, 16383);
    println!(
        "Task11 reused actual buffers 0 and 1 with fixed 8192 capacities; pinned third unchanged; fourth read refused before I/O"
    );
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
    SuffixFork,
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
    hold_deadline: Mutex<Option<Instant>>,
    hold_expired: AtomicBool,
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
            hold_deadline: Mutex::new(None),
            hold_expired: AtomicBool::new(false),
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
        let deadline = *locked(&self.hold_deadline);
        while !*released {
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.hold_expired.store(true, Ordering::Release);
                    break;
                }
                released = self.release.wait_timeout(released, remaining).unwrap().0;
            } else {
                released = self.release.wait(released).unwrap();
            }
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
    CountIncremented,
    CountOrDrop,
    BeforeLatc,
    LastMutation,
    Returned,
}
#[derive(Debug, Clone, Copy)]
struct PhysicalAdmission {
    invocation_id: u64,
    site: u32,
    cpu: usize,
    generation: Option<u32>,
    actual_sample_ns: u64,
    known_drop: bool,
}
#[derive(Clone, Copy)]
struct PhysicalCall {
    site: u32,
    cpu: usize,
    sample_ns: u64,
    fresh: bool,
    fail_insert: bool,
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
    maps_cpu1: Mutex<WriterMaps>,
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
            maps_cpu1: Mutex::new(WriterMaps::default()),
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
        self.run_physical(
            PhysicalCall {
                site: 100,
                cpu: 0,
                sample_ns,
                fresh,
                fail_insert,
            },
            hold_enabled,
        )
    }
    fn cpu_maps(&self, cpu: usize) -> &Mutex<WriterMaps> {
        match cpu {
            0 => &self.maps,
            1 => &self.maps_cpu1,
            _ => panic!("fixture has exactly two possible CPUs"),
        }
    }
    fn run_physical(
        self: &Arc<Self>,
        call: PhysicalCall,
        hold_enabled: bool,
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
                    site: call.site,
                    cpu: call.cpu,
                    generation: None,
                    actual_sample_ns: call.sample_ns,
                    known_drop: call.fail_insert,
                });
                index
            };
            writer.at(WriterStage::WindowPassed, hold_enabled);
            writer.cpu_maps(call.cpu).lock().unwrap().admitted += 1;
            writer.at(WriterStage::AdmittedLedger, hold_enabled);
            // GEN is sampled by this producer after ADMITTED, independently of
            // both count-map lookup and the eventual controller's routing.
            let generation = writer.generation.load(Ordering::Acquire);
            writer.ledger.0.lock().unwrap()[physical_index].generation = Some(generation);
            writer.at(WriterStage::GenerationRead, hold_enabled);
            let key = osslscope_ebpf_common::make_key(call.site, generation);
            let existing = writer.maps.lock().unwrap().rows.get(&key).is_some();
            assert_eq!(
                existing, !call.fresh,
                "the existing branch requires a real successful lookup"
            );
            writer.at(WriterStage::ExistingLookup, hold_enabled);
            if call.fresh {
                if !call.fail_insert {
                    // A successful per-CPU hash insertion creates the key on
                    // every CPU, including untouched zero-valued slots.
                    for cpu in 0..2 {
                        writer
                            .cpu_maps(cpu)
                            .lock()
                            .unwrap()
                            .rows
                            .entry(key)
                            .or_default();
                    }
                }
                writer.at(WriterStage::FreshInsert, hold_enabled);
            }
            {
                let mut maps = writer.cpu_maps(call.cpu).lock().unwrap();
                if call.fail_insert {
                    maps.dropfail += 1;
                } else {
                    let row = maps
                        .rows
                        .get_mut(&key)
                        .expect("existing or successful fresh relookup");
                    if row.count == 0 {
                        row.first_ns = call.sample_ns;
                    }
                    row.count += 1;
                }
            }
            // Model bump's separate count and last-time stores. Releasing
            // the map lock lets the real owner reader observe that interval.
            writer.at(WriterStage::CountIncremented, hold_enabled);
            if !call.fail_insert {
                writer
                    .cpu_maps(call.cpu)
                    .lock()
                    .unwrap()
                    .rows
                    .get_mut(&key)
                    .unwrap()
                    .last_ns = call.sample_ns;
            }
            writer.at(WriterStage::CountOrDrop, hold_enabled);
            if call.fresh {
                writer.at(WriterStage::BeforeLatc, hold_enabled);
                writer.cpu_maps(call.cpu).lock().unwrap().latc += 1;
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
    seal_clock: Option<Arc<Mutex<std::collections::VecDeque<Option<u64>>>>>,
    publication_gate: Option<Arc<Probe>>,
    registry_hook: Option<Arc<dyn Fn(RegistryEvent) + Send + Sync>>,
    seal_claim_gate: Option<Arc<Probe>>,
    mailbox_observer: Option<Arc<dyn Fn(MailboxEvent) + Send + Sync>>,
    lookup_gate: Option<(Arc<AtomicU64>, Arc<Probe>)>,
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
            seal_clock: None,
            publication_gate: None,
            registry_hook: None,
            seal_claim_gate: None,
            mailbox_observer: None,
            lookup_gate: None,
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
    seal_clock: Option<Arc<Mutex<std::collections::VecDeque<Option<u64>>>>>,
    lookup_gate: Option<(Arc<AtomicU64>, Arc<Probe>)>,
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
        if let Some((held_key, gate)) = &self.lookup_gate {
            if map == CountMap::Counts && k == held_key.load(Ordering::Acquire) {
                gate.event(Event::Started);
                gate.hold();
            }
        }
        let maps = [
            writer.maps.lock().unwrap(),
            writer.maps_cpu1.lock().unwrap(),
        ];
        value.fill(0);
        if map == CountMap::Counts {
            if !maps[0].rows.contains_key(&k) {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            for (cpu, slot) in value.chunks_exact_mut(24).enumerate() {
                if let Some(row) = maps[cpu].rows.get(&k) {
                    slot[..8].copy_from_slice(&row.count.to_ne_bytes());
                    slot[8..16].copy_from_slice(&row.first_ns.to_ne_bytes());
                    slot[16..24].copy_from_slice(&row.last_ns.to_ne_bytes());
                }
            }
        } else {
            for (cpu, slot) in value.chunks_exact_mut(8).enumerate() {
                let n = match map {
                    CountMap::Admitted => maps[cpu].admitted,
                    CountMap::Dropfail => maps[cpu].dropfail,
                    CountMap::Latc if k == 0 => maps[cpu].latc,
                    CountMap::Latc => 0,
                    _ => panic!("invalid model read"),
                };
                slot.copy_from_slice(&n.to_ne_bytes());
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
        if let Some(clock) = &self.seal_clock {
            return clock
                .lock()
                .unwrap()
                .pop_front()
                .expect("explicit modeled stop sample");
        }
        self.map.monotonic_ns()
    }
}
fn terminal_engine(
    probe: &Arc<MapProbe>,
    writer: Option<Arc<StagedWriter>>,
    faults: TerminalFaults,
) -> (CountEngine, Arc<Mutex<Vec<(TerminalEvent, Instant)>>>) {
    terminal_engine_preparation(probe, writer, faults, None)
}
fn terminal_engine_preparation(
    probe: &Arc<MapProbe>,
    writer: Option<Arc<StagedWriter>>,
    faults: TerminalFaults,
    setup: Option<SetupPreparation>,
) -> (CountEngine, Arc<Mutex<Vec<(TerminalEvent, Instant)>>>) {
    let barrier = setup.as_ref().map_or_else(
        || Arc::new(CountForkBarrier::new()),
        |s| Arc::clone(&s.admission.as_ref().unwrap().barrier),
    );
    if let Some(s) = &setup {
        s.journal.begin();
    }
    let observed = Arc::clone(&probe.owner);
    let registry_hook = faults.registry_hook.clone();
    let mut hooks = PrepareHooks::host();
    hooks.kernel_profile = faults.profile;
    hooks.final_references = faults.references;
    hooks.writer_family = faults.family;
    hooks.fail_attach_publication = faults.fail_publication;
    hooks.mailbox_observer = faults.mailbox_observer.clone();
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
    let engine = CountEngine::prepare_inner(
        input(barrier),
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
                seal_clock: faults.seal_clock,
                lookup_gate: faults.lookup_gate,
            }
        },
        spawn_owner,
        setup,
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

// Reuse the staged physical producer through the actual session, mailbox,
// reader and router. Two CPU slots contribute to one shared physical key;
// the independently recorded invocation IDs never come from count rows.
fn physical_session(
    writer: &Arc<StagedWriter>,
) -> (
    crate::count_session::CountSession<SessionOwnerPort>,
    Arc<MapProbe>,
    SessionPlan,
) {
    let probe = MapProbe::new();
    let mut session = crate::count_session::CountSession::new(
        1,
        session_owner_port(&probe, Some(Arc::clone(writer)), TerminalFaults::default()),
    );
    let plan = SessionPlan::new(3);
    plan.attach(&mut session, 7);
    for position in 0..3 {
        assert_eq!(plan.cookie(&session, position), position as u32);
    }
    session
        .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
        .unwrap();
    for (site, cpu, sample_ns, fresh) in
        [(0, 0, 1100, true), (0, 1, 1120, false), (1, 1, 1130, true)]
    {
        writer
            .run_physical(
                PhysicalCall {
                    site,
                    cpu,
                    sample_ns,
                    fresh,
                    fail_insert: false,
                },
                false,
            )
            .join()
            .unwrap();
    }
    plan.attach(&mut session, 9);
    session
        .fence(
            crate::count_session::FenceReason::CandidatesChanged,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    for (cpu, sample_ns, fresh) in [(1, 1200, true), (0, 1210, false)] {
        writer
            .run_physical(
                PhysicalCall {
                    site: 0,
                    cpu,
                    sample_ns,
                    fresh,
                    fail_insert: false,
                },
                false,
            )
            .join()
            .unwrap();
    }
    let retained = crate::count_session::tests::read_for_fixture(
        &mut session,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(retained.current.iter().map(|s| s.calls).sum::<u64>(), 2);
    assert_eq!(
        retained.fenced[0]
            .sites
            .iter()
            .map(|s| s.calls)
            .sum::<u64>(),
        3
    );
    (session, probe, plan)
}

fn physical_equality_sample(writer: &StagedWriter) -> (bool, u64) {
    let maps = [
        writer.maps.lock().unwrap(),
        writer.maps_cpu1.lock().unwrap(),
    ];
    let admitted = maps.iter().map(|m| m.admitted).sum::<u64>();
    let counts = maps
        .iter()
        .flat_map(|m| m.rows.values())
        .map(|v| v.count)
        .sum::<u64>();
    let drops = maps.iter().map(|m| m.dropfail).sum::<u64>();
    let physical = writer.ledger.admitted_calls();
    println!(
        "Task11 old/faulted equality sample: admitted={admitted} counts={counts} drops={drops} equal={} physical={physical} short={}",
        admitted == counts + drops,
        physical.saturating_sub(counts + drops),
    );
    (admitted == counts + drops, counts + drops)
}

fn assert_physical_routing(
    writer: &StagedWriter,
    plan: &SessionPlan,
    drain: &crate::count_session::CountDrain,
) {
    let physical = writer.ledger.0.lock().unwrap();
    assert_eq!(
        physical.iter().map(|p| p.invocation_id).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        physical.iter().map(|p| p.cpu).collect::<Vec<_>>(),
        [0, 1, 1, 1, 0, 1]
    );
    assert_eq!(
        physical
            .iter()
            .map(|p| p.actual_sample_ns)
            .collect::<Vec<_>>(),
        [1100, 1120, 1130, 1200, 1210, 1500]
    );
    assert_eq!(
        physical
            .iter()
            .map(|p| p.generation.unwrap())
            .collect::<Vec<_>>(),
        [0, 0, 0, 1, 1, 1]
    );
    let mut expected = std::collections::BTreeMap::<(u32, u32), (u64, u64, u64)>::new();
    for call in physical.iter().filter(|p| !p.known_drop) {
        let value = expected
            .entry((call.site, call.generation.unwrap()))
            .or_insert((0, u64::MAX, 0));
        value.0 += 1;
        value.1 = value.1.min(call.actual_sample_ns);
        value.2 = value.2.max(call.actual_sample_ns);
    }
    let mut actual = std::collections::BTreeMap::new();
    for site in drain
        .current
        .iter()
        .chain(drain.fenced.iter().flat_map(|f| &f.sites))
    {
        let position = plan
            .offsets
            .iter()
            .position(|offset| *offset == site.site.offset)
            .unwrap() as u32;
        assert!(
            actual
                .insert(
                    (position, site.generation),
                    (site.calls, site.first_ns, site.last_ns)
                )
                .is_none()
        );
        assert!(
            site.candidates
                .iter()
                .all(|candidate| candidate.funcid == if site.generation == 0 { 7 } else { 9 })
        );
    }
    assert_eq!(actual, expected);
    let known_drops = physical.iter().filter(|p| p.known_drop).count() as u64;
    assert_eq!(
        session_counter(drain, "count.map_insert_dropped").unwrap_or(0),
        known_drops
    );
    assert_eq!(session_counter(drain, "count.unattributed").unwrap_or(0), 0);
    assert_eq!(drain.total_calls() + known_drops, physical.len() as u64);
}

#[test]
fn g1_terminal_physical_sites_cpus_and_generation_routing() {
    for (stage, fresh, fail_insert) in [
        (WriterStage::WindowPassed, true, false),
        (WriterStage::AdmittedLedger, true, false),
        (WriterStage::ExistingLookup, false, false),
        (WriterStage::FreshInsert, true, false),
        (WriterStage::FreshInsert, true, true),
        (WriterStage::BeforeLatc, true, false),
    ] {
        for held in [true, false] {
            let writer = StagedWriter::new(held.then_some(stage));
            let (mut session, probe, plan) = physical_session(&writer);
            let producer = writer.run_physical(
                PhysicalCall {
                    site: if fresh { 2 } else { 0 },
                    cpu: 1,
                    sample_ns: 1500,
                    fresh,
                    fail_insert,
                },
                true,
            );
            if held {
                writer.wait_at(stage);
            } else {
                writer.wait_returned();
            }
            let (equal, observed) = physical_equality_sample(&writer);
            if held && stage == WriterStage::WindowPassed {
                assert!(
                    equal,
                    "the equality negative must falsely complete, not return Err"
                );
                assert_eq!((observed, writer.ledger.admitted_calls()), (5, 6));
            }
            let terminal = thread::scope(|scope| {
                let closing = scope.spawn(|| session.terminal_shared(session_close()));
                if held {
                    probe.owner.wait(|events| {
                        events.iter().any(|(_, event)| {
                            matches!(
                                event,
                                Event::Registry(RegistryEvent::CloseIssued(ResourceId::Link(_)))
                            )
                        })
                    });
                    assert!(!writer.returned.load(Ordering::Acquire));
                    writer.release();
                }
                closing.join().unwrap()
            });
            producer.join().unwrap();
            assert!(matches!(
                terminal.receipt.writers,
                WriterCompletion::Finished(_)
            ));
            assert_physical_routing(&writer, &plan, &terminal.retained_drain);
            assert_eq!(
                terminal
                    .retained_drain
                    .fenced
                    .iter()
                    .flat_map(|f| &f.sites)
                    .map(|s| s.calls)
                    .sum::<u64>(),
                3
            );
            assert_eq!(
                terminal
                    .receipt
                    .checkpoint
                    .as_ref()
                    .unwrap()
                    .snapshot
                    .admitted,
                Component::Available(6)
            );
            assert_eq!(session.backend().terminal_calls, 1);
            task3_cleanup(&probe.owner, 10);
            println!(
                "Task11 {stage:?} held={held} fresh={fresh} fail_insert={fail_insert}: physical=6 conserved after release"
            );
        }
    }
}

fn assert_fwr_i1_equal_count_terminal(fenced: bool) {
    let writer = StagedWriter::new(Some(WriterStage::CountIncremented));
    let probe = MapProbe::new();
    let mut session = crate::count_session::CountSession::new(
        1,
        session_owner_port(&probe, Some(Arc::clone(&writer)), TerminalFaults::default()),
    );
    let plan = SessionPlan::new(1);
    plan.attach(&mut session, 7);
    session
        .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
        .unwrap();
    writer
        .run_physical(
            PhysicalCall {
                site: 0,
                cpu: 0,
                sample_ns: 1100,
                fresh: true,
                fail_insert: false,
            },
            false,
        )
        .join()
        .unwrap();
    let producer = writer.run_physical(
        PhysicalCall {
            site: 0,
            cpu: 0,
            sample_ns: 1500,
            fresh: false,
            fail_insert: false,
        },
        true,
    );
    writer.wait_at(WriterStage::CountIncremented);
    let before = crate::count_session::tests::read_for_fixture(
        &mut session,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(
        (
            before.current[0].calls,
            before.current[0].first_ns,
            before.current[0].last_ns
        ),
        (2, 1100, 1100)
    );
    let original_candidates = before.current[0].candidates.clone();
    if fenced {
        plan.attach(&mut session, 9);
        session
            .fence(
                crate::count_session::FenceReason::CandidatesChanged,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
    }
    writer.release();
    producer.join().unwrap();
    let terminal = session.terminal_shared(session_close());
    assert!(matches!(
        terminal.receipt.writers,
        WriterCompletion::Finished(_)
    ));
    assert_eq!(terminal.retained_drain.total_calls(), 2);
    let rows = if fenced {
        &terminal.retained_drain.fenced[0].sites
    } else {
        &terminal.retained_drain.current
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].candidates, original_candidates);
    assert_eq!(rows[0].generation, 0);
    assert_eq!(
        (rows[0].calls, rows[0].first_ns, rows[0].last_ns),
        (2, 1100, 1500),
        "fenced={fenced}: equal count must retain the completed callback's actual last-time store"
    );
    assert_eq!(writer.ledger.admitted_calls(), 2);
    assert_eq!(session.backend().terminal_calls, 1);
    assert!(Arc::ptr_eq(
        &terminal,
        &session.terminal_shared(session_close())
    ));
    task3_cleanup(&probe.owner, 10);
    println!(
        "FWR-I1 fenced={fenced}: ordinary=(2,1100,1100), terminal=(2,1100,1500), original candidates retained"
    );
}

#[test]
fn fwr_i1_equal_count_terminal_refines_current_physical_timestamps() {
    assert_fwr_i1_equal_count_terminal(false);
}
#[test]
fn fwr_i1_equal_count_terminal_refines_fenced_physical_timestamps() {
    assert_fwr_i1_equal_count_terminal(true);
}

#[test]
fn g1_terminal_physical_pre_admitted_cutoff_cannot_finalize_equal_short() {
    let writer = StagedWriter::new(Some(WriterStage::WindowPassed));
    let (mut session, probe, _plan) = physical_session(&writer);
    let producer = writer.run_physical(
        PhysicalCall {
            site: 2,
            cpu: 1,
            sample_ns: 1500,
            fresh: true,
            fail_insert: false,
        },
        true,
    );
    writer.wait_at(WriterStage::WindowPassed);
    assert_eq!(physical_equality_sample(&writer), (true, 5));
    // Keep the producer held until coordinator finalization. This makes a
    // falsely Finished equal/short snapshot deterministic, rather than racing
    // release against a read or using an arbitrary error as the negative.
    let terminal = session.terminal_shared(crate::count_session::CloseRequest {
        started_at: Instant::now(),
        grace: Duration::from_millis(200),
        reason: crate::count_session::CloseReason::Interrupted,
    });
    let held_at_finalization = !writer.returned.load(Ordering::Acquire);
    writer.release();
    producer.join().unwrap();
    task3_cleanup(&probe.owner, 10);
    assert!(held_at_finalization);
    assert!(
        !matches!(terminal.receipt.writers, WriterCompletion::Finished(_)),
        "equal/short snapshot falsely Finished while physical=6, finalized={}, receipt={:?}",
        terminal.retained_drain.total_calls(),
        terminal.receipt.writers
    );
    assert_eq!(terminal.retained_drain.total_calls(), 5);
    assert_eq!(
        session_counter(&terminal.retained_drain, "count.quiescence_unknown"),
        Some(1)
    );
    let repeated = session.shared_terminal(terminal.receipt.terminal_id);
    assert!(Arc::ptr_eq(&terminal, &repeated));
    assert_eq!(session.backend().terminal_calls, 1);
    let maps = [
        writer.maps.lock().unwrap(),
        writer.maps_cpu1.lock().unwrap(),
    ];
    assert_eq!(
        maps.iter()
            .flat_map(|m| m.rows.values())
            .map(|r| r.count)
            .sum::<u64>(),
        6
    );
    println!(
        "Task11 pre-ADMITTED cutoff: held at finalization, retained=5 physical=6 unknown tail; after release physical maps=6, finalized Arc unchanged"
    );
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
    struct ReleaseOnPanic<'a> {
        engine: &'a CountEngine,
        owner: &'a Probe,
    }
    impl Drop for ReleaseOnPanic<'_> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.engine.abandon();
                self.owner.release();
            }
        }
    }
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
        // Drop before the scope's implicit join if any assertion unwinds.
        let _release_on_panic = ReleaseOnPanic {
            engine: &engine,
            owner: &probe.owner,
        };
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
        // Resolve the ordinary caller's publication-lock access while the raw owner stays held.
        assert_eq!(
            ordinary.join().unwrap().err().unwrap().cleanup_ticket,
            Some(receipt.cleanup_ticket)
        );
        assert_eq!(
            engine.cleanup_progress().unwrap().active_operation,
            Some(CountOperation::Generation)
        );
        assert!(engine.fork_permit(Instant::now()).is_err());
        assert_eq!(probe.calls.lock().unwrap().len(), 1);
        probe.owner.release();
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

#[test]
fn g1_fork_barrier_covers_all_count_resources() {
    struct ReleaseOnDrop(Arc<Probe>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    for (held_close, expected) in [
        (1, None),
        (2, Some(ResourceId::Pin(0))),
        (3, Some(ResourceId::Program)),
        (4, Some(ResourceId::Map(CountMap::Counts))),
    ] {
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
        let attached = engine.attach(attach_request(1, 1)).unwrap();
        let expected = expected.unwrap_or(ResourceId::Link(attached.value.links[0].id()));
        let request = terminal_request(&engine, Instant::now() + Duration::from_secs(5));
        thread::scope(|scope| {
            let release = ReleaseOnDrop(Arc::clone(&probe.owner));
            let terminal = scope.spawn(|| engine.terminal(request));
            probe.owner.wait(|events| {
                events
                    .iter()
                    .filter(|(_, e)| matches!(e, Event::EnterClose))
                    .count()
                    == held_close
            });
            assert!(
                engine
                    .resource_summary()
                    .resources
                    .iter()
                    .any(|r| r.resource == expected && r.state == ResourceState::CloseIssued)
            );
            // The injected suffix operation is never entered on refusal.
            for _ in 0..2 {
                if let Ok(_permit) = engine.fork_permit(Instant::now()) {
                    probe.owner.event(Event::SuffixFork);
                }
            }
            assert!(
                !probe
                    .owner
                    .log
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|(_, e)| matches!(e, Event::SuffixFork)),
                "suffix while {expected:?} unresolved"
            );
            drop(release);
            terminal.join().unwrap();
        });
        task3_cleanup(&probe.owner, 10);
        let _permit = engine
            .fork_permit(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert!(engine.resource_summary().cleanup_complete);
        probe.owner.event(Event::SuffixFork);
        let log = probe.owner.log.lock().unwrap();
        let all_checked = log
            .events
            .iter()
            .rposition(|(_, e)| matches!(e, Event::Registry(RegistryEvent::CloseReturned(_))))
            .unwrap();
        let suffix = log
            .events
            .iter()
            .position(|(_, e)| matches!(e, Event::SuffixFork))
            .unwrap();
        assert!(all_checked < suffix, "{expected:?}: {:?}", log.events);
    }
}

#[test]
fn g1_prefix_permit_survives_owned_fork_and_excludes_owner_acquisition() {
    let barrier = Arc::new(CountForkBarrier::new());
    let permit = barrier.prefix_permit(Instant::now()).unwrap();
    let mut child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".to_string()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let probe = Probe::new();
    let failed = injected(
        Arc::clone(&probe),
        Faults::default(),
        Arc::clone(&barrier),
        Instant::now() + Duration::from_millis(20),
        PrepareHooks::host(),
    );
    child.resolve_setup_failure().unwrap();
    assert!(failed.is_err());
    assert!(
        !probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::Started | Event::EnterAcquire(_)))
    );
    drop(permit);
    let engine = injected(
        Arc::clone(&probe),
        Faults::default(),
        barrier,
        Instant::now() + Duration::from_secs(3),
        PrepareHooks::host(),
    )
    .unwrap();
    engine.abandon();
    task3_cleanup(&probe, 8);
}

// Host producer/owner interleaving only. This never loads BPF or qualifies a
// real kernel/clock domain. The independent physical ledger samples after the
// held TARGET read, not at the controller's eventual acknowledgment.
#[test]
fn g1_target_read_before_seal_timestamp_after_seal_adapts_actual_terminal() {
    use crate::capture::{
        AdmissionMode, AdmissionProjection, count_effective_end, project_admission,
    };
    use crate::count_session::{CloseReason, CountSession};
    use crate::evidence::{
        self, CaptureWindow, ExpectedScope, FinalizeInput, LegacyCallPartition, ObjectId,
        ObjectRecord, OpensslVersion, ScopeCoverage, TargetRecord,
    };
    let writer = StagedWriter::new(Some(WriterStage::TargetRead));
    let probe = MapProbe::new();
    let seal_clock = Arc::new(Mutex::new(std::collections::VecDeque::from([
        Some(1500),
        Some(1510),
    ])));
    let mut session = CountSession::new(
        1,
        session_owner_port(
            &probe,
            Some(Arc::clone(&writer)),
            TerminalFaults {
                seal_clock: Some(Arc::clone(&seal_clock)),
                ..Default::default()
            },
        ),
    );
    // The staged producer's physical site is cookie100. Bind it through the
    // actual session/owner attach rather than relabeling its final map key.
    let plan = SessionPlan::new(101);
    plan.attach(&mut session, 7);
    assert_eq!(plan.cookie(&session, 100), 100);
    session
        .open_window(1000, 2000, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let producer = writer.run_invocation(true, false, true, 1600);
    writer.wait_at(WriterStage::TargetRead);
    let (session, terminal) = thread::scope(|scope| {
        let closing = scope.spawn(move || {
            let terminal = session.terminal(crate::count_session::CloseRequest {
                started_at: Instant::now(),
                grace: Duration::from_secs(5),
                reason: CloseReason::Interrupted,
            });
            (session, terminal)
        });
        probe.owner.wait(|events| {
            events.iter().any(|(_, e)| {
                matches!(
                    e,
                    Event::Registry(RegistryEvent::CloseIssued(ResourceId::Link(_)))
                )
            })
        });
        assert!(
            seal_clock.lock().unwrap().is_empty(),
            "both actual modeled stop samples precede the resumed writer"
        );
        assert_eq!(writer.ledger.admitted_calls(), 0);
        assert!(writer.maps.lock().unwrap().rows.is_empty());
        writer.release();
        closing.join().unwrap()
    });
    producer.join().unwrap();
    task3_cleanup(&probe.owner, 10);
    assert!(
        terminal.runtime_failure.is_none(),
        "{:?}",
        terminal.runtime_failure
    );
    assert_eq!(terminal.receipt.evidence_domain, EvidenceDomain::HostModel);
    assert_eq!(terminal.receipt.seal.before_ns, Some(1500));
    assert_eq!(terminal.receipt.seal.after_ns, Some(1510));
    assert!(matches!(
        terminal.receipt.writers,
        WriterCompletion::Finished(_)
    ));
    assert_eq!(writer.ledger.admitted_calls(), 1);
    assert_eq!(writer.ledger.0.lock().unwrap()[0].actual_sample_ns, 1600);
    assert_eq!(terminal.retained_drain.total_calls(), 1);
    assert_eq!(terminal.retained_drain.current[0].last_ns, 1600);
    let endpoint = count_effective_end(CloseReason::Interrupted, 2000, terminal.receipt.seal, 1100);
    assert_eq!(endpoint.end_ns, 1500);
    assert!(!endpoint.uncertain);
    let mut window = CaptureWindow {
        requested_start_ns: 1100,
        requested_end_ns: 2100,
        effective_start_ns: 1100,
        effective_end_ns: endpoint.end_ns,
        signal_cut: true,
        count_admission: None,
    };
    let programmed = session.programmed_admission().unwrap();
    let projection = project_admission(
        Some(programmed),
        None,
        &window,
        &terminal.retained_drain,
        AdmissionMode::Degraded,
    )
    .unwrap();
    let AdmissionProjection::RenderBound(bound) = projection else {
        panic!("missing actual Open projection")
    };
    assert_eq!((bound.start_ns, bound.deadline_ns), (1000, 2000));
    window.count_admission = Some(bound);
    let mut document = evidence::finalize(FinalizeInput {
        window,
        sites: terminal.retained_drain.current.clone(),
        fenced: terminal.retained_drain.fenced.clone(),
        objects: ["original-object", "provider-object"]
            .map(|name| ObjectRecord {
                id: ObjectId(name.into()),
                device: 1,
                inode: 2,
                display_locator: "model".into(),
            })
            .into(),
        coverage: vec![ScopeCoverage {
            scope: "provider/default".into(),
            expected: ExpectedScope::Unknown,
            discovered: 101,
            attached: 101,
        }],
        counters: terminal.retained_drain.counters.clone(),
        fatal: None,
        target: TargetRecord::new(1, "model".into(), String::new(), String::new()),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition {
            non_legacy_exclusive: 1,
            ..Default::default()
        },
        engine_observations: Vec::new(),
        traversal: None,
    });
    let verdict = crate::policy::evaluate_document(
        &[crate::policy::PolicyRule::deny_algorithm("digest")],
        &document,
    );
    assert_eq!(verdict.rules[0].bounds.definite, 1);
    assert_eq!(verdict.rules[0].bounds.possible, None);
    document.policy = Some(crate::check::policy_record(&verdict));
    let bytes = crate::report::render_json(&document).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema_version"], "observed-crypto-v2.3");
    assert_eq!(value["sites"][0]["last_ns"], 1600);
    assert_eq!(value["window"]["effective_end_ns"], 1500);
    assert_eq!(value["window"]["count_admission"]["deadline_ns"], 2000);
    assert!(
        value["policy"]["rules"][0]
            .get("possible")
            .unwrap()
            .is_null()
    );
    crate::schema::validate_v2(&value).unwrap();
    crate::schema::check_v2_semantics(&value).unwrap();
}

#[test]
fn g1_actual_owner_open_recovery_reaches_capture_and_cli_consumer() {
    use crate::capture::{
        self, ClockPort, CustodyResolution, DiscoveryPort, LifecyclePort, PreObservationCount,
        PreObservationFailure, ProcPort, TargetPort,
    };
    use crate::discovery::session::{DiscoveryDelta, DiscoverySnapshot, PollBudget};
    use crate::report::{self, CaptureCommand, OutputDest, OutputFormat, OutputRequest};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    // The prepared owner, mailbox, actual map operation frontiers, checked
    // resource registry, terminal selection and capture/CLI consumers are real.
    // Existing pipe-FD I/O models the kernel; no BPF or live target is used.
    struct OpenPort {
        owner: SessionOwnerPort,
        lose_reply: bool,
        requests: Rc<Cell<usize>>,
        terminals: Rc<Cell<usize>>,
        selected: Rc<RefCell<Option<TerminalRequest>>>,
    }
    impl crate::count_session::CountBackend for OpenPort {
        type Link = LinkToken;
        fn ready(&self) -> &Ready {
            &self.owner.engine.ready
        }
        fn attach(&mut self, r: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
            self.owner.engine.attach(r)
        }
        fn set_generation(&mut self, r: GenerationRequest) -> CommandResult<()> {
            self.owner.engine.set_generation(r)
        }
        fn drain(&mut self, r: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
            self.owner.engine.drain(r)
        }
        fn open_window(&mut self, r: OpenRequest) -> CommandResult<OpenReceipt> {
            if !self.lose_reply {
                return self.owner.engine.open_window(r);
            }
            // Publish a real ordinary Open exactly as the existing lost-reply
            // owner control does, then leave the actual completed reply unread.
            let engine = &self.owner.engine;
            {
                let mut state = locked(&engine.shared.state);
                state.last_command_seq = Some(r.seq);
                state.frontier.pending = Some(PendingCommandId {
                    seq: r.seq,
                    operation: CountOperation::Open,
                });
                state.pending_open = Some(r);
                state.resolved_open = Some(OpenReceipt::pending(engine.ready.owner_epoch, &r));
                assert!(
                    state
                        .ordinary
                        .publish_request(OwnerRequest::Open(r))
                        .is_ok()
                );
            }
            engine.shared.worker.get().unwrap().unpark();
            let cutoff = Instant::now() + Duration::from_secs(3);
            let mut state = locked(&engine.shared.state);
            while state.ordinary.reply.is_none() {
                let remaining = cutoff.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "actual owner did not complete Open");
                state = engine
                    .shared
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap()
                    .0;
            }
            assert_eq!(state.resolved_open.unwrap().outcome, OpenOutcome::Completed);
            assert_eq!(
                state.resolved_open.unwrap().completed_writes,
                OpenWriteFrontier::Target
            );
            drop(state);
            Err(CommandFailure {
                seq: r.seq,
                completion: CommandCompletion::Unknown,
                publication: CommandPublication::Published,
                cleanup_ticket: None,
                failure: OwnerFailure::engine(CountOperation::Open, FailureClass::Disconnected),
            })
        }
        fn terminal_request(
            &mut self,
            deadline: Instant,
            frontier: ControllerFrontier,
        ) -> TerminalRequest {
            self.requests.set(self.requests.get() + 1);
            let r = self.owner.engine.terminal_request(
                deadline,
                self.owner.engine.ready.evidence_domain,
                self.owner.engine.ready.writer_object_identity,
                frontier,
            );
            if let Some(first) = self.selected.borrow().as_ref() {
                assert_eq!(first, &r);
            }
            *self.selected.borrow_mut() = Some(r.clone());
            r
        }
        fn terminal(&mut self, r: TerminalRequest) -> RawTerminal {
            self.terminals.set(self.terminals.get() + 1);
            self.owner.engine.terminal(r)
        }
        fn progress(&self) -> Option<RawCheckpoint> {
            self.owner.engine.progress()
        }
        fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
            self.owner.engine.fork_permit(deadline)
        }
    }
    struct Clock {
        now: Instant,
    }
    impl ClockPort for Clock {
        fn checked_monotonic_ns(&self) -> Option<u64> {
            Some(1300)
        }
        fn monotonic_ns(&self) -> u64 {
            1300
        }
        fn now(&self) -> Instant {
            self.now
        }
        fn wall_now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000)
        }
        fn sleep(&self, _d: Duration) {
            panic!("Open recovery must not enter the observation loop")
        }
    }
    struct Discovery {
        cancelled: bool,
    }
    impl DiscoveryPort for Discovery {
        fn poll(&mut self, _b: PollBudget) -> anyhow::Result<DiscoveryDelta> {
            assert!(self.cancelled, "Open recovery precedes baseline discovery");
            Ok(DiscoveryDelta::default())
        }
        fn snapshot(&self) -> DiscoverySnapshot {
            DiscoverySnapshot::default()
        }
        fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
            Ok(self.snapshot())
        }
    }
    struct Target {
        owned: bool,
        finishes: Rc<Cell<usize>>,
        resolves: Rc<Cell<usize>>,
    }
    impl TargetPort for Target {
        fn pid(&self) -> u32 {
            1
        }
        fn is_owned(&self) -> bool {
            self.owned
        }
        fn release(&mut self) -> anyhow::Result<()> {
            panic!("cancelled or external target cannot be released")
        }
        fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
            assert!(self.owned, "external target cannot be waited on");
            Ok((self.resolves.get() > 0).then_some(137))
        }
        fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
            assert!(self.owned, "external target has no owned custody");
            self.resolves.set(self.resolves.get() + 1);
            Ok(())
        }
        fn finish_observation(&mut self) -> anyhow::Result<crate::target::TargetDisposition> {
            self.finishes.set(self.finishes.get() + 1);
            Ok(crate::target::TargetDisposition::Detached { pid: 1 })
        }
        fn verify(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }
    struct Lifecycle;
    impl LifecyclePort for Lifecycle {
        fn poll(&mut self) -> capture::LifecycleDelta {
            capture::LifecycleDelta::default()
        }
        fn fallback_partial(&self) -> bool {
            false
        }
    }
    struct Proc {
        cancelled: bool,
    }
    impl ProcPort for Proc {
        fn read_maps(&mut self, _p: u32) -> anyhow::Result<Vec<crate::discovery::maps::Mapping>> {
            assert!(self.cancelled, "Open recovery precedes proc polling");
            Ok(Vec::new())
        }
        fn read_file(&mut self, _p: &str) -> anyhow::Result<Vec<u8>> {
            panic!("unexpected file read")
        }
        fn read_file_bound(&mut self, _p: &str, _n: usize) -> io::Result<(Arc<[u8]>, (u64, u64))> {
            panic!("unexpected file read")
        }
        fn stat_file(&mut self, _p: &str) -> Option<capture::FileStat> {
            None
        }
        fn read_exe(&mut self, _p: u32) -> Option<std::path::PathBuf> {
            None
        }
        fn file_len(&mut self, _p: &str) -> Option<u64> {
            None
        }
        fn read_comm(&mut self, _p: u32) -> Option<String> {
            None
        }
    }
    // Partial Open, completed Open with a lost reply, and cancellation
    // followed by actual owner stop EIO, stop panic, or an expired budget.
    for mode in 0..5 {
        for check in [false, true] {
            for failure in 0..3 {
                let lost = mode == 1;
                let cancelled = mode >= 2;
                let probe = MapProbe::new();
                let seal_clock = Arc::new(Mutex::new(std::collections::VecDeque::from([
                    Some(1450),
                    Some(1460),
                ])));
                let owner = session_owner_port(
                    &probe,
                    None,
                    TerminalFaults {
                        map: MapFaults {
                            write_error: match mode {
                                0 => Some(3),
                                2 => Some(5),
                                _ => None,
                            },
                            panic_call: (mode == 3).then_some(5),
                            ..Default::default()
                        },
                        seal_clock: Some(seal_clock),
                        ..Default::default()
                    },
                );
                let epoch = owner.engine.ready.owner_epoch;
                let requests = Rc::new(Cell::new(0));
                let terminals = Rc::new(Cell::new(0));
                let selected = Rc::new(RefCell::new(None));
                let finishes = Rc::new(Cell::new(0));
                let resolves = Rc::new(Cell::new(0));
                let count = crate::count_session::CountSession::new(
                    1,
                    OpenPort {
                        owner,
                        lose_reply: lost,
                        requests: requests.clone(),
                        terminals: terminals.clone(),
                        selected: selected.clone(),
                    },
                );
                let clock = Clock {
                    now: Instant::now(),
                };
                let cfg = capture::Config {
                    harvest_object: None,
                    count_object: None,
                    members_object: None,
                    provider: None,
                    builtin: false,
                    table: None,
                    force_offset: None,
                    provider_enrollment: None,
                    resolved_provider: None,
                    duration: Duration::from_nanos(1000),
                    settle: Duration::ZERO,
                    harvest_timeout: Duration::from_secs(5),
                    grace: if mode == 4 {
                        Duration::ZERO
                    } else {
                        Duration::from_secs(1)
                    },
                    image_digest: String::new(),
                };
                let info = capture::TargetInfo {
                    pid: 1,
                    owned: cancelled,
                    comm: "owner-host-model".into(),
                    cmdline: String::new(),
                    container_id: String::new(),
                    kernel_release: "host-model".into(),
                    provider_build_id: String::new(),
                    provider_path: String::new(),
                    image_digest: String::new(),
                    acquired_ns: 1000,
                    acquired_instant: clock.now,
                    acquired_wall: clock.wall_now(),
                };
                let result = capture::observe(
                    &cfg,
                    &info,
                    capture::SessionSet {
                        discovery: Discovery { cancelled },
                        count,
                        target: Target {
                            owned: cancelled,
                            finishes: finishes.clone(),
                            resolves: resolves.clone(),
                        },
                        lifecycle: Lifecycle,
                    },
                    &clock,
                    &mut Proc { cancelled },
                    &|| cancelled,
                );
                let terminal = if lost {
                    let c = result.as_ref().unwrap();
                    assert_eq!(c.programmed_admission.unwrap().start_ns(), 1300);
                    assert_eq!(c.document.window.requested_start_ns, 1000);
                    assert_eq!(c.document.window.requested_end_ns, 2000);
                    assert_eq!(c.document.window.effective_start_ns, 1300);
                    assert_eq!(c.document.window.effective_end_ns, 1450);
                    let PreObservationCount::Terminal(t) =
                        &c.failure_context.as_ref().unwrap().count
                    else {
                        panic!("lost actual terminal")
                    };
                    t.clone()
                } else {
                    let f = result
                        .as_ref()
                        .err()
                        .unwrap()
                        .downcast_ref::<PreObservationFailure>()
                        .unwrap();
                    if cancelled {
                        assert_eq!(f.cause, capture::PreObservationCause::Cancelled);
                        assert!(f.failure.is_none());
                        assert_eq!(f.custody.child_exit, Some(137));
                    } else {
                        assert_eq!(f.failure.as_ref().unwrap().errno, Some(libc::EIO));
                    }
                    let PreObservationCount::Terminal(t) = &f.count else {
                        panic!("lost actual terminal")
                    };
                    t.clone()
                };
                let open = terminal.receipt.resolved_open.unwrap();
                assert_eq!(open.owner_epoch, epoch);
                assert_eq!(
                    open.outcome,
                    if mode != 0 {
                        OpenOutcome::Completed
                    } else {
                        OpenOutcome::Failed
                    }
                );
                assert_eq!(
                    open.completed_writes,
                    if mode != 0 {
                        OpenWriteFrontier::Target
                    } else {
                        OpenWriteFrontier::WindowDeadline
                    }
                );
                if mode == 2 || mode == 3 {
                    let f = terminal.runtime_failure.unwrap();
                    assert_eq!(
                        f.class,
                        if mode == 2 {
                            FailureClass::Io
                        } else {
                            FailureClass::Panic
                        }
                    );
                    if mode == 2 {
                        assert_eq!(f.errno, Some(libc::EIO));
                    }
                }
                assert_eq!(
                    terminal.receipt.terminal_id,
                    selected.borrow().as_ref().unwrap().id
                );
                assert_eq!(
                    terminal.receipt.deadline,
                    selected.borrow().as_ref().unwrap().deadline
                );
                assert_eq!(
                    terminal.receipt.cleanup_ticket.terminal_id,
                    terminal.receipt.terminal_id
                );
                let result = match result {
                    Ok(c) => Err(anyhow::Error::new(capture::CaptureRuntimeFailure {
                        terminal: Some(terminal.clone()),
                        capture: Arc::new(c),
                        kind: capture::RuntimeBoundaryKind::SetupAfterOpen,
                    })
                    .context("inner actual owner")
                    .context("outer actual owner")),
                    Err(e) => Err(e
                        .context("inner actual owner")
                        .context("outer actual owner")),
                };
                let dir = std::env::temp_dir()
                    .join("osslscope-g1-production-consumer")
                    .join(format!(
                        "actual-owner-{}-{mode}-{check}-{failure}",
                        std::process::id()
                    ));
                std::fs::create_dir_all(&dir).unwrap();
                let request = OutputRequest {
                    format: OutputFormat::Json,
                    primary: OutputDest::File(dir.join(if failure == 1 {
                        "missing/primary.json"
                    } else {
                        "primary.json"
                    })),
                    cbom: Some(OutputDest::File(dir.join(if failure == 2 {
                        "missing/cbom.json"
                    } else {
                        "cbom.json"
                    }))),
                };
                let rules = [crate::policy::PolicyRule::deny_provider("default")];
                let consumed = report::consume_capture_result_with_diagnostics(
                    result,
                    if check {
                        CaptureCommand::Check { rules: &rules }
                    } else {
                        CaptureCommand::Report
                    },
                    &request,
                    false,
                    &mut Vec::new(),
                );
                assert_eq!(
                    consumed.exit_code,
                    if lost || (mode == 4 && failure != 0) {
                        1
                    } else if mode == 4 {
                        if check { 11 } else { 3 }
                    } else {
                        4
                    }
                );
                assert_eq!(consumed.delivery.primary.ok, failure != 1);
                assert_eq!(consumed.delivery.cbom.as_ref().unwrap().ok, failure != 2);
                assert_eq!(consumed.child_exit, cancelled.then_some(137));
                assert_eq!(
                    consumed.disposition,
                    Some(if cancelled {
                        crate::target::TargetDisposition::Exited { code: 137 }
                    } else {
                        crate::target::TargetDisposition::Detached { pid: 1 }
                    })
                );
                let context = consumed.failure_context.as_ref().unwrap();
                assert_eq!(
                    context.custody.resolution,
                    if cancelled {
                        CustodyResolution::Resolved
                    } else {
                        CustodyResolution::NotOwned
                    }
                );
                let PreObservationCount::Terminal(retained) = &context.count else {
                    panic!("consumer dropped actual terminal")
                };
                assert!(Arc::ptr_eq(retained, &terminal));
                if check {
                    let policy = consumed.document.policy.as_ref().unwrap();
                    assert_eq!(
                        policy.verdict,
                        if lost || mode == 4 {
                            crate::evidence::PolicyVerdict::Inconclusive
                        } else {
                            crate::evidence::PolicyVerdict::NoVerdict
                        }
                    );
                    if lost || mode == 4 {
                        assert_eq!(policy.rules.len(), 1);
                        assert_eq!(policy.rules[0].possible, None);
                    }
                }
                if cancelled {
                    assert_eq!(consumed.document.window.requested_start_ns, 0);
                    assert_eq!(consumed.document.window.requested_end_ns, 0);
                    assert_eq!(consumed.document.window.effective_start_ns, 0);
                    assert_eq!(consumed.document.window.effective_end_ns, 0);
                    assert!(consumed.document.sites.is_empty());
                    assert!(consumed.document.fenced.is_empty());
                    assert!(consumed.document.window.count_admission.is_none());
                }
                let value: serde_json::Value =
                    serde_json::from_slice(&report::render_json(&consumed.document).unwrap())
                        .unwrap();
                crate::schema::validate_v2(&value).unwrap();
                crate::schema::check_v2_semantics(&value).unwrap();
                if failure != 1 {
                    let actual: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(dir.join("primary.json")).unwrap())
                            .unwrap();
                    assert_eq!(value, actual);
                }
                if failure != 2 {
                    let cbom: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(dir.join("cbom.json")).unwrap())
                            .unwrap();
                    assert_eq!(cbom["bomFormat"], "CycloneDX");
                }
                std::fs::write(
                    dir.join("human.txt"),
                    report::render_human(&consumed.document),
                )
                .unwrap();
                assert_eq!(
                    requests.get(),
                    1,
                    "one selected terminal request must not be resubmitted by capture"
                );
                assert_eq!(terminals.get(), 1);
                assert_eq!(finishes.get(), usize::from(lost));
                assert_eq!(resolves.get(), usize::from(cancelled));
                probe.cleanup();
            }
        }
    }
}

#[test]
fn w079_setup_barrier_all_exits() {
    // Borrowed ordinary prefix users retain their old contract.
    let borrowed = CountForkBarrier::new();
    drop(borrowed.prefix_permit(Instant::now()).unwrap());
    assert!(borrowed.prefix_permit(Instant::now()).is_ok());
    for outcome in ["provider", "lifecycle", "cancel", "panic", "disconnect"] {
        let barrier = Arc::new(CountForkBarrier::new());
        let lease = Arc::new(barrier.reserve_setup().unwrap());
        let worker = Arc::clone(&lease);
        let held_permit = lease
            .prefix_permit(Instant::now() + Duration::from_secs(2))
            .unwrap();
        let worker_result = std::panic::catch_unwind(|| -> Result<(), &'static str> {
            let _phase = worker.prefix_phase();
            let permit = worker
                .prefix_permit(Instant::now() + Duration::from_secs(2))
                .unwrap();
            drop(permit);
            match outcome {
                "panic" => panic!("controlled setup worker panic"),
                "disconnect" => {
                    let (tx, rx) = std::sync::mpsc::channel::<()>();
                    drop(rx);
                    tx.send(()).map_err(|_| "disconnected")
                }
                "cancel" => {
                    let cancelled = AtomicBool::new(true);
                    if cancelled.load(Ordering::SeqCst) {
                        Err("cancelled")
                    } else {
                        Ok(())
                    }
                }
                "provider" => Err("provider failure"),
                "lifecycle" => Err("lifecycle failure"),
                _ => unreachable!(),
            }
        });
        assert_eq!(worker_result.is_err(), outcome == "panic");
        assert!(barrier.prefix_permit(Instant::now()).is_err(), "{outcome}");
        assert!(worker.prefix_permit(Instant::now()).is_err(), "{outcome}");
        assert!(
            lease.reserve_count().is_err(),
            "in-flight fork still owns permit"
        );
        assert!(
            barrier
                .admit(OwnerEpoch::checked(800).unwrap(), Instant::now())
                .is_err()
        );
        lease.abort(); // Independent controller abandonment is idempotent.
        drop(held_permit);
        assert!(lease.reserve_count().is_err());
        // Worker/cleanup disposal are still held: dropping a scoped permit
        // must not reopen admission, and dropping the last lease fails closed.
        drop(worker);
        drop(lease);
        assert_eq!(
            barrier.prefix_permit(Instant::now()).err(),
            Some(ForkBlocked::Unresolved)
        );
        assert!(
            barrier
                .admit(OwnerEpoch::checked(801).unwrap(), Instant::now())
                .is_err()
        );
    }
}

#[test]
fn w079_count_reservation_gap() {
    let barrier = Arc::new(CountForkBarrier::new());
    let lease = barrier.reserve_setup().unwrap();
    let permit = lease
        .prefix_permit(Instant::now() + Duration::from_secs(2))
        .unwrap();
    lease.close_prefix();
    assert!(lease.reserve_count().is_err());
    drop(permit);
    let token = lease.reserve_count().unwrap();
    assert!(
        lease.reserve_count().is_err(),
        "only one Count reservation may exist"
    );
    let epoch = OwnerEpoch::checked(987).unwrap();
    assert!(
        barrier
            .admit(epoch, Instant::now() + Duration::from_secs(1))
            .is_err(),
        "ordinary Count admission stole held setup preflight"
    );
    assert!(barrier.prefix_permit(Instant::now()).is_err());
    assert!(lease.prefix_permit(Instant::now()).is_err());
    assert!(barrier.terminal_permit(epoch, Instant::now()).is_err());
    barrier.admit_setup(token, epoch).unwrap();
    assert!(barrier.admit(epoch, Instant::now()).is_err());
    assert!(
        barrier.terminal_permit(epoch, Instant::now()).is_err(),
        "admission is not an actual Count cleanup receipt"
    );
    barrier.spawn_failed(epoch);
    assert!(
        barrier.prefix_permit(Instant::now()).is_err(),
        "spawn failure reopened prefix"
    );
    assert!(
        barrier.terminal_permit(epoch, Instant::now()).is_err(),
        "spawn failure invented cleanup"
    );
    drop(lease);

    for drop_token in [true, false] {
        let barrier = Arc::new(CountForkBarrier::new());
        let lease = barrier.reserve_setup().unwrap();
        drop(
            lease
                .prefix_permit(Instant::now() + Duration::from_secs(2))
                .unwrap(),
        );
        lease.close_prefix();
        let token = lease.reserve_count().unwrap();
        if drop_token {
            drop(token); // Fallible preflight unwinds before admission.
        } else {
            lease.abort(); // A late worker cannot admit after controller cancel.
            assert!(barrier.admit_setup(token, epoch).is_err());
        }
        assert!(lease.reserve_count().is_err());
        lease.complete_abort().unwrap();
        assert!(
            barrier.reserve_setup().is_err(),
            "completed abort reused barrier"
        );
        assert!(barrier.admit(epoch, Instant::now()).is_err());
        assert!(barrier.prefix_permit(Instant::now()).is_err());
    }
    // Admission checks the original deadline after preflight and wrong barriers
    // cannot consume a reservation belonging to this barrier.
    let barrier = Arc::new(CountForkBarrier::new());
    let lease = barrier.reserve_setup().unwrap();
    let first_deadline = Instant::now() + Duration::from_secs(60);
    drop(lease.prefix_permit(first_deadline).unwrap());
    // A later lifecycle scope cannot replace the original spawn deadline.
    drop(
        lease
            .prefix_permit(Instant::now() + Duration::from_secs(120))
            .unwrap(),
    );
    assert_eq!(
        locked(&barrier.state).setup.as_ref().unwrap().deadline,
        Some(first_deadline)
    );
    lease.close_prefix();
    let token = lease.reserve_count().unwrap();
    // Expire only after preflight reservation: scheduling cannot prevent the
    // test from reaching the intended late-admission branch.
    locked(&barrier.state).setup.as_mut().unwrap().deadline =
        Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert_eq!(
        barrier.admit_setup(token, epoch).unwrap_err().class,
        FailureClass::Deadline
    );
    lease.complete_abort().unwrap();

    let barrier = Arc::new(CountForkBarrier::new());
    let lease = barrier.reserve_setup().unwrap();
    drop(
        lease
            .prefix_permit(Instant::now() + Duration::from_secs(1))
            .unwrap(),
    );
    lease.close_prefix();
    let token = lease.reserve_count().unwrap();
    assert!(CountForkBarrier::new().admit_setup(token, epoch).is_err());
    lease.complete_abort().unwrap();
}

#[test]
fn w079_count_prepare_holds_cpu_return_cannot_start_late_owner() {
    fn held_cpu() -> io::Result<usize> {
        std::thread::sleep(Duration::from_millis(40));
        Ok(2)
    }
    let spawned = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&spawned);
    let mut hooks = PrepareHooks::live();
    hooks.possible_cpu_count = held_cpu;
    let failure = CountEngine::prepare_with(
        input(Arc::new(CountForkBarrier::new())),
        CountOwnerLimits::from_allowance(18, 2).unwrap(),
        Instant::now() + Duration::from_millis(20),
        hooks,
        || -> PipeDriver { panic!("expired preflight cannot create a driver") },
        move |_task| {
            observed.store(true, Ordering::Release);
            Err(io::Error::from_raw_os_error(libc::EAGAIN))
        },
    )
    .err()
    .unwrap();
    assert_eq!(failure.failure.class, FailureClass::Deadline);
    assert!(!spawned.load(Ordering::Acquire));
    assert_eq!(failure.cleanup_ticket, None);
}

fn w079_progress(watch: &CountSetupWatch) -> CountSetupProgress {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(progress) = watch.progress() {
            return progress;
        }
        assert!(Instant::now() < until, "owner publication remained busy");
        std::thread::yield_now();
    }
}
fn w079_owner_disposed(watch: &CountSetupWatch) {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if watch
            .progress()
            .is_some_and(|p| p.owner_cleanup_acknowledged && p.owner_task_disposed)
        {
            return;
        }
        assert!(Instant::now() < until, "actual owner task did not dispose");
        std::thread::yield_now();
    }
}
// Exact held-fixture cleanup; poison recovery cannot skip releasing this gate.
fn w079_release_held(probe: &Probe) {
    *locked(&probe.released) = true;
    probe.release.notify_all();
}
// Called only after the exact preparation/session caller has been joined.
// No published epoch means that joined caller cannot later start an owner.
fn w079_dispose_joined_owner(watch: &CountSetupWatch) {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if watch
            .progress()
            .is_some_and(|p| p.owner_epoch.is_none() || p.owner_task_disposed)
        {
            return;
        }
        assert!(
            Instant::now() < until,
            "released Count owner task did not dispose"
        );
        std::thread::yield_now();
    }
}
fn w079_snapshot(watch: &CountSetupWatch) -> crate::capture::CountSetupSnapshot {
    crate::capture::CountSetupSnapshot::from_progress(w079_progress(watch))
        .expect("invoked pending state")
}

fn w079_reservation(
    deadline: Instant,
) -> (
    Arc<CountForkBarrier>,
    Arc<SetupBarrierLease>,
    CountSetupAdmission,
) {
    let barrier = Arc::new(CountForkBarrier::new());
    let lease = Arc::new(barrier.reserve_setup().unwrap());
    drop(lease.prefix_permit(deadline).unwrap());
    lease.close_prefix();
    let admission = lease.reserve_count().unwrap();
    (barrier, lease, admission)
}

#[test]
fn w079_count_prepare_holds_independent_abandon_returns_with_actual_ticket() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (barrier, lease, admission) = w079_reservation(deadline);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    assert_eq!(w079_progress(&watch).phase, CountSetupPhase::NotInvoked);
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let probe = Probe::new();
    let owner_probe = Arc::clone(&probe);
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let caller = std::thread::spawn(move || {
        let result = CountEngine::prepare_controlled_with(
            input(barrier),
            CountOwnerLimits::from_allowance(18, 2).unwrap(),
            deadline,
            PrepareHooks::host(),
            move || {
                owner_probe.event(Event::Started);
                PipeDriver {
                    probe: owner_probe,
                    faults: Faults {
                        hold_acquire: Some(1),
                        ..Default::default()
                    },
                    deadline,
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                }
            },
            spawn_owner,
            SetupPreparation {
                admission: Some(admission),
                control,
                journal,
            },
        );
        sent.send(result.err().unwrap()).unwrap();
    });
    let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        probe.wait(|events| {
            events
                .iter()
                .any(|(_, e)| matches!(e, Event::EnterAcquire(1)))
        });
        let before = w079_progress(&watch);
        watch.abandon();
        let result = received.recv_timeout(Duration::from_millis(100));
        let pending_output = w079_report_count(crate::capture::PreObservationCount::SetupPending(
            w079_snapshot(&watch),
        ));
        (before, result, pending_output)
    }));
    let abandoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.abandon()));
    w079_release_held(&probe);
    let joined = caller.join();
    w079_dispose_joined_owner(&watch);
    let (before, result, pending_output) =
        observations.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    abandoned.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    joined.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    assert_eq!(before.phase, CountSetupPhase::OwnerStarted);
    assert!(before.owner_epoch.is_some());
    let failure = result.expect(
        "independent abort must bound actual Prepare wait, with original deadline far away",
    );
    assert_eq!(failure.failure.class, FailureClass::Cancelled);
    assert!(
        pending_output
            .diagnostics
            .iter()
            .any(|s| s.contains("phase=owner-started")
                && s.contains("cleanup=pending unresolved-slots=unknown"))
    );
    let ticket = failure.cleanup_ticket.expect("actual owner was admitted");
    assert_eq!(ticket.owner_epoch, before.owner_epoch.unwrap());
    assert_eq!(watch.seal(deadline + Duration::from_secs(10)), Some(ticket));
    probe.assert_cleanup(1, std::thread::current().id());
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if watch
            .progress()
            .and_then(|p| p.cleanup)
            .is_some_and(|p| p.status == CleanupStatus::Complete)
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "actual owner never acknowledged disposal"
        );
        std::thread::yield_now();
    }
    w079_owner_disposed(&watch);
    drop(watch);
    drop(lease);
}

#[test]
fn w079_count_prepare_holds_preflight_stages_abort_before_next_effect() {
    for held in [
        CountPrepareStage::FdInventory,
        CountPrepareStage::OuterCpu,
        CountPrepareStage::OwnerCpu,
        CountPrepareStage::Hash,
        CountPrepareStage::Parse,
        CountPrepareStage::Allocation,
    ] {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (barrier, lease, admission) = w079_reservation(deadline);
        let journal = CountSetupJournal::new();
        let watch = journal.watch();
        let cancelled = Arc::new(AtomicBool::new(false));
        let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
            deadline,
            crate::capture_setup::SetupInterrupt::Owned(cancelled.clone()),
        ));
        let gate = Probe::new();
        let observed = gate.clone();
        let stage: Arc<dyn Fn(CountPrepareStage) + Send + Sync> = Arc::new(move |actual| {
            if actual == held {
                observed.event(Event::Started);
                observed.hold();
            }
        });
        let fd_stage = stage.clone();
        let cpu_stage = stage.clone();
        let caller = std::thread::spawn(move || {
            let mut hooks = if held == CountPrepareStage::OwnerCpu {
                PrepareHooks::live()
            } else {
                PrepareHooks::host()
            };
            hooks.possible_cpu_count = || Ok(2);
            hooks.stage_observer = Some(stage);
            crate::capture::prepare_count_backend_controlled_with(
                input(barrier),
                deadline,
                admission,
                &control,
                &journal,
                (
                    move || {
                        fd_stage(CountPrepareStage::FdInventory);
                        Ok(crate::capture::CountFdAdmission {
                            soft_limit: 2070,
                            non_count_open: 0,
                            non_count_reserved: 0,
                        })
                    },
                    move || {
                        cpu_stage(CountPrepareStage::OuterCpu);
                        Ok(2)
                    },
                ),
                move |input, limits, deadline, admission, control, journal| {
                    CountEngine::prepare_controlled_with(
                        input,
                        limits,
                        deadline,
                        hooks,
                        || -> PipeDriver {
                            panic!("cancelled preflight must never construct owner driver")
                        },
                        |_task| panic!("cancelled preflight must never spawn owner"),
                        SetupPreparation {
                            admission: Some(admission),
                            control: control.clone(),
                            journal: journal.clone(),
                        },
                    )
                },
            )
            .err()
            .unwrap()
        });
        let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.wait(|events| events.iter().any(|(_, e)| matches!(e, Event::Started)));
            let pending = w079_progress(&watch);
            let started = Instant::now();
            watch.abandon();
            let seal = watch.seal(deadline);
            let snapshot = w079_snapshot(&watch);
            (
                pending,
                seal,
                snapshot,
                started.elapsed() < Duration::from_millis(100),
            )
        }));
        cancelled.store(true, Ordering::Release);
        let abandoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.abandon()));
        w079_release_held(&gate);
        let joined = caller.join();
        w079_dispose_joined_owner(&watch);
        let (pending, seal, snapshot, bounded) =
            observations.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
        abandoned.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
        let failure = joined.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
        assert_eq!(pending.phase, CountSetupPhase::Preflight, "{held:?}");
        assert_eq!(pending.owner_epoch, None);
        assert_eq!(pending.cleanup_ticket, None);
        assert_eq!(seal, None);
        assert!(bounded, "watch must not wait on held preflight {held:?}");
        assert_eq!(snapshot.phase(), crate::capture::CountSetupPhase::Preflight);
        assert_eq!(failure.failure.class, FailureClass::Cancelled, "{held:?}");
        assert_eq!(failure.cleanup_ticket, None);
        let complete = w079_progress(&watch);
        assert_eq!(complete.phase, CountSetupPhase::Failed);
        assert_eq!(complete.owner_epoch, None);
        assert_eq!(complete.known_failure, Some(failure.failure));
        lease.abort();
        lease.complete_abort().unwrap();
    }
}

fn w079_report_count(
    count: crate::capture::PreObservationCount,
) -> crate::report::CaptureCommandResult {
    use crate::capture::{
        CustodyReceipt, CustodyResolution, PreObservationCause, PreObservationFailure,
    };
    static OUTPUT: AtomicU64 = AtomicU64::new(0);
    let path = std::path::PathBuf::from(
        std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").expect("leased fixture dir"),
    )
    .join(format!(
        "w079-count-report-{}-{}.json",
        std::process::id(),
        OUTPUT.fetch_add(1, Ordering::Relaxed)
    ));
    let expected_exit = if count.actual_failure().is_some() {
        4
    } else {
        3
    };
    let failure = PreObservationFailure {
        cause: PreObservationCause::Cancelled,
        failure: None,
        count,
        release: None,
        custody: CustodyReceipt {
            disposition: Some(crate::target::TargetDisposition::Exited { code: 0 }),
            child_exit: Some(0),
            resolution: CustodyResolution::Resolved,
            failure: None,
        },
        target: crate::evidence::TargetRecord::new(
            1,
            "count-host-control".into(),
            String::new(),
            String::new(),
        ),
        context: None,
    };
    let mut diagnostics = Vec::new();
    let result = crate::report::consume_capture_result_with_diagnostics(
        Err(anyhow::Error::new(failure)),
        crate::report::CaptureCommand::Report,
        &crate::report::OutputRequest {
            format: crate::report::OutputFormat::Json,
            primary: crate::report::OutputDest::File(path.clone()),
            cbom: None,
        },
        false,
        &mut diagnostics,
    );
    let emitted = std::fs::read(&path).unwrap();
    assert!(!emitted.is_empty());
    std::fs::remove_file(&path).unwrap();
    assert_eq!(result.child_exit, Some(0));
    assert_eq!(result.document.total_calls(), 0);
    assert!(result.document.coverage.is_empty());
    assert!(result.document.window.count_admission.is_none());
    assert!(result.document.window.signal_cut);
    assert_eq!(result.exit_code, expected_exit);
    result
}

#[test]
fn w079_pending_count_output_actual_preflight_unknown_and_not_invoked() {
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    assert!(crate::capture::CountSetupSnapshot::from_watch(&watch).is_none());
    let absent = w079_report_count(crate::capture::PreObservationCount::NotPrepared);
    assert!(
        absent
            .diagnostics
            .iter()
            .any(|s| s.contains("cleanup=not-acquired unresolved-slots=0"))
    );
    journal.begin();
    let pending = w079_snapshot(&watch);
    let output = w079_report_count(crate::capture::PreObservationCount::SetupPending(pending));
    assert!(output.diagnostics.iter().any(|s| s.contains(
        "phase=preflight epoch=unknown ticket=unknown cleanup=unknown unresolved-slots=unknown"
    )));
    assert!(output.diagnostics.iter().any(|s| {
        s.contains("known-rows=unknown known-calls=unknown enumeration=unknown tail=unknown")
    }));
    assert!(
        !output.diagnostics.iter().any(|s| s.contains("not-acquired")
            || s.contains("unresolved-slots=0")
            || s.contains("count terminal="))
    );
}

#[test]
fn w079_count_late_receipts_owner_published_abort_before_start() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (barrier, lease, admission) = w079_reservation(deadline);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let gate = Probe::new();
    let held = gate.clone();
    let probe = Probe::new();
    let owner = probe.clone();
    let caller = std::thread::spawn(move || {
        CountEngine::prepare_controlled_with(
            input(barrier),
            CountOwnerLimits::from_allowance(18, 2).unwrap(),
            deadline,
            PrepareHooks::host(),
            move || {
                owner.event(Event::Started);
                PipeDriver {
                    probe: owner,
                    faults: Faults::default(),
                    deadline,
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                }
            },
            move |task| {
                held.event(Event::Started);
                held.hold();
                spawn_owner(task)
            },
            SetupPreparation {
                admission: Some(admission),
                control,
                journal,
            },
        )
        .err()
        .unwrap()
    });
    let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gate.wait(|events| !events.is_empty());
        let before = w079_progress(&watch);
        let ticket = watch.seal(deadline);
        watch.abandon();
        let output = w079_report_count(crate::capture::PreObservationCount::SetupPending(
            w079_snapshot(&watch),
        ));
        (before, ticket, output)
    }));
    let abandoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.abandon()));
    w079_release_held(&gate);
    let joined = caller.join();
    w079_dispose_joined_owner(&watch);
    let (before, ticket, output) =
        observations.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    abandoned.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    let failure = joined.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    let ticket = ticket.expect("actual owner admission established a seal ticket");
    let until = Instant::now() + Duration::from_secs(3);
    while !watch
        .progress()
        .and_then(|p| p.cleanup)
        .is_some_and(|p| p.status == CleanupStatus::Complete)
    {
        assert!(Instant::now() < until);
        std::thread::yield_now();
    }
    w079_owner_disposed(&watch);
    assert_eq!(before.phase, CountSetupPhase::OwnerPublished);
    assert_eq!(ticket.owner_epoch, before.owner_epoch.unwrap());
    assert_eq!(failure.cleanup_ticket, Some(ticket));
    assert_eq!(failure.failure.class, FailureClass::Cancelled);
    assert!(
        output
            .diagnostics
            .iter()
            .any(|s| s.contains("phase=owner-published")
                && s.contains("cleanup=pending unresolved-slots=unknown"))
    );
    assert!(
        !probe
            .log
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::EnterAcquire(_)))
    );
    drop(lease);
}

#[test]
fn w079_count_late_receipts_ready_session_canonical_terminal_once() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (_barrier, lease, admission) = w079_reservation(deadline);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let probe = MapProbe::new();
    let (engine, _) = terminal_engine_preparation(
        &probe,
        None,
        TerminalFaults::default(),
        Some(SetupPreparation {
            admission: Some(admission),
            control,
            journal,
        }),
    );
    let epoch = engine.ready.owner_epoch;
    assert_eq!(engine.shared.setup_deadline, deadline);
    assert_eq!(w079_progress(&watch).phase, CountSetupPhase::Ready);
    // The independent observer never owns a frontend or chooses its frontier.
    let port = SessionOwnerPort {
        engine,
        wait_inventory: false,
        requests: Vec::new(),
        terminal_calls: 0,
        generation_refusal: None,
        open_refusal: None,
        refuse_published: Arc::new(AtomicBool::new(false)),
        last_failure: None,
        replay: None,
        late_release: None,
        progress_cutoff: None,
    };
    let mut session = crate::count_session::CountSession::new(1, port);
    let cutoff = Instant::now() + Duration::from_secs(1);
    let ticket = watch.seal(cutoff).unwrap();
    watch.abandon();
    let snapshot = w079_snapshot(&watch);
    let pending = w079_report_count(crate::capture::PreObservationCount::SetupPending(snapshot));
    let close = crate::count_session::CloseRequest {
        started_at: cutoff,
        grace: Duration::from_secs(10),
        reason: crate::count_session::CloseReason::SetupAbort,
    };
    let terminal = session.terminal_shared(close);
    let again = session.terminal_shared(close);
    task3_cleanup(&probe.owner, 8);
    w079_owner_disposed(&watch);
    assert!(Arc::ptr_eq(&terminal, &again));
    assert_eq!(session.backend().terminal_calls, 1);
    assert_eq!(terminal.receipt.cleanup_ticket, ticket);
    assert_eq!(terminal.receipt.owner_epoch, epoch);
    assert_eq!(terminal.receipt.deadline, cutoff);
    assert!(
        pending
            .diagnostics
            .iter()
            .any(|s| s.contains("phase=late-ready") && s.contains("unresolved-slots=unknown"))
    );
    let output = w079_report_count(crate::capture::PreObservationCount::Terminal(terminal));
    assert!(
        output
            .diagnostics
            .iter()
            .any(|s| s.contains("count terminal="))
    );
    drop(session);
    drop(lease);
}

#[test]
fn w079_pending_count_output_actual_open_pending_and_late_session_cleanup() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (_barrier, lease, admission) = w079_reservation(deadline);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let probe = MapProbe::new();
    let mut caller = None;
    // Own cleanup before constructing the owner with its armed map-I/O gate;
    // preparation, attach, caller creation and report errors share this scope.
    let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (engine, _) = terminal_engine_preparation(
            &probe,
            None,
            TerminalFaults {
                map: MapFaults {
                    hold_call: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(SetupPreparation {
                admission: Some(admission),
                control,
                journal,
            }),
        );
        let port = SessionOwnerPort {
            engine,
            wait_inventory: false,
            requests: Vec::new(),
            terminal_calls: 0,
            generation_refusal: None,
            open_refusal: None,
            refuse_published: Arc::new(AtomicBool::new(false)),
            last_failure: None,
            replay: None,
            late_release: None,
            progress_cutoff: None,
        };
        let mut session = crate::count_session::CountSession::new(1, port);
        SessionPlan::new(1).attach(&mut session, 7);
        caller = Some(std::thread::spawn(move || {
            let result = session.open_window(1000, 2000, deadline);
            (session, result)
        }));
        probe.wait_calls(1);
        let ticket = watch.seal(Instant::now());
        watch.abandon();
        let before = w079_progress(&watch);
        let snapshot = w079_snapshot(&watch);
        // Supplied custody fixture is independent of this actual held map I/O.
        let output = w079_report_count(crate::capture::PreObservationCount::SetupPending(snapshot));
        let (mut session, opened) = caller
            .take()
            .expect("exact Open caller")
            .join()
            .unwrap_or_else(|failure| std::panic::resume_unwind(failure));
        let terminal = session.terminal_shared(crate::count_session::CloseRequest {
            started_at: Instant::now(),
            grace: Duration::from_secs(3),
            reason: crate::count_session::CloseReason::SetupAbort,
        });
        let again = session.terminal_shared(session_close());
        let fallback_progress = w079_progress(&watch);
        (
            ticket,
            before,
            output,
            session,
            opened,
            terminal,
            again,
            fallback_progress,
        )
    }));
    let abandoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.abandon()));
    w079_release_held(&probe.owner);
    // A pre-join observation failure must not detach this exact caller. A join
    // failure is retained until the independently reachable owner has disposed.
    let join_failure = caller.take().and_then(|caller| caller.join().err());
    w079_dispose_joined_owner(&watch);
    let (ticket, before, output, session, opened, terminal, again, fallback_progress) =
        observations.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    abandoned.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    if let Some(failure) = join_failure {
        std::panic::resume_unwind(failure);
    }
    let ticket = ticket.expect("actual Open owner established a seal ticket");
    task3_cleanup(&probe.owner, 10);
    w079_owner_disposed(&watch);
    assert!(!fallback_progress.owner_cleanup_acknowledged);
    assert_eq!(
        fallback_progress.cleanup.unwrap().status,
        CleanupStatus::Pending
    );
    assert!(before.open_pending);
    assert_eq!(before.cleanup.unwrap().status, CleanupStatus::Pending);
    assert!(opened.is_err());
    assert!(Arc::ptr_eq(&terminal, &again));
    assert_eq!(terminal.receipt.cleanup_ticket, ticket);
    assert_eq!(session.backend().terminal_calls, 1);
    assert!(
        output
            .diagnostics
            .iter()
            .any(|s| s.contains("phase=open-pending")
                && s.contains("cleanup=pending unresolved-slots=unknown"))
    );
    assert!(
        output
            .diagnostics
            .iter()
            .any(|s| s.contains("known-rows=unknown known-calls=unknown"))
    );
    assert!(session.backend().requests[0].frontier.pending.is_some());
    assert!(!locked(&session.backend().engine.shared.state).terminal_contradiction);
    drop(session);
    drop(lease);
}

#[test]
fn w079_count_late_receipts_spawn_failure_needs_actual_capture_disposal() {
    for retain in [false, true] {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (barrier, lease, admission) = w079_reservation(deadline);
        let journal = CountSetupJournal::new();
        let watch = journal.watch();
        let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
            deadline,
            crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        ));
        let retained = Arc::new(Mutex::new(None));
        let capture = retained.clone();
        let failure = CountEngine::prepare_controlled_with(
            input(barrier),
            CountOwnerLimits::from_allowance(18, 2).unwrap(),
            deadline,
            PrepareHooks::host(),
            || -> PipeDriver { panic!("failed spawn must never enter owner") },
            move |task| {
                if retain {
                    *capture.lock().unwrap() = Some(task);
                }
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            },
            SetupPreparation {
                admission: Some(admission),
                control,
                journal,
            },
        )
        .err()
        .unwrap();
        let before = w079_progress(&watch);
        let snapshot = w079_snapshot(&watch);
        let sticky = if retain { watch.seal(deadline) } else { None };
        let captured = retained.lock().unwrap().take();
        drop(captured);
        let after = w079_progress(&watch);
        assert_eq!(failure.failure.class, FailureClass::Io);
        assert_eq!(failure.failure.errno, Some(libc::EAGAIN));
        assert_eq!(failure.cleanup_ticket, None);
        assert_eq!(before.phase, CountSetupPhase::OwnerPublished);
        assert_eq!(before.owner_cleanup_acknowledged, !retain);
        assert!(after.owner_cleanup_acknowledged);
        assert_eq!(after.owner_epoch, before.owner_epoch);
        assert_eq!(after.cleanup_ticket, sticky);
        assert!(after.owner_task_disposed);
        assert_eq!(
            snapshot.phase(),
            crate::capture::CountSetupPhase::OwnerPublished
        );
        assert_eq!(snapshot.cleanup_ticket(), None);
        drop(lease);
    }
}

#[test]
fn w079_count_prepare_preflight_failure_keeps_exact_receipt_and_reserve() {
    assert_eq!(crate::capture_setup::COUNT_NON_COUNT_FD_RESERVE, 2052);
    for (soft_limit, cancelled, want) in [
        (2069, false, FailureClass::Capacity),
        (2070, true, FailureClass::Cancelled),
    ] {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (barrier, lease, admission) = w079_reservation(deadline);
        let journal = CountSetupJournal::new();
        let watch = journal.watch();
        let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
            deadline,
            crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(cancelled))),
        ));
        let failure = crate::capture::prepare_count_backend_controlled_with::<CountEngine>(
            input(barrier),
            deadline,
            admission,
            &control,
            &journal,
            (
                || {
                    Ok(crate::capture::CountFdAdmission {
                        soft_limit,
                        non_count_open: 0,
                        non_count_reserved: 0,
                    })
                },
                || panic!("capacity/cancel must stop before first CPU read"),
            ),
            |_, _, _, _, _, _| panic!("preflight refusal cannot invoke Count owner"),
        )
        .err()
        .unwrap();
        let converted =
            crate::capture::PreObservationCount::from_setup_progress(w079_progress(&watch))
                .unwrap();
        let crate::capture::PreObservationCount::PrepareFailed(actual) = converted else {
            panic!("completed preflight must keep its actual PrepareFailed receipt")
        };
        assert_eq!(actual, failure);
        assert_eq!(failure.failure.class, want);
        assert_eq!(failure.cleanup_ticket, None);
        assert!(crate::capture::CountSetupSnapshot::from_watch(&watch).is_none());
        lease.abort();
        lease.complete_abort().unwrap();
    }
}

#[test]
fn w079_count_prepare_retains_original_token_deadline_and_valid_cpu_preflight() {
    static OWNER_CPU_READS: AtomicU64 = AtomicU64::new(0);
    fn cpu() -> io::Result<usize> {
        OWNER_CPU_READS.fetch_add(1, Ordering::Relaxed);
        Ok(2)
    }
    let original = Instant::now() + Duration::from_secs(2);
    let (barrier, lease, admission) = w079_reservation(original);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        original + Duration::from_secs(20),
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let outer_cpu = Arc::new(AtomicU64::new(0));
    let reads = outer_cpu.clone();
    let mut hooks = PrepareHooks::live();
    hooks.possible_cpu_count = cpu;
    let failure = crate::capture::prepare_count_backend_controlled_with(
        input(barrier),
        original + Duration::from_secs(30),
        admission,
        &control,
        &journal,
        (
            || {
                Ok(crate::capture::CountFdAdmission {
                    soft_limit: 2070,
                    non_count_open: 0,
                    non_count_reserved: 0,
                })
            },
            move || {
                reads.fetch_add(1, Ordering::Relaxed);
                Ok(2)
            },
        ),
        move |input, limits, deadline, admission, control, journal| {
            assert_eq!(deadline, original);
            CountEngine::prepare_controlled_with(
                input,
                limits,
                deadline,
                hooks,
                || -> PipeDriver {
                    panic!("CPU-only preflight must not label modeled owner effects Live")
                },
                |_task| Err(io::Error::from_raw_os_error(libc::EAGAIN)),
                SetupPreparation {
                    admission: Some(admission),
                    control: control.clone(),
                    journal: journal.clone(),
                },
            )
        },
    )
    .err()
    .unwrap();
    assert_eq!(failure.failure.errno, Some(libc::EAGAIN));
    assert_eq!(outer_cpu.load(Ordering::Relaxed), 1);
    assert_eq!(OWNER_CPU_READS.load(Ordering::Relaxed), 1);
    let progress = w079_progress(&watch);
    assert!(progress.owner_cleanup_acknowledged);
    drop(lease);
}

#[test]
fn w079_count_failure_classes_preserve_deadline_cancel_and_actual_io() {
    for class in [
        FailureClass::Deadline,
        FailureClass::Cancelled,
        FailureClass::Io,
    ] {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (barrier, lease, admission) = w079_reservation(deadline);
        let journal = CountSetupJournal::new();
        let watch = journal.watch();
        let control_deadline = if class == FailureClass::Deadline {
            Instant::now()
        } else {
            deadline
        };
        let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
            control_deadline,
            crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(
                class == FailureClass::Cancelled,
            ))),
        ));
        let probe = Probe::new();
        let owner = probe.clone();
        let failure = CountEngine::prepare_controlled_with(
            input(barrier),
            CountOwnerLimits::from_allowance(18, 2).unwrap(),
            deadline,
            PrepareHooks::host(),
            move || {
                owner.event(Event::Started);
                PipeDriver {
                    probe: owner,
                    faults: Faults {
                        fail_acquire_from: Some(1),
                        ..Default::default()
                    },
                    deadline,
                    attempts: 0,
                    acquired: 0,
                    closes: 0,
                }
            },
            spawn_owner,
            SetupPreparation {
                admission: Some(admission),
                control,
                journal,
            },
        )
        .err()
        .unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        if class == FailureClass::Io {
            while !watch
                .progress()
                .is_some_and(|p| p.owner_cleanup_acknowledged)
            {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
        }
        if class == FailureClass::Io {
            w079_owner_disposed(&watch);
        }
        let converted =
            crate::capture::PreObservationCount::from_setup_progress(w079_progress(&watch))
                .unwrap();
        assert_eq!(failure.failure.class, class);
        let actual = converted.actual_failure();
        if matches!(class, FailureClass::Deadline | FailureClass::Cancelled) {
            assert!(actual.is_none());
        } else {
            assert_eq!(
                actual.unwrap().class,
                if class == FailureClass::Io {
                    crate::capture::BoundaryFailureClass::Io
                } else {
                    crate::capture::BoundaryFailureClass::Cancelled
                }
            );
        }
        if class == FailureClass::Io {
            assert!(matches!(
                converted,
                crate::capture::PreObservationCount::SetupPending(_)
            ));
            assert_eq!(failure.failure.errno, Some(libc::EMFILE));
            assert_eq!(w079_progress(&watch).cleanup_ticket, failure.cleanup_ticket);
        } else {
            assert!(matches!(
                converted,
                crate::capture::PreObservationCount::PrepareFailed(_)
            ));
            lease.abort();
            lease.complete_abort().unwrap();
        }
    }
}

#[test]
fn w079_count_actual_host_preflight_validates_before_owner_effects() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (barrier, lease, admission) = w079_reservation(deadline);
    let journal = CountSetupJournal::new();
    let watch = journal.watch();
    let control = CountPrepareControl::new(crate::capture_setup::SetupControl::new(
        deadline,
        crate::capture_setup::SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
    ));
    let mut input = input(barrier);
    input.object_sha256[0] ^= 1;
    // Real process FD inventory and both production CPU reads, then hash refusal;
    // no Count owner can start and no BPF syscall is reachable with this input.
    let failure = crate::capture::prepare_count_backend_controlled(
        input, deadline, admission, &control, &journal,
    )
    .err()
    .unwrap();
    assert_eq!(failure.failure.class, FailureClass::ObjectDrift);
    let progress = w079_progress(&watch);
    assert_eq!(progress.phase, CountSetupPhase::Failed);
    assert_eq!(progress.owner_epoch, None);
    assert_eq!(failure.cleanup_ticket, None);
    lease.abort();
    lease.complete_abort().unwrap();
}

// The app keeps actual file pins/identity while existing host drivers model
// only Count kernel effects. Every file remains registered with the real owner.
struct W079AppDriver(TerminalDriver);
impl CountIoDriver for W079AppDriver {
    fn map_create(&mut self, spec: &crate::loader::MapSpecLite) -> io::Result<OwnedFd> {
        self.0.map_create(spec)
    }
    fn load_program(&mut self, i: &[u8], n: &str, l: Option<&mut [u8]>) -> io::Result<OwnedFd> {
        self.0.load_program(i, n, l)
    }
    fn open_pin(&mut self, path: &CStr) -> io::Result<OwnedFd> {
        let pin = LiveCountIoDriver.open_pin(path)?;
        self.0
            .map
            .base
            .probe
            .event(Event::PinOpened(pin.as_raw_fd()));
        Ok(pin)
    }
    fn pin_identity(&mut self, pin: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        LiveCountIoDriver.pin_identity(pin)
    }
    fn attach(
        &mut self,
        prog: BorrowedFd<'_>,
        path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        pid: u32,
    ) -> io::Result<OwnedFd> {
        self.0.attach(prog, path, offsets, cookies, pid)
    }
    unsafe fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
        unsafe { self.0.update(fd, key, value) }
    }
    unsafe fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8],
        value: &mut [u8],
    ) -> io::Result<()> {
        unsafe { self.0.lookup(fd, key, value) }
    }
    unsafe fn next_key(
        &mut self,
        fd: BorrowedFd<'_>,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> io::Result<()> {
        unsafe { self.0.next_key(fd, key, next) }
    }
    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        self.0.close(fd)
    }
    fn now(&self) -> Instant {
        self.0.now()
    }
    fn monotonic_ns(&self) -> Option<u64> {
        self.0.monotonic_ns()
    }
}
// Narrow application fixture bridge: the same owner, mailbox, controlled token,
// map driver, FD sentinels and physical cleanup observations used above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum W079AppPrepareHold {
    FdInventory,
    OuterCpu,
    OwnerCpu,
    Hash,
    Parse,
    Allocation,
    OwnerStart,
    PrepareReply,
}
pub(crate) struct W079AppCountFixture {
    probe: Arc<MapProbe>,
    open_fault: std::sync::atomic::AtomicU8,
    hold_map_call: Option<usize>,
    hold_close: bool,
    hold_attach: bool,
    prepare_hold: Option<W079AppPrepareHold>,
    prepare_entered: Arc<AtomicBool>,
}
impl W079AppCountFixture {
    pub(crate) fn new(
        hold_map_call: Option<usize>,
        hold_close: bool,
        hold_attach: bool,
        prepare_hold: Option<W079AppPrepareHold>,
    ) -> Self {
        let probe = MapProbe::new();
        *locked(&probe.owner.hold_deadline) = Some(Instant::now() + Duration::from_secs(10));
        Self {
            probe,
            open_fault: std::sync::atomic::AtomicU8::new(0),
            hold_map_call,
            hold_close,
            hold_attach,
            prepare_hold,
            prepare_entered: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) fn fail_open(&self, unwind: bool) {
        self.open_fault
            .store(if unwind { 2 } else { 1 }, Ordering::Release);
    }
    pub(crate) fn prepare_entered(&self) -> bool {
        if self.prepare_hold == Some(W079AppPrepareHold::PrepareReply) {
            return locked(&self.probe.owner.log)
                .events
                .iter()
                .any(|(_, event)| matches!(event, Event::EnterAcquire(8)));
        }
        self.prepare_entered.load(Ordering::Acquire)
    }
    fn stage(&self, stage: W079AppPrepareHold) {
        if self.prepare_hold == Some(stage) {
            self.prepare_entered.store(true, Ordering::Release);
            self.probe.owner.hold();
        }
    }
    pub(crate) fn release(&self) {
        self.probe.owner.release();
    }
    pub(crate) fn wait_map_call(&self, n: usize) {
        self.probe.wait_calls(n);
    }
    pub(crate) fn attach_entered(&self) -> bool {
        locked(&self.probe.owner.log)
            .events
            .iter()
            .any(|(_, event)| matches!(event, Event::EnterAcquire(9)))
    }
    pub(crate) fn close_entered(&self) -> bool {
        locked(&self.probe.owner.log)
            .events
            .iter()
            .any(|(_, event)| matches!(event, Event::EnterClose))
    }
    pub(crate) fn open_target_writes(&self) -> usize {
        locked(&self.probe.calls)
            .iter()
            .filter(|(_, action)| {
                matches!(action,
            MapAction::Write(CountMap::Target, _, value) if value.iter().any(|byte| *byte != 0))
            })
            .count()
    }
    pub(crate) fn descriptors_closed(&self) -> bool {
        let log = locked(&self.probe.owner.log);
        let acquired = log
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Acquired(_)))
            .count();
        let closed = log
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Closed(_)))
            .count();
        let pins = log
            .events
            .iter()
            .filter(|(_, e)| matches!(e, Event::PinOpened(_)))
            .count();
        (acquired >= 8 || self.prepare_hold.is_some())
            && closed == acquired + pins
            && !self.probe.owner.hold_expired.load(Ordering::Acquire)
    }
    pub(crate) fn prepare(
        &self,
        pid: u32,
        admission: CountSetupAdmission,
        control: &CountPrepareControl,
        journal: &CountSetupJournal,
    ) -> Result<CountEngine, CountPrepareFailure> {
        let mut input = input(admission.barrier.clone());
        input.target_tgid = pid;
        let probe = self.probe.clone();
        let observed = probe.owner.clone();
        let mut hooks = if self.prepare_hold == Some(W079AppPrepareHold::OwnerCpu) {
            PrepareHooks::live()
        } else {
            PrepareHooks::host()
        };
        hooks.possible_cpu_count = || Ok(2);
        let stage_hold = self.prepare_hold;
        let stage_entered = self.prepare_entered.clone();
        let stage_probe = probe.owner.clone();
        hooks.stage_observer = Some(Arc::new(move |stage| {
            let stage = match stage {
                CountPrepareStage::OwnerCpu => Some(W079AppPrepareHold::OwnerCpu),
                CountPrepareStage::Hash => Some(W079AppPrepareHold::Hash),
                CountPrepareStage::Parse => Some(W079AppPrepareHold::Parse),
                CountPrepareStage::Allocation => Some(W079AppPrepareHold::Allocation),
                _ => None,
            };
            if stage.is_some() && stage == stage_hold {
                stage_entered.store(true, Ordering::Release);
                stage_probe.hold();
            }
        }));
        hooks.kernel_profile = KernelApplicability::reviewed_fixture(1);
        hooks.registry_observer = Some(Arc::new(move |event| {
            observed.event(Event::Registry(event))
        }));
        let cutoff = control.deadline();
        let hold_map_call = self.hold_map_call;
        let open_fault = self.open_fault.load(Ordering::Acquire);
        let hold_close = self.hold_close;
        let hold_attach = self.hold_attach;
        let prepare_hold = self.prepare_hold;
        let spawn_probe = probe.owner.clone();
        let spawn_entered = self.prepare_entered.clone();
        crate::capture::prepare_count_backend_controlled_with(
            input,
            cutoff,
            admission,
            control,
            journal,
            (
                || {
                    self.stage(W079AppPrepareHold::FdInventory);
                    let mut sampled = crate::capture::CountFdAdmission::snapshot(
                        crate::capture_setup::COUNT_NON_COUNT_FD_RESERVE,
                    )?;
                    // Existing host model uses a conservative24-FD owner allowance;
                    // the real inventory is measured and the2052 reserve unchanged.
                    sampled.soft_limit = sampled
                        .soft_limit
                        .min(sampled.non_count_open + sampled.non_count_reserved + 24);
                    Ok(sampled)
                },
                || {
                    self.stage(W079AppPrepareHold::OuterCpu);
                    let _actual = aya::util::nr_cpus().map_err(|error| {
                        OwnerFailure::io(CountOperation::Load, ResourceId::Engine, &error.1)
                    })?;
                    Ok(2) // explicit existing two-CPU HostModel driver, not live qualification
                },
            ),
            move |input, limits, cutoff, admission, control, journal| {
                CountEngine::prepare_controlled_with(
                    input,
                    limits,
                    cutoff,
                    hooks,
                    move || {
                        probe.owner.event(Event::Started);
                        W079AppDriver(TerminalDriver {
                            map: MapDriver {
                                base: PipeDriver {
                                    probe: probe.owner.clone(),
                                    faults: Faults {
                                        hold_close: hold_close.then_some(1),
                                        hold_acquire: if prepare_hold
                                            == Some(W079AppPrepareHold::PrepareReply)
                                        {
                                            Some(8)
                                        } else {
                                            hold_attach.then_some(9)
                                        },
                                        ..Faults::default()
                                    },
                                    deadline: cutoff,
                                    attempts: 0,
                                    acquired: 0,
                                    closes: 0,
                                },
                                probe,
                                faults: MapFaults {
                                    hold_call: hold_map_call,
                                    write_error: (open_fault == 1).then_some(5),
                                    panic_call: (open_fault == 2).then_some(5),
                                    ..MapFaults::default()
                                },
                                maps: [-1; 7],
                                map_count: 0,
                                next_position: 0,
                                writes: 0,
                                cpus: 2,
                                cutoff,
                            },
                            writer: None,
                            links: Vec::with_capacity(4),
                            timeline: Arc::new(Mutex::new(Vec::new())),
                            clock_panic_after_close: false,
                            clock: None,
                            seal_clock: None,
                            lookup_gate: None,
                        })
                    },
                    move |task| {
                        if prepare_hold == Some(W079AppPrepareHold::OwnerStart) {
                            spawn_owner(Box::new(move || {
                                spawn_entered.store(true, Ordering::Release);
                                spawn_probe.hold();
                                task();
                            }))
                        } else {
                            spawn_owner(task)
                        }
                    },
                    SetupPreparation {
                        admission: Some(admission),
                        control: control.clone(),
                        journal: journal.clone(),
                    },
                )
            },
        )
    }
}
