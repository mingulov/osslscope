//! SPDX-License-Identifier: GPL-3.0-or-later
//! Host routing controls; these do not qualify kernel writer completion.
use osslscope::count_session::*;
use osslscope::discovery::maps::Mapping;
use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CounterKind, CounterSource, CounterUnits, GapCounter,
    ObjectId, SiteKey,
};
use osslscope::{capture::CountFdAdmission, plan};
use osslscope_ebpf_common::CountValue;
use std::cell::Cell;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
const PID: u32 = 4242;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn close() -> CloseRequest {
    CloseRequest {
        started_at: Instant::now(),
        grace: Duration::from_secs(1),
        reason: CloseReason::Failure,
    }
}
fn value(count: u64, first_ns: u64, last_ns: u64) -> CountValue {
    CountValue {
        count,
        first_ns,
        last_ns,
    }
}
fn counter(drain: &CountDrain, name: &str) -> Option<u64> {
    drain
        .counters
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value)
}
struct Fixture {
    dir: PathBuf,
    device: u64,
    inode: u64,
    offsets: Vec<u64>,
    live: Vec<Mapping>,
    files: HashMap<String, plan::FileBytes>,
}
impl Fixture {
    fn new(n: usize) -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "osslscope-terminal-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let ph = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == goblin::elf::program_header::PT_LOAD
                    && p.p_flags & goblin::elf::program_header::PF_X != 0
            })
            .unwrap();
        let offsets = (0..n).map(|i| ph.p_offset + 16 + i as u64 * 16).collect();
        let path = dir.join("provider.so");
        std::fs::write(&path, &bytes).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let path = path.to_str().unwrap().to_owned();
        let device = plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev()));
        let inode = meta.ino();
        let live = vec![Mapping {
            start: 0x7000_0000,
            end: 0x8000_0000,
            x: true,
            offset: 0,
            dev: plan::render_device(device),
            ino: inode,
            path: path.clone(),
        }];
        let files = HashMap::from([(
            path,
            plan::FileBytes {
                bytes: bytes.into(),
                dev: device,
                ino: inode,
            },
        )]);
        Self {
            dir,
            device,
            inode,
            offsets,
            live,
            files,
        }
    }
    fn delta(&self, meaning: u32) -> CountDelta {
        CountDelta {
            discovered: self
                .offsets
                .iter()
                .map(|offset| DiscoveredSite {
                    site: SiteKey {
                        object: ObjectId("exact-object".into()),
                        device: self.device,
                        inode: self.inode,
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
        }
    }
    fn attach<B: CountBackend>(
        &self,
        s: &mut CountSession<B>,
        meaning: u32,
    ) -> anyhow::Result<AttachReport> {
        s.attach_delta(
            &self.delta(meaning),
            &self.live,
            &self.files,
            900,
            deadline(),
        )
    }
    fn cookie<B: CountBackend>(&self, s: &CountSession<B>, position: usize) -> u32 {
        s.cookie_for(self.device, self.inode, self.offsets[position])
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
#[derive(Default)]
struct Scripted {
    inner: FakeCountBackend,
    lose_generation: bool,
    lose_open: bool,
    lose_attach: bool,
    replay: Option<Arc<RawSnapshot>>,
    foreign: bool,
    prefixes: Vec<(u32, u32, CountValue)>,
    calls: Rc<Cell<u32>>,
    attach_sizes: Vec<usize>,
}
fn lost(seq: CommandSeq, operation: CountOperation) -> CommandFailure {
    CommandFailure {
        seq,
        completion: CommandCompletion::Unknown,
        publication: CommandPublication::Published,
        cleanup_ticket: None,
        failure: OwnerFailure {
            operation,
            resource: ResourceId::Engine,
            class: FailureClass::Deadline,
            errno: None,
        },
    }
}
impl CountBackend for Scripted {
    type Link = FakeLink;
    fn ready(&self) -> &Ready {
        self.inner.ready()
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<FakeLink>> {
        self.attach_sizes.push(request.offsets.len());
        let seq = request.seq;
        let ack = self.inner.attach(request)?;
        if self.lose_attach {
            Err(lost(seq, CountOperation::Attach))
        } else {
            Ok(ack)
        }
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        let ack = self.inner.open_window(request)?;
        if self.lose_open {
            Err(lost(request.seq, CountOperation::Open))
        } else {
            Ok(ack)
        }
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        let ack = self.inner.set_generation(request)?;
        if self.lose_generation {
            Err(lost(request.seq, CountOperation::Generation))
        } else {
            Ok(ack)
        }
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        let mut ack = self.inner.drain(request)?;
        if let Some(replay) = self.replay.take() {
            ack.value = replay;
        }
        Ok(ack)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        self.inner.terminal_request(deadline, frontier)
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        self.calls.set(self.calls.get() + 1);
        for (cookie, generation, delta) in self.prefixes.drain(..) {
            self.inner.inject_row(cookie, generation, delta);
            self.inner.publish_checkpoint().unwrap();
        }
        if self.foreign {
            let mut foreign = FakeCountBackend::new();
            let request = foreign.terminal_request(request.deadline, ControllerFrontier::default());
            foreign.terminal(request)
        } else {
            self.inner.terminal(request)
        }
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.inner.progress()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.inner.fork_permit(deadline)
    }
}
fn staged_current_and_fenced(f: &Fixture) -> CountSession<Scripted> {
    let mut s = CountSession::new(PID, Scripted::default());
    f.attach(&mut s, 7).unwrap();
    s.open_window(1000, 2000, deadline()).unwrap();
    let cookie = f.cookie(&s, 0);
    s.backend_mut().inner.fire(PID, cookie, 1100, 11);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    s.backend_mut().inner.fire(PID, cookie, 1200, 3);
    s.backend_mut().inner.fire(PID, cookie, 1300, 4);
    f.attach(&mut s, 9).unwrap();
    s.backend_mut().lose_generation = true;
    assert!(s.fence(FenceReason::CandidatesChanged, deadline()).is_err());
    assert!(s.is_closed());
    s
}
#[test]
fn g1_salvage_routes_checkpoint_once() {
    // Current=7, fenced=11. Newly published prefixes are cumulative 2 then 5.
    let f = Fixture::new(2);
    let mut s = staged_current_and_fenced(&f);
    let cookie = f.cookie(&s, 0);
    s.backend_mut().prefixes = vec![
        (cookie, 2, value(2, 1400, 1400)),
        (cookie, 2, value(3, 1600, 1600)),
    ];
    s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
        read_error: true,
        enumeration: Some(EnumerationStatus::Unfinished),
        ..Default::default()
    });
    let terminal = s.terminal(close());
    assert_eq!(terminal.retained_drain.total_calls(), 23);
    let current = &terminal.retained_drain.current[0];
    assert_eq!(
        (
            current.calls,
            current.generation,
            current.candidates[0].funcid,
            current.first_ns,
            current.last_ns
        ),
        (5, 2, 9, 1400, 1600)
    );
    assert_eq!(terminal.retained_drain.fenced[0].sites[0].calls, 11);
    assert_eq!(
        (
            terminal.retained_drain.fenced[1].sites[0].first_ns,
            terminal.retained_drain.fenced[1].sites[0].last_ns
        ),
        (1200, 1300)
    );
    for site in terminal
        .retained_drain
        .current
        .iter()
        .chain(terminal.retained_drain.fenced.iter().flat_map(|g| &g.sites))
    {
        assert_eq!(
            (site.site.device, site.site.inode, site.site.offset),
            (f.device, f.inode, f.offsets[0])
        );
        assert_eq!(site.site.object, ObjectId("exact-object".into()));
        assert_eq!(site.installed_at, Some(900));
    }
    let a = s.salvage_view(s.terminal_id().unwrap());
    let b = s.salvage_view(s.terminal_id().unwrap());
    let c = s.salvage_view(s.terminal_id().unwrap());
    assert_eq!(a.retained_drain, b.retained_drain);
    assert_eq!(b.retained_drain, c.retained_drain);
    assert!(std::ptr::eq(&*a.receipt, &*terminal.receipt));
    assert!(Arc::ptr_eq(
        &a.receipt.checkpoint.as_ref().unwrap().snapshot,
        &b.receipt.checkpoint.as_ref().unwrap().snapshot
    ));
    assert_eq!(s.backend().calls.get(), 1);
    let per_link: Vec<_> = terminal
        .receipt
        .manifest
        .iter()
        .map(|r| {
            terminal
                .receipt
                .close_outcomes
                .iter()
                .filter(|o| o.id == r.id)
                .count()
        })
        .collect();
    assert_eq!(per_link, vec![1, 1]);
    assert_eq!(
        counter(&terminal.retained_drain, "count.ledger_delta"),
        None
    );
    assert_eq!(
        counter(&terminal.retained_drain, "count.drain_unenumerated"),
        Some(1)
    );
    assert!(!s.window_open());
}
#[test]
fn g1_lost_generation_ack_keeps_retired_meaning() {
    let f = Fixture::new(1);
    let mut s = staged_current_and_fenced(&f);
    let cookie = f.cookie(&s, 0);
    s.backend_mut()
        .inner
        .inject_row(cookie, 1, value(2, 1500, 1500));
    s.backend_mut()
        .inner
        .inject_row(cookie, 2, value(3, 1700, 1700));
    let t = s.terminal(close());
    assert_eq!(t.retained_drain.total_calls(), 23);
    assert_eq!(s.generation(), 2);
    let old = &t.retained_drain.fenced[1].sites[0];
    assert_eq!(
        (
            old.calls,
            old.generation,
            old.candidates[0].funcid,
            old.first_ns,
            old.last_ns
        ),
        (9, 1, 7, 1200, 1500)
    );
    assert_eq!(
        (
            t.retained_drain.current[0].calls,
            t.retained_drain.current[0].candidates[0].funcid
        ),
        (3, 9)
    );
    assert_eq!(counter(&t.retained_drain, "count.stale_events"), Some(2));
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), Some(5));
    assert_eq!(s.terminal(close()).retained_drain, t.retained_drain);
}
#[test]
fn g1_unresolved_frontier_never_guesses_new_meaning() {
    let f = Fixture::new(1);
    let mut s = staged_current_and_fenced(&f);
    let cookie = f.cookie(&s, 0);
    s.backend_mut()
        .inner
        .inject_row(cookie, 2, value(5, 1500, 1600));
    s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
        forget_frontier: true,
        ..Default::default()
    });
    let t = s.terminal(close());
    assert_eq!(s.generation(), 1);
    assert_eq!(t.retained_drain.total_calls(), 18);
    assert_eq!(t.retained_drain.current[0].candidates[0].funcid, 7);
    assert_eq!(counter(&t.retained_drain, "count.unattributed"), Some(5));
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
    assert_eq!(
        counter(&t.retained_drain, "count.reference_inventory_invalid"),
        Some(1)
    );
}

#[test]
fn g1_unavailable_terminal_inventory_is_partial_with_prior_positives() {
    let f = Fixture::new(1);
    let mut s = staged_current_and_fenced(&f);
    s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
        inventory_unavailable: true,
        ..Default::default()
    });
    let t = s.terminal(close());
    assert!(t.receipt.inventory.is_none());
    assert_eq!(t.retained_drain.total_calls(), 18);
    assert!(
        t.runtime_failure.is_none(),
        "unavailable proof after deadline is not a returned runtime error"
    );
    assert_eq!(
        counter(&t.retained_drain, "count.quiescence_unknown"),
        Some(1)
    );
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
    let retained = s.close_for_capture(Duration::from_secs(60)).unwrap();
    assert!(retained.runtime_failure().is_none());
    assert_eq!(retained.into_drain().total_calls(), 18);
    assert!(s.close_and_drain(Duration::from_secs(60)).is_err());
}
#[test]
fn g1_reconciliation_requires_all_inputs() {
    for missing in 0..3 {
        let f = Fixture::new(1);
        let mut s = CountSession::new(PID, Scripted::default());
        f.attach(&mut s, 7).unwrap();
        s.open_window(1000, 2000, deadline()).unwrap();
        let cookie = f.cookie(&s, 0);
        s.backend_mut().inner.fire(PID, cookie, 1100, 4);
        s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
            admitted_unavailable: missing == 0,
            dropfail_unavailable: missing == 1,
            enumeration: (missing == 2).then_some(EnumerationStatus::Unfinished),
            ..Default::default()
        });
        let t = s.terminal(close());
        assert_eq!(t.retained_drain.total_calls(), 4);
        assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
        if missing == 2 {
            assert_eq!(counter(&t.retained_drain, "count.drain_shortfall"), None);
        }
        if missing == 0 {
            assert_eq!(counter(&t.retained_drain, "count.ledger_admitted"), None);
        }
        if missing == 1 {
            assert_eq!(counter(&t.retained_drain, "count.map_insert_dropped"), None);
        }
        assert_eq!(
            counter(&t.retained_drain, "count.drain_read_failed"),
            Some(1)
        );
    }
}
#[test]
fn g1_prior_loss_never_disappears() {
    let f = Fixture::new(1);
    let mut s = CountSession::new(PID, Scripted::default());
    let mut delta = f.delta(7);
    delta.losses.push(GapCounter {
        name: "discovery.prior_loss".into(),
        kind: CounterKind::Loss,
        units: CounterUnits::Events,
        source: CounterSource::Discovery,
        value: 3,
    });
    s.attach_delta(&delta, &f.live, &f.files, 900, deadline())
        .unwrap();
    s.open_window(1000, 2000, deadline()).unwrap();
    let cookie = f.cookie(&s, 0);
    s.backend_mut().inner.fire(PID, cookie, 1200, 4);
    s.backend_mut().inner.set_shortfall(2);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
        read_error: true,
        ..Default::default()
    });
    let t = s.terminal(close());
    assert_eq!(t.retained_drain.total_calls(), 4);
    assert_eq!(counter(&t.retained_drain, "discovery.prior_loss"), Some(3));
    assert_eq!(counter(&t.retained_drain, "count.drain_shortfall"), Some(2));
    assert!(t.runtime_failure.is_some());
    assert_eq!(counter(&t.retained_drain, "count.owner_failed"), Some(1));
    assert_eq!(
        s.salvage_view(s.terminal_id().unwrap()).retained_drain,
        t.retained_drain
    );
}
#[test]
fn g1_partial_attach_binds_exact_manifest_survivors() {
    for refused in [vec![1], vec![0, 2]] {
        let f = Fixture::new(3);
        let mut backend = Scripted {
            lose_attach: true,
            ..Default::default()
        };
        for position in &refused {
            backend.inner.poison_offset(f.offsets[*position]);
        }
        let mut s = CountSession::new(PID, backend);
        s.open_window(1000, 2000, deadline()).unwrap();
        assert!(f.attach(&mut s, 7).is_err());
        for position in 0..3 {
            let cookie = f.cookie(&s, position);
            s.backend_mut()
                .inner
                .fire(PID, cookie, 1200, position as u64 + 1);
        }
        let t = s.terminal(close());
        let mut got: Vec<_> = t
            .retained_drain
            .current
            .iter()
            .map(|e| (e.site.offset, e.calls))
            .collect();
        got.sort();
        let expected: Vec<_> = (0..3)
            .filter(|i| !refused.contains(i))
            .map(|i| (f.offsets[i], i as u64 + 1))
            .collect();
        assert_eq!(got, expected);
        assert_eq!(
            counter(&t.retained_drain, "count.unattributed"),
            Some(refused.iter().map(|i| *i as u64 + 1).sum())
        );
        assert!(
            s.attach_delta(&f.delta(9), &f.live, &f.files, 1800, deadline())
                .is_err()
        );
        assert_eq!(
            s.salvage_view(s.terminal_id().unwrap()).retained_drain,
            t.retained_drain
        );
    }
}

#[test]
fn g1_attach_capacity_seals_after_bounded_batches() {
    let f = Fixture::new(8193);
    let mut s = CountSession::new(PID, Scripted::default());
    assert!(
        f.attach(&mut s, 7).is_err(),
        "capacity must refuse, preserving prior acquired positions"
    );
    assert_eq!(s.backend().attach_sizes, vec![8192, 1]);
    assert!(s.is_closed());
    assert_eq!(
        s.provenance(f.cookie(&s, 8191)).unwrap().installed_at,
        Some(900)
    );
    assert_eq!(s.provenance(f.cookie(&s, 8192)).unwrap().installed_at, None);
    let t = s.terminal(close());
    assert_eq!(counter(&t.retained_drain, "count.owner_capacity"), Some(1));
    assert_eq!(t.runtime_failure.unwrap().class, FailureClass::Capacity);
}
#[test]
fn g1_lost_open_reply_requires_exact_resolved_binding() {
    let mut s = CountSession::new(
        PID,
        Scripted {
            lose_open: true,
            ..Default::default()
        },
    );
    assert!(s.open_window(1000, 2000, deadline()).is_err());
    assert!(s.programmed_admission().is_none());
    let t = s.terminal(close());
    let a = s.programmed_admission().unwrap();
    assert_eq!(
        (a.tgid(), a.generation(), a.start_ns(), a.deadline_ns()),
        (u64::from(PID), 0, 1000, 2000)
    );
    assert_eq!(t.receipt.resolved_open.unwrap().seq, a.open_seq());
}

#[test]
fn g1_acknowledged_open_cannot_disappear_from_terminal_journal() {
    let f = Fixture::new(1);
    let mut s = CountSession::new(PID, Scripted::default());
    f.attach(&mut s, 7).unwrap();
    s.open_window(1000, 2000, deadline()).unwrap();
    let admission = *s.programmed_admission().unwrap();
    let cookie = f.cookie(&s, 0);
    s.backend_mut().inner.fire(PID, cookie, 1100, 4);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    s.backend_mut().inner.fire(PID, cookie, 1200, 3);
    s.backend_mut().inner.terminal_faults(FakeTerminalFaults {
        omit_resolved_open: true,
        ..Default::default()
    });
    let t = s.terminal(close());
    assert!(t.receipt.resolved_open.is_none());
    assert!(
        t.runtime_failure.is_some(),
        "self-consistent omission contradicts the acknowledged Open"
    );
    assert_eq!(
        t.retained_drain.total_calls(),
        4,
        "invalid terminal cannot authorize new rows"
    );
    assert_eq!(*s.programmed_admission().unwrap(), admission);
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
}
#[test]
fn g1_component_high_water_and_stale_images_never_invent_samples() {
    let f = Fixture::new(1);
    let mut s = CountSession::new(PID, Scripted::default());
    f.attach(&mut s, 7).unwrap();
    s.open_window(1000, 2000, deadline()).unwrap();
    let cookie = f.cookie(&s, 0);
    s.backend_mut().inner.fire(PID, cookie, 1100, 2);
    s.backend_mut().inner.inject_latency(0, 2);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    let old = s.backend().inner.progress().unwrap().snapshot;
    let mut faults = FakeTerminalFaults::default();
    faults.latc_unavailable[0] = true;
    faults.latc_unavailable[7] = true;
    s.backend_mut().inner.inject_latency(0, 5);
    s.backend_mut().inner.inject_latency(7, 3);
    s.backend_mut().inner.terminal_faults(faults);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    s.backend_mut().replay = Some(old);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    let t = s.terminal(close());
    assert_eq!(t.retained_drain.total_calls(), 2);
    assert_eq!(counter(&t.retained_drain, "count.lat_bucket_00"), Some(2));
    assert_eq!(counter(&t.retained_drain, "count.lat_bucket_07"), None);
    assert_eq!(counter(&t.retained_drain, "count.lat_bucket_01"), Some(0));
    for name in [
        "count.lat_samples",
        "count.lat_median_ns",
        "count.lat_p99_ns",
    ] {
        assert_eq!(counter(&t.retained_drain, name), None);
    }
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
}
#[test]
fn g1_saturated_totals_and_histogram_do_not_wrap() {
    let f = Fixture::new(1);
    let mut s = CountSession::new(PID, Scripted::default());
    f.attach(&mut s, 7).unwrap();
    s.open_window(1000, 2000, deadline()).unwrap();
    let cookie = f.cookie(&s, 0);
    s.backend_mut().inner.fire(PID, cookie, 1100, u64::MAX);
    s.backend_mut().inner.inject_latency(2, u64::MAX);
    s.backend_mut().inner.inject_latency(3, u64::MAX);
    s.fence(FenceReason::MappingsChanged, deadline()).unwrap();
    let t = s.terminal(close());
    assert_eq!(t.retained_drain.total_calls(), u64::MAX);
    assert_eq!(
        counter(&t.retained_drain, "count.lat_samples"),
        Some(u64::MAX)
    );
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), Some(0));
}
#[test]
fn g1_foreign_terminal_cannot_replace_retained_provenance() {
    let f = Fixture::new(1);
    let mut s = staged_current_and_fenced(&f);
    s.backend_mut().foreign = true;
    let t = s.terminal(close());
    assert_eq!(t.retained_drain.total_calls(), 18);
    assert!(t.runtime_failure.is_some());
    assert_eq!(
        counter(&t.retained_drain, "count.reference_inventory_invalid"),
        Some(1)
    );
    assert_eq!(counter(&t.retained_drain, "count.ledger_delta"), None);
    let retained = s.retained_for_capture(s.terminal_id().unwrap()).unwrap();
    assert!(retained.runtime_failure().is_some());
    assert_eq!(retained.into_drain().total_calls(), 18);
    let again = s.close_for_capture(Duration::from_secs(60)).unwrap();
    assert_eq!(again.into_drain().total_calls(), 18);
    assert_eq!(s.backend().calls.get(), 1);
    let mut other = CountSession::new(PID, FakeCountBackend::new());
    other.terminal(close());
    assert!(
        s.retained_for_capture(other.terminal_id().unwrap())
            .is_err()
    );
}
#[test]
fn g1_fd_admission_checks_process_allowance_and_ceiling() {
    for (soft, open, reserved, want) in [
        (20, 1, 1, 18),
        (16402, 1, 1, 16400),
        (u64::MAX, 9, 7, 16400),
    ] {
        assert_eq!(
            CountFdAdmission {
                soft_limit: soft,
                non_count_open: open,
                non_count_reserved: reserved
            }
            .allowance()
            .unwrap(),
            want
        );
    }
    for (soft, open, reserved) in [
        (19, 1, 1),
        (0, 1, 0),
        (u64::MAX, u64::MAX, 1),
        (u64::MAX, 1, u64::MAX),
    ] {
        assert!(
            CountFdAdmission {
                soft_limit: soft,
                non_count_open: open,
                non_count_reserved: reserved
            }
            .allowance()
            .is_err()
        );
    }
    assert!(CountOwnerLimits::from_allowance(17, 1).is_err());
    assert_eq!(
        CountOwnerLimits::from_allowance(18, 1)
            .unwrap()
            .link_slots(),
        1
    );
    assert_eq!(
        CountOwnerLimits::from_allowance(16400, 1)
            .unwrap()
            .link_slots(),
        8192
    );
    assert!(CountOwnerLimits::from_allowance(16400, usize::MAX).is_err());
}
#[test]
fn g1_known_empty_is_no_observation_not_available_zero() {
    let mut s = CountSession::new(PID, FakeCountBackend::new());
    let t = s.terminal(CloseRequest {
        started_at: Instant::now(),
        grace: Duration::ZERO,
        reason: CloseReason::SetupAbort,
    });
    assert!(matches!(t.receipt.writers, WriterCompletion::KnownEmpty(_)));
    assert_eq!(t.receipt.read_status, ReadStatus::NotStarted);
    assert!(t.receipt.checkpoint.is_none());
    assert!(matches!(
        t.receipt.kernel_profile,
        KernelApplicability::Unknown(_)
    ));
    assert_eq!(t.retained_drain.total_calls(), 0);
    for name in [
        "count.ledger_delta",
        "count.ledger_admitted",
        "count.map_insert_dropped",
        "count.lat_samples",
        "count.drain_shortfall",
    ] {
        assert_eq!(counter(&t.retained_drain, name), None);
    }
}
