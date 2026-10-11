//! SPDX-License-Identifier: GPL-3.0-or-later
//! T07 count-window deadline tests (spec R05).
//!
//! Pins the `WINDOW` admission contract shared by the kernel
//! `count_entry` program and the host double: counts are admitted
//! only inside the declared monotonic `[start, deadline)` interval,
//! the window admits nothing before it opens, map-full inserts fail
//! loud into an explicit loss counter (bounded non-LRU map —
//! entries are never evicted), and per-key counts stay exact under
//! threaded hammering.

use osslscope::count_session::{
    CountBackend, CountDelta, CountSession, DiscoveredSite, FakeCountBackend, FakeLink, FenceReason,
};
use osslscope::discovery::maps::Mapping;
use osslscope::evidence::{CandidateCoverage, CandidateIdentity, ObjectId};
use osslscope::plan;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

const PID: u32 = 4242;

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

fn obj(id: &str) -> ObjectId {
    ObjectId(id.to_string())
}

fn self_bytes() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

fn x_offsets(bytes: &[u8], n: usize) -> Vec<u64> {
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let ph = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
        .unwrap();
    // Distinct 8-aligned sites spread across the X segment.
    let span = ph.p_filesz.saturating_sub(64);
    assert!(span > (n as u64) * 16, "X segment too small for {n} keys");
    (0..n)
        .map(|i| ph.p_offset + 8 + (i as u64) * (span / (n as u64)).max(16))
        .collect()
}

struct Staged {
    path: String,
    device: u64,
    ino: u64,
}

struct Stage {
    dir: PathBuf,
}

impl Stage {
    fn fresh(test: &str) -> Self {
        let seq = STAGE_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "osslscope-t07-{}-{}-{}-{}",
            test,
            std::process::id(),
            seq,
            format!("{:?}", std::thread::current().id()).replace(['(', ')', ' '], "")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Staged {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        Staged {
            path: path.to_str().unwrap().to_string(),
            device: plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
            ino: meta.ino(),
        }
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn mapping(staged: &Staged) -> Mapping {
    Mapping {
        start: 0x7f00_0000_0000,
        end: 0x7f00_0000_1000,
        x: true,
        offset: 0,
        dev: plan::render_device(staged.device),
        ino: staged.ino,
        path: staged.path.clone(),
    }
}

fn candidate(funcid: u32) -> CandidateIdentity {
    CandidateIdentity::new(
        obj("prov"),
        "default".to_string(),
        1,
        funcid,
        vec!["digest".to_string()],
        false,
    )
}

fn site(staged: &Staged, offset: u64, funcid: u32) -> DiscoveredSite {
    DiscoveredSite {
        site: osslscope::evidence::SiteKey {
            object: obj("fp-A"),
            device: staged.device,
            inode: staged.ino,
            offset,
        },
        candidates: vec![candidate(funcid)],
        candidates_coverage: CandidateCoverage::Complete,
    }
}

fn session_with(backend: FakeCountBackend) -> CountSession<FakeCountBackend> {
    CountSession::new(PID, backend)
}

fn counter_value(drain: &osslscope::count_session::CountDrain, name: &str) -> Option<u64> {
    drain
        .counters
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value)
}

#[test]
fn kernel_deadline_excludes_late_calls() {
    // Admission is exactly [start, deadline): the start edge counts,
    // the deadline edge does not, pre-window and late hits never
    // appear, and foreign TGIDs cannot contribute.
    let stage = Stage::fresh("deadline");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    let fire = |s: &mut CountSession<FakeCountBackend>, tgid: u32, now: u64, n: u64| {
        s.backend_mut().fire(tgid, cookie, now, n);
    };
    fire(&mut s, PID, 999, 100); // pre-window: dropped
    fire(&mut s, PID, 1000, 1); // start edge: admitted
    fire(&mut s, PID, 1500, 7); // in-window: admitted
    fire(&mut s, PID, 1999, 1); // deadline-1 edge: admitted
    fire(&mut s, PID, 2000, 100); // deadline edge: excluded
    fire(&mut s, PID, 2500, 100); // late: excluded
    fire(&mut s, PID + 1, 1500, 100); // foreign tgid: dropped

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 9, "only [1000, 2000) admitted");
    assert_eq!(drain.current.len(), 1);
    let exec = &drain.current[0];
    assert_eq!((exec.calls, exec.first_ns, exec.last_ns), (9, 1000, 1999));
    // Nothing late leaked anywhere: no fenced buckets, no
    // unattributed spill, no drops.
    assert!(drain.fenced.is_empty());
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(0));
    assert_eq!(counter_value(&drain, "count.map_insert_dropped"), Some(0));
}

#[test]
fn window_closed_until_open() {
    // The zeroed window admits nothing: pre-open hits drop, an empty
    // window is a fail-closed error, and closing ends admission.
    let stage = Stage::fresh("closed");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();

    s.backend_mut().fire(PID, cookie, 1500, 11);
    assert_eq!(s.backend().ledger_total(cookie, 0), 0, "pre-open drops");
    // Isolate the zeroed interval from the target guard: armed
    // target, zeroed WINDOW — still nothing admitted.
    let mut armed = session_with(FakeCountBackend::new());
    armed.attach_delta(&d, &live, &files).unwrap();
    let cookie_a = armed.cookie_for(a.device, a.ino, off).unwrap();
    armed.open_window(1000, 2000).unwrap();
    armed.backend_mut().deprogram_window();
    armed.backend_mut().fire(PID, cookie_a, 1500, 11);
    assert_eq!(
        armed.backend().ledger_total(cookie_a, 0),
        0,
        "zeroed WINDOW admits nothing even while armed"
    );
    assert!(s.open_window(2000, 2000).is_err(), "empty window rejected");
    assert!(
        s.open_window(2000, 1000).is_err(),
        "inverted window rejected"
    );
    assert!(!s.window_open());
    s.open_window(1000, 2000).unwrap();
    assert!(s.open_window(1000, 2000).is_err(), "double open rejected");
    s.backend_mut().fire(PID, cookie, 1500, 4);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 4);
    // Post-close hits drop: userspace cancellation ends counting.
    s.backend_mut().fire(PID, cookie, 1500, 9);
    assert_eq!(s.backend().ledger_total(cookie, 0), 4);
}

#[test]
fn map_full_is_explicit() {
    // A saturated COUNTS map never evicts: excess inserts fail into
    // the explicit drop-loss counter while admitted keys stay exact.
    let stage = Stage::fresh("mapfull");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 3);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::with_capacity(2));
    let d = CountDelta {
        discovered: offs
            .iter()
            .enumerate()
            .map(|(i, off)| site(&a, *off, 7 + i as u32))
            .collect(),
        losses: Vec::new(),
    };
    let rep = s.attach_delta(&d, &live, &files).unwrap();
    assert_eq!(rep.attached, 3);
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 2000).unwrap();
    s.backend_mut().fire(PID, cookies[0], 1500, 5);
    s.backend_mut().fire(PID, cookies[1], 1500, 3);
    s.backend_mut().fire(PID, cookies[2], 1500, 9); // no room: drops

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 8, "admitted keys stay exact");
    assert_eq!(drain.current.len(), 2);
    // The surviving keys keep their own identities and counts — the
    // dropped key evicts nothing and perturbs nothing.
    let by_offset: HashMap<u64, u64> = drain
        .current
        .iter()
        .map(|e| (e.site.offset, e.calls))
        .collect();
    assert_eq!(by_offset.get(&offs[0]), Some(&5));
    assert_eq!(by_offset.get(&offs[1]), Some(&3));
    assert!(!by_offset.contains_key(&offs[2]));
    assert_eq!(
        counter_value(&drain, "count.map_insert_dropped"),
        Some(9),
        "saturation is explicit loss"
    );
    // Drops are loss, not unattributed misrouting.
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(0));
}

#[test]
fn per_key_threaded_counts() {
    // Eight keys hammered from four threads through a shared
    // session: every per-key total and the grand total are exact —
    // no lost updates through the shared handle, no cross-key
    // bleed, conservation holds. This pins threaded-caller
    // correctness of the session ledger, not lock-free BPF
    // concurrency (production aggregation is per-CPU in-kernel plus
    // a single-threaded drain; the live rate lane proves that).
    const KEYS: usize = 8;
    const THREADS: usize = 4;
    const PER_THREAD_PER_KEY: u64 = 250;
    let stage = Stage::fresh("threaded");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, KEYS);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: offs
            .iter()
            .enumerate()
            .map(|(i, off)| site(&a, *off, 7 + i as u32))
            .collect(),
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files).unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    assert_eq!(cookies.len(), KEYS);
    s.open_window(1000, 2000).unwrap();

    let shared = Arc::new(Mutex::new(s));
    let mut handles = Vec::new();
    for t in 0..THREADS {
        let shared = Arc::clone(&shared);
        let cookies = cookies.clone();
        handles.push(std::thread::spawn(move || {
            for m in 0..PER_THREAD_PER_KEY {
                for (k, cookie) in cookies.iter().enumerate() {
                    // Deterministic in-window timestamps.
                    let now = 1000 + ((t as u64 * 131 + m * 17 + k as u64 * 7) % 999);
                    shared
                        .lock()
                        .unwrap()
                        .backend_mut()
                        .fire(PID, *cookie, now, 1);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let mut s = match Arc::try_unwrap(shared) {
        Ok(mutex) => match mutex.into_inner() {
            Ok(s) => s,
            Err(_) => panic!("session mutex poisoned"),
        },
        Err(_) => panic!("session arc still shared"),
    };
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    let expect_per_key = THREADS as u64 * PER_THREAD_PER_KEY;
    assert_eq!(drain.current.len(), KEYS);
    // Identity-matched per-key exactness: every planned offset
    // appears exactly once with the full threaded total, so a
    // balanced misattribution (two keys swapped, one doubled and one
    // dropped) cannot pass.
    let by_offset: HashMap<u64, u64> = drain
        .current
        .iter()
        .map(|e| (e.site.offset, e.calls))
        .collect();
    assert_eq!(by_offset.len(), KEYS);
    for off in &offs {
        assert_eq!(by_offset.get(off), Some(&expect_per_key));
    }
    for exec in &drain.current {
        assert!(exec.first_ns <= exec.last_ns);
        assert!((1000..2000).contains(&exec.first_ns));
        assert!((1000..2000).contains(&exec.last_ns));
    }
    assert_eq!(drain.total_calls(), KEYS as u64 * expect_per_key);
    // Backend ledgers agree key-by-key with the routed output.
    for cookie in &cookies {
        assert_eq!(s.backend().ledger_total(*cookie, 0), expect_per_key);
    }
}

#[test]
fn kernel_source_enforces_window() {
    // Tripwire, not execution proof (same precedent as the privacy
    // source-shape pins): the BPF program must declare the WINDOW
    // interval map and enforce start-inclusive / deadline-exclusive
    // admission from the shared ABI cells. Removing the kernel check
    // fails here; the privileged live lane proves execution.
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/src/bin/count.rs"),
    )
    .unwrap();
    assert!(
        src.contains("static WINDOW: Array<u64>"),
        "count program must declare the WINDOW interval map"
    );
    assert!(
        src.contains("now < start || now >= deadline"),
        "count program must enforce [start, deadline) admission"
    );
    assert!(
        src.contains("WINDOW_START") && src.contains("WINDOW_DEADLINE"),
        "count program must index WINDOW from the shared ABI"
    );
    assert!(
        !src.contains("bpf_probe_read"),
        "count program stays entry-only: no target-memory reads"
    );
}

/// Backend double that swaps the attached file mid-attach (models a
/// same-path replacement landing between the pre and post samples).
struct SwapBackend {
    inner: FakeCountBackend,
    swap: std::cell::RefCell<Option<(PathBuf, Vec<u8>)>>,
}

impl SwapBackend {
    fn fire(&mut self, tgid: u32, cookie: u32, now_ns: u64, n: u64) {
        self.inner.fire(tgid, cookie, now_ns, n);
    }
}

impl CountBackend for SwapBackend {
    type Link = FakeLink;

    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<FakeLink>, Vec<usize>) {
        if let Some((p, bytes)) = self.swap.borrow_mut().take() {
            std::fs::remove_file(&p).unwrap();
            std::fs::write(&p, &bytes).unwrap();
        }
        self.inner.attach(path, offsets, cookies)
    }

    fn open_window(
        &mut self,
        tgid: u64,
        generation: u32,
        start_ns: u64,
        deadline_ns: u64,
    ) -> anyhow::Result<()> {
        self.inner
            .open_window(tgid, generation, start_ns, deadline_ns)
    }

    fn set_generation(&mut self, generation: u32) -> anyhow::Result<()> {
        self.inner.set_generation(generation)
    }

    fn close_window(&mut self) -> anyhow::Result<()> {
        self.inner.close_window()
    }

    fn drain(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> anyhow::Result<osslscope::count_session::DrainedCounts> {
        self.inner.drain(deadline)
    }
}

#[test]
fn replaced_during_attach_quarantines_hits() {
    // A1: the path moves mid-attach (pre=old, post=new): links drop
    // AND the cookie quarantines — hits recorded under the dropped
    // links drain as unattributed loss, never misattributed to the
    // stale provenance.
    let stage = Stage::fresh("a1drop");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let backend = SwapBackend {
        inner: FakeCountBackend::new(),
        swap: std::cell::RefCell::new(Some((PathBuf::from(&a.path), bytes.clone()))),
    };
    let mut s = CountSession::new(PID, backend);
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s.attach_delta(&d, &live, &files).unwrap();
    assert!(
        report.missed.iter().any(|m| m.reason == "replaced"),
        "mid-attach replacement must drop links: {report:?}"
    );
    assert_eq!(report.attached, 0);
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    // In-flight hits under the dropped links (recorded while they
    // were briefly live, drained after the drop).
    s.backend_mut().fire(PID, cookie, 1500, 7);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert!(
        drain.current.is_empty(),
        "dropped-link hits must not attribute: {:?}",
        drain.current
    );
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(7));
}

#[test]
fn fake_backend_folds_bounds_monotonically() {
    // Out-of-order fires (the thread-interleave model) keep
    // first<=last: the single-slot fake emulates per-CPU slots +
    // the userspace min/max fold, not last-write-wins. Pins the
    // per_key_threaded_counts flake (first>last under race).
    let stage = Stage::fresh("fakefold");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 1);
    s.backend_mut().fire(PID, cookie, 1000, 1);
    s.backend_mut().fire(PID, cookie, 1999, 1);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.current.len(), 1);
    let exec = &drain.current[0];
    assert_eq!((exec.calls, exec.first_ns, exec.last_ns), (3, 1000, 1999));
}

#[test]
fn quarantined_cookie_skips_reattach_until_fence() {
    // A1: a dropped cookie stays quarantined for the generation
    // (re-attach reports quarantined, never re-binds), and the
    // fence clears quarantine (the stale identity then fails its
    // verify as replaced — the new file needs re-discovery).
    let stage = Stage::fresh("a1quar");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let backend = SwapBackend {
        inner: FakeCountBackend::new(),
        swap: std::cell::RefCell::new(Some((PathBuf::from(&a.path), bytes.clone()))),
    };
    let mut s = CountSession::new(PID, backend);
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s.attach_delta(&d, &live, &files).unwrap();
    assert!(report.missed.iter().any(|m| m.reason == "replaced"));
    // Same generation, same (stale) row: quarantined, not rebound.
    let report2 = s.attach_delta(&d, &live, &files).unwrap();
    assert_eq!(report2.attached, 0);
    assert!(
        report2.missed.iter().any(|m| m.reason == "quarantined"),
        "quarantined cookie must report quarantined: {report2:?}"
    );
    // Fence clears quarantine: the stale identity fails verify as
    // replaced (no silent re-bind, no quarantine shadow).
    s.open_window(1000, 2000).unwrap();
    s.fence(FenceReason::ProviderChanged).unwrap();
    let report3 = s.attach_delta(&d, &live, &files).unwrap();
    assert!(
        !report3.missed.iter().any(|m| m.reason == "quarantined"),
        "fence must clear quarantine: {report3:?}"
    );
    assert!(
        report3.missed.iter().any(|m| m.reason == "replaced"),
        "stale identity must fail verify as replaced: {report3:?}"
    );
}
