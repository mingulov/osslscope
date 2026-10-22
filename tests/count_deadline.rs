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

use osslscope::count_session::*;

fn test_deadline() -> std::time::Instant {
    std::time::Instant::now() + Duration::from_secs(5)
}

const PID: u32 = 4242;

// Incidental attach stamp for the tests that predate installed-at:
// none of them assert on it.
const ATTACH_AT: u64 = 900;

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
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
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
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();

    s.backend_mut().fire(PID, cookie, 1500, 11);
    assert_eq!(s.backend().ledger_total(cookie, 0), 0, "pre-open drops");
    // Isolate the zeroed interval from the target guard: armed
    // target, zeroed WINDOW — still nothing admitted.
    let mut armed = session_with(FakeCountBackend::new());
    armed
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie_a = armed.cookie_for(a.device, a.ino, off).unwrap();
    armed.open_window(1000, 2000, test_deadline()).unwrap();
    armed.backend_mut().deprogram_window();
    armed.backend_mut().fire(PID, cookie_a, 1500, 11);
    assert_eq!(
        armed.backend().ledger_total(cookie_a, 0),
        0,
        "zeroed WINDOW admits nothing even while armed"
    );
    assert!(
        s.open_window(2000, 2000, test_deadline()).is_err(),
        "empty window rejected"
    );
    assert!(
        s.open_window(2000, 1000, test_deadline()).is_err(),
        "inverted window rejected"
    );
    assert!(!s.window_open());
    s.open_window(1000, 2000, test_deadline()).unwrap();
    assert!(
        s.open_window(1000, 2000, test_deadline()).is_err(),
        "double open rejected"
    );
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
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    let rep = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(rep.attached, 3);
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 2000, test_deadline()).unwrap();
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
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    assert_eq!(cookies.len(), KEYS);
    s.open_window(1000, 2000, test_deadline()).unwrap();

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
fn ledger_admitted_reconciles_to_zero() {
    // c6 independent physical ledger: every admitted hit accounts
    // into routed calls or map-full drops — the reconciliation
    // delta is exactly zero on a clean window.
    const KEYS: usize = 4;
    const PER_KEY: u64 = 250;
    let stage = Stage::fresh("ledger-clean");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, KEYS);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    for (k, cookie) in cookies.iter().enumerate() {
        for m in 0..PER_KEY {
            let now = 1000 + ((m * 17 + k as u64 * 7) % 999);
            s.backend_mut().fire(PID, *cookie, now, 1);
        }
    }
    let expect = KEYS as u64 * PER_KEY;
    assert_eq!(s.backend().admitted_ledger(), expect);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), expect);
    assert_eq!(counter_value(&drain, "count.ledger_admitted"), Some(expect));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn ledger_delta_sounds_on_unaccounted_admission() {
    // The ledger is INDEPENDENT of the routed rows: a row that
    // bypasses admission (inject_row models a backend anomaly)
    // sounds count.ledger_delta instead of vanishing.
    let stage = Stage::fresh("ledger-anomaly");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 10);
    s.backend_mut().inject_row(
        cookie,
        0,
        osslscope_ebpf_common::CountValue {
            count: 5,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 15);
    assert_eq!(counter_value(&drain, "count.ledger_admitted"), Some(10));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(5));
}

#[test]
fn ledger_unreconciled_under_shortfall() {
    // Under drain shortfall the unread keys' calls are unknowable:
    // no count.ledger_delta Loss is emitted (it would be a lie);
    // the open gap stays visible as count.ledger_unreconciled.
    let stage = Stage::fresh("ledger-shortfall");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 2);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: offs.iter().map(|off| site(&a, *off, 7)).collect(),
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let mut opened = false;
    for off in &offs {
        let cookie = s.cookie_for(a.device, a.ino, *off).unwrap();
        if !opened {
            assert!(s.open_window(1000, 2000, test_deadline()).is_ok());
            opened = true;
        } else {
            s.open_window(1000, 2000, test_deadline()).unwrap_or(());
        }
        s.backend_mut().fire(PID, cookie, 1500, 10);
    }
    s.backend_mut().set_shortfall(2);
    let terminal = s.terminal(CloseRequest {
        started_at: Instant::now(),
        grace: Duration::from_secs(5),
        reason: CloseReason::Expired,
    });
    assert!(
        s.close_and_drain(Duration::from_secs(5)).is_err(),
        "incomplete terminal must not pass the temporary bridge"
    );
    let drain = terminal.retained_drain;
    assert_eq!(counter_value(&drain, "count.drain_shortfall"), Some(2));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), None);
    assert!(counter_value(&drain, "count.ledger_unreconciled").is_some());
}

#[test]
fn hot_key_concentration_exact() {
    // c6 hot-key conservation: one 100k hot key plus cold keys —
    // every per-key total and the grand total exact, ledger silent.
    const COLD: usize = 7;
    const HOT_N: u64 = 100_000;
    const COLD_N: u64 = 13;
    let stage = Stage::fresh("hotkey");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1 + COLD);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    for m in 0..HOT_N {
        s.backend_mut().fire(PID, cookies[0], 1000 + (m % 999), 1);
    }
    for (k, cookie) in cookies.iter().enumerate().skip(1) {
        for m in 0..COLD_N {
            s.backend_mut()
                .fire(PID, *cookie, 1000 + ((m * 17 + k as u64) % 999), 1);
        }
    }
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    let by_offset: HashMap<u64, u64> = drain
        .current
        .iter()
        .map(|e| (e.site.offset, e.calls))
        .collect();
    assert_eq!(by_offset.get(&offs[0]), Some(&HOT_N));
    for off in offs.iter().skip(1) {
        assert_eq!(by_offset.get(off), Some(&COLD_N));
    }
    assert_eq!(drain.total_calls(), HOT_N + COLD as u64 * COLD_N);
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn fanout_eight_cpus_fold_exact() {
    // c6 >2-CPU fan-out fold: 8 CPUs x 6 keys land in per-CPU
    // slots and fold to exact per-key totals with in-window
    // bounds. Compile-RED: fire_cpu is new this task.
    const CPUS: u32 = 8;
    const KEYS: usize = 6;
    const PER_CPU_PER_KEY: u64 = 250;
    let stage = Stage::fresh("fanout8");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, KEYS);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    for cpu in 0..CPUS {
        for (k, cookie) in cookies.iter().enumerate() {
            for m in 0..PER_CPU_PER_KEY {
                let now = 1000 + ((cpu as u64 * 131 + m * 17 + k as u64 * 7) % 999);
                s.backend_mut().fire_cpu(cpu, PID, *cookie, now, 1);
            }
        }
    }
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    let expect_per_key = CPUS as u64 * PER_CPU_PER_KEY;
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
    }
    assert_eq!(drain.total_calls(), KEYS as u64 * expect_per_key);
    for cookie in &cookies {
        assert_eq!(s.backend().ledger_total(*cookie, 0), expect_per_key);
    }
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn fanout_mixed_fire_and_fire_cpu_conserves() {
    // Mixed single-slot and per-CPU fires on one key sum exactly
    // once — no double-count, no bleed into the sibling key.
    let stage = Stage::fresh("fanout-mixed");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 2);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: offs.iter().map(|off| site(&a, *off, 7)).collect(),
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let c0 = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    let c1 = s.cookie_for(a.device, a.ino, offs[1]).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, c0, 1500, 40);
    s.backend_mut().fire_cpu(3, PID, c0, 1501, 60);
    s.backend_mut().fire_cpu(7, PID, c1, 1502, 25);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    let by_offset: HashMap<u64, u64> = drain
        .current
        .iter()
        .map(|e| (e.site.offset, e.calls))
        .collect();
    assert_eq!(by_offset.get(&offs[0]), Some(&100));
    assert_eq!(by_offset.get(&offs[1]), Some(&25));
    assert_eq!(drain.total_calls(), 125);
    assert_eq!(s.backend().ledger_total(c0, 0), 100);
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn fresh_key_churn_across_fence_conserves() {
    // c6 fresh-key churn: 64 fresh keys fire once in gen 0 and
    // once in gen 1 — every key totals exactly 2 across the
    // fence, nothing relabeled, ledger silent.
    const KEYS: usize = 64;
    let stage = Stage::fresh("churn");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, KEYS);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 3000, test_deadline()).unwrap();
    for (k, cookie) in cookies.iter().enumerate() {
        s.backend_mut().fire(PID, *cookie, 1100 + k as u64, 1);
    }
    s.fence(
        osslscope::count_session::FenceReason::MappingsChanged,
        test_deadline(),
    )
    .unwrap();
    for (k, cookie) in cookies.iter().enumerate() {
        s.backend_mut().fire(PID, *cookie, 2100 + k as u64, 1);
    }
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].generation, 0);
    let fenced_calls: u64 = drain.fenced[0].sites.iter().map(|e| e.calls).sum();
    let current_calls: u64 = drain.current.iter().map(|e| e.calls).sum();
    assert_eq!(fenced_calls, KEYS as u64);
    assert_eq!(current_calls, KEYS as u64);
    assert_eq!(drain.total_calls(), 2 * KEYS as u64);
    for exec in drain.fenced[0].sites.iter().chain(drain.current.iter()) {
        assert_eq!(exec.calls, 1);
    }
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn per_key_conservation_across_two_fences() {
    // Per-key totals stay exact across two fences with distinct
    // per-generation counts (10/20/30 per key).
    const KEYS: usize = 4;
    let stage = Stage::fresh("two-fences");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, KEYS);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookies: Vec<u32> = offs
        .iter()
        .map(|off| s.cookie_for(a.device, a.ino, *off).unwrap())
        .collect();
    s.open_window(1000, 4000, test_deadline()).unwrap();
    for (round, n) in [10u64, 20, 30].into_iter().enumerate() {
        for (k, cookie) in cookies.iter().enumerate() {
            let now = 1100 + round as u64 * 1000 + k as u64;
            s.backend_mut().fire(PID, *cookie, now, n);
        }
        if round < 2 {
            s.fence(
                osslscope::count_session::FenceReason::MappingsChanged,
                test_deadline(),
            )
            .unwrap();
        }
    }
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 2);
    for (g, expect) in [(0usize, 10u64), (1, 20)] {
        assert_eq!(drain.fenced[g].generation, g as u32);
        let by_offset: HashMap<u64, u64> = drain.fenced[g]
            .sites
            .iter()
            .map(|e| (e.site.offset, e.calls))
            .collect();
        for off in &offs {
            assert_eq!(by_offset.get(off), Some(&expect));
        }
    }
    let by_offset: HashMap<u64, u64> = drain
        .current
        .iter()
        .map(|e| (e.site.offset, e.calls))
        .collect();
    for off in &offs {
        assert_eq!(by_offset.get(off), Some(&30));
    }
    assert_eq!(drain.total_calls(), KEYS as u64 * 60);
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
}

#[test]
fn p6_subpoll_replacement_keeps_old_meaning() {
    // P6 sub-poll replacement: a changed candidate set stages a
    // pending meaning; pre-fence hits keep the OLD meaning and
    // seal under it — old records are never relabeled.
    let stage = Stage::fresh("p6-subpoll");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d0 = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d0, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    let before = s.provenance(cookie).unwrap().candidates.clone();
    s.open_window(1000, 3000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 50);
    // Sub-poll replacement: same triple, new candidates.
    let d1 = CountDelta {
        discovered: vec![site(&a, offs[0], 9)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&d1, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert!(
        report.candidates_changed,
        "replacement must stage an update"
    );
    s.backend_mut().fire(PID, cookie, 1600, 30);
    s.fence(
        osslscope::count_session::FenceReason::CandidatesChanged,
        test_deadline(),
    )
    .unwrap();
    s.backend_mut().fire(PID, cookie, 2500, 20);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites.len(), 1);
    assert_eq!(drain.fenced[0].sites[0].calls, 80);
    assert_eq!(
        drain.fenced[0].sites[0].candidates, before,
        "fenced generation must keep the pre-replacement meaning"
    );
    assert_eq!(drain.current.len(), 1);
    assert_eq!(drain.current[0].calls, 20);
    assert_ne!(
        drain.current[0].candidates, before,
        "current generation must carry the replacement meaning"
    );
    assert_eq!(counter_value(&drain, "count.stale_events"), Some(0));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
    assert_eq!(drain.total_calls(), 100);
}

#[test]
fn p6_stale_queued_events_keep_old_generation() {
    // P6 stale queued: old-generation hits landing after their
    // fence drain attribute under the OLD meaning while the
    // staleness memo records the crossing.
    let stage = Stage::fresh("p6-stale");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    let before = s.provenance(cookie).unwrap().candidates.clone();
    s.open_window(1000, 3000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 40);
    s.fence(
        osslscope::count_session::FenceReason::MappingsChanged,
        test_deadline(),
    )
    .unwrap();
    // Queued pre-fence hit lands after the fence drain.
    s.backend_mut().inject_row(
        cookie,
        0,
        osslscope_ebpf_common::CountValue {
            count: 15,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites.len(), 1);
    assert_eq!(drain.fenced[0].sites[0].calls, 55);
    assert_eq!(drain.fenced[0].sites[0].candidates, before);
    assert!(drain.current.is_empty());
    assert_eq!(counter_value(&drain, "count.stale_events"), Some(15));
    // The injected row bypasses admission, so the independent
    // ledger sounds exactly its 15 (Task 1 semantics).
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(15));
    assert_eq!(drain.total_calls(), 55);
}

#[test]
fn p6_unknown_generation_stays_unattributed() {
    // Defensive P6 arm: a generation never fenced is conserved
    // as explicit unattributed loss, never misattributed to the
    // live meaning — unavailable continuity stays a precise gap.
    let stage = Stage::fresh("p6-unknowngen");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().inject_row(
        cookie,
        9,
        osslscope_ebpf_common::CountValue {
            count: 5,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert!(drain.current.is_empty());
    assert!(drain.fenced.is_empty());
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(5));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(5));
}

#[test]
fn p6_impl_only_backing_replacement_never_relabels() {
    // P6 impl-only backing replacement: same candidates on a new
    // backing triple mints a new cookie; the old cookie's records
    // seal under gen 0 and are never relabeled as the replacement.
    let stage = Stage::fresh("p6-implonly");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let b = stage.write("prov2.so", &bytes);
    let live = vec![mapping(&a), mapping(&b)];
    let files = HashMap::from([
        (
            a.path.clone(),
            plan::FileBytes {
                bytes: std::fs::read(&a.path).unwrap().into(),
                dev: a.device,
                ino: a.ino,
            },
        ),
        (
            b.path.clone(),
            plan::FileBytes {
                bytes: std::fs::read(&b.path).unwrap().into(),
                dev: b.device,
                ino: b.ino,
            },
        ),
    ]);
    let mut s = session_with(FakeCountBackend::new());
    let d0 = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d0, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let c1 = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    let meaning1 = s.provenance(c1).unwrap().clone();
    s.open_window(1000, 3000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, c1, 1500, 40);
    // Same candidates, new backing triple (impl-only change).
    let d1 = CountDelta {
        discovered: vec![site(&b, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d1, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let c2 = s.cookie_for(b.device, b.ino, offs[0]).unwrap();
    assert_ne!(c1, c2, "new backing triple must mint a new cookie");
    assert_ne!(
        s.provenance(c1).unwrap().site,
        s.provenance(c2).unwrap().site
    );
    s.fence(
        osslscope::count_session::FenceReason::ProviderChanged,
        test_deadline(),
    )
    .unwrap();
    s.backend_mut().fire(PID, c2, 2500, 25);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites.len(), 1);
    assert_eq!(drain.fenced[0].sites[0].calls, 40);
    assert_eq!(drain.fenced[0].sites[0].site, meaning1.site);
    assert_eq!(drain.fenced[0].sites[0].candidates, meaning1.candidates);
    assert_eq!(drain.current.len(), 1);
    assert_eq!(drain.current[0].calls, 25);
    assert_eq!(drain.current[0].site, s.provenance(c2).unwrap().site);
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(0));
    assert_eq!(drain.total_calls(), 65);
}

#[test]
fn lat_bucket_boundaries_exact() {
    // Log2-ns buckets: k covers [2^k, 2^(k+1)); 15 clamps >=32768.
    use osslscope_ebpf_common::lat_bucket;
    assert_eq!(lat_bucket(0), 0);
    assert_eq!(lat_bucket(1), 0);
    assert_eq!(lat_bucket(2), 1);
    assert_eq!(lat_bucket(3), 1);
    assert_eq!(lat_bucket(2048), 11);
    assert_eq!(lat_bucket(4000), 11, "4us budget line sits in bucket 11");
    assert_eq!(lat_bucket(4095), 11);
    assert_eq!(lat_bucket(4096), 12);
    assert_eq!(lat_bucket(32767), 14);
    assert_eq!(lat_bucket(32768), 15);
    assert_eq!(lat_bucket(u64::MAX), 15);
}

#[test]
fn lat_median_p99_from_buckets() {
    // Upper-bucket-edge quantiles: 90 samples in bucket 5
    // ([32,64)) + 10 in bucket 14 ([16384,32768)) -> median 64,
    // p99 32768, samples 100.
    let stage = Stage::fresh("lat-quant");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 10);
    s.backend_mut().inject_latency(5, 90);
    s.backend_mut().inject_latency(14, 10);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(counter_value(&drain, "count.lat_samples"), Some(100));
    assert_eq!(counter_value(&drain, "count.lat_median_ns"), Some(64));
    assert_eq!(counter_value(&drain, "count.lat_p99_ns"), Some(32768));
    assert_eq!(counter_value(&drain, "count.lat_bucket_05"), Some(90));
    assert_eq!(counter_value(&drain, "count.lat_bucket_14"), Some(10));
    assert_eq!(counter_value(&drain, "count.lat_bucket_00"), Some(0));
}

#[test]
fn drain_stats_shape_recorded() {
    // c8 drain/memory score shape: a clean close runs exactly 2
    // quiesce passes (route + clean), total >= max, RSS sampled.
    let stage = Stage::fresh("drain-stats");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 2);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: offs.iter().map(|off| site(&a, *off, 7)).collect(),
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    for off in &offs {
        let cookie = s.cookie_for(a.device, a.ino, *off).unwrap();
        s.backend_mut().fire(PID, cookie, 1500, 5);
    }
    s.open_window(1000, 2000, test_deadline()).unwrap();
    for off in &offs {
        let cookie = s.cookie_for(a.device, a.ino, *off).unwrap();
        s.backend_mut().fire(PID, cookie, 1500, 5);
    }
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 10);
    assert_eq!(counter_value(&drain, "count.drain_passes"), Some(1));
    let total = counter_value(&drain, "count.drain_pass_ns_total").unwrap();
    let max = counter_value(&drain, "count.drain_pass_ns_max").unwrap();
    assert!(total >= max, "total {total} < max {max}");
    assert!(counter_value(&drain, "count.drain_rss_bytes").unwrap() > 0);
}

#[test]
fn drain_scan_tail_counts_exactly() {
    // c8 scan-tail: an expired drain stops re-scanning after one
    // pass (passes == 1) and the shortfall keys count exactly as
    // shortfall — never folded, never re-added.
    let stage = Stage::fresh("drain-tail");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 2);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: offs.iter().map(|off| site(&a, *off, 7)).collect(),
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    for off in &offs {
        let cookie = s.cookie_for(a.device, a.ino, *off).unwrap();
        s.backend_mut().fire(PID, cookie, 1500, 10);
    }
    s.backend_mut().set_shortfall(3);
    let terminal = s.terminal(CloseRequest {
        started_at: Instant::now(),
        grace: Duration::from_secs(5),
        reason: CloseReason::Expired,
    });
    assert!(
        s.close_and_drain(Duration::from_secs(5)).is_err(),
        "incomplete terminal must not pass the temporary bridge"
    );
    let drain = terminal.retained_drain;
    assert_eq!(counter_value(&drain, "count.drain_passes"), Some(1));
    assert_eq!(counter_value(&drain, "count.drain_shortfall"), Some(3));
    assert_eq!(counter_value(&drain, "count.ledger_delta"), None);
    assert_eq!(counter_value(&drain, "count.ledger_unreconciled"), Some(0));
}

#[test]
fn lat_fence_partial_deltas_fold_once() {
    // fence()+latency partial deltas (review-5 §2 probe): 80
    // samples in bucket 5 + 10 in bucket 14 pre-fence fold at
    // fence(); 20 more in bucket 5 post-fence; close folds only
    // the remainder — 110/100/10, each sample exactly once.
    let stage = Stage::fresh("lat-fence");
    let bytes = self_bytes();
    let offs = x_offsets(&bytes, 1);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, offs[0], 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, offs[0]).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 10);
    s.backend_mut().inject_latency(5, 80);
    s.backend_mut().inject_latency(14, 10);
    s.fence(
        osslscope::count_session::FenceReason::MappingsChanged,
        test_deadline(),
    )
    .unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 5);
    s.backend_mut().inject_latency(5, 20);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(counter_value(&drain, "count.lat_samples"), Some(110));
    assert_eq!(counter_value(&drain, "count.lat_bucket_05"), Some(100));
    assert_eq!(counter_value(&drain, "count.lat_bucket_14"), Some(10));
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
    assert!(
        src.contains("bump(slot, now)"),
        "count program must bump the present slot on the slow path"
    );
    assert!(
        src.matches("bump(slot, now)").count() >= 2,
        "both hit paths (fast + slow) must bump"
    );
}

/// Backend double that swaps the attached file mid-attach (models a
/// same-path replacement landing between the pre and post samples).
struct SwapBackend {
    inner: FakeCountBackend,
    swap: std::cell::RefCell<Option<(PathBuf, Vec<u8>)>>,
}

impl CountBackend for SwapBackend {
    type Link = FakeLink;
    fn ready(&self) -> &Ready {
        self.inner.ready()
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<FakeLink>> {
        let ack = self.inner.attach(request);
        if let Some((p, bytes)) = self.swap.borrow_mut().take() {
            // Create-then-rename (never remove-then-recreate:
            // freed inodes are reused immediately on some
            // filesystems — observed in CI).
            let tmp = p.with_extension("swap");
            std::fs::write(&tmp, &bytes).unwrap();
            std::fs::rename(&tmp, &p).unwrap();
        }
        ack
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        self.inner.open_window(request)
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        self.inner.set_generation(request)
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<std::sync::Arc<RawSnapshot>> {
        self.inner.drain(request)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        self.inner.terminal_request(deadline, frontier)
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        self.inner.terminal(request)
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.inner.progress()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.inner.fork_permit(deadline)
    }
}

#[test]
fn h4_t4_rejected_resolve_attaches_nothing_drains_empty() {
    // H4 (quarantine-by-construction guard): a resolve the
    // session rejects (planned identity no longer on disk)
    // binds NO link — backend.attach is never invoked — so
    // the drain is exactly empty: no sites, no unattributed
    // (nothing was ever bound, nothing in flight to route).
    // GREEN before and after the H4 refactor — the refactor
    // must not break it.
    let stage = Stage::fresh("h4t4");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    // Replace BEFORE attach (new inode; planned identity stale).
    // Replace via create-then-rename: two coexisting files never
    // share an ino, so the new identity holds even on filesystems
    // that immediately reuse a freed inode (observed in CI).
    let swap = stage.write("prov.swap", &bytes);
    assert_ne!(swap.ino, a.ino);
    std::fs::rename(&swap.path, &a.path).unwrap();
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert!(
        report.missed.iter().any(|m| m.reason == "replaced"),
        "stale plan must not bind: {report:?}"
    );
    assert_eq!(report.attached, 0);
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    assert_eq!(
        s.backend().attached_path(cookie),
        None,
        "rejected resolve must never reach the backend"
    );
    s.open_window(1000, 2000, test_deadline()).unwrap();
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert!(drain.current.is_empty());
    assert_eq!(
        counter_value(&drain, "count.unattributed"),
        Some(0),
        "rejected resolve routes nothing to unattributed"
    );
}

#[test]
fn h4_t3_pin_survives_path_deletion_until_session_drop() {
    // H4: the link table owns the pin — deleting the path does
    // not release the inode (the fd-path still stats to the
    // pinned identity), and dropping the session releases it
    // (the fd-path goes dangling — or, if the number was
    // recycled, it never stats to the deleted inode again).
    let stage = Stage::fresh("h4t3");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report.attached, 1);
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    let at = s
        .backend()
        .attached_path(cookie)
        .expect("backend records the attach path")
        .to_string();
    assert!(at.starts_with("/proc/self/fd/"), "fd-path form: {at:?}");
    std::fs::remove_file(&a.path).unwrap();
    assert_eq!(
        std::fs::metadata(&at).unwrap().ino(),
        a.ino,
        "pin must retain the deleted inode"
    );
    drop(s);
    match std::fs::metadata(&at) {
        Err(_) => {}
        Ok(meta) => assert_ne!(meta.ino(), a.ino, "session drop must release the pin"),
    }
}

#[test]
fn h4_t1_mid_attach_swap_binds_pinned_inode_via_fd_path() {
    // H4: the A→B→A race is unrepresentable — the session pins
    // (open+fstat) BEFORE backend.attach, so a mid-attach swap
    // is simply not observed: the attach binds the pinned
    // (planned) inode through an fd-path, records it, and an
    // immediate re-attach reuses the live link (no quarantine
    // stickiness — nothing was ever bound wrong).
    // RED pre-H4 (backend receives the group path; replaced).
    let stage = Stage::fresh("h4t1");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
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
    let report = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report.attached, 1, "pinned attach must bind: {report:?}");
    assert!(
        report.missed.iter().all(|m| m.reason != "replaced"),
        "no replacement observed mid-attach: {report:?}"
    );
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    let at = s
        .backend()
        .inner
        .attached_path(cookie)
        .expect("backend records the attach path")
        .to_string();
    assert!(
        at.starts_with("/proc/self/fd/"),
        "backend must receive an fd-path, got {at:?}"
    );
    // The pin holds the PLANNED (old) inode, not the swap's.
    assert_eq!(
        std::fs::metadata(&at).unwrap().ino(),
        a.ino,
        "fd-path must stat to the pinned inode"
    );
    assert_ne!(
        std::fs::metadata(&a.path).unwrap().ino(),
        a.ino,
        "the swap must have landed (race actually raced)"
    );
    // Immediate re-attach: the live pinned link reuses (old
    // behavior quarantined here — the stickiness is gone).
    let report2 = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report2.reused, 1, "live pin must reuse: {report2:?}");
    assert!(
        report2.missed.iter().all(|m| m.reason != "quarantined"),
        "nothing quarantines post-H4: {report2:?}"
    );
}

#[test]
fn h4_unbound_cookie_hits_route_unattributed() {
    // H4 rework of replaced_during_attach_quarantines_hits: the
    // !bound setup (mid-attach race → rollback) is unrepresentable
    // post-pin — but the drain-side proposition survives: hits
    // under a cookie with NO bound link (backend anomaly model)
    // drain as unattributed loss, never misattributed.
    let stage = Stage::fresh("h4unbound");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    // Stale plan: nothing binds (H4-T4 shape).
    // Replace via create-then-rename: two coexisting files never
    // share an ino, so the new identity holds even on filesystems
    // that immediately reuse a freed inode (observed in CI).
    let swap = stage.write("prov.swap", &bytes);
    assert_ne!(swap.ino, a.ino);
    std::fs::rename(&swap.path, &a.path).unwrap();
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report.attached, 0);
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    // Backend anomaly: hits under the unbound cookie.
    s.backend_mut().fire(PID, cookie, 1500, 7);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert!(
        drain.current.is_empty(),
        "unbound-cookie hits must not attribute: {:?}",
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
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 1);
    s.backend_mut().fire(PID, cookie, 1000, 1);
    s.backend_mut().fire(PID, cookie, 1999, 1);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.current.len(), 1);
    let exec = &drain.current[0];
    assert_eq!((exec.calls, exec.first_ns, exec.last_ns), (3, 1000, 1999));
}

#[test]
fn h4_stale_plan_misses_replaced_per_attempt() {
    // H4 rework of quarantined_cookie_skips_reattach_until_fence:
    // no quarantine set exists — a stale plan misses `replaced`
    // on EVERY attempt (same generation, across fences), having
    // bound nothing; recovery arrives only via a fresh delta
    // planned against the current file.
    let stage = Stage::fresh("h4stale");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    // Replace before any attach: the plan below is born stale.
    // Replace via create-then-rename: two coexisting files never
    // share an ino, so the new identity holds even on filesystems
    // that immediately reuse a freed inode (observed in CI).
    let swap = stage.write("prov.swap", &bytes);
    assert_ne!(swap.ino, a.ino);
    std::fs::rename(&swap.path, &a.path).unwrap();
    let meta = std::fs::metadata(&a.path).unwrap();
    let b = Staged {
        path: a.path.clone(),
        device: plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
        ino: meta.ino(),
    };
    assert_ne!(a.ino, b.ino, "replace must move the inode");
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let stale = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&stale, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report.attached, 0);
    assert!(report.missed.iter().any(|m| m.reason == "replaced"));
    // Same generation, same stale row: replaced again (no
    // quarantine shadow — per-attempt re-resolve).
    let report2 = s
        .attach_delta(&stale, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report2.attached, 0);
    assert!(
        report2.missed.iter().any(|m| m.reason == "replaced"),
        "stale plan must miss replaced per attempt: {report2:?}"
    );
    assert!(
        report2.missed.iter().all(|m| m.reason != "quarantined"),
        "no quarantine vocabulary post-H4: {report2:?}"
    );
    // Across a fence: still replaced (recovery needs re-discovery).
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.fence(FenceReason::ProviderChanged, test_deadline())
        .unwrap();
    let report3 = s
        .attach_delta(&stale, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert!(
        report3.missed.iter().any(|m| m.reason == "replaced"),
        "stale identity stays replaced across fences: {report3:?}"
    );
    // Fresh delta against the current file (with re-discovered
    // bytes bound to the new identity): binds.
    let fresh = CountDelta {
        discovered: vec![site(&b, off, 7)],
        losses: Vec::new(),
    };
    let live_b = vec![mapping(&b)];
    let files_b = HashMap::from([(
        b.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&b.path).unwrap().into(),
            dev: b.device,
            ino: b.ino,
        },
    )]);
    let report4 = s
        .attach_delta(&fresh, &live_b, &files_b, ATTACH_AT, test_deadline())
        .unwrap();
    assert_eq!(report4.attached, 1, "fresh plan must bind: {report4:?}");
}

// ── R04: forced two-CPU first-hit rendezvous model (F05) ──
//
// Models the BPF `count_entry` fresh-key transaction step by step
// (lookup → NOEXIST insert → …) and drives the schedule the
// threaded host tests cannot: BOTH CPUs miss the same fresh key
// before either inserts, so the second insert collides. The script
// below must track `crates/ebpf/src/bin/count.rs` line by line;
// `r04_source_binds_model_to_branch` plus disassembly inspection
// of the compiled `count_entry` bind the model to the actual
// control flow.
//
// LIMITS (read before citing): this is a host-side schedule
// driver over an emulated map. It proves the transaction shape
// counts a forced collision correctly; it does NOT execute BPF,
// does not run two kernel CPUs, and does not replace the
// authorized two-CPU fresh-key/fresh-generation exact-ledger run
// owned by R21.
mod r04_rendezvous {
    use osslscope_ebpf_common::CountValue;
    use std::collections::HashMap;

    /// The forced schedule uses exactly two CPUs.
    pub const NCPU: usize = 2;

    #[derive(Debug, PartialEq, Eq)]
    pub enum InsertOutcome {
        Inserted,
        Exists,
        NoSpace,
    }

    /// Emulated `COUNTS` per-CPU hash: shared keys, one
    /// `CountValue` slot per CPU, bounded capacity, no eviction.
    /// A helper insert seeds the CURRENT CPU's slot and zeroes
    /// the rest (matches the validated F05 schedule: one count,
    /// one DROPFAIL pre-fix; post-fix the seed is all-zero so
    /// every slot starts 0 under either seeding rule).
    pub struct FirstHitMap {
        cap: usize,
        entries: HashMap<u64, [CountValue; NCPU]>,
        pub dropfail: u64,
        /// Fault injection: the next relookup reports None even
        /// when the key exists (models an unavailable slot).
        pub fail_relookup_once: bool,
    }

    impl FirstHitMap {
        pub fn new(cap: usize) -> Self {
            Self {
                cap,
                entries: HashMap::new(),
                dropfail: 0,
                fail_relookup_once: false,
            }
        }

        /// First lookup: is the shared key present?
        pub fn lookup(&self, key: u64) -> bool {
            self.entries.contains_key(&key)
        }

        /// Slow-path relookup after the zero-seed insert.
        pub fn relookup(&mut self, key: u64) -> bool {
            if self.fail_relookup_once {
                self.fail_relookup_once = false;
                return false;
            }
            self.entries.contains_key(&key)
        }

        /// `insert(key, seed, BPF_NOEXIST)`: fresh key under
        /// capacity inserts; an existing key collides; a fresh
        /// key at capacity is genuine exhaustion.
        pub fn insert_noexist(&mut self, cpu: usize, key: u64, seed: CountValue) -> InsertOutcome {
            if self.entries.contains_key(&key) {
                return InsertOutcome::Exists;
            }
            if self.entries.len() >= self.cap {
                return InsertOutcome::NoSpace;
            }
            let mut slots = [CountValue::default(); NCPU];
            slots[cpu] = seed;
            self.entries.insert(key, slots);
            InsertOutcome::Inserted
        }

        /// The ordinary per-CPU bump shared by every hit path:
        /// stamp first touch, saturating-add one, stamp last.
        /// Panics on an absent key: callers bump only slots a
        /// lookup just proved present.
        pub fn bump(&mut self, cpu: usize, key: u64, now: u64) {
            let slots = self.entries.get_mut(&key).expect("bump needs a slot");
            let v = &mut slots[cpu];
            if v.count == 0 {
                v.first_ns = now;
            }
            v.count = v.count.saturating_add(1);
            v.last_ns = now;
        }

        pub fn dropfail(&mut self) {
            self.dropfail = self.dropfail.saturating_add(1);
        }

        /// Userspace drain fold over this key's CPU slots.
        pub fn fold_total(&self, key: u64) -> u64 {
            self.entries
                .get(&key)
                .map(|slots| slots.iter().map(|v| v.count).sum())
                .unwrap_or(0)
        }
    }

    /// Mirror of the FIXED `count_entry` miss path (`count.rs`):
    /// zero-seed NOEXIST insert — a collision is recoverable, so
    /// the result is ignored — then one ordinary relookup:
    /// present → the single bump, absent → DROPFAIL.
    pub fn miss_path(map: &mut FirstHitMap, cpu: usize, key: u64, now: u64) {
        let zero = CountValue {
            count: 0,
            first_ns: 0,
            last_ns: 0,
        };
        let _ = map.insert_noexist(cpu, key, zero);
        if map.relookup(key) {
            map.bump(cpu, key, now);
        } else {
            map.dropfail();
        }
    }
}

#[test]
fn r04_two_cpu_first_hits_both_count_fresh_key() {
    // Forced collision on a FRESH key with spare capacity: both
    // CPUs miss, cpu0's zero-insert wins, cpu1's collides — and
    // both hits count with no drop (the relookup recovers the
    // collision). RED pre-fix: count 1, drop 1.
    use osslscope_ebpf_common::make_key;
    use r04_rendezvous::{FirstHitMap, miss_path};
    let key = make_key(41, 0);
    let mut map = FirstHitMap::new(8192);
    // Rendezvous: both first lookups miss BEFORE either insert.
    assert!(!map.lookup(key), "cpu0 first lookup misses fresh key");
    assert!(!map.lookup(key), "cpu1 first lookup misses fresh key");
    miss_path(&mut map, 0, key, 1500);
    miss_path(&mut map, 1, key, 1501);
    assert_eq!(map.fold_total(key), 2, "both first hits count");
    assert_eq!(map.dropfail, 0, "no loss with spare capacity");
}

#[test]
fn r04_two_cpu_first_hits_both_count_fresh_generation() {
    // Same forced collision on a FRESH GENERATION of an already
    // counted cookie: the fenced key is new, so both hits count
    // without loss while the old generation stays exact.
    // RED pre-fix: new-gen count 1, drop 1.
    use osslscope_ebpf_common::make_key;
    use r04_rendezvous::{FirstHitMap, miss_path};
    let old_key = make_key(41, 0);
    let new_key = make_key(41, 1);
    let mut map = FirstHitMap::new(8192);
    // Old generation counted earlier (sequential, uncontended).
    miss_path(&mut map, 0, old_key, 1400);
    map.bump(0, old_key, 1401);
    assert_eq!(map.fold_total(old_key), 2);
    // Rendezvous on the fresh fenced key.
    assert!(!map.lookup(new_key), "cpu0 misses fresh generation");
    assert!(!map.lookup(new_key), "cpu1 misses fresh generation");
    miss_path(&mut map, 0, new_key, 1500);
    miss_path(&mut map, 1, new_key, 1501);
    assert_eq!(map.fold_total(new_key), 2, "both fenced hits count");
    assert_eq!(map.dropfail, 0, "no loss with spare capacity");
    assert_eq!(
        map.fold_total(old_key),
        2,
        "fenced collision perturbs nothing old"
    );
}

#[test]
fn r04_exhaustion_stays_loss() {
    // Guard (GREEN before and after): a saturated map still fails
    // loud — both colliding hits drop, admitted keys stay exact,
    // nothing evicts. R04 must not trade this loss accounting
    // for collision recovery.
    use osslscope_ebpf_common::make_key;
    use r04_rendezvous::{FirstHitMap, miss_path};
    let mut map = FirstHitMap::new(1);
    let admitted = make_key(7, 0);
    miss_path(&mut map, 0, admitted, 1500);
    assert_eq!(map.fold_total(admitted), 1);
    let fresh = make_key(8, 0);
    assert!(!map.lookup(fresh));
    assert!(!map.lookup(fresh));
    miss_path(&mut map, 0, fresh, 1500);
    miss_path(&mut map, 1, fresh, 1501);
    assert_eq!(map.fold_total(fresh), 0, "no room: nothing counted");
    assert_eq!(map.dropfail, 2, "both exhausted hits are loud loss");
    assert_eq!(map.fold_total(admitted), 1, "admitted key stays exact");
}

#[test]
fn r04_unavailable_relookup_stays_loss() {
    // Guard: when the relookup finds no slot — allocation failed
    // and no racing insert landed — the hit is loud DROPFAIL
    // loss, not a phantom count. The model forces one relookup
    // miss via fault injection; a later hit on the landed key
    // then bumps normally, proving the zero slot left behind
    // corrupts nothing.
    use osslscope_ebpf_common::make_key;
    use r04_rendezvous::{FirstHitMap, miss_path};
    let mut map = FirstHitMap::new(8192);
    let key = make_key(9, 0);
    assert!(!map.lookup(key), "fresh key misses");
    map.fail_relookup_once = true;
    miss_path(&mut map, 0, key, 1500);
    assert_eq!(map.fold_total(key), 0, "unavailable slot counts nothing");
    assert_eq!(map.dropfail, 1, "unavailable relookup is loud loss");
    // The zero-seeded key exists now: a later hit counts once.
    miss_path(&mut map, 1, key, 1501);
    assert_eq!(map.fold_total(key), 1, "later hit bumps the landed key");
    assert_eq!(map.dropfail, 1, "no further loss");
}

#[test]
fn r04_source_binds_model_to_branch() {
    // Tripwire (same precedent as `kernel_source_enforces_window`):
    // the BPF miss path must BE the bounded zero-seed + relookup
    // transaction the model scripts — zero insert with NOEXIST,
    // insert result NOT funneled to DROPFAIL, a second lookup
    // feeding one ordinary bump, no retry loop — with the
    // target/generation/deadline guards intact. RED pre-fix: the
    // current branch seeds count 1 and drops every insert error.
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/src/bin/count.rs"),
    )
    .unwrap();
    let start = src.find("pub fn count_entry").expect("count_entry exists");
    let end = src.find("fn dropfail").expect("dropfail anchor exists");
    let body = &src[start..end];
    assert!(
        body.contains("CountValue { count: 0"),
        "miss path must zero-seed the insert"
    );
    assert!(
        body.contains("insert(&key, &zero, BPF_NOEXIST)"),
        "miss path must NOEXIST-insert the zero seed"
    );
    assert!(
        !body.contains("is_err()"),
        "insert collision must not funnel to DROPFAIL"
    );
    assert!(
        body.matches("COUNTS.get_ptr_mut(&key)").count() >= 2,
        "miss path must relookup after the insert"
    );
    // (Strip line comments: the disposition note below names the
    // forbidden loop out loud.)
    let code: String = body
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("loop") && !code.contains("while ") && !code.contains("for "),
        "bounded transaction: no spin/retry loop on the miss path"
    );
    assert!(
        body.contains("TARGET.get(0)"),
        "target guard must survive the rewrite"
    );
    assert!(
        body.contains("GEN.get(0)"),
        "generation keying must survive the rewrite"
    );
    assert!(
        body.contains("now < start || now >= deadline"),
        "deadline admission must survive the rewrite"
    );
}

#[test]
fn h4_stale_retries_count_missed_once_each() {
    // H4 rework of quarantined_retry_counts_missed_once
    // (slice-A review Minor-1 survives): each stale attempt
    // counts exactly once into count.missed_attaches — two
    // attempts, counter 2, never double-counted at any
    // aggregate.
    let stage = Stage::fresh("h4quarcount");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    // Born-stale plan (replace before any attach).
    // Replace via create-then-rename: two coexisting files never
    // share an ino, so the new identity holds even on filesystems
    // that immediately reuse a freed inode (observed in CI).
    let swap = stage.write("prov.swap", &bytes);
    assert_ne!(swap.ino, a.ino);
    std::fs::rename(&swap.path, &a.path).unwrap();
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    let report = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert!(report.missed.iter().any(|m| m.reason == "replaced"));
    let report2 = s
        .attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    assert!(report2.missed.iter().any(|m| m.reason == "replaced"));
    s.open_window(1000, 2000, test_deadline()).unwrap();
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(
        counter_value(&drain, "count.missed_attaches"),
        Some(2),
        "each stale attempt must count once: {:?}",
        drain.counters
    );
}

// ---------------------------------------------------------------------------
// R20 count-close assurance: quiesce recovery + delayed-hit countermodel.
// ---------------------------------------------------------------------------

use osslscope_ebpf_common::CountValue;
use std::time::Instant;

/// Model a callback completion before the terminal writer witness. The
/// delegated terminal performs one final read; ordinary drains stay unchanged.
struct MidDrainBackend {
    inner: FakeCountBackend,
    cookie: u32,
    generation: u32,
    injected: bool,
}

impl CountBackend for MidDrainBackend {
    type Link = FakeLink;
    fn ready(&self) -> &Ready {
        self.inner.ready()
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<FakeLink>> {
        self.inner.attach(request)
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        self.inner.open_window(request)
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        self.inner.set_generation(request)
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<std::sync::Arc<RawSnapshot>> {
        self.inner.drain(request)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        self.inner.terminal_request(deadline, frontier)
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        if !self.injected {
            self.injected = true;
            self.inner.inject_row(
                self.cookie,
                self.generation,
                CountValue {
                    count: 2,
                    first_ns: 1500,
                    last_ns: 1500,
                },
            );
        }
        self.inner.terminal(request)
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.inner.progress()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.inner.fork_permit(deadline)
    }
}

#[test]
fn close_model_includes_completion_before_terminal_witness() {
    // Model the admitted completion before the model terminal witness.
    // One post-witness read includes it; no equality scan is needed.
    let stage = Stage::fresh("quiesce");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = CountSession::new(
        PID,
        MidDrainBackend {
            inner: FakeCountBackend::new(),
            cookie: 0,
            generation: 0,
            injected: false,
        },
    );
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.backend_mut().cookie = cookie;
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().inner.fire(PID, cookie, 1500, 5);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(
        drain.total_calls(),
        7,
        "5 fired + 2 completed before the model witness"
    );
    assert_eq!(counter_value(&drain, "count.drain_shortfall"), Some(0));
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(0));
    assert_eq!(counter_value(&drain, "count.map_insert_dropped"), Some(0));
    // c6: the injected row bypasses admission (5
    // admitted, 7 routed) — the anomaly hook sounds the delta.
    assert_eq!(counter_value(&drain, "count.ledger_delta"), Some(2));
}

#[test]
fn close_model_pending_work_completes_before_witness() {
    // Ordinary admitted model calls are present in the single terminal read.
    // This fixture is a compatibility check, not held-writer proof.
    let stage = Stage::fresh("pending-work");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 5);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 5, "pending pre-close hits complete");
    assert_eq!(counter_value(&drain, "count.map_insert_dropped"), Some(0));
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(0));
    assert_eq!(counter_value(&drain, "count.drain_shortfall"), Some(0));
}

#[test]
fn terminal_model_artifact_ignores_injected_late_row() {
    // Raw injection bypasses model admission and its writer witness. It cannot
    // replace a selected artifact; kernel completion has separate owner tests.
    let stage = Stage::fresh("delayed-hit");
    let bytes = self_bytes();
    let off = x_offsets(&bytes, 1)[0];
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = HashMap::from([(
        a.path.clone(),
        plan::FileBytes {
            bytes: std::fs::read(&a.path).unwrap().into(),
            dev: a.device,
            ino: a.ino,
        },
    )]);
    let mut s = session_with(FakeCountBackend::new());
    let d = CountDelta {
        discovered: vec![site(&a, off, 7)],
        losses: Vec::new(),
    };
    s.attach_delta(&d, &live, &files, ATTACH_AT, test_deadline())
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000, test_deadline()).unwrap();
    s.backend_mut().fire(PID, cookie, 1500, 5);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 5);
    // The delayed completion lands after the drain returned.
    s.backend_mut().inject_row(
        cookie,
        0,
        CountValue {
            count: 3,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    // The drain-vs-backend divergence (not drain-vs-itself) proves
    // the hit is invisible everywhere: the backend ledger holds
    // 5 + 3 while the returned drain still reports 5 with no loss
    // recorded — quiesce passes cannot prove completion.
    assert_eq!(drain.total_calls(), 5, "post-drain hit excluded");
    assert_eq!(
        s.backend().ledger_total(cookie, 0),
        8,
        "backend holds the delayed hit the drain cannot see"
    );
    assert_eq!(counter_value(&drain, "count.map_insert_dropped"), Some(0));
    assert_eq!(counter_value(&drain, "count.unattributed"), Some(0));
    assert_eq!(counter_value(&drain, "count.drain_shortfall"), Some(0));
}
