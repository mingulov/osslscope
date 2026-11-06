//! SPDX-License-Identifier: GPL-3.0-or-later
//! R1 finding 2 hostile-memory proofs: the exit fold retains O(1)
//! heap across windows (F2a) and spill/publication assembly streams
//! through bounded buffers (F2b). A counting global allocator
//! measures live-heap high-water across the REAL `service`
//! paths (this binary is its own process — fresh high-water).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// High-water above current live bytes, then reset the peak to live
/// (fresh measurement from here).
fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
}

fn peak_delta() -> usize {
    PEAK.load(Ordering::SeqCst)
        .saturating_sub(LIVE.load(Ordering::SeqCst))
}

fn scratch(case: &str) -> std::path::PathBuf {
    let root = std::env::var("OSSL_TEST_ROOT")
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    let dir = std::path::PathBuf::from(root).join(format!("hostile-{case}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_doc(sites: usize) -> osslscope::evidence::CaptureDocument {
    use osslscope::evidence::*;
    let rows: Vec<SiteExecution> = (0..sites as u32)
        .map(|i| SiteExecution {
            site: SiteKey {
                object: ObjectId(format!("lib{i}")),
                device: 7,
                inode: 8,
                offset: 9,
            },
            generation: 1,
            candidates: Vec::new(),
            candidates_coverage: CandidateCoverage::Complete,
            calls: 3,
            first_ns: 1,
            last_ns: 90,
            installed_at: None,
        })
        .collect();
    finalize(FinalizeInput {
        corpse_wait: None,
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 100,
            effective_start_ns: 0,
            effective_end_ns: 100,
            signal_cut: false,
            count_admission: None,
        },
        sites: rows,
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::new(9, "t".to_string(), String::new(), String::new()),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    })
}

/// F2a: folding 20 000 windows retains O(1) heap (the
/// `run.windows` full-document clone blew ~32 MB here pre-fix).
#[test]
fn f2a_fold_inputs_bounded() {
    use osslscope::policy::PolicyOutcome;
    use osslscope::service::exit::RunFold;
    let doc = test_doc(10);
    assert!(
        serde_json::to_vec(&doc).unwrap().len() > 512,
        "probe validity: the folded doc is nontrivial"
    );
    assert!(
        std::mem::size_of::<RunFold>() <= 64,
        "probe validity: the accumulator is fixed-small"
    );
    let usable = doc.has_usable_evidence();
    let mut acc = RunFold::new();
    reset_peak();
    for _ in 0..20_000 {
        acc.add(PolicyOutcome::Pass, &doc.status, usable, false);
    }
    let code = acc.fold(None, false);
    let peak = peak_delta();
    drop(acc);
    assert_eq!(code, 0);
    assert!(
        peak < 2 << 20,
        "fold inputs bounded: peak {} bytes over 20 000 windows (cap 2 MiB)",
        peak
    );
}

/// F2a refactor guard: the §7.3 fold truth table (every row —
/// the accumulator refactor must preserve exit codes exactly).
#[test]
fn f2a_fold_truth_table() {
    use osslscope::evidence::Completeness;
    use osslscope::policy::PolicyOutcome;
    use osslscope::service::exit::{RunFold, RunToolFailure};
    struct W {
        outcome: PolicyOutcome,
        status: Completeness,
        delivery_failed: bool,
    }
    let one = |w: W, tool: Option<RunToolFailure>, interrupted: bool| {
        let mut doc = test_doc(0);
        doc.status = w.status.clone();
        let usable = doc.has_usable_evidence();
        let mut acc = RunFold::new();
        acc.add(w.outcome, &w.status, usable, w.delivery_failed);
        acc.fold(tool, interrupted)
    };
    let mk = |outcome: PolicyOutcome| W {
        outcome,
        status: Completeness::Complete,
        delivery_failed: false,
    };
    // Priority 10: violation.
    assert_eq!(one(mk(PolicyOutcome::Violation), None, false), 10);
    assert_eq!(one(mk(PolicyOutcome::Violation), None, true), 10);
    // Priority 1: fatal + usable.
    let fatal = W {
        outcome: PolicyOutcome::Pass,
        status: Completeness::Fatal {
            kind: osslscope::evidence::FatalKind::Runtime("t".to_string()),
            reasons: Vec::new(),
        },
        delivery_failed: false,
    };
    let mut probe = test_doc(0);
    probe.status = fatal.status.clone();
    assert!(probe.has_usable_evidence(), "probe validity: usable");
    assert_eq!(one(fatal, None, false), 1);
    // Priority 4: zero windows / no-verdict.
    assert_eq!(RunFold::new().fold(None, false), 4);
    assert_eq!(one(mk(PolicyOutcome::NoVerdict), None, false), 4);
    // Priority 11: inconclusive. Priority 3: interrupted/partial.
    assert_eq!(one(mk(PolicyOutcome::Inconclusive), None, false), 11);
    let open = W {
        outcome: PolicyOutcome::Pass,
        status: Completeness::Partial {
            reasons: Vec::new(),
        },
        delivery_failed: false,
    };
    assert_eq!(one(open, None, false), 3);
    // Priority 1: tool failure / delivery failure.
    assert_eq!(
        one(
            mk(PolicyOutcome::Pass),
            Some(RunToolFailure::SinkIdentity),
            false
        ),
        1
    );
    let undelivered = W {
        outcome: PolicyOutcome::Pass,
        status: Completeness::Complete,
        delivery_failed: true,
    };
    assert_eq!(one(undelivered, None, false), 1);
    // Priority 3: interrupted.
    assert_eq!(one(mk(PolicyOutcome::Pass), None, true), 3);
    // Priority 0: clean.
    assert_eq!(one(mk(PolicyOutcome::Pass), None, false), 0);
}

/// One JSON line of exactly ~`len` bytes (valid, newline-free).
fn json_line(len: usize, seq: usize) -> Vec<u8> {
    let mut v = format!(r#"{{"kind":"gap","seq":{seq},"pad":""#).into_bytes();
    v.extend(std::iter::repeat(b'x').take(len.saturating_sub(v.len() + 2)));
    v.extend_from_slice(b"\"}");
    v
}

/// Byte-counting writer (holds O(1): total length + a head/tail
/// sample — the streamed bulk is never retained).
struct CountingWriter {
    len: u64,
    head: Vec<u8>,
    head_cap: usize,
    tail: std::collections::VecDeque<u8>,
}

impl CountingWriter {
    fn new(head_cap: usize) -> Self {
        Self {
            len: 0,
            head: Vec::new(),
            head_cap,
            tail: std::collections::VecDeque::with_capacity(64),
        }
    }
}

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.len += buf.len() as u64;
        if self.head.len() < self.head_cap {
            let want = (self.head_cap - self.head.len()).min(buf.len());
            self.head.extend_from_slice(&buf[..want]);
        }
        for b in buf {
            if self.tail.len() == 64 {
                self.tail.pop_front();
            }
            self.tail.push_back(*b);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// F2b (spills): assembling 64 × 1 MiB spill tmps streams
/// (peak ≪ spill volume — the old hold-and-parse peaked ~69 MiB)
/// and emits every byte verbatim (no truncation — the D-record
/// forbids it). One record per spill tmp (the spill-path
/// invariant). The counting writer retains O(1).
#[test]
fn f2b_spill_assembly_bounded_and_complete() {
    use osslscope::service::staging::{SpilledRecord, assemble_inner_into};
    let dir = scratch("spill");
    let line = json_line(1 << 20, 7);
    let mut spilled = Vec::with_capacity(64);
    for i in 0..64 {
        let tmp = dir.join(format!("spill.{i}.json"));
        let mut content = line.clone();
        content.push(b'\n');
        std::fs::write(&tmp, &content).unwrap();
        spilled.push(SpilledRecord {
            tmp,
            bytes: content.len() as u64,
            tick: 0,
            valid: true,
            seal_segment: None,
            content_sha: sha256_of(&line),
        });
    }
    let mut sink = CountingWriter::new(line.len() + 1);
    reset_peak();
    let counts = assemble_inner_into(&[], &spilled, None, None, false, &mut sink).unwrap();
    let peak = peak_delta();
    // Completeness (compact — 64 MiB never dumps): 64 verbatim
    // records comma-joined.
    assert_eq!(counts.inner_len, 64 * line.len() as u64 + 63);
    assert_eq!(sink.len, counts.inner_len);
    let mut expect_head = line.clone();
    expect_head.push(b',');
    assert_eq!(sink.head, expect_head);
    let tail: Vec<u8> = sink.tail.into_iter().collect();
    assert_eq!(&tail[..], &line[line.len() - 64..]);
    assert_eq!(counts.skipped_invalid, 0);
    assert_eq!(counts.spilled_records, 64);
    assert!(
        peak < 16 << 20,
        "spill assembly streams: peak {} bytes for 64 MiB of spills (cap 16 MiB)",
        peak
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// F2b (staged): assembling 64 MiB of staged raws writes
/// through (peak ≪ staged size — the old second hold peaked
/// ~67 MiB).
#[test]
fn f2b_staged_assembly_bounded() {
    use osslscope::service::staging::{StagedRecord, assemble_inner_into};
    let line = json_line(1 << 16, 9);
    let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
    let mut staged = Vec::with_capacity(1024);
    for _ in 0..1024 {
        staged.push(StagedRecord {
            raw: line.clone(),
            value: Some(value.clone()),
            tick: 0,
        });
    }
    let mut sink = CountingWriter::new(line.len() + 1);
    reset_peak();
    let counts = assemble_inner_into(&staged, &[], None, None, false, &mut sink).unwrap();
    let peak = peak_delta();
    assert_eq!(counts.skipped_invalid, 0);
    assert_eq!(counts.inner_len, 1024 * line.len() as u64 + 1023);
    assert_eq!(sink.len, counts.inner_len);
    assert!(
        peak < 16 << 20,
        "staged assembly streams: peak {} bytes for 64 MiB staged (cap 16 MiB)",
        peak
    );
}
