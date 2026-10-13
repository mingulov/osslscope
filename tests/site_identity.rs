//! SPDX-License-Identifier: GPL-3.0-or-later
//! T07 immutable planner identity and count-session tests (spec R01/R02/R05).
//!
//! Pins: cookie identity binds verified physical backing
//! (device, inode, file offset) — never the link path. A replacement
//! inode mints a new cookie, the same inode through another path
//! dedupes, coexisting old/new mappings keep independent identities
//! and ledgers, candidate-set changes version at a fence (old
//! generations keep old meaning), and fences preserve every
//! candidate including weak aliases. Counts are conserved per
//! generation across all of it.
//!
//! Provider files are real staged executables (copies of the test
//! binary, so the X-segment validation runs for real) with real
//! (device, inode) identities; the alias case uses a hardlink. Live
//! maps are synthetic but carry those same real identities, and the
//! session's open-file verification runs against the staged paths.

use osslscope::count_session::{
    CountBackend, CountDelta, CountSession, DiscoveredSite, DrainedCounts, FakeCountBackend,
    FakeLink, FenceReason,
};
use osslscope::discovery::maps::Mapping;
use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, Completeness,
    FinalizeInput, LegacyCallPartition, ObjectId, OpensslVersion, RuleVerdict, SiteExecution,
    TargetRecord, finalize,
};
use osslscope::plan;
use osslscope::policy::{PolicyRule, evaluate_document};
use osslscope_ebpf_common::CountValue;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PID: u32 = 4242;

// Incidental attach stamp for the tests that predate installed-at:
// none of them assert on it (the installed-at tests below pass
// their own meaningful literals).
const ATTACH_AT: u64 = 900;

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

fn obj(id: &str) -> ObjectId {
    ObjectId(id.to_string())
}

/// Real executable bytes (self): offsets derived from its own program
/// headers (same precedent as `plan::tests`).
fn self_bytes() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

/// An offset inside an X LOAD segment of `bytes`.
fn x_offset(bytes: &[u8]) -> u64 {
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let ph = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
        .unwrap();
    ph.p_offset + 8
}

/// One staged provider file: real path plus its real backing identity.
struct Staged {
    path: String,
    device: u64,
    ino: u64,
}

impl Staged {
    fn stat(path: &std::path::Path) -> (u64, u64) {
        let meta = std::fs::metadata(path).unwrap();
        let device = plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev()));
        (device, meta.ino())
    }
}

/// A fresh temp directory of staged provider files, removed on drop.
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
            // Thread id disambiguates parallel tests in one process.
            format!("{:?}", std::thread::current().id()).replace(['(', ')', ' '], "")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Staged {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let (device, ino) = Staged::stat(&path);
        Staged {
            path: path.to_str().unwrap().to_string(),
            device,
            ino,
        }
    }

    /// A second link to the same file: same (device, inode), new path.
    fn hardlink(&self, name: &str, target: &Staged) -> Staged {
        let path = self.dir.join(name);
        std::fs::hard_link(&target.path, &path).unwrap();
        let (device, ino) = Staged::stat(&path);
        assert_eq!((device, ino), (target.device, target.ino));
        Staged {
            path: path.to_str().unwrap().to_string(),
            device,
            ino,
        }
    }

    /// Replace the file at `victim`'s path with fresh bytes: same
    /// path, new inode (atomic rename-over on the same filesystem).
    fn replace(&self, name: &str, victim: &Staged, bytes: &[u8]) -> Staged {
        let incoming = self.dir.join(format!("{name}.new"));
        std::fs::write(&incoming, bytes).unwrap();
        std::fs::rename(&incoming, &victim.path).unwrap();
        let (device, ino) = Staged::stat(std::path::Path::new(&victim.path));
        assert_ne!(ino, victim.ino, "rename-over must yield a new inode");
        Staged {
            path: victim.path.clone(),
            device,
            ino,
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

fn candidate(
    provider: &str,
    class: &str,
    op: u32,
    funcid: u32,
    classes: &[&str],
    weak: bool,
) -> CandidateIdentity {
    CandidateIdentity::new(
        obj(provider),
        class.to_string(),
        op,
        funcid,
        classes.iter().map(|s| s.to_string()).collect(),
        weak,
    )
}

fn site(
    staged: &Staged,
    offset: u64,
    object: &str,
    candidates: Vec<CandidateIdentity>,
) -> DiscoveredSite {
    DiscoveredSite {
        site: osslscope::evidence::SiteKey {
            object: obj(object),
            device: staged.device,
            inode: staged.ino,
            offset,
        },
        candidates,
        candidates_coverage: CandidateCoverage::Complete,
    }
}

fn delta(sites: Vec<DiscoveredSite>) -> CountDelta {
    CountDelta {
        discovered: sites,
        losses: Vec::new(),
    }
}

fn session() -> CountSession<FakeCountBackend> {
    CountSession::new(PID, FakeCountBackend::new())
}

fn files_for(staged: &[&Staged]) -> HashMap<String, plan::FileBytes> {
    staged
        .iter()
        .map(|s| {
            (
                s.path.clone(),
                plan::FileBytes {
                    bytes: std::fs::read(&s.path).unwrap(),
                    dev: s.device,
                    ino: s.ino,
                },
            )
        })
        .collect()
}

fn fire(session: &mut CountSession<FakeCountBackend>, cookie: u32, now_ns: u64, n: u64) {
    session.backend_mut().fire(PID, cookie, now_ns, n);
}

fn finalize_doc(sites: Vec<SiteExecution>) -> CaptureDocument {
    finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 1_000,
            requested_end_ns: 2_000,
            effective_start_ns: 1_000,
            effective_end_ns: 2_000,
            signal_cut: false,
        },
        sites,
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
    })
}

fn cbom_assets(doc: &CaptureDocument) -> Vec<serde_json::Value> {
    let bytes = osslscope::report::render_cbom(doc).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["components"].as_array().cloned().unwrap_or_default()
}

#[test]
fn replacement_inode_gets_new_cookie() {
    let stage = Stage::fresh("replace");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    // Generation 0: inode A backs the path.
    let a = stage.write("prov.so", &bytes);
    let live_a = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d0 = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    let rep = s.attach_delta(&d0, &live_a, &files, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 1, "one site attached: {rep:?}");
    assert!(rep.missed.is_empty(), "{:?}", rep.missed);
    let old = s.cookie_for(a.device, a.ino, off).expect("old cookie");
    s.open_window(1000, 2000).unwrap();
    fire(&mut s, old, 1500, 7);

    // The file is replaced: same path and offset, new inode. The old
    // mapping is gone; the delta now describes inode B.
    let b = stage.replace("prov.so", &a, &bytes);
    assert_eq!(a.path, b.path);
    let live_b = vec![mapping(&b)];
    let files_b = files_for(&[&b]);
    let d1 = delta(vec![site(
        &b,
        off,
        "fp-B",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    let rep = s.attach_delta(&d1, &live_b, &files_b, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 1, "replacement attaches fresh: {rep:?}");
    let new = s.cookie_for(b.device, b.ino, off).expect("new cookie");
    assert_ne!(old, new, "replacement inode must mint a new cookie");
    // The old cookie still names the old backing — its meaning is
    // immutable even though the path now resolves elsewhere.
    let prov = s.provenance(old).expect("old provenance survives");
    assert_eq!(prov.site.inode, a.ino);
    assert_eq!(prov.site.object, obj("fp-A"));
    fire(&mut s, new, 1600, 3);

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 10, "7 old + 3 new conserved");
    assert_eq!(drain.current.len(), 2);
    for exec in &drain.current {
        if exec.site.inode == a.ino {
            assert_eq!((exec.calls, exec.site.object.clone()), (7, obj("fp-A")));
        } else {
            assert_eq!(exec.site.inode, b.ino);
            assert_eq!((exec.calls, exec.site.object.clone()), (3, obj("fp-B")));
        }
    }
}

#[test]
fn same_inode_alias_path_dedupes() {
    let stage = Stage::fresh("alias");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    // One file, two link paths (hardlink): both mappings carry the
    // same (device, inode).
    let a = stage.write("prov.so", &bytes);
    let alias = stage.hardlink("alias.so", &a);
    let live = vec![mapping(&a), mapping(&alias)];
    let files = files_for(&[&a, &alias]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    let rep = s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 1, "one inode attaches once: {rep:?}");
    assert_eq!(s.cookie_count(), 1, "aliases share one cookie");
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    // A second delta describing the same site reuses the cookie and
    // re-attaches nothing (inode probes cover every mapping).
    let rep = s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 0, "survivor re-attaches nothing: {rep:?}");
    assert_eq!(rep.reused, 1);
    assert_eq!(s.cookie_for(a.device, a.ino, off).unwrap(), cookie);

    s.open_window(1000, 2000).unwrap();
    fire(&mut s, cookie, 1500, 11);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 11);
    assert_eq!(drain.current.len(), 1);
    assert_eq!(drain.current[0].calls, 11);
}

#[test]
fn old_mapping_keeps_old_identity() {
    let stage = Stage::fresh("oldnew");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    // Old and new mappings coexist (reload without unload): the
    // provider ledger splits across two independent cookies.
    let a = stage.write("a.so.1", &bytes);
    let b = stage.write("a.so.2", &bytes);
    assert_ne!((a.device, a.ino), (b.device, b.ino));
    let live = vec![mapping(&a), mapping(&b)];
    let files = files_for(&[&a, &b]);
    let d = delta(vec![
        site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov-old", "default", 1, 7, &["digest"], false)],
        ),
        site(
            &b,
            off,
            "fp-B",
            vec![candidate("prov-new", "default", 1, 7, &["digest"], false)],
        ),
    ]);
    let rep = s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 2, "{rep:?}");
    let old = s.cookie_for(a.device, a.ino, off).unwrap();
    let new = s.cookie_for(b.device, b.ino, off).unwrap();
    assert_ne!(old, new);

    s.open_window(1000, 2000).unwrap();
    // Independent A/B provider ledgers: each mapping's executions hit
    // only its own cookie.
    fire(&mut s, old, 1200, 5);
    fire(&mut s, new, 1300, 9);
    fire(&mut s, old, 1400, 2);
    assert_eq!(s.backend().ledger_total(old, 0), 7);
    assert_eq!(s.backend().ledger_total(new, 0), 9);

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 16, "A/B ledgers conserved");
    assert_eq!(drain.current.len(), 2);
    // No counts move to the newest label: each site keeps its own
    // object, provider and count.
    for exec in &drain.current {
        if exec.site.inode == a.ino {
            assert_eq!(exec.calls, 7);
            assert_eq!(exec.site.object, obj("fp-A"));
            assert_eq!(exec.candidates.len(), 1);
            assert_eq!(exec.candidates[0].provider, obj("prov-old"));
        } else {
            assert_eq!(exec.site.inode, b.ino);
            assert_eq!(exec.calls, 9);
            assert_eq!(exec.site.object, obj("fp-B"));
            assert_eq!(exec.candidates.len(), 1);
            assert_eq!(exec.candidates[0].provider, obj("prov-new"));
        }
    }
}

#[test]
fn changed_candidates_version_identity() {
    let stage = Stage::fresh("version");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d0 = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d0, &live, &files, ATTACH_AT).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 3000).unwrap();
    fire(&mut s, cookie, 1500, 7);

    // Discovery refines the attribution set: the same physical site
    // now carries two candidates. The cookie is NOT relabeled in
    // place — the change versions at a fence.
    let d1 = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![
            candidate("prov", "default", 1, 7, &["digest"], false),
            candidate("prov", "default", 1, 9, &["digest"], true),
        ],
    )]);
    let rep = s.attach_delta(&d1, &live, &files, ATTACH_AT).unwrap();
    assert!(
        rep.candidates_changed,
        "attribution change must request a fence: {rep:?}"
    );
    assert_eq!(rep.attached, 0, "same physical site, no re-attach");
    // Pre-fence provenance is untouched.
    assert_eq!(s.provenance(cookie).unwrap().candidates.len(), 1);

    s.fence(FenceReason::CandidatesChanged).unwrap();
    assert_eq!(s.generation(), 1);
    // Post-fence provenance carries both candidates.
    assert_eq!(s.provenance(cookie).unwrap().candidates.len(), 2);
    fire(&mut s, cookie, 2500, 4);

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    // Per-generation conserved counts: 7 under gen-0 meaning, 4 under
    // gen-1 meaning, 11 total.
    assert_eq!(drain.fenced.len(), 1);
    let g0 = &drain.fenced[0];
    assert_eq!(g0.generation, 0);
    assert_eq!(g0.sites.len(), 1);
    assert_eq!(g0.sites[0].calls, 7);
    assert_eq!(g0.sites[0].candidates.len(), 1, "old meaning kept");
    assert_eq!(drain.current.len(), 1);
    assert_eq!(drain.current[0].calls, 4);
    assert_eq!(drain.current[0].generation, 1);
    assert_eq!(drain.current[0].candidates.len(), 2, "new meaning current");
    assert_eq!(drain.total_calls(), 11);
}

#[test]
fn fence_keeps_aliases() {
    let stage = Stage::fresh("fence");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("shared.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    // One site shared by a strong canonical candidate and a weak
    // alias from another provider object.
    let d = delta(vec![site(
        &a,
        off,
        "fp-shared",
        vec![
            candidate("prov-a", "default", 1, 7, &["digest"], false),
            candidate(
                "prov-b",
                "third-party:xyz",
                1,
                7,
                &["digest", "other"],
                true,
            ),
        ],
    )]);
    s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 3000).unwrap();
    fire(&mut s, cookie, 1500, 6);

    s.fence(FenceReason::MappingsChanged).unwrap();
    fire(&mut s, cookie, 2500, 5);

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 11);
    // Both generations preserve the full candidate set: no alias may
    // disappear across a drain/fence, weak metadata included.
    for exec in drain
        .current
        .iter()
        .chain(drain.fenced.iter().flat_map(|g| g.sites.iter()))
    {
        assert_eq!(exec.candidates.len(), 2, "aliases survive: {exec:?}");
        assert!(exec.candidates.iter().any(|c| !c.weak_alias));
        let weak = exec
            .candidates
            .iter()
            .find(|c| c.weak_alias)
            .expect("weak alias survives");
        assert_eq!(weak.provider, obj("prov-b"));
        assert_eq!(weak.provider_class, "third-party:xyz");
        assert_eq!(weak.algorithm_classes, vec!["digest", "other"]);
        assert_eq!(weak.op, 1);
        assert_eq!(weak.funcid, 7);
    }
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites[0].calls, 6);
    assert_eq!(drain.current[0].calls, 5);
}

#[test]
fn duplicate_sites_union_candidates() {
    // Two delta entries for one backing triple are simultaneous
    // aliases: they union under one cookie instead of racing as
    // competing updates.
    let stage = Stage::fresh("dup");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![
        site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov", "default", 1, 7, &["digest"], false)],
        ),
        site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov", "default", 1, 9, &["cipher"], true)],
        ),
    ]);
    let rep = s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    assert_eq!(rep.attached, 1, "{rep:?}");
    assert!(!rep.candidates_changed);
    assert_eq!(s.cookie_count(), 1);
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    let prov = s.provenance(cookie).unwrap();
    assert_eq!(prov.candidates.len(), 2, "aliases union: {prov:?}");
    assert!(prov.candidates.iter().any(|c| c.funcid == 7));
    assert!(prov.candidates.iter().any(|c| c.weak_alias));

    s.open_window(1000, 2000).unwrap();
    fire(&mut s, cookie, 1500, 4);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 4);
    assert_eq!(drain.current[0].candidates.len(), 2);
}

#[test]
fn duplicate_merge_preserves_ambiguity_in_both_orders() {
    // R01 fix round 3: the duplicate-triple merge (attach_delta) is
    // coverage-conservative — AmbiguousComplete survives merging in
    // BOTH input orders (ambiguity is contagious: Complete +
    // AmbiguousComplete = AmbiguousComplete either way). One triple,
    // two legs; candidates agree on algorithm/provider/op/funcid and
    // differ only in weak metadata — the shape `definite_asset`
    // would otherwise mint into a false definite 7 + CBOM asset.
    for complete_first in [true, false] {
        let tag = if complete_first {
            "complete-first"
        } else {
            "ambiguous-first"
        };
        let stage = Stage::fresh("dup-amb");
        let bytes = self_bytes();
        let off = x_offset(&bytes);
        let mut s = session();
        let a = stage.write("prov.so", &bytes);
        let live = vec![mapping(&a)];
        let files = files_for(&[&a]);
        let mut leg_complete = site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov", "default", 1, 7, &["AES-128-GCM"], false)],
        );
        leg_complete.candidates_coverage = CandidateCoverage::Complete;
        let mut leg_ambiguous = site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov", "default", 1, 7, &["AES-128-GCM"], true)],
        );
        leg_ambiguous.candidates_coverage = CandidateCoverage::AmbiguousComplete;
        let legs = if complete_first {
            vec![leg_complete, leg_ambiguous]
        } else {
            vec![leg_ambiguous, leg_complete]
        };
        let rep = s
            .attach_delta(&delta(legs), &live, &files, ATTACH_AT)
            .unwrap();
        assert_eq!(rep.attached, 1, "{tag}: {rep:?}");
        assert_eq!(s.cookie_count(), 1, "{tag}");
        let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
        s.open_window(1000, 2000).unwrap();
        fire(&mut s, cookie, 1500, 7);
        let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
        assert_eq!(drain.total_calls(), 7, "{tag}");
        assert_eq!(drain.current.len(), 1, "{tag}");
        assert_eq!(drain.current[0].candidates.len(), 2, "{tag}: aliases union");
        // End-to-end consequence: no definite attribution, finite
        // upper over the 7 observed calls, no CBOM asset.
        let doc = finalize_doc(drain.current.clone());
        assert!(
            matches!(doc.status, Completeness::Complete),
            "{tag}: merged ambiguous duplicates stay COMPLETE"
        );
        for rule in [
            PolicyRule::require_executed("AES-128-GCM"),
            PolicyRule::deny_algorithm("AES-128-GCM"),
        ] {
            let v = evaluate_document(std::slice::from_ref(&rule), &doc);
            assert_eq!(
                v.rules[0].bounds.definite, 0,
                "{tag}: {} must not mint definite",
                rule.name
            );
            assert_eq!(v.rules[0].bounds.possible, Some(7), "{tag}: {}", rule.name);
            assert_eq!(
                v.rules[0].verdict,
                RuleVerdict::Inconclusive,
                "{tag}: {}",
                rule.name
            );
        }
        assert_eq!(cbom_assets(&doc).len(), 0, "{tag}");
        // Direct contract pin: the merge preserved ambiguity.
        assert_eq!(
            drain.current[0].candidates_coverage,
            CandidateCoverage::AmbiguousComplete,
            "{tag}: merge keeps the weakest claim"
        );
    }
}

#[test]
fn conflicting_objects_in_one_delta_fails() {
    // One backing triple claimed by two object fingerprints in a
    // single delta is a producer contradiction: fail closed rather
    // than silently keeping the first.
    let stage = Stage::fresh("conflict");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![
        site(
            &a,
            off,
            "fp-A",
            vec![candidate("prov", "default", 1, 7, &["digest"], false)],
        ),
        site(
            &a,
            off,
            "fp-B",
            vec![candidate("prov", "default", 1, 7, &["digest"], false)],
        ),
    ]);
    assert!(s.attach_delta(&d, &live, &files, ATTACH_AT).is_err());
}

#[test]
fn staged_update_reverted_before_fence() {
    // A staged update is newest-delta-wins: when the next delta
    // re-affirms the live meaning, the staged one cancels and the
    // fence must NOT install it.
    let stage = Stage::fresh("revert");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let mk = |extra: bool| {
        let mut cands = vec![candidate("prov", "default", 1, 7, &["digest"], false)];
        if extra {
            cands.push(candidate("prov", "default", 1, 9, &["digest"], true));
        }
        delta(vec![site(&a, off, "fp-A", cands)])
    };
    s.attach_delta(&mk(false), &live, &files, ATTACH_AT)
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 3000).unwrap();
    fire(&mut s, cookie, 1200, 3);

    let rep = s.attach_delta(&mk(true), &live, &files, ATTACH_AT).unwrap();
    assert!(rep.candidates_changed);
    // Revert: the live meaning re-affirmed, no fence requested.
    let rep = s
        .attach_delta(&mk(false), &live, &files, ATTACH_AT)
        .unwrap();
    assert!(!rep.candidates_changed, "revert cancels staging: {rep:?}");

    s.fence(FenceReason::MappingsChanged).unwrap();
    assert_eq!(s.provenance(cookie).unwrap().candidates.len(), 1);
    fire(&mut s, cookie, 2500, 2);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 5);
    for exec in drain
        .current
        .iter()
        .chain(drain.fenced.iter().flat_map(|g| g.sites.iter()))
    {
        assert_eq!(exec.candidates.len(), 1, "stale B never installs");
    }
}

#[test]
fn changed_object_fingerprint_versions_identity() {
    // Same backing triple, new verified fingerprint (modified in
    // place, or inode reuse): the site key versions at a fence like
    // any attribution change — the fenced generation keeps the old
    // fingerprint, the new one carries the new.
    let stage = Stage::fresh("fpversion");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let mk = |fp: &str| {
        delta(vec![site(
            &a,
            off,
            fp,
            vec![candidate("prov", "default", 1, 7, &["digest"], false)],
        )])
    };
    s.attach_delta(&mk("fp-A"), &live, &files, ATTACH_AT)
        .unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 3000).unwrap();
    fire(&mut s, cookie, 1500, 7);

    let rep = s
        .attach_delta(&mk("fp-B"), &live, &files, ATTACH_AT)
        .unwrap();
    assert!(
        rep.candidates_changed,
        "fingerprint change versions: {rep:?}"
    );
    assert_eq!(s.provenance(cookie).unwrap().site.object, obj("fp-A"));

    s.fence(FenceReason::ProviderChanged).unwrap();
    assert_eq!(s.provenance(cookie).unwrap().site.object, obj("fp-B"));
    fire(&mut s, cookie, 2500, 4);

    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 11);
    assert_eq!(drain.fenced[0].sites[0].site.object, obj("fp-A"));
    assert_eq!(drain.fenced[0].sites[0].calls, 7);
    assert_eq!(drain.current[0].site.object, obj("fp-B"));
    assert_eq!(drain.current[0].calls, 4);
}

/// Backend double that lands one straggler increment just after the
/// first drain scan returns: the close quiesce loop must catch it on
/// a follow-up pass instead of losing it.
struct StragglerBackend {
    inner: FakeCountBackend,
    straggler: Option<(u32, u32, CountValue)>,
}

impl CountBackend for StragglerBackend {
    type Link = FakeLink;

    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<Self::Link>, Vec<usize>) {
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

    fn drain(&mut self, deadline: Option<Instant>) -> anyhow::Result<DrainedCounts> {
        let out = self.inner.drain(deadline)?;
        if let Some((cookie, generation, value)) = self.straggler.take() {
            self.inner.inject_row(cookie, generation, value);
        }
        Ok(out)
    }
}

#[test]
fn close_drain_quiesces_inflight_increment() {
    let stage = Stage::fresh("quiesce");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let mut s = CountSession::new(
        PID,
        StragglerBackend {
            inner: FakeCountBackend::new(),
            straggler: None,
        },
    );
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    s.backend_mut().inner.fire(PID, cookie, 1500, 7);
    // Admitted pre-close, landing after the first scan.
    s.backend_mut().straggler = Some((
        cookie,
        0,
        CountValue {
            count: 5,
            first_ns: 1600,
            last_ns: 1600,
        },
    ));
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 12, "in-flight increment quiesced");
    assert!(!s.window_open());
    assert!(s.is_closed());
}

#[test]
fn future_generation_row_is_unattributed_loss() {
    // A known cookie with a generation that was never fenced must
    // not acquire the live generation's meaning: explicit
    // unattributed loss, conserved.
    let stage = Stage::fresh("futuregen");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let mut s = session();
    let a = stage.write("prov.so", &bytes);
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, ATTACH_AT).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    s.backend_mut().inject_row(
        cookie,
        99,
        CountValue {
            count: 5,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.total_calls(), 0);
    assert!(drain.current.is_empty());
    let unattributed = drain
        .counters
        .iter()
        .find(|c| c.name == "count.unattributed")
        .expect("unattributed counter present");
    assert_eq!(unattributed.value, 5);
    assert!(!s.window_open());
    assert!(s.is_closed());
}

// P6 installed-at: the probe-attachment wall per cookie. Minting a
// cookie is not installing it — `installed_at` stamps the monotonic
// moment the first bind succeeds, never relabels, and stays unset
// for cookies whose bind missed.

#[test]
fn attach_stamps_installed_at_on_first_bind() {
    let stage = Stage::fresh("installed-first");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    let rep = s.attach_delta(&d, &live, &files, 900).unwrap();
    assert_eq!(rep.attached, 1, "{rep:?}");
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    assert_eq!(
        s.provenance(cookie).unwrap().installed_at,
        Some(900),
        "first bind stamps the caller-provided wall"
    );
}

#[test]
fn reattach_keeps_first_installed_at() {
    let stage = Stage::fresh("installed-stable");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, 900).unwrap();
    let rep = s.attach_delta(&d, &live, &files, 1500).unwrap();
    assert_eq!(rep.reused, 1, "survivor re-attaches nothing: {rep:?}");
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    assert_eq!(
        s.provenance(cookie).unwrap().installed_at,
        Some(900),
        "re-attach must not relabel the install wall"
    );
}

#[test]
fn missed_bind_leaves_installed_at_unset() {
    let stage = Stage::fresh("installed-miss");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    // Swap the backing before attach: the plan goes stale.
    let swap = stage.write("prov.swap", &bytes);
    assert_ne!(swap.ino, a.ino);
    std::fs::rename(&swap.path, &a.path).unwrap();
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    let report = s.attach_delta(&d, &live, &files, 900).unwrap();
    assert_eq!(report.attached, 0);
    assert!(
        report.missed.iter().any(|m| m.reason == "replaced"),
        "stale plan must not bind: {report:?}"
    );
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    assert_eq!(
        s.provenance(cookie).unwrap().installed_at,
        None,
        "minted-but-never-bound cookies carry no install wall"
    );
}

// P6 installed-at surfacing: every rendered site carries its
// cookie's install wall, so installed-at vs first-counted is
// distinguishable per site (P5d §4, first two legs).

#[test]
fn drained_site_carries_installed_at() {
    let stage = Stage::fresh("installed-drain");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, 900).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    fire(&mut s, cookie, 1500, 7);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.current.len(), 1);
    let exec = &drain.current[0];
    assert_eq!(exec.calls, 7);
    assert_eq!(
        exec.installed_at,
        Some(900),
        "drained site carries the bind wall"
    );
    assert_eq!(
        exec.first_ns, 1500,
        "first-counted stays distinct from installed-at"
    );
}

#[test]
fn fenced_site_carries_installed_at() {
    let stage = Stage::fresh("installed-fence");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, 900).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 3000).unwrap();
    fire(&mut s, cookie, 1500, 7);
    s.fence(FenceReason::MappingsChanged).unwrap();
    fire(&mut s, cookie, 2500, 4);
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites.len(), 1);
    assert_eq!(
        drain.fenced[0].sites[0].installed_at,
        Some(900),
        "fenced seal preserves the install wall"
    );
    assert_eq!(drain.current.len(), 1);
    assert_eq!(
        drain.current[0].installed_at,
        Some(900),
        "post-fence site keeps the install wall"
    );
}

#[test]
fn straggler_bucket_carries_installed_at() {
    // No gen-0 counts before the fence: the sealed bucket is empty
    // and the late gen-0 row takes the straggler PUSH path (not the
    // fold into an existing site).
    let stage = Stage::fresh("installed-straggler");
    let bytes = self_bytes();
    let off = x_offset(&bytes);
    let a = stage.write("prov.so", &bytes);
    let mut s = session();
    let live = vec![mapping(&a)];
    let files = files_for(&[&a]);
    let d = delta(vec![site(
        &a,
        off,
        "fp-A",
        vec![candidate("prov", "default", 1, 7, &["digest"], false)],
    )]);
    s.attach_delta(&d, &live, &files, 900).unwrap();
    let cookie = s.cookie_for(a.device, a.ino, off).unwrap();
    s.open_window(1000, 2000).unwrap();
    s.fence(FenceReason::MappingsChanged).unwrap();
    s.backend_mut().inject_row(
        cookie,
        0,
        CountValue {
            count: 5,
            first_ns: 1500,
            last_ns: 1500,
        },
    );
    let drain = s.close_and_drain(Duration::from_secs(5)).unwrap();
    assert!(drain.current.is_empty(), "straggler must not land current");
    assert_eq!(drain.fenced.len(), 1);
    assert_eq!(drain.fenced[0].sites.len(), 1);
    let exec = &drain.fenced[0].sites[0];
    assert_eq!(exec.calls, 5);
    assert_eq!(
        exec.installed_at,
        Some(900),
        "straggler site carries the retired install wall"
    );
    let stale = drain
        .counters
        .iter()
        .find(|c| c.name == "count.stale_events")
        .expect("stale_events counter present");
    assert_eq!(stale.value, 5, "row took the straggler path");
}

// ---------------------------------------------------------------------------
// R14: bounded identity-bound reads (covers F17).
// ---------------------------------------------------------------------------

/// Scripted `ReadBoundedSource` (R14): serves `data` through a
/// cursor while reporting scripted before/after identities, so
/// mid-read growth and replacement are deterministic (no
/// filesystem timing). No test allocates anywhere near the real
/// 128 MiB policy ceiling.
struct ScriptedSource {
    data: std::io::Cursor<Vec<u8>>,
    before: (u64, u64, u64),
    after: (u64, u64, u64),
    identity_calls: std::cell::Cell<usize>,
}

impl ScriptedSource {
    fn stable(data: Vec<u8>, dev: u64, ino: u64) -> Self {
        let len = data.len() as u64;
        Self {
            data: std::io::Cursor::new(data),
            before: (dev, ino, len),
            after: (dev, ino, len),
            identity_calls: std::cell::Cell::new(0),
        }
    }
}

impl std::io::Read for ScriptedSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.read(buf)
    }
}

impl plan::ReadBoundedSource for ScriptedSource {
    fn bound_identity(&self) -> std::io::Result<(u64, u64, u64)> {
        let n = self.identity_calls.get();
        self.identity_calls.set(n + 1);
        Ok(if n == 0 { self.before } else { self.after })
    }
}

#[test]
fn r14_bounded_read_accepts_exactly_at_cap() {
    // Cap: a file of exactly the allowance reads fully with its
    // read-time identity.
    let stage = Stage::fresh("r14-cap");
    let exact = stage.write("exact.so", &[0x7fu8; 64]);
    let fb = plan::read_file_bounded(&exact.path, 64).unwrap();
    assert_eq!(fb.bytes.len(), 64);
    assert_eq!((fb.dev, fb.ino), (exact.device, exact.ino));
    assert_eq!(
        plan::MAX_OBJECT_BYTES,
        128 * 1024 * 1024,
        "per-object policy ceiling"
    );
}

#[test]
fn r14_bounded_read_refuses_cap_plus_one() {
    // Cap+1 (GREEN evolution of the RED scaffold): the bounded
    // reader refuses past the allowance instead of reading on.
    let stage = Stage::fresh("r14-cap-plus-one");
    let over = stage.write("over.so", &[0x7fu8; 65]);
    let err = plan::read_file_bounded(&over.path, 64).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
}

#[test]
fn r14_bounded_read_refuses_huge_advertised_length() {
    // A sparse file advertising terabytes refuses on fstat alone:
    // no multi-gigabyte allocation, no read.
    let stage = Stage::fresh("r14-huge");
    let path = stage.dir.join("huge.so");
    std::fs::write(&path, [0x7fu8; 8]).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1u64 << 40)
        .unwrap();
    let err = plan::read_file_bounded(path.to_str().unwrap(), 1024).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
}

#[test]
fn r14_bounded_read_refuses_growth_mid_read() {
    // A grower serving past the allowance trips the
    // overflow-detection byte DURING the read (the fstat
    // pre-check alone cannot catch it).
    let growing = || ScriptedSource {
        data: std::io::Cursor::new(vec![0x7fu8; 70]),
        before: (7, 7, 64),
        after: (7, 7, 70),
        identity_calls: std::cell::Cell::new(0),
    };
    let err = plan::read_bounded_from(growing(), 64).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
    // Growth within the allowance still refuses: the after-length
    // no longer matches, so the bytes may have torn.
    let err = plan::read_bounded_from(growing(), 128).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn r14_bounded_read_refuses_replacement_mid_read() {
    // Same-path inode/device replacement between the two fstats
    // refuses (InvalidData tear refusal, unchanged from pre-R14).
    for (label, after) in [
        ("inode", (7u64, 8u64, 64u64)),
        ("device", (8u64, 7u64, 64u64)),
    ] {
        let src = ScriptedSource {
            data: std::io::Cursor::new(vec![0x7fu8; 64]),
            before: (7, 7, 64),
            after,
            identity_calls: std::cell::Cell::new(0),
        };
        let err = plan::read_bounded_from(src, 64).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{label}");
    }
    // A stable scripted source binds fine (control).
    let fb = plan::read_bounded_from(ScriptedSource::stable(vec![0x7fu8; 64], 7, 7), 64).unwrap();
    assert_eq!((fb.dev, fb.ino), (7, 7));
    assert_eq!(fb.bytes.len(), 64);
}

#[test]
fn r14_bounded_read_empty_file_with_zero_budget() {
    // Allowance zero still binds empty files (a drained round
    // budget skips only nonempty objects).
    let stage = Stage::fresh("r14-empty");
    let empty = stage.write("empty.so", &[]);
    let fb = plan::read_file_bounded(&empty.path, 0).unwrap();
    assert!(fb.bytes.is_empty());
    let one = stage.write("one.so", &[0x7fu8]);
    let err = plan::read_file_bounded(&one.path, 0).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
}

#[test]
fn r14_legacy_wrapper_caps_single_object() {
    // The old-spelling wrapper still serves small files (now
    // bounded per object at the policy ceiling).
    let stage = Stage::fresh("r14-wrapper");
    let small = stage.write("small.so", &[0x7fu8; 32]);
    let fb = plan::read_file_bound(&small.path).unwrap();
    assert_eq!(fb.bytes.len(), 32);
    assert_eq!((fb.dev, fb.ino), (small.device, small.ino));
}
