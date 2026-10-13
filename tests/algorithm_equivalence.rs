//! SPDX-License-Identifier: GPL-3.0-or-later
//! R01 algorithm-equivalence gates (F01/F02): finite semantic identity.
//!
//! Composed classifier→adapter→policy→renderer path using production
//! `build_alg_entries`, `classify_alg_with`, `adapt_delta`, policy and
//! renderers. Synonyms (same semantic identity) match every admitted
//! spelling in either alias order; same-family distinct algorithms
//! never yield a definite attribution.

use osslscope::capture::{AdapterCtx, AdapterState, adapt_delta};
use osslscope::discovery::harvest::build_alg_entries;
use osslscope::discovery::maps::Mapping;
use osslscope::discovery::session::{
    BackingRef, CoverageState, DiscoveredCandidate, DiscoveryDelta, TableCoverage,
};
use osslscope::evidence::{
    CandidateCoverage, CaptureDocument, CaptureWindow, Completeness, FencedGeneration,
    FinalizeInput, GapCounter, LegacyCallPartition, ObjectId, OpensslVersion, RuleVerdict,
    SiteExecution, SiteKey, TargetRecord, finalize,
};
use osslscope::kinds;
use osslscope::plan;
use osslscope::policy::{PolicyRule, evaluate_document};
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

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
            "osslscope-r01-{}-{}-{}-{:?}",
            test,
            std::process::id(),
            seq,
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Staged {
        use std::os::unix::fs::MetadataExt as _;
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

fn self_bytes() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
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

fn backing_of(staged: &Staged, offset: u64) -> Option<BackingRef> {
    Some(BackingRef {
        dev: plan::render_device(staged.device),
        ino: staged.ino,
        offset,
    })
}

fn terminated(op: u32, epoch: u64) -> TableCoverage {
    TableCoverage {
        op,
        epoch,
        state: CoverageState::Terminated { len: 4 },
        trunc_bits: 0,
    }
}

/// Classify one alias list through the production shared classifier.
fn classify_list(table: &HashMap<u64, wire::AlgClassValue>, names: &str) -> (String, bool, String) {
    let mut buf = [0u8; wire::ALG_WINDOW];
    let nb = names.as_bytes();
    let n = nb.len().min(wire::ALG_WINDOW);
    buf[..n].copy_from_slice(&nb[..n]);
    let v = wire::classify_alg_with(&buf, nb.len(), false, |h| table.get(&h).copied());
    let label = kinds::alg_class_label(v.class).unwrap().to_string();
    let status = wire::alg_status_name(v.status).unwrap().to_string();
    (label, v.weak, status)
}

/// Adapt arrivals through production `adapt_delta`: one
/// [`DiscoveredCandidate`] per `(class, weak, status)` triple, same
/// triple, same poll. Returns the discovered site's candidates +
/// coverage.
fn adapt_many(
    staged: &Staged,
    live: &[Mapping],
    op: u32,
    arrivals: &[(String, bool, String)],
    offset: u64,
) -> (
    Vec<osslscope::evidence::CandidateIdentity>,
    CandidateCoverage,
) {
    let files: HashMap<String, plan::FileBytes> = HashMap::new();
    let fresh: HashSet<(String, u64)> = HashSet::new();
    let mut state = AdapterState::default();
    let delta = DiscoveryDelta {
        candidates: arrivals
            .iter()
            .map(|(class, weak, status)| DiscoveredCandidate {
                advertising: staged.path.clone(),
                advertising_dev: String::new(),
                advertising_ino: 0,
                backing: backing_of(staged, offset),
                op,
                funcid: 7,
                class: class.clone(),
                weak: *weak,
                status: status.clone(),
                epoch: 0,
                impl_addr: 0,
                arr: 0,
            })
            .collect(),
        tables: vec![terminated(op, 0)],
        ..DiscoveryDelta::default()
    };
    let adapted = adapt_delta(
        &mut state,
        &delta,
        &AdapterCtx {
            live,
            files: &files,
            pinned_provider: None,
            fresh: &fresh,
            post_settle: false,
            baseline: false,
        },
    );
    assert_eq!(adapted.delta.discovered.len(), 1);
    let site = &adapted.delta.discovered[0];
    (site.candidates.clone(), site.candidates_coverage)
}

/// Adapt one classified candidate through production `adapt_delta`.
/// Returns the discovered site's candidates + coverage.
fn adapt_one(
    staged: &Staged,
    live: &[Mapping],
    op: u32,
    class: &str,
    weak: bool,
    status: &str,
    offset: u64,
) -> (
    Vec<osslscope::evidence::CandidateIdentity>,
    CandidateCoverage,
) {
    adapt_many(
        staged,
        live,
        op,
        &[(class.to_string(), weak, status.to_string())],
        offset,
    )
}

fn exact_window() -> CaptureWindow {
    CaptureWindow {
        requested_start_ns: 1_000,
        requested_end_ns: 2_000,
        effective_start_ns: 1_000,
        effective_end_ns: 2_000,
        signal_cut: false,
    }
}

fn site_with_calls(
    staged: &Staged,
    offset: u64,
    candidates: Vec<osslscope::evidence::CandidateIdentity>,
    coverage: CandidateCoverage,
    calls: u64,
) -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: ObjectId("exe-fingerprint".to_string()),
            device: staged.device,
            inode: staged.ino,
            offset,
        },
        generation: 0,
        candidates,
        candidates_coverage: coverage,
        calls,
        first_ns: 100,
        last_ns: 200,
        installed_at: None,
    }
}

fn complete_doc(sites: Vec<SiteExecution>) -> CaptureDocument {
    finalize(FinalizeInput {
        window: exact_window(),
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

/// Run one alias list end-to-end: classify → adapt → finalize(7 calls).
/// Returns the finalized COMPLETE document.
fn doc_for_alias(
    stage_tag: &str,
    op: u32,
    alias: &str,
    offset: u64,
) -> (CaptureDocument, String, bool, String) {
    let table: HashMap<u64, wire::AlgClassValue> =
        build_alg_entries().unwrap().into_iter().collect();
    let (label, weak, status) = classify_list(&table, alias);
    let stage = Stage::fresh(stage_tag);
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let (candidates, coverage) = adapt_one(&staged, &live, op, &label, weak, &status, offset);
    let site = site_with_calls(&staged, offset, candidates, coverage, 7);
    let doc = complete_doc(vec![site]);
    (doc, label, weak, status)
}

/// Run one mixed alias list end-to-end with its finite alternatives
/// enumerated: classify the full list (production verdict), classify
/// each `:` segment (production per-alternative identity), adapt one
/// mixed-sourced arrival per recognized alternative (the row's `mixed`
/// verdict rides every arrival — status is per provider row, one
/// verdict per `(arr, idx)` slot — with the class/weak of its
/// enumerated alternative), finalize with 7 calls. Returns the
/// finalized document plus the full-list status.
fn doc_for_mixed_alternatives(
    stage_tag: &str,
    op: u32,
    alias: &str,
    offset: u64,
) -> (CaptureDocument, String) {
    let table: HashMap<u64, wire::AlgClassValue> =
        build_alg_entries().unwrap().into_iter().collect();
    let (_, _, status) = classify_list(&table, alias);
    let mut alternatives = Vec::new();
    for seg in alias.split(':') {
        let (label, weak, seg_status) = classify_list(&table, seg);
        assert_eq!(
            seg_status, "ok",
            "every enumerated alternative must be a recognized spelling: {seg:?} in {alias:?}"
        );
        alternatives.push((label, weak, "mixed".to_string()));
    }
    let stage = Stage::fresh(stage_tag);
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let (candidates, coverage) = adapt_many(&staged, &live, op, &alternatives, offset);
    let site = site_with_calls(&staged, offset, candidates, coverage, 7);
    let doc = complete_doc(vec![site]);
    (doc, status)
}

const KEM_OP: u32 = 14;
const DIGEST_OP: u32 = 1;
const CIPHER_OP: u32 = 2;
const KEYMGMT_OP: u32 = 10;

#[test]
fn synonyms_match_every_admitted_spelling() {
    // ML-KEM-768 synonyms (verified provider alias set) in either order.
    let ml_sets: &[&[&str]] = &[
        &[
            "ML-KEM-768",
            "MLKEM768",
            "2.16.840.1.101.3.4.4.2",
            "id-alg-ml-kem-768",
        ],
        &[
            "ML-KEM-512",
            "MLKEM512",
            "2.16.840.1.101.3.4.4.1",
            "id-alg-ml-kem-512",
        ],
    ];
    for set in ml_sets {
        let a = set[0];
        let b = set[2]; // OID spelling
        for alias in [format!("{a}:{b}"), format!("{b}:{a}")] {
            let (doc, label, weak, status) = doc_for_alias("syn-ml", KEM_OP, &alias, 0x100);
            assert_eq!(status, "ok", "synonyms must stay OK: {alias:?}");
            assert!(!weak, "ML-KEM aliases are not weak: {alias:?}");
            assert!(
                set.contains(&label.as_str()),
                "min label {label:?} must be a set member for {alias:?}"
            );
            // Every admitted spelling gives identical definite bounds.
            for spelling in *set {
                assert!(
                    kinds::is_known_alg(spelling),
                    "admitted spelling must be registered: {spelling:?}"
                );
                let req = PolicyRule::require_executed(spelling);
                let v = evaluate_document(std::slice::from_ref(&req), &doc);
                assert_eq!(
                    v.rules[0].bounds.definite, 7,
                    "require {spelling:?} over {alias:?}"
                );
                assert_eq!(
                    v.rules[0].bounds.possible,
                    Some(7),
                    "require {spelling:?} over {alias:?}"
                );
                assert_eq!(
                    v.rules[0].verdict,
                    RuleVerdict::Pass,
                    "require {spelling:?} over {alias:?}"
                );
                let deny = PolicyRule::deny_algorithm(spelling);
                let v = evaluate_document(std::slice::from_ref(&deny), &doc);
                assert_eq!(
                    v.rules[0].bounds.definite, 7,
                    "deny {spelling:?} over {alias:?}"
                );
                assert_eq!(
                    v.rules[0].verdict,
                    RuleVerdict::Violation,
                    "deny {spelling:?} over {alias:?}"
                );
            }
            // Definite CBOM asset + conserved total.
            assert_eq!(cbom_assets(&doc).len(), 1, "alias {alias:?}");
            assert_eq!(doc.total_calls(), 7, "alias {alias:?}");
        }
    }

    // SHA2-256 synonyms in either order.
    let sha_set = ["SHA2-256", "SHA256", "SHA-256", "2.16.840.1.101.3.4.2.1"];
    for alias in [
        "SHA2-256:SHA256".to_string(),
        "SHA256:SHA2-256".to_string(),
        "SHA-256:2.16.840.1.101.3.4.2.1".to_string(),
        "2.16.840.1.101.3.4.2.1:SHA-256".to_string(),
    ] {
        let (doc, label, weak, status) = doc_for_alias("syn-sha", DIGEST_OP, &alias, 0x200);
        assert_eq!(status, "ok", "synonyms must stay OK: {alias:?}");
        assert!(!weak);
        assert!(sha_set.contains(&label.as_str()), "label {label:?}");
        for spelling in sha_set {
            let req = PolicyRule::require_executed(spelling);
            let v = evaluate_document(std::slice::from_ref(&req), &doc);
            assert_eq!(v.rules[0].bounds.definite, 7, "{spelling:?} over {alias:?}");
            assert_eq!(
                v.rules[0].bounds.possible,
                Some(7),
                "{spelling:?} over {alias:?}"
            );
            assert_eq!(
                v.rules[0].verdict,
                RuleVerdict::Pass,
                "{spelling:?} over {alias:?}"
            );
        }
        assert_eq!(cbom_assets(&doc).len(), 1, "alias {alias:?}");
        assert_eq!(doc.total_calls(), 7);
    }

    // Weak control: SHA1 synonyms keep weak metadata and match.
    let (doc, _, weak, status) = doc_for_alias("syn-weak", DIGEST_OP, "SHA1:SHA-1", 0x300);
    assert_eq!(status, "ok");
    assert!(weak, "SHA1 alias must stay weak");
    for spelling in ["SHA1", "SHA-1"] {
        let v = evaluate_document(
            std::slice::from_ref(&PolicyRule::require_executed(spelling)),
            &doc,
        );
        assert_eq!(v.rules[0].bounds.definite, 7, "{spelling:?}");
    }
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);

    // Fenced control: the same synonym site in a fenced generation
    // counts once, still definite.
    let table: HashMap<u64, wire::AlgClassValue> =
        build_alg_entries().unwrap().into_iter().collect();
    let (label, weak, status) = classify_list(&table, "ML-KEM-768:2.16.840.1.101.3.4.4.2");
    assert_eq!(status, "ok");
    let stage = Stage::fresh("syn-fenced");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let (candidates, coverage) = adapt_one(&staged, &live, KEM_OP, &label, weak, &status, 0x400);
    let site = site_with_calls(&staged, 0x400, candidates, coverage, 7);
    let doc = finalize(FinalizeInput {
        window: exact_window(),
        sites: Vec::new(),
        fenced: vec![FencedGeneration {
            generation: 0,
            sites: vec![site],
        }],
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
    });
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("MLKEM768")),
        &doc,
    );
    assert_eq!(v.rules[0].bounds.definite, 7);
    assert_eq!(doc.total_calls(), 7);

    // PARTIAL control: relevant loss keeps definite evidence but the
    // upper bound is unknown; verdicts stay definite on proved use.
    let (mut doc, _, _, _) = doc_for_alias("syn-partial", DIGEST_OP, "SHA2-256:SHA256", 0x500);
    // Force PARTIAL with a relevant loss counter.
    doc = finalize(FinalizeInput {
        window: exact_window(),
        sites: doc.sites.clone(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: vec![GapCounter {
            name: "discovery.table_aborted".to_string(),
            kind: osslscope::evidence::CounterKind::Loss,
            units: osslscope::evidence::CounterUnits::Events,
            source: osslscope::evidence::CounterSource::Discovery,
            value: 1,
        }],
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
    });
    assert!(matches!(doc.status, Completeness::Partial { .. }));
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA256")),
        &doc,
    );
    assert_eq!(v.rules[0].bounds.definite, 7);
    assert_eq!(v.rules[0].bounds.possible, None);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
}

#[test]
fn stock_provider_alias_rows_stay_ok() {
    // Verbatim OSSL_ALGORITHM rows from the pinned provider census
    // (host OpenSSL 3.5.5, default provider, 2026-10-13; row strings
    // copied character-for-character, expectations hardcoded — never
    // derived via `kinds::algorithm_semantic_id`). Ordinary stock
    // alias lists must classify OK with definite attribution in a
    // COMPLETE document, in either alias order.
    let rows: &[(&str, u32, &[&str])] = &[
        (
            "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6",
            CIPHER_OP,
            &["AES-128-GCM", "id-aes128-GCM", "2.16.840.1.101.3.4.1.6"],
        ),
        (
            "AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2",
            CIPHER_OP,
            &["AES-128-CBC", "AES128", "2.16.840.1.101.3.4.1.2"],
        ),
        (
            "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42",
            CIPHER_OP,
            &["AES-256-CBC", "AES256", "2.16.840.1.101.3.4.1.42"],
        ),
        (
            "SM3:1.2.156.10197.1.401",
            DIGEST_OP,
            &["SM3", "1.2.156.10197.1.401"],
        ),
        (
            "RSA:rsaEncryption:1.2.840.113549.1.1.1",
            KEYMGMT_OP,
            &["RSA", "rsaEncryption", "1.2.840.113549.1.1.1"],
        ),
        (
            "DES-EDE3-CBC:DES3:1.2.840.113549.3.7",
            CIPHER_OP,
            &["DES-EDE3-CBC", "DES3", "1.2.840.113549.3.7"],
        ),
    ];
    for (row, op, spellings) in rows {
        for ordered in [
            row.to_string(),
            row.split(':').rev().collect::<Vec<_>>().join(":"),
        ] {
            let (doc, label, weak, status) = doc_for_alias("stock", *op, &ordered, 0xB00);
            assert_eq!(status, "ok", "stock row must stay OK: {ordered:?}");
            assert!(!weak, "stock row is not weak: {ordered:?}");
            assert!(
                spellings.contains(&label.as_str()),
                "min label {label:?} must be a row member for {ordered:?}"
            );
            assert!(
                matches!(doc.status, Completeness::Complete),
                "stock row stays COMPLETE: {ordered:?}"
            );
            for spelling in *spellings {
                let req = PolicyRule::require_executed(spelling);
                let v = evaluate_document(std::slice::from_ref(&req), &doc);
                assert_eq!(
                    v.rules[0].bounds.definite, 7,
                    "require {spelling:?} over {ordered:?}"
                );
                assert_eq!(
                    v.rules[0].bounds.possible,
                    Some(7),
                    "require {spelling:?} over {ordered:?}"
                );
                assert_eq!(
                    v.rules[0].verdict,
                    RuleVerdict::Pass,
                    "require {spelling:?} over {ordered:?}"
                );
                let deny = PolicyRule::deny_algorithm(spelling);
                let v = evaluate_document(std::slice::from_ref(&deny), &doc);
                assert_eq!(
                    v.rules[0].bounds.definite, 7,
                    "deny {spelling:?} over {ordered:?}"
                );
                assert_eq!(
                    v.rules[0].verdict,
                    RuleVerdict::Violation,
                    "deny {spelling:?} over {ordered:?}"
                );
            }
            assert_eq!(cbom_assets(&doc).len(), 1, "row {ordered:?}");
            assert_eq!(doc.total_calls(), 7, "row {ordered:?}");
        }
    }
}

#[test]
fn same_family_distinct_algorithms_are_not_definite() {
    // Same macro family, distinct semantics: no definite either way.
    // The full list mixes (production classifier verdict); its finite
    // alternatives enumerate to a COMPLETE ambiguous site: definite 0,
    // finite upper Some(7) per alternative, no definite CBOM asset,
    // total 7.
    let cases: &[(&str, u32, &[&str])] = &[
        (
            "ML-KEM-512:ML-KEM-768",
            KEM_OP,
            &["ML-KEM-512", "ML-KEM-768", "MLKEM512", "MLKEM768"],
        ),
        (
            "SHA2-256:SHA2-512",
            DIGEST_OP,
            &["SHA2-256", "SHA2-512", "SHA256", "SHA512"],
        ),
    ];
    for (alias, op, spellings) in cases {
        for ordered in [
            alias.to_string(),
            alias.split(':').rev().collect::<Vec<_>>().join(":"),
        ] {
            let (doc, status) = doc_for_mixed_alternatives("diff", *op, &ordered, 0x600);
            assert_eq!(
                status, "mixed",
                "distinct family members must mix: {ordered:?}"
            );
            assert!(
                matches!(doc.status, Completeness::Complete),
                "finite alternatives stay COMPLETE: {ordered:?}"
            );
            // No definite alternative in either direction; the finite
            // upper per alternative is the 7 observed calls.
            for spelling in *spellings {
                for rule in [
                    PolicyRule::require_executed(spelling),
                    PolicyRule::deny_algorithm(spelling),
                ] {
                    let v = evaluate_document(std::slice::from_ref(&rule), &doc);
                    assert_eq!(
                        v.rules[0].bounds.definite, 0,
                        "{} {spelling:?} over {ordered:?}",
                        rule.name
                    );
                    assert_eq!(
                        v.rules[0].bounds.possible,
                        Some(7),
                        "{} {spelling:?} over {ordered:?}",
                        rule.name
                    );
                    assert_eq!(
                        v.rules[0].verdict,
                        RuleVerdict::Inconclusive,
                        "{} {spelling:?} over {ordered:?}",
                        rule.name
                    );
                }
            }
            // Physical-site conservation: 7 calls total, no definite asset.
            assert_eq!(doc.total_calls(), 7, "{ordered:?}");
            assert_eq!(cbom_assets(&doc).len(), 0, "{ordered:?}");
        }
    }

    // Cross-family control: still mixed, still no definite.
    let (doc, _, _, status) = doc_for_alias("diff-cross", DIGEST_OP, "AES-256-GCM:MD5", 0x700);
    assert_eq!(status, "mixed");
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &doc,
    );
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(cbom_assets(&doc).len(), 0);
    assert_eq!(doc.total_calls(), 7);

    // Unknown control: unregistered spellings never become definite.
    let (doc, label, _, status) =
        doc_for_alias("diff-unknown", DIGEST_OP, "canary-DOOM-7QZ", 0x800);
    assert_eq!(status, "unknown");
    assert_eq!(label, "other");
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &doc,
    );
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(cbom_assets(&doc).len(), 0);

    // Weak control: a mixed weak/strong family pair keeps weak but
    // yields no definite algorithm.
    let (_doc, _, weak, status) = doc_for_alias("diff-weak", DIGEST_OP, "SHA2-256:SHA2-512", 0x900);
    assert_eq!(status, "mixed");
    assert!(!weak);
    // SHA1 (weak) vs MD5 (weak, distinct): mixed, weak preserved.
    let table: HashMap<u64, wire::AlgClassValue> =
        build_alg_entries().unwrap().into_iter().collect();
    let (label, weak, status) = classify_list(&table, "SHA1:MD5");
    assert_eq!(status, "mixed", "distinct DIGEST members must mix");
    assert!(weak);
    let stage = Stage::fresh("diff-weak2");
    let bytes = self_bytes();
    let staged = stage.write("prov.so", &bytes);
    let live = vec![mapping(&staged)];
    let (candidates, coverage) = adapt_one(&staged, &live, DIGEST_OP, &label, weak, &status, 0xA00);
    assert_eq!(coverage, CandidateCoverage::Unknown);
    assert!(candidates.iter().any(|c| c.weak_alias));
    let _ = label;
}
