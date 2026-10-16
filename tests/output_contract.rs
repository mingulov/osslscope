//! SPDX-License-Identifier: GPL-3.0-or-later
//! T11 v2 output contract (C3 `output_contract`, spec R08).
//!
//! Pins: actual JSON Schema validation of every rendered v2 artifact
//! (wrong types, negative/overflow counts, unexpected address/argv
//! fields — not a required-key walker), cross-field semantics
//! (object refs, window consistency, record invariants, privacy
//! shape), old-reader major rejection, ambiguous-site conservation,
//! input-order independence, honest human uncertainty, definite-only
//! CBOM, and independent artifact delivery (unwritable primary vs
//! writable CBOM and reverse, broken pipe, fatal/partial/
//! inconclusive/violation/runtime artifacts from one document —
//! no second capture). v2 goldens pin bytes; examples in docs come
//! from these fixtures, never invented.

use osslscope::check::policy_record;
use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureContext, CaptureDocument, CaptureWindow,
    Completeness, CounterKind, CounterSource, CounterUnits, DispositionRecord, EngineObservation,
    EngineWindow, ExpectedScope, FatalKind, FencedGeneration, FinalizeInput, GapCounter,
    LegacyCallPartition, ObjectId, ObjectRecord, OpensslVersion, PolicyRecord, PolicyRuleResult,
    PolicyVerdict, RuleVerdict, ScopeCoverage, SiteExecution, SiteKey, TargetRecord, engine_index,
    finalize,
};
use osslscope::policy::{PolicyOutcome, PolicyRule, evaluate_document};
use osslscope::report::{
    OutputDest, OutputFormat, OutputRequest, exit_for, render_cbom, render_human, render_json,
    setup_failure_document, write_artifacts,
};
use osslscope::schema::{
    FORBIDDEN_V2_KEYS, V2_SCHEMA_JSON, check_v2_semantics, check_version, check_version_v2,
    validate_v2,
};
use serde_json::{Value, json};
use std::path::PathBuf;

// ---------------------------------------------------------------- fixtures

const FP_A: &str = "build:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FP_B: &str = "build:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const FP_C: &str = "unverified:8:123456";

fn obj(id: &str) -> ObjectId {
    ObjectId(id.to_string())
}

fn cand(
    provider: &str,
    class: &str,
    op: u32,
    func: u32,
    algs: &[&str],
    weak: bool,
) -> CandidateIdentity {
    CandidateIdentity::new(
        obj(provider),
        class.to_string(),
        op,
        func,
        algs.iter().map(|a| a.to_string()).collect(),
        weak,
    )
}

#[allow(clippy::too_many_arguments)]
fn site_at(
    object: &str,
    device: u64,
    inode: u64,
    offset: u64,
    generation: u32,
    calls: u64,
    cands: Vec<CandidateIdentity>,
    cov: CandidateCoverage,
) -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: obj(object),
            device,
            inode,
            offset,
        },
        generation,
        candidates: cands,
        candidates_coverage: cov,
        calls,
        first_ns: 10,
        last_ns: 90,
        installed_at: None,
    }
}

fn objects_fixture() -> Vec<ObjectRecord> {
    vec![
        ObjectRecord {
            id: obj(FP_A),
            device: 8,
            inode: 100,
            display_locator: "/usr/lib/x86_64-linux-gnu/ossl-modules/default.so".to_string(),
        },
        ObjectRecord {
            id: obj(FP_B),
            device: 8,
            inode: 200,
            display_locator: "/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so".to_string(),
        },
        ObjectRecord {
            id: obj(FP_C),
            device: 8,
            inode: 300,
            display_locator: "/opt/vendor/lib/third-party.so".to_string(),
        },
    ]
}

fn loss_counter(name: &str, source: CounterSource, value: u64) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind: CounterKind::Loss,
        units: CounterUnits::Events,
        source,
        value,
    }
}

fn input_base() -> FinalizeInput {
    FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 100,
            effective_start_ns: 0,
            effective_end_ns: 100,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: objects_fixture(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::new(7, "demo".to_string(), String::new(), String::new()),
        openssl: OpensslVersion::verified("3.5.1".to_string()),
        disposition: Some(DispositionRecord::exited(0)),
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    }
}

/// Finalize with an honest legacy partition: no fixture in this
/// file enrolls legacy-class candidates, so every counted call
/// (current plus fenced) lands non-legacy-exclusive. Keeps the
/// conservation check passing for its intended subject, never as
/// the failure under test. Attaches the deterministic R12 fixture
/// context (live captures carry the real uname/wall values).
fn finalize_honest(mut input: FinalizeInput) -> CaptureDocument {
    let mut total = 0u64;
    for site in &input.sites {
        total = total.saturating_add(site.calls);
    }
    for bucket in &input.fenced {
        for site in &bucket.sites {
            total = total.saturating_add(site.calls);
        }
    }
    input.legacy_partition = LegacyCallPartition {
        legacy_exclusive: 0,
        non_legacy_exclusive: total,
        shared_ambiguous: 0,
        unfenced_tails: 0,
    };
    let mut doc = finalize(input);
    doc.context = Some(fixture_context());
    doc
}

/// COMPLETE report document: two definite sites (500 + 300 calls),
/// one ambiguous site (2 candidates incl. a weak alias, 100 calls),
/// one quiet site, full coverage, zero loss.
fn complete_doc() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![
        site_at(
            FP_A,
            8,
            100,
            0x1000,
            0,
            500,
            vec![cand(FP_A, "default", 2, 21, &["AES-128-GCM"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_A,
            8,
            100,
            0x2000,
            0,
            300,
            vec![cand(FP_A, "default", 1, 7, &["SHA-256"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_B,
            8,
            200,
            0x1000,
            0,
            100,
            vec![
                cand(FP_B, "default", 2, 21, &["AES-256-GCM"], false),
                cand(FP_B, "default", 2, 21, &["ARIA-256-GCM"], true),
            ],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_C,
            8,
            300,
            0x3000,
            0,
            0,
            vec![cand(FP_C, "third-party:xyz", 1, 9, &["SHA-384"], false)],
            CandidateCoverage::Complete,
        ),
    ];
    input.coverage = vec![
        ScopeCoverage {
            scope: "provider/default".to_string(),
            expected: ExpectedScope::Applicable { sites: 3 },
            discovered: 3,
            attached: 3,
        },
        ScopeCoverage {
            scope: "provider/legacy".to_string(),
            expected: ExpectedScope::NotApplicable,
            discovered: 0,
            attached: 0,
        },
    ];
    input.counters = vec![
        loss_counter("count.map_insert_dropped", CounterSource::KernelMap, 0),
        GapCounter {
            name: "count.windows_closed".to_string(),
            kind: osslscope::evidence::CounterKind::Activity,
            units: CounterUnits::Events,
            source: CounterSource::Drain,
            value: 1,
        },
    ];
    let doc = finalize_honest(input);
    assert_eq!(doc.status, Completeness::Complete);
    assert_eq!(doc.total_calls(), 900);
    doc
}

/// PARTIAL report document: startup + tail gaps, one loss, an
/// undiscovered scope, an unattributed (unknown-coverage) site,
/// unknown OpenSSL version, detached disposition.
fn partial_doc() -> CaptureDocument {
    let mut input = input_base();
    input.window = CaptureWindow {
        requested_start_ns: 0,
        requested_end_ns: 100,
        effective_start_ns: 5,
        effective_end_ns: 95,
        signal_cut: false,
    };
    input.sites = vec![
        site_at(
            FP_A,
            8,
            100,
            0x1000,
            0,
            200,
            vec![cand(FP_A, "default", 2, 21, &["AES-128-GCM"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_B,
            8,
            200,
            0x4000,
            0,
            50,
            vec![cand(FP_B, "default", 1, 7, &["SHA-256"], false)],
            CandidateCoverage::Unknown,
        ),
    ];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 3 },
        discovered: 2,
        attached: 1,
    }];
    input.counters = vec![loss_counter(
        "count.map_insert_dropped",
        CounterSource::KernelRing,
        3,
    )];
    input.target = TargetRecord::new(
        9,
        "staging".to_string(),
        "cid-1".to_string(),
        "sha256:abc".to_string(),
    );
    input.openssl = OpensslVersion::unknown();
    input.disposition = Some(DispositionRecord::detached_running(9));
    let doc = finalize_honest(input);
    assert!(matches!(doc.status, Completeness::Partial { .. }));
    doc
}

/// Traversal-bearing report document: the complete shape plus a
/// fully-populated traversal section (all ten keys incl. the
/// round-4/5 additive census/entry fields) — the I4 conformance
/// subject: emitter evidence the schema must accept.
pub(crate) fn traversal_doc() -> CaptureDocument {
    use osslscope::evidence::{TraversalObject, TraversalRecord, TraversalRecordEntry};
    use osslscope::scan::oracle::{Outcome, PartialReason, TrueT};
    use std::collections::BTreeMap;
    let mut doc = complete_doc();
    doc.traversal = Some(TraversalRecord {
        harvest: TraversalObject {
            path: "/lib/osslscope/osslscope-harvest".to_string(),
            sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .to_string(),
        },
        count: TraversalObject {
            path: "/lib/osslscope/osslscope-count".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
        },
        members: TraversalObject {
            path: "/lib/osslscope/osslscope-members".to_string(),
            sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
                .to_string(),
        },
        records: 2,
        findings: 1,
        polls: 3,
        admitted: BTreeMap::from([(7u32, 10u64), (12u32, 4u64)]),
        entries: vec![
            TraversalRecordEntry {
                tid: 7,
                seq: 0,
                op: 7,
                outcome: Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
                true_t: TrueT::Proven(6),
                alg_count: 7,
                row_count: 3,
                generation: Some(9),
            },
            TraversalRecordEntry {
                tid: 7,
                seq: 1,
                op: 12,
                outcome: Outcome::Partial {
                    reasons: vec![
                        PartialReason::Holes(vec![3]),
                        PartialReason::Trunc(6),
                        PartialReason::CacheShrink {
                            cached: 9,
                            observed: 4,
                        },
                        PartialReason::DrainLoss,
                    ],
                },
                true_t: TrueT::Candidate(4),
                alg_count: 5,
                row_count: 0,
                generation: None,
            },
        ],
        admitted_unknown: vec![9],
        census_loss: 2,
    });
    doc
}

/// FATAL document: recycled pid, no usable evidence.
fn fatal_doc() -> CaptureDocument {
    let mut input = input_base();
    input.window = CaptureWindow {
        requested_start_ns: 1000,
        requested_end_ns: 31000,
        effective_start_ns: 31000,
        effective_end_ns: 31000,
        signal_cut: false,
    };
    input.objects = Vec::new();
    input.fatal = Some(FatalKind::Recycled);
    input.target = TargetRecord::new(11, "gone".to_string(), String::new(), String::new());
    input.openssl = OpensslVersion::unknown();
    input.disposition = None;
    let doc = finalize_honest(input);
    assert!(matches!(
        doc.status,
        Completeness::Fatal {
            kind: FatalKind::Recycled,
            ..
        }
    ));
    doc
}

fn evidence_ref(
    object: &str,
    device: u64,
    inode: u64,
    offset: u64,
    generation: u32,
    calls: u64,
) -> osslscope::evidence::PolicyEvidenceRef {
    osslscope::evidence::PolicyEvidenceRef {
        object: obj(object),
        device,
        inode,
        offset,
        generation,
        calls,
    }
}

/// Violation check document: definite DES use (current + fenced) +
/// evaluated policy with site evidence.
fn violation_doc() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_A,
        8,
        100,
        0x1000,
        0,
        500,
        vec![cand(FP_A, "default", 2, 21, &["DES"], false)],
        CandidateCoverage::Complete,
    )];
    input.fenced = vec![FencedGeneration {
        generation: 1,
        sites: vec![site_at(
            FP_A,
            8,
            100,
            0x1000,
            1,
            50,
            vec![cand(FP_A, "default", 2, 21, &["DES"], false)],
            CandidateCoverage::Complete,
        )],
    }];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 1 },
        discovered: 1,
        attached: 1,
    }];
    input.counters = vec![loss_counter(
        "count.map_insert_dropped",
        CounterSource::KernelMap,
        0,
    )];
    input.policy = Some(PolicyRecord {
        verdict: PolicyVerdict::Violation,
        rules: vec![
            PolicyRuleResult {
                rule: "deny-algorithm".to_string(),
                predicate: "algorithm=DES".to_string(),
                result: RuleVerdict::Violation,
                definite: 550,
                possible: Some(550),
                evidence: vec![
                    evidence_ref(FP_A, 8, 100, 0x1000, 0, 500),
                    evidence_ref(FP_A, 8, 100, 0x1000, 1, 50),
                ],
                engine_evidence: Vec::new(),
            },
            PolicyRuleResult {
                rule: "deny-weak".to_string(),
                predicate: "weak-alias".to_string(),
                result: RuleVerdict::Pass,
                definite: 0,
                possible: Some(0),
                evidence: Vec::new(),
                engine_evidence: Vec::new(),
            },
        ],
    });
    let doc = finalize_honest(input);
    assert!(matches!(doc.status, Completeness::Complete));
    doc
}

/// Salvaged Runtime-fatal violation document: definite DES use with an
/// evaluated policy — usable evidence under a fatal status.
fn runtime_violation_doc() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_A,
        8,
        100,
        0x1000,
        0,
        500,
        vec![cand(FP_A, "default", 2, 21, &["DES"], false)],
        CandidateCoverage::Complete,
    )];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 1 },
        discovered: 1,
        attached: 1,
    }];
    input.counters = vec![loss_counter(
        "discovery.finish_failed",
        CounterSource::Discovery,
        1,
    )];
    input.fatal = Some(FatalKind::Runtime("discovery finish: boom".to_string()));
    input.policy = Some(PolicyRecord {
        verdict: PolicyVerdict::Violation,
        rules: vec![PolicyRuleResult {
            rule: "deny-algorithm".to_string(),
            predicate: "algorithm=DES".to_string(),
            result: RuleVerdict::Violation,
            definite: 500,
            possible: None,
            evidence: vec![evidence_ref(FP_A, 8, 100, 0x1000, 0, 500)],
            engine_evidence: Vec::new(),
        }],
    });
    let doc = finalize_honest(input);
    assert!(matches!(
        doc.status,
        Completeness::Fatal {
            kind: FatalKind::Runtime(_),
            ..
        }
    ));
    assert!(doc.has_usable_evidence());
    doc
}

/// Inconclusive check document: only an ambiguous site + a possible
/// (unproven) algorithm match.
fn inconclusive_doc() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_B,
        8,
        200,
        0x1000,
        0,
        100,
        vec![
            cand(FP_B, "default", 2, 21, &["AES-256-GCM"], false),
            cand(FP_B, "default", 2, 21, &["ARIA-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    )];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 1 },
        discovered: 1,
        attached: 1,
    }];
    input.policy = Some(PolicyRecord {
        verdict: PolicyVerdict::Inconclusive,
        rules: vec![PolicyRuleResult {
            rule: "deny-algorithm".to_string(),
            predicate: "algorithm=AES-256-GCM".to_string(),
            result: RuleVerdict::Inconclusive,
            definite: 0,
            possible: Some(100),
            evidence: Vec::new(),
            engine_evidence: Vec::new(),
        }],
    });
    finalize_honest(input)
}

/// Pass check document: definite SHA use, denied DES cleanly absent.
fn pass_doc() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_A,
        8,
        100,
        0x2000,
        0,
        300,
        vec![cand(FP_A, "default", 1, 7, &["SHA-256"], false)],
        CandidateCoverage::Complete,
    )];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 1 },
        discovered: 1,
        attached: 1,
    }];
    input.policy = Some(PolicyRecord {
        verdict: PolicyVerdict::Pass,
        rules: vec![PolicyRuleResult {
            rule: "deny-algorithm".to_string(),
            predicate: "algorithm=DES".to_string(),
            result: RuleVerdict::Pass,
            definite: 0,
            possible: Some(0),
            evidence: Vec::new(),
            engine_evidence: Vec::new(),
        }],
    });
    finalize_honest(input)
}

fn json_of(doc: &CaptureDocument) -> Value {
    let bytes = render_json(doc).expect("render_json succeeds");
    serde_json::from_slice(&bytes).expect("rendered JSON parses")
}

fn cbom_of(doc: &CaptureDocument) -> Value {
    let bytes = render_cbom(doc).expect("render_cbom succeeds");
    serde_json::from_slice(&bytes).expect("rendered CBOM parses")
}

// ---------------------------------------------------------------- schema

#[test]
fn v2_schema_file_is_well_formed() {
    let schema: Value = serde_json::from_str(V2_SCHEMA_JSON).expect("schema parses");
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        schema["$id"],
        "https://osslscope.dev/schemas/observed-crypto-v2.json"
    );
    // Producer-facing required top-level keys (disposition/policy
    // ride report/check paths and stay optional).
    let required = schema["required"].as_array().unwrap();
    for key in [
        "schema_version",
        "target",
        "openssl",
        "window",
        "completeness",
        "sites",
        "fenced",
        "objects",
        "coverage",
    ] {
        assert!(required.iter().any(|v| v == key), "schema requires {key}");
    }
}

#[test]
fn rendered_fixtures_validate_against_v2_schema() {
    for (name, doc) in [
        ("complete", complete_doc()),
        ("partial", partial_doc()),
        ("fatal", fatal_doc()),
        ("violation", violation_doc()),
        ("inconclusive", inconclusive_doc()),
        ("pass", pass_doc()),
        ("traversal", traversal_doc()),
    ] {
        let v = json_of(&doc);
        validate_v2(&v).unwrap_or_else(|e| panic!("{name} fails schema: {e}"));
        check_v2_semantics(&v).unwrap_or_else(|e| panic!("{name} fails semantics: {e}"));
    }
}

#[test]
fn h5_t4b_anonymous_advertising_provider_assembles_and_validates() {
    // H5 (B-5): an advertising-only provider assembles and
    // validates — the anonymous record registers like any
    // object, and the provider ref resolves. Without the
    // record the doc is a dangling ref — rejected, never
    // sealed.
    const ANON: &str = "unverified-advertising:anonymous";
    let site = || {
        site_at(
            FP_A,
            8,
            100,
            0x1000,
            0,
            10,
            vec![cand(ANON, "unknown", 2, 21, &["other"], false)],
            CandidateCoverage::Complete,
        )
    };
    let mut input = input_base();
    input.sites = vec![site()];
    input.objects.push(ObjectRecord {
        id: obj(ANON),
        device: 0,
        inode: 0,
        display_locator: String::new(),
    });
    let v = json_of(&finalize_honest(input));
    validate_v2(&v).expect("anonymous-provider doc fails schema");
    check_v2_semantics(&v).expect("anonymous-provider doc fails semantics");
    // Negative pin: the same site without the anonymous record
    // is an unlisted ref — rejected.
    let mut input = input_base();
    input.sites = vec![site()];
    let v = json_of(&finalize_honest(input));
    let err = check_v2_semantics(&v).expect_err("dangling anonymous provider accepted");
    assert!(err.contains("unlisted object"), "unexpected: {err}");
}

#[test]
fn every_cli_rule_renders_a_schema_valid_predicate() {
    // F-E/B1: evaluator -> policy-record -> renderer for every CLI
    // rule constructor. deny-engine/deny-weak once emitted
    // "predicate": "" against minLength 1; every rule must render
    // a nonempty predicate and validate end to end.
    for (name, rule) in [
        ("require-provider", PolicyRule::require_provider("default")),
        ("deny-provider", PolicyRule::deny_provider("legacy")),
        ("deny-engine", PolicyRule::deny_engine()),
        ("deny-algorithm", PolicyRule::deny_algorithm("DES")),
        ("deny-weak", PolicyRule::deny_weak()),
        (
            "require-executed",
            PolicyRule::require_executed("AES-256-GCM"),
        ),
    ] {
        let v = evaluate_document(std::slice::from_ref(&rule), &complete_doc());
        let record = policy_record(&v);
        assert_eq!(record.rules.len(), 1, "{name} yields one rule");
        assert!(
            !record.rules[0].predicate.is_empty(),
            "{name} predicate must be nonempty"
        );
        let mut doc = complete_doc();
        doc.policy = Some(record);
        let rendered = json_of(&doc);
        validate_v2(&rendered).unwrap_or_else(|e| panic!("{name} fails schema: {e}"));
        check_v2_semantics(&rendered).unwrap_or_else(|e| panic!("{name} fails semantics: {e}"));
    }
}

#[test]
fn schema_version_gate() {
    // v2 reader matrix (mirrors the v1 compat_matrix shape).
    for ok in [
        "observed-crypto-v2.0",
        "observed-crypto-v2.9",
        "observed-crypto-v2",
    ] {
        assert!(check_version_v2(ok), "v2 reader accepts {ok}");
    }
    for bad in [
        "observed-crypto-v1.0",
        "observed-crypto-v1",
        "observed-crypto-v3.0",
        "observed-crypto-v0.9",
        "0.2-provisional",
        "",
        "observed-crypto-v2.x",
        "observed-crypto-vX",
        "2.0",
    ] {
        assert!(!check_version_v2(bad), "v2 reader rejects {bad}");
    }
    // Old-reader major rejection: a v1 reader refuses v2 documents.
    assert!(!check_version("observed-crypto-v2.0"));
    assert!(!check_version("observed-crypto-v2.9"));
    // Renders carry exactly the current producer version.
    for doc in [complete_doc(), violation_doc(), fatal_doc()] {
        assert_eq!(json_of(&doc)["schema_version"], "observed-crypto-v2.1");
    }
}

#[test]
fn schema_rejects_wrong_types() {
    // (case, JSON pointer, bad value): every flip must fail actual
    // schema validation, not just a key walker.
    let cases: Vec<(&str, &str, Value)> = vec![
        ("calls str", "/sites/0/calls", json!("500")),
        ("op str", "/sites/0/candidates/0/op", json!("2")),
        ("funcid str", "/sites/0/candidates/0/funcid", json!("21")),
        (
            "weak_alias str",
            "/sites/0/candidates/0/weak_alias",
            json!("no"),
        ),
        ("signal_cut str", "/window/signal_cut", json!("false")),
        ("pid str", "/target/pid", json!("7")),
        (
            "counter value str",
            "/completeness/counters/0/value",
            json!("3"),
        ),
        ("disposition code str", "/disposition/code", json!("0")),
        ("version num", "/openssl/version", json!(7)),
        ("status case", "/completeness/status", json!("complete")),
        (
            "candidates_coverage case",
            "/sites/0/candidates_coverage",
            json!("COMPLETE"),
        ),
        (
            "counter kind",
            "/completeness/counters/0/kind",
            json!("los"),
        ),
        (
            "counter units",
            "/completeness/counters/0/units",
            json!("callz"),
        ),
        (
            "counter source",
            "/completeness/counters/0/source",
            json!("kernel"),
        ),
        ("disposition outcome", "/disposition/outcome", json!("exit")),
        ("sites obj", "/sites", json!({})),
        ("reasons str", "/completeness/reasons", json!("x")),
        ("counters obj", "/completeness/counters", json!({})),
        ("openssl state", "/openssl/state", json!("VERIFIED")),
        (
            "expected state",
            "/coverage/0/expected/state",
            json!("applicable-ish"),
        ),
    ];
    assert!(!cases.is_empty());
    for (name, pointer, bad) in &cases {
        for doc in [complete_doc(), violation_doc(), partial_doc()] {
            let mut v = json_of(&doc);
            let target = v.pointer_mut(pointer).unwrap_or_else(|| {
                panic!("fixture lacks {pointer} (case {name}) — update fixture or case")
            });
            *target = bad.clone();
            assert!(
                validate_v2(&v).is_err(),
                "schema accepted wrong type (case {name})"
            );
        }
    }
    // Policy-section cases run on check documents only.
    let policy_cases: Vec<(&str, &str, Value)> = vec![
        ("definite str", "/policy/rules/0/definite", json!("550")),
        ("policy verdict", "/policy/verdict", json!("PASS")),
        ("rule result", "/policy/rules/0/result", json!("maybe")),
        ("possible str", "/policy/rules/0/possible", json!("unknown")),
        ("rules str", "/policy/rules", json!("x")),
    ];
    for (name, pointer, bad) in &policy_cases {
        for doc in [violation_doc(), inconclusive_doc(), pass_doc()] {
            let mut v = json_of(&doc);
            *v.pointer_mut(pointer)
                .unwrap_or_else(|| panic!("fixture lacks {pointer} (case {name})")) = bad.clone();
            assert!(
                validate_v2(&v).is_err(),
                "schema accepted wrong type (case {name})"
            );
        }
    }
    // Reason-shape case runs on the PARTIAL fixture (COMPLETE has no
    // reasons); a bogus kind matches no anyOf branch.
    let mut v = json_of(&partial_doc());
    assert!(!v["completeness"]["reasons"].as_array().unwrap().is_empty());
    v["completeness"]["reasons"][0] = json!({"kind": "bogus"});
    assert!(validate_v2(&v).is_err(), "bogus reason kind accepted");
}

#[test]
fn schema_rejects_negative_and_overflow_counts() {
    let big: Value = serde_json::from_str("18446744073709551616").unwrap(); // 2^64
    let cases: Vec<(&str, &str, Value)> = vec![
        ("calls negative", "/sites/0/calls", json!(-1)),
        ("calls overflow", "/sites/0/calls", big.clone()),
        (
            "counter value negative",
            "/completeness/counters/0/value",
            json!(-1),
        ),
        ("device negative", "/sites/0/device", json!(-1)),
        ("offset overflow", "/sites/0/offset", big.clone()),
        ("pid overflow", "/target/pid", big.clone()),
        ("op overflow", "/sites/0/candidates/0/op", big.clone()),
        ("generation negative", "/sites/0/generation", json!(-1)),
        (
            "window ns negative",
            "/window/requested_start_ns",
            json!(-1),
        ),
        (
            "disposition code overflow",
            "/disposition/code",
            big.clone(),
        ),
        ("first_ns overflow", "/sites/0/first_ns", big.clone()),
    ];
    assert!(!cases.is_empty());
    for (name, pointer, bad) in &cases {
        for doc in [complete_doc(), violation_doc()] {
            let mut v = json_of(&doc);
            *v.pointer_mut(pointer)
                .unwrap_or_else(|| panic!("fixture lacks {pointer} (case {name})")) = bad.clone();
            assert!(
                validate_v2(&v).is_err(),
                "schema accepted bad count (case {name})"
            );
        }
    }
    // Policy-bound cases run on the check document only.
    for (name, pointer) in [
        ("definite negative", "/policy/rules/0/definite"),
        ("possible negative", "/policy/rules/0/possible"),
    ] {
        let mut v = json_of(&violation_doc());
        *v.pointer_mut(pointer).unwrap() = json!(-1);
        assert!(
            validate_v2(&v).is_err(),
            "schema accepted bad count (case {name})"
        );
    }
    // Boundary acceptance: u64::MAX counts and i32 exit codes validate.
    let max_u64: Value = serde_json::from_str("18446744073709551615").unwrap();
    let mut v = json_of(&complete_doc());
    v["sites"][0]["calls"] = max_u64;
    validate_v2(&v).expect("u64::MAX calls validate");
    let mut v = json_of(&complete_doc());
    v["disposition"]["code"] = json!(-1073741824);
    validate_v2(&v).expect("negative i32 exit code validates");
}

#[test]
fn schema_rejects_unexpected_address_argv_fields() {
    // Raw addresses/argv must fail the public output validator
    // wherever they are smuggled in (R07).
    let fields: Vec<(&str, Value)> = vec![
        ("address", json!(140737348900864u64)),
        ("runtime_address", json!("0x7ffd4a3b2c10")),
        ("argv", json!(["sh", "-c", "secret"])),
        ("cmdline", json!("demo --password hunter2")),
        ("raw_address", json!(4096)),
    ];
    let parents = [
        "",
        "/target",
        "/sites/0",
        "/sites/0/candidates/0",
        "/objects/0",
        "/window",
        "/completeness",
    ];
    assert!(!fields.is_empty());
    for (field, value) in &fields {
        for parent in &parents {
            let mut v = json_of(&complete_doc());
            let node = if parent.is_empty() {
                &mut v
            } else {
                v.pointer_mut(parent).unwrap()
            };
            node.as_object_mut()
                .unwrap()
                .insert(field.to_string(), value.clone());
            assert!(
                validate_v2(&v).is_err(),
                "schema accepted {field} under {parent:?}"
            );
            assert!(
                check_v2_semantics(&v).is_err(),
                "semantics accepted {field} under {parent:?}"
            );
        }
    }
    // Same for the policy section of a check document.
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]
        .as_object_mut()
        .unwrap()
        .insert("address".to_string(), json!(1));
    assert!(validate_v2(&v).is_err());
}

#[test]
fn schema_rejects_unknown_keys_and_missing_required() {
    let mut v = json_of(&complete_doc());
    v.as_object_mut()
        .unwrap()
        .insert("extra".to_string(), json!(1));
    assert!(validate_v2(&v).is_err(), "top-level extra key accepted");
    let mut v = json_of(&complete_doc());
    v["sites"][0].as_object_mut().unwrap().remove("calls");
    assert!(validate_v2(&v).is_err(), "missing required key accepted");
    let mut v = json_of(&complete_doc());
    v.as_object_mut().unwrap().remove("window");
    assert!(validate_v2(&v).is_err(), "missing window accepted");
    // Optional sections stay optional: report shape omits policy,
    // fatal shape omits disposition — both validate.
    let v = json_of(&complete_doc());
    assert!(v.get("policy").is_none());
    validate_v2(&v).expect("report shape validates");
    let v = json_of(&fatal_doc());
    assert!(v.get("disposition").is_none());
    validate_v2(&v).expect("fatal shape validates");
}

#[test]
fn semantics_rejects_missing_object_refs() {
    // Referential integrity is beyond plain JSON Schema: these pass
    // the schema but must fail semantics.
    let mut v = json_of(&complete_doc());
    v["sites"][0]["object"] = json!("build:no-such-object");
    assert!(validate_v2(&v).is_ok(), "schema cannot express refs");
    assert!(
        check_v2_semantics(&v).is_err(),
        "dangling site object accepted"
    );

    let mut v = json_of(&complete_doc());
    v["sites"][0]["candidates"][0]["provider"] = json!("build:no-such-provider");
    assert!(
        check_v2_semantics(&v).is_err(),
        "dangling provider accepted"
    );

    let mut v = json_of(&complete_doc());
    v["objects"] = json!([]);
    assert!(check_v2_semantics(&v).is_err(), "emptied objects accepted");

    // Policy evidence refs must resolve to a listed site key.
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["evidence"][0]["offset"] = json!(0x9999);
    assert!(
        check_v2_semantics(&v).is_err(),
        "dangling evidence ref accepted"
    );
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["evidence"][0]["generation"] = json!(7);
    assert!(
        check_v2_semantics(&v).is_err(),
        "wrong-generation ref accepted"
    );
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["evidence"][0]["calls"] = json!(50000);
    assert!(
        check_v2_semantics(&v).is_err(),
        "evidence over-claiming site calls accepted"
    );
}

#[test]
fn semantics_rejects_inconsistent_windows() {
    let mut v = json_of(&complete_doc());
    v["window"]["effective_start_ns"] = json!(50);
    v["window"]["requested_start_ns"] = json!(60);
    assert!(
        check_v2_semantics(&v).is_err(),
        "effective-before-requested accepted"
    );

    let mut v = json_of(&complete_doc());
    v["window"]["effective_end_ns"] = json!(1000);
    assert!(
        check_v2_semantics(&v).is_err(),
        "effective-past-requested accepted"
    );

    let mut v = json_of(&complete_doc());
    v["window"]["requested_end_ns"] = json!(0);
    v["window"]["requested_start_ns"] = json!(50);
    assert!(
        check_v2_semantics(&v).is_err(),
        "inverted requested window accepted"
    );

    let mut v = json_of(&complete_doc());
    v["window"]["effective_start_ns"] = json!(90);
    v["window"]["effective_end_ns"] = json!(80);
    assert!(
        check_v2_semantics(&v).is_err(),
        "inverted effective window accepted"
    );
}

#[test]
fn semantics_rejects_site_activity_outside_effective_window() {
    // Bm1: site first/last must sit inside the effective window —
    // counting cannot precede the clock or run past the deadline.
    // (Window here is 0..100; fixture sites run 10..90.)
    let mut v = json_of(&complete_doc());
    v["sites"][0]["last_ns"] = json!(500);
    assert!(
        check_v2_semantics(&v).is_err(),
        "site activity past effective end accepted"
    );

    // First-touch before the effective start (PARTIAL fixture with
    // a narrowed 5..95 window isolates containment from the
    // COMPLETE reconciliation below).
    let mut v = json_of(&partial_doc());
    v["sites"][0]["first_ns"] = json!(0);
    assert!(
        check_v2_semantics(&v).is_err(),
        "site activity before effective start accepted"
    );

    // Fenced sites are contained too.
    let mut v = json_of(&violation_doc());
    v["fenced"][0]["sites"][0]["last_ns"] = json!(500);
    assert!(
        check_v2_semantics(&v).is_err(),
        "fenced site activity past effective end accepted"
    );

    // Boundaries are inclusive: touching the clock edges is fine.
    let mut v = json_of(&complete_doc());
    v["sites"][0]["first_ns"] = json!(0);
    v["sites"][0]["last_ns"] = json!(100);
    assert!(
        check_v2_semantics(&v).is_ok(),
        "boundary-contained site rejected: {:?}",
        check_v2_semantics(&v).err()
    );
}

#[test]
fn semantics_rejects_complete_contradicting_underlying_fields() {
    // Bm1: COMPLETE must reconcile window gaps, coverage, and loss
    // data — not just the reasons array.
    // Nonzero loss counter (fixture counter 0 is a zero loss).
    let mut v = json_of(&complete_doc());
    v["completeness"]["counters"][0]["value"] = json!(1);
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with nonzero loss accepted"
    );

    // Unknown denominator.
    let mut v = json_of(&complete_doc());
    v["coverage"][0]["expected"]["state"] = json!("unknown");
    v["coverage"][0]["expected"]["sites"] = Value::Null;
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with unknown coverage accepted"
    );

    // Applicable shortfall: fewer discovered than expected.
    let mut v = json_of(&complete_doc());
    v["coverage"][0]["discovered"] = json!(1);
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with undiscovered sites accepted"
    );

    // Narrowed effective window (still consistent: 0..95 in 0..100).
    let mut v = json_of(&complete_doc());
    v["window"]["effective_end_ns"] = json!(95);
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with a tail gap accepted"
    );

    // Signal-cut window.
    let mut v = json_of(&complete_doc());
    v["window"]["signal_cut"] = json!(true);
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with signal_cut accepted"
    );

    // Executed-but-unattributed site (calls 500, set unknown).
    let mut v = json_of(&complete_doc());
    v["sites"][0]["candidates_coverage"] = json!("unknown");
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with unattributed calls accepted"
    );

    // R01: bounded ambiguity is attributed-but-unresolvable, not
    // unattributed — a COMPLETE doc with an ambiguous_complete
    // executed site validates structurally and semantically.
    let mut v = json_of(&complete_doc());
    v["sites"][0]["candidates_coverage"] = json!("ambiguous_complete");
    validate_v2(&v).unwrap_or_else(|e| panic!("ambiguous_complete fails schema: {e}"));
    check_v2_semantics(&v).unwrap_or_else(|e| panic!("ambiguous_complete fails semantics: {e}"));

    // PARTIAL keeps accepting all of these shapes (reconciliation
    // binds COMPLETE only).
    assert!(
        check_v2_semantics(&json_of(&partial_doc())).is_ok(),
        "valid PARTIAL rejected: {:?}",
        check_v2_semantics(&json_of(&partial_doc())).err()
    );
}

#[test]
fn semantics_rejects_inconsistent_records() {
    let mut v = json_of(&complete_doc());
    v["openssl"]["version"] = Value::Null;
    assert!(
        check_v2_semantics(&v).is_err(),
        "verified-without-version accepted"
    );
    let mut v = json_of(&partial_doc());
    v["openssl"]["version"] = json!("9.9.9");
    assert!(
        check_v2_semantics(&v).is_err(),
        "unknown-with-version accepted"
    );
    let mut v = json_of(&complete_doc());
    v["disposition"]["code"] = Value::Null;
    assert!(
        check_v2_semantics(&v).is_err(),
        "exited-without-code accepted"
    );
    let mut v = json_of(&partial_doc());
    v["disposition"]["pid"] = Value::Null;
    assert!(
        check_v2_semantics(&v).is_err(),
        "detached-without-pid accepted"
    );
    let mut v = json_of(&complete_doc());
    v["disposition"]["pid"] = json!(7);
    assert!(check_v2_semantics(&v).is_err(), "exited-with-pid accepted");
    // Fatal kind tracks status exactly.
    let mut v = json_of(&fatal_doc());
    v["completeness"]["fatal_kind"] = Value::Null;
    assert!(
        check_v2_semantics(&v).is_err(),
        "fatal-without-kind accepted"
    );
    let mut v = json_of(&complete_doc());
    v["completeness"]["fatal_kind"] = json!({"kind": "recycled", "detail": Value::Null});
    assert!(
        check_v2_semantics(&v).is_err(),
        "complete-with-fatal-kind accepted"
    );
    // Site timestamps order.
    let mut v = json_of(&complete_doc());
    v["sites"][0]["first_ns"] = json!(95);
    v["sites"][0]["last_ns"] = json!(90);
    assert!(
        check_v2_semantics(&v).is_err(),
        "inverted site times accepted"
    );
}

#[test]
fn semantics_enforces_privacy_shape() {
    // argv_redacted is const-true and required.
    let mut v = json_of(&complete_doc());
    v["target"]["argv_redacted"] = json!(false);
    assert!(validate_v2(&v).is_err(), "argv_redacted=false accepted");
    let mut v = json_of(&complete_doc());
    v["target"].as_object_mut().unwrap().remove("argv_redacted");
    assert!(validate_v2(&v).is_err(), "missing argv_redacted accepted");
}

// ---------------------------------------------------------------- conservation

#[test]
fn ambiguous_sites_conserve_counts() {
    // Two algorithms sharing one site with N calls render N site
    // calls, not 2N algorithm calls (R01); candidates carry no
    // counts of their own.
    let doc = complete_doc();
    let v = json_of(&doc);
    let json_total: u64 = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["calls"].as_u64().unwrap())
        .sum::<u64>()
        .saturating_add(
            v["fenced"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|g| g["sites"].as_array().unwrap())
                .map(|s| s["calls"].as_u64().unwrap())
                .sum::<u64>(),
        );
    assert_eq!(json_total, doc.total_calls());
    assert_eq!(json_total, 900);
    // Each site key appears once (no per-candidate duplication).
    let mut keys = std::collections::BTreeSet::new();
    for s in v["sites"].as_array().unwrap() {
        let key = format!(
            "{}:{}:{}:{}:{}",
            s["object"], s["device"], s["inode"], s["offset"], s["generation"]
        );
        assert!(keys.insert(key), "duplicated site key in JSON");
        for c in s["candidates"].as_array().unwrap() {
            assert!(
                c.get("calls").is_none() && c.get("count").is_none(),
                "candidate must not carry counts"
            );
        }
    }
    // Ambiguous site keeps both candidates (weak alias survives).
    let amb = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["candidates"].as_array().unwrap().len() == 2)
        .expect("ambiguous site renders");
    assert_eq!(amb["calls"], 100);
    assert_eq!(amb["candidates_coverage"], "complete");
    let weak: Vec<&Value> = amb["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["weak_alias"].as_bool().unwrap())
        .collect();
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0]["algorithm_classes"], json!(["ARIA-256-GCM"]));
    // Fenced detail conserves too.
    let v = json_of(&violation_doc());
    let fenced_total: u64 = v["fenced"][0]["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["calls"].as_u64().unwrap())
        .sum();
    assert_eq!(fenced_total, 50);
}

fn xorshift_shuffled<T: Clone>(mut v: Vec<T>, seed: u64) -> Vec<T> {
    // Deterministic Fisher-Yates (fixed seeds; no rng dependency).
    let mut s = seed | 1;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for i in (1..v.len()).rev() {
        let j = (rnd() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

fn shuffled_variants() -> Vec<CaptureDocument> {
    // Same evidence in several randomized arrival orders (sites,
    // candidates, objects, coverage, counters, policy rules all
    // shuffled): finalize canonicalizes every list.
    let base_sites = vec![
        site_at(
            FP_A,
            8,
            100,
            0x1000,
            0,
            500,
            vec![cand(FP_A, "default", 2, 21, &["AES-128-GCM"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_B,
            8,
            200,
            0x1000,
            0,
            100,
            vec![
                cand(FP_B, "default", 2, 21, &["AES-256-GCM"], false),
                cand(FP_B, "default", 2, 21, &["ARIA-256-GCM"], true),
            ],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_A,
            8,
            100,
            0x2000,
            0,
            300,
            vec![cand(FP_A, "default", 1, 7, &["SHA-256"], false)],
            CandidateCoverage::Complete,
        ),
    ];
    (0..4)
        .map(|round| {
            let mut input = input_base();
            input.sites = xorshift_shuffled(base_sites.clone(), 0x1234 + round);
            for site in &mut input.sites {
                site.candidates = xorshift_shuffled(site.candidates.clone(), 0x777 + round * 131);
            }
            input.objects = xorshift_shuffled(objects_fixture(), 0x555 + round);
            input.coverage = xorshift_shuffled(
                vec![
                    ScopeCoverage {
                        scope: "provider/default".to_string(),
                        expected: ExpectedScope::Applicable { sites: 3 },
                        discovered: 3,
                        attached: 3,
                    },
                    ScopeCoverage {
                        scope: "provider/legacy".to_string(),
                        expected: ExpectedScope::NotApplicable,
                        discovered: 0,
                        attached: 0,
                    },
                ],
                0x999 + round,
            );
            input.counters = xorshift_shuffled(
                vec![
                    loss_counter("count.map_insert_dropped", CounterSource::KernelMap, 0),
                    loss_counter("capture.over_budget", CounterSource::Drain, 0),
                ],
                0xabc + round,
            );
            input.policy = Some(PolicyRecord {
                verdict: PolicyVerdict::Pass,
                rules: xorshift_shuffled(
                    vec![
                        PolicyRuleResult {
                            rule: "deny-algorithm".to_string(),
                            predicate: "algorithm=DES".to_string(),
                            result: RuleVerdict::Pass,
                            definite: 0,
                            possible: Some(0),
                            evidence: Vec::new(),
                            engine_evidence: Vec::new(),
                        },
                        PolicyRuleResult {
                            rule: "deny-weak".to_string(),
                            predicate: "weak-alias".to_string(),
                            result: RuleVerdict::Pass,
                            definite: 0,
                            possible: Some(0),
                            evidence: Vec::new(),
                            engine_evidence: Vec::new(),
                        },
                    ],
                    0xdef + round,
                ),
            });
            finalize_honest(input)
        })
        .collect()
}

#[test]
fn rendering_is_input_order_independent() {
    let variants = shuffled_variants();
    assert!(variants.len() >= 2);
    let first_json = render_json(&variants[0]).unwrap();
    let first_human = render_human(&variants[0]);
    let first_cbom = render_cbom(&variants[0]).unwrap();
    for (i, doc) in variants.iter().enumerate().skip(1) {
        assert_eq!(
            render_json(doc).unwrap(),
            first_json,
            "JSON differs for order variant {i}"
        );
        assert_eq!(
            render_human(doc),
            first_human,
            "human differs for order variant {i}"
        );
        assert_eq!(
            render_cbom(doc).unwrap(),
            first_cbom,
            "CBOM differs for order variant {i}"
        );
    }
    // Rendered artifacts are byte-stable (sorted keys, pretty,
    // trailing newline) under re-serialization.
    let v: Value = serde_json::from_slice(&first_json).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&v).unwrap() + "\n",
        String::from_utf8(first_json.clone()).unwrap()
    );
    let v: Value = serde_json::from_slice(&first_cbom).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&v).unwrap() + "\n",
        String::from_utf8(first_cbom).unwrap()
    );
}

// ---------------------------------------------------------------- human

#[test]
fn human_shows_uncertainty_honestly() {
    let text = render_human(&complete_doc());
    // Definite sites name their single agreed algorithm; the total
    // is the conserved site total (900, not per-candidate).
    assert!(text.contains("900 calls"), "{text}");
    assert!(text.contains("definite: AES-128-GCM"), "{text}");
    assert!(text.contains("definite: SHA-256"), "{text}");
    // Ambiguous sites say so and list candidates without counts.
    assert!(text.contains("AMBIGUOUS"), "{text}");
    assert!(text.contains("attribution uncertain"), "{text}");
    assert!(text.contains("2 candidates"), "{text}");
    assert!(text.contains("ARIA-256-GCM"), "{text}");
    assert!(text.contains("weak"), "{text}");
    for line in text.lines() {
        if line.contains("candidate:") {
            assert!(
                !line.contains("calls"),
                "candidate line must not carry counts: {line}"
            );
        }
    }
    // Unknown-coverage sites are unattributed, never guessed.
    let text = render_human(&partial_doc());
    assert!(text.contains("UNATTRIBUTED"), "{text}");
    assert!(text.contains("candidate set incomplete"), "{text}");
    // Absence doctrine rides every human artifact.
    assert!(text.contains("absence = not-observed in window"), "{text}");
}

#[test]
fn human_verified_vs_unknown_openssl() {
    let text = render_human(&complete_doc());
    assert!(
        text.contains("openssl: 3.5.1 (verified object metadata)"),
        "{text}"
    );
    let text = render_human(&partial_doc());
    assert!(
        text.contains("openssl: unknown (no verified version)"),
        "{text}"
    );
    let text = render_human(&fatal_doc());
    assert!(text.contains("openssl: unknown"), "{text}");
}

#[test]
fn human_covers_losses_disposition_actionability() {
    let text = render_human(&partial_doc());
    // Source-tagged loss with units, not a bare number.
    assert!(text.contains("count.map_insert_dropped"), "{text}");
    assert!(text.contains("kernel-ring"), "{text}");
    assert!(text.contains("startup-gap"), "{text}");
    assert!(text.contains("tail-gap"), "{text}");
    // Disposition, safe actionability, coverage.
    assert!(
        text.contains("disposition: detached-running pid=9"),
        "{text}"
    );
    assert!(text.contains("argv_redacted=true"), "{text}");
    assert!(text.contains("pid=9 (staging)"), "{text}");
    assert!(text.contains("provider/default"), "{text}");
    assert!(text.contains("status=PARTIAL"), "{text}");

    let text = render_human(&complete_doc());
    assert!(text.contains("disposition: exited code=0"), "{text}");
    assert!(text.contains("status=COMPLETE"), "{text}");

    // Fatal: kind, reasons, no invented evidence.
    let text = render_human(&fatal_doc());
    assert!(text.contains("status=FATAL"), "{text}");
    assert!(text.contains("recycled"), "{text}");
    assert!(text.contains("0 calls"), "{text}");
    assert!(
        text.contains("disposition: unknown (not recorded)"),
        "{text}"
    );

    // Policy section rides check documents only.
    let text = render_human(&violation_doc());
    assert!(text.contains("policy: violation"), "{text}");
    assert!(text.contains("deny-algorithm"), "{text}");
    assert!(text.contains("definite=550"), "{text}");
    let text = render_human(&inconclusive_doc());
    assert!(text.contains("policy: inconclusive"), "{text}");
    assert!(text.contains("possible=100"), "{text}");
    let text = render_human(&complete_doc());
    assert!(text.contains("policy: (not evaluated)"), "{text}");
}

#[test]
fn human_contains_no_address_shaped_bytes() {
    for doc in [
        complete_doc(),
        partial_doc(),
        fatal_doc(),
        violation_doc(),
        inconclusive_doc(),
        traversal_doc(),
    ] {
        let text = render_human(&doc);
        assert!(
            !contains_hex_address(&text),
            "human output contains address-shaped bytes:\n{text}"
        );
        assert!(!text.contains("cmdline"), "human leaks cmdline:\n{text}");
        // File offsets render decimal and labeled, never bare hex.
        assert!(!text.contains("0x1000"), "{text}");
    }
}

fn contains_hex_address(text: &str) -> bool {
    // `0x` followed by a hex run: file offsets render decimal, so
    // any match is address-shaped output.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'0' && bytes[i + 1] == b'x' && bytes[i + 2].is_ascii_hexdigit() {
            return true;
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------- CBOM

fn cbom_props(component: &Value) -> std::collections::BTreeMap<String, String> {
    component["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_string(),
                p["value"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn cbom_metadata(cbom: &Value) -> std::collections::BTreeMap<String, String> {
    cbom["metadata"]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_string(),
                p["value"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[test]
fn cbom_exports_only_definite_assets() {
    let cbom = cbom_of(&complete_doc());
    assert_eq!(cbom["bomFormat"], "CycloneDX");
    assert_eq!(cbom["specVersion"], "1.6");
    let comps = cbom["components"].as_array().unwrap();
    // Two definite sites → two components; the ambiguous site and
    // the quiet site contribute none.
    assert_eq!(comps.len(), 2);
    let algs: Vec<String> = comps
        .iter()
        .map(|c| cbom_props(c)["osslscope:algorithm"].clone())
        .collect();
    assert!(algs.contains(&"AES-128-GCM".to_string()), "{algs:?}");
    assert!(algs.contains(&"SHA-256".to_string()), "{algs:?}");
    for c in comps {
        assert_eq!(c["type"], "cryptographic-asset");
        assert_eq!(c["cryptoProperties"]["assetType"], "algorithm");
        let p = cbom_props(c);
        assert_eq!(p["osslscope:backing-object"], FP_A);
        assert_eq!(p["osslscope:generation"], "0");
        assert_eq!(p["osslscope:execution-evidence-completeness"], "COMPLETE");
    }
    // Omitted ambiguous counts + evidence refs stay explicit.
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "1");
    assert_eq!(meta["osslscope:omitted-ambiguous-calls"], "100");
    assert!(
        meta["osslscope:omitted-evidence-refs"].contains("4096"),
        "evidence refs must name the omitted site: {:?}",
        meta["osslscope:omitted-evidence-refs"]
    );
}

#[test]
fn cbom_never_invents_per_candidate_assets() {
    // One ambiguous site with 100 calls and 2 candidates: zero
    // components (never one full-count asset per candidate).
    let cbom = cbom_of(&inconclusive_doc());
    assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "1");
    assert_eq!(meta["osslscope:omitted-ambiguous-calls"], "100");
    assert_eq!(meta["osslscope:policy-verdict"], "inconclusive");
}

#[test]
fn cbom_covers_fenced_and_policy() {
    let cbom = cbom_of(&violation_doc());
    let comps = cbom["components"].as_array().unwrap();
    assert_eq!(comps.len(), 2);
    let gens: Vec<String> = comps
        .iter()
        .map(|c| cbom_props(c)["osslscope:generation"].clone())
        .collect();
    assert!(gens.contains(&"0".to_string()), "{gens:?}");
    assert!(gens.contains(&"1".to_string()), "{gens:?}");
    // Every component references its actual backing object.
    for c in comps {
        assert_eq!(cbom_props(c)["osslscope:backing-object"], FP_A);
    }
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:policy-verdict"], "violation");
}

#[test]
fn setup_failure_document_renders_fatal_report_and_check_shapes() {
    // F-E/B4: a capture setup failure must still attempt every
    // requested artifact from a typed no-evidence document — a
    // fatal primary plus (for check) a no-verdict policy section
    // and an explicit-empty fatal CBOM — instead of returning
    // with nothing written.
    let doc = setup_failure_document(FatalKind::Environment("mock setup failure".to_string()));
    assert!(matches!(doc.status, Completeness::Fatal { .. }));
    assert!(doc.policy.is_none());
    let v = json_of(&doc);
    validate_v2(&v).expect("fatal report shape validates");
    check_v2_semantics(&v).expect("fatal report shape is sound");
    let mut cdoc = setup_failure_document(FatalKind::Environment("mock setup failure".to_string()));
    let verdict = evaluate_document(&[], &cdoc);
    assert!(verdict.no_verdict);
    cdoc.policy = Some(policy_record(&verdict));
    let cv = json_of(&cdoc);
    validate_v2(&cv).expect("fatal check shape validates");
    check_v2_semantics(&cv).expect("fatal check shape is sound");
    assert_eq!(cv["policy"]["verdict"], "no-verdict");
    let cbom = cbom_of(&cdoc);
    assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    let disclaimer = &cbom_metadata(&cbom)["osslscope:completeness-disclaimer"];
    assert!(disclaimer.contains("FATAL"), "{disclaimer}");
}

#[test]
fn cbom_fatal_is_explicit_empty() {
    let cbom = cbom_of(&fatal_doc());
    assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    let meta = cbom_metadata(&cbom);
    let disclaimer = &meta["osslscope:completeness-disclaimer"];
    assert!(disclaimer.contains("FATAL"), "{disclaimer}");
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
}

#[test]
fn cbom_carries_same_window() {
    for doc in [
        complete_doc(),
        partial_doc(),
        violation_doc(),
        inconclusive_doc(),
        fatal_doc(),
    ] {
        let cbom = cbom_of(&doc);
        let meta = cbom_metadata(&cbom);
        assert_eq!(
            meta["osslscope:window-requested-start-ns"],
            doc.window.requested_start_ns.to_string()
        );
        assert_eq!(
            meta["osslscope:window-requested-end-ns"],
            doc.window.requested_end_ns.to_string()
        );
        assert_eq!(
            meta["osslscope:window-effective-start-ns"],
            doc.window.effective_start_ns.to_string()
        );
        assert_eq!(
            meta["osslscope:window-effective-end-ns"],
            doc.window.effective_end_ns.to_string()
        );
        assert_eq!(meta["osslscope:schema-version"], "observed-crypto-v2.1");
    }
    // PARTIAL disclaimer names the gaps.
    let meta = cbom_metadata(&cbom_of(&partial_doc()));
    let disclaimer = &meta["osslscope:completeness-disclaimer"];
    assert!(disclaimer.contains("PARTIAL"), "{disclaimer}");
    assert!(disclaimer.contains("startup-gap"), "{disclaimer}");
}

// ---------------------------------------------------------------- delivery

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "osslscope-output-contract-{}-{name}",
        std::process::id()
    ));
    p
}

fn remove_quiet(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

fn assert_diagnostics_bounded(diagnostics: &[String]) {
    assert!(
        diagnostics.len() <= 8,
        "diagnostics exceed 8 lines: {diagnostics:?}"
    );
    for line in diagnostics {
        assert!(
            line.chars().count() <= 200,
            "diagnostic exceeds 200 chars: {line:?}"
        );
        assert!(!line.contains('\n'), "diagnostic is not one line: {line:?}");
    }
}

#[test]
fn delivery_attempts_cbom_despite_primary_failure() {
    // Unwritable primary (missing parent) vs writable CBOM: both
    // attempted from the one document, CBOM bytes exact.
    let missing_parent = temp_path("no-such-dir/report.json");
    let _ = std::fs::remove_dir_all(missing_parent.parent().unwrap());
    let cbom_path = temp_path("ok.cbom.json");
    remove_quiet(&cbom_path);
    let doc = complete_doc();
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(missing_parent.clone()),
        cbom: Some(OutputDest::File(cbom_path.clone())),
    };
    let res = write_artifacts(&doc, &req);
    assert!(!res.primary.ok, "unwritable primary must fail");
    assert_eq!(res.primary.bytes, 0);
    assert!(res.primary.error.is_some());
    let cbom = res
        .cbom
        .as_ref()
        .expect("cbom attempted despite primary failure");
    assert!(cbom.ok, "writable CBOM must succeed: {cbom:?}");
    assert!(cbom.bytes > 0);
    assert_eq!(
        std::fs::read(&cbom_path).unwrap(),
        render_cbom(&doc).unwrap(),
        "CBOM bytes must equal a direct render (no second capture)"
    );
    assert!(res.failed());
    assert!(!res.delivered_all());
    assert!(!res.diagnostics.is_empty());
    assert_diagnostics_bounded(&res.diagnostics);
    remove_quiet(&cbom_path);
}

#[test]
fn delivery_attempts_primary_despite_cbom_failure() {
    // Reverse failure: primary succeeds with exact bytes while the
    // CBOM fails; the failure is recorded, not silent.
    let primary_path = temp_path("ok.report.json");
    remove_quiet(&primary_path);
    let missing_parent = temp_path("no-such-dir/cbom.json");
    let _ = std::fs::remove_dir_all(missing_parent.parent().unwrap());
    let doc = violation_doc();
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(primary_path.clone()),
        cbom: Some(OutputDest::File(missing_parent)),
    };
    let res = write_artifacts(&doc, &req);
    assert!(
        res.primary.ok,
        "writable primary must succeed: {:?}",
        res.primary
    );
    assert_eq!(
        std::fs::read(&primary_path).unwrap(),
        render_json(&doc).unwrap()
    );
    let cbom = res.cbom.as_ref().expect("cbom attempted");
    assert!(!cbom.ok, "unwritable CBOM must fail");
    assert!(res.failed());
    assert_diagnostics_bounded(&res.diagnostics);
    remove_quiet(&primary_path);
}

#[test]
fn delivery_human_primary_matches_direct_render() {
    let primary_path = temp_path("ok.report.txt");
    remove_quiet(&primary_path);
    let doc = partial_doc();
    let req = OutputRequest {
        format: OutputFormat::Human,
        primary: OutputDest::File(primary_path.clone()),
        cbom: None,
    };
    let res = write_artifacts(&doc, &req);
    assert!(res.delivered_all(), "{res:?}");
    assert!(res.cbom.is_none());
    assert_eq!(
        std::fs::read_to_string(&primary_path).unwrap(),
        render_human(&doc)
    );
    assert!(res.diagnostics.is_empty());
    remove_quiet(&primary_path);
}

#[cfg(target_os = "linux")]
#[test]
fn delivery_broken_pipe_is_recorded() {
    // Closed read end: the write fails EPIPE (Rust ignores SIGPIPE,
    // so this surfaces as an error, never a kill).
    unsafe {
        let mut fds = [0; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let (read_end, write_end) = (fds[0], fds[1]);
        assert_eq!(libc::close(read_end), 0);
        let path = format!("/proc/self/fd/{write_end}");
        let req = OutputRequest {
            format: OutputFormat::Json,
            primary: OutputDest::File(PathBuf::from(&path)),
            cbom: None,
        };
        let res = write_artifacts(&fatal_doc(), &req);
        assert!(!res.primary.ok, "broken pipe must fail");
        assert_eq!(res.primary.bytes, 0);
        let err = res.primary.error.clone().unwrap();
        assert!(err.contains("Broken pipe"), "expected EPIPE, got {err:?}");
        assert!(res.failed());
        assert_diagnostics_bounded(&res.diagnostics);
        libc::close(write_end);
    }
}

#[test]
fn delivery_rejects_dual_stdout() {
    // Primary + CBOM both to stdout would concatenate two artifacts
    // into unparseable bytes: the CBOM attempt is refused with a
    // diagnostic while the primary still delivers.
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::Stdout,
        cbom: Some(OutputDest::Stdout),
    };
    let res = write_artifacts(&fatal_doc(), &req);
    assert!(res.primary.ok, "primary to stdout must succeed");
    assert!(res.primary.bytes > 0);
    let cbom = res.cbom.as_ref().expect("cbom outcome recorded");
    assert!(!cbom.ok, "dual stdout CBOM must be refused");
    assert!(res.failed());
    assert!(
        res.diagnostics.iter().any(|d| d.contains("stdout")),
        "diagnostic must name stdout: {:?}",
        res.diagnostics
    );
    assert_diagnostics_bounded(&res.diagnostics);
}

#[test]
fn delivery_stdout_primary_succeeds() {
    // Exercises the stdout branch (harness captures the bytes).
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::Stdout,
        cbom: None,
    };
    let res = write_artifacts(&fatal_doc(), &req);
    assert!(res.delivered_all(), "{res:?}");
    assert!(res.diagnostics.is_empty());
}

#[test]
fn delivery_writes_all_verdict_artifacts_without_second_capture() {
    // Fatal/partial/inconclusive/violation/pass/runtime artifacts
    // from one document each: delivered bytes equal direct renders
    // and validate (schema + semantics).
    for (name, doc) in [
        ("fatal", fatal_doc()),
        ("partial", partial_doc()),
        ("inconclusive", inconclusive_doc()),
        ("violation", violation_doc()),
        ("pass", pass_doc()),
        ("runtime", runtime_violation_doc()),
    ] {
        let primary_path = temp_path(&format!("verdict-{name}.json"));
        let cbom_path = temp_path(&format!("verdict-{name}.cdx.json"));
        remove_quiet(&primary_path);
        remove_quiet(&cbom_path);
        let req = OutputRequest {
            format: OutputFormat::Json,
            primary: OutputDest::File(primary_path.clone()),
            cbom: Some(OutputDest::File(cbom_path.clone())),
        };
        let res = write_artifacts(&doc, &req);
        assert!(res.delivered_all(), "{name}: {res:?}");
        let primary = std::fs::read(&primary_path).unwrap();
        let cbom = std::fs::read(&cbom_path).unwrap();
        assert_eq!(
            primary,
            render_json(&doc).unwrap(),
            "{name} primary drifted"
        );
        assert_eq!(cbom, render_cbom(&doc).unwrap(), "{name} cbom drifted");
        let v: Value = serde_json::from_slice(&primary).unwrap();
        validate_v2(&v).unwrap_or_else(|e| panic!("{name} fails schema: {e}"));
        check_v2_semantics(&v).unwrap_or_else(|e| panic!("{name} fails semantics: {e}"));
        // Same window in the CBOM sidecar.
        let meta = cbom_metadata(&serde_json::from_slice::<Value>(&cbom).unwrap());
        assert_eq!(
            meta["osslscope:window-requested-start-ns"],
            doc.window.requested_start_ns.to_string(),
            "{name} CBOM window drifted"
        );
        remove_quiet(&primary_path);
        remove_quiet(&cbom_path);
    }
}

#[test]
fn delivery_runtime_readback_retains_evidence() {
    // R02 fix round 1: a delivered Runtime-fatal violation is
    // independently validated — both destinations are read back, the
    // retained primary bytes carry the verdict and the evidence, the
    // retained CBOM carries the asset, and the exit derives from the
    // actual delivery result (never a fabricated outcome).
    let doc = runtime_violation_doc();
    let primary_path = temp_path("runtime.report.json");
    let cbom_path = temp_path("runtime.report.cdx.json");
    remove_quiet(&primary_path);
    remove_quiet(&cbom_path);
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(primary_path.clone()),
        cbom: Some(OutputDest::File(cbom_path.clone())),
    };
    let res = write_artifacts(&doc, &req);
    assert!(res.delivered_all(), "{res:?}");
    assert!(res.diagnostics.is_empty(), "{:?}", res.diagnostics);
    let primary = std::fs::read(&primary_path).unwrap();
    let cbom_bytes = std::fs::read(&cbom_path).unwrap();
    assert_eq!(
        primary,
        render_json(&doc).unwrap(),
        "delivered primary drifted from the direct render"
    );
    assert_eq!(
        cbom_bytes,
        render_cbom(&doc).unwrap(),
        "delivered CBOM drifted from the direct render"
    );
    let v: Value = serde_json::from_slice(&primary).unwrap();
    validate_v2(&v).expect("delivered Runtime primary fails schema");
    check_v2_semantics(&v).expect("delivered Runtime primary fails semantics");
    assert_eq!(v["policy"]["verdict"], "violation");
    assert_eq!(v["policy"]["rules"][0]["definite"], 500);
    assert_eq!(v["policy"]["rules"][0]["evidence"][0]["calls"], 500);
    assert_eq!(v["sites"][0]["calls"], 500);
    let cbom: Value = serde_json::from_slice(&cbom_bytes).unwrap();
    let comps = cbom["components"].as_array().unwrap();
    assert_eq!(comps.len(), 1);
    let props = cbom_props(&comps[0]);
    assert_eq!(props["osslscope:algorithm"], "DES");
    assert_eq!(props["osslscope:calls"], "500");
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
    assert_eq!(meta["osslscope:omitted-unknown-coverage-sites"], "0");
    assert_eq!(meta["osslscope:policy-verdict"], "violation");
    let disclaimer = &meta["osslscope:completeness-disclaimer"];
    assert!(disclaimer.contains("FATAL"), "{disclaimer}");
    assert!(disclaimer.contains("salvaged"), "{disclaimer}");
    assert!(!disclaimer.contains("no usable evidence"), "{disclaimer}");
    // A proved violation dominates the tool failure, driven by the
    // actual delivery result.
    assert_eq!(exit_for(PolicyOutcome::Violation, None, &doc, &res), 10);
    remove_quiet(&primary_path);
    remove_quiet(&cbom_path);
}

#[test]
fn delivery_diagnostics_stay_bounded_on_long_paths() {
    // A 300-char unwritable path still yields ≤200-char diagnostics.
    let mut missing = temp_path("no-such-dir");
    missing.push("x".repeat(300));
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(missing),
        cbom: None,
    };
    let res = write_artifacts(&complete_doc(), &req);
    assert!(res.failed());
    assert!(!res.diagnostics.is_empty());
    assert_diagnostics_bounded(&res.diagnostics);
    // The outcome keeps the full destination for operators; only
    // the one-line error and diagnostics are bounded.
    assert!(res.primary.dest.chars().count() > 200);
    assert!(res.primary.error.as_ref().unwrap().chars().count() <= 200);
}

// ---------------------------------------------------------------- goldens

fn assert_golden(name: &str, actual: &str) {
    let path = format!("{}/tests/goldens/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var("OSSLSCOPE_REGENERATE_GOLDENS").is_ok() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {name} (regenerate explicitly)"));
    assert_eq!(want, actual, "golden {name} mismatch (never auto-update)");
}

#[test]
fn v2_goldens_pinned() {
    let complete = complete_doc();
    assert_golden(
        "report-v2-complete.json",
        &String::from_utf8(render_json(&complete).unwrap()).unwrap(),
    );
    assert_golden("report-v2-complete.txt", &render_human(&complete));
    assert_golden(
        "cbom-v2-complete.json",
        &String::from_utf8(render_cbom(&complete).unwrap()).unwrap(),
    );
    let partial = partial_doc();
    assert_golden(
        "report-v2-partial.json",
        &String::from_utf8(render_json(&partial).unwrap()).unwrap(),
    );
    assert_golden("report-v2-partial.txt", &render_human(&partial));
    assert_golden(
        "cbom-v2-partial.json",
        &String::from_utf8(render_cbom(&partial).unwrap()).unwrap(),
    );
    let fatal = fatal_doc();
    assert_golden(
        "report-v2-fatal.json",
        &String::from_utf8(render_json(&fatal).unwrap()).unwrap(),
    );
    assert_golden("report-v2-fatal.txt", &render_human(&fatal));
    assert_golden(
        "cbom-v2-fatal.json",
        &String::from_utf8(render_cbom(&fatal).unwrap()).unwrap(),
    );
    let violation = violation_doc();
    assert_golden(
        "report-v2-violation.json",
        &String::from_utf8(render_json(&violation).unwrap()).unwrap(),
    );
    let inconclusive = inconclusive_doc();
    assert_golden(
        "report-v2-inconclusive.json",
        &String::from_utf8(render_json(&inconclusive).unwrap()).unwrap(),
    );
    let traversal = traversal_doc();
    assert_golden(
        "report-v2-traversal.json",
        &String::from_utf8(render_json(&traversal).unwrap()).unwrap(),
    );
}

#[test]
fn traversal_section_conforms() {
    // I4/T2-1: the traversal-bearing document passes rendered
    // schema validation + cross-field semantics, and the section
    // pins its published shape (all ten keys, entry envelopes,
    // census fields). On the pre-fix schema this FAILS (unknown
    // keys + unsupported `pattern` keyword) — the emitter
    // evidence the schema must accept.
    let doc = traversal_doc();
    let bytes = render_json(&doc).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    validate_v2(&v).expect("traversal doc validates");
    check_v2_semantics(&v).expect("traversal doc semantics hold");
    let t = v["traversal"].as_object().expect("traversal section");
    let mut keys: Vec<&str> = t.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "admitted",
            "admitted_unknown",
            "census_loss",
            "count",
            "entries",
            "findings",
            "harvest",
            "members",
            "polls",
            "records"
        ],
        "published traversal keys"
    );
    assert_eq!(t["admitted"], json!({"7": 10, "12": 4}));
    assert_eq!(t["admitted_unknown"], json!([9]));
    assert_eq!(t["census_loss"], json!(2));
    let entries = t["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0]["outcome"],
        json!({"Complete": {"true_t": 6, "cached": false}})
    );
    assert_eq!(entries[0]["true_t"], json!({"Proven": 6}));
    assert_eq!(entries[0]["generation"], json!(9));
    assert_eq!(
        entries[1]["outcome"]["Partial"]["reasons"],
        json!([
            {"Holes": [3]},
            {"Trunc": 6},
            {"CacheShrink": {"cached": 9, "observed": 4}},
            "DrainLoss"
        ])
    );
    assert_eq!(entries[1]["true_t"], json!({"Candidate": 4}));
    assert!(entries[1]["generation"].is_null());
}

#[test]
fn traversal_emission_matches_allowlist_inventory() {
    // T2-2 (emission side): every emitted traversal key must be
    // allowlisted. The doc's Optional `traversal` bullet
    // enumerates the approved field inventory as backtick idents;
    // the rendered section must add nothing beyond it. (Exact
    // rendered shape is pinned by traversal_section_conforms;
    // the doc-side approved baseline by
    // privacy_allowlist::traversal_inventory_is_approved.)
    let text = std::fs::read_to_string(format!(
        "{}/docs/privacy/allowlist-v1.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut bullet = String::new();
    let mut in_bullet = false;
    for line in text.lines() {
        if line.starts_with("- Optional `traversal`") {
            in_bullet = true;
        } else if in_bullet && !line.starts_with(' ') && !line.is_empty() {
            break;
        }
        if in_bullet {
            bullet.push_str(line);
            bullet.push('\n');
        }
    }
    assert!(
        !bullet.is_empty(),
        "allowlist lacks the Optional `traversal` bullet"
    );
    let listed: std::collections::BTreeSet<&str> = bullet
        .split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s)
        .collect();
    let bytes = render_json(&traversal_doc()).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let t = v["traversal"].as_object().expect("traversal section");
    for key in t.keys() {
        assert!(
            listed.contains(key.as_str()),
            "emitted traversal key {key:?} is not in the allowlist inventory"
        );
    }
}

/// Parse the variant names of `pub enum {name}` from Rust source
/// (leading identifiers of non-comment, non-attribute lines up to
/// the closing brace).
fn enum_variants(src: &str, name: &str) -> Vec<String> {
    let decl = format!("pub enum {name} {{");
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("enum {name} declaration not found"));
    let mut out = Vec::new();
    for line in src[start..].lines().skip(1) {
        let t = line.trim();
        if t == "}" {
            break;
        }
        if t.is_empty() || t.starts_with('/') || t.starts_with('#') {
            continue;
        }
        let ident: String = t
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() && ident.chars().next().unwrap().is_uppercase() {
            out.push(ident);
        }
    }
    out
}

/// Parse the field names of `pub struct {name}` from Rust source
/// (`pub name:` lines up to the closing brace).
fn struct_fields(src: &str, name: &str) -> Vec<String> {
    let decl = format!("pub struct {name} {{");
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("struct {name} declaration not found"));
    let mut out = Vec::new();
    for line in src[start..].lines().skip(1) {
        let t = line.trim();
        if t == "}" {
            break;
        }
        if let Some(rest) = t.strip_prefix("pub ") {
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                out.push(ident);
            }
        }
    }
    out
}

#[test]
fn traversal_schema_covers_oracle_vocabulary() {
    // I4/T2-1 drift guard: every Outcome / TrueT / PartialReason /
    // AbandonReason variant and every TraversalRecord field must
    // appear in the shipped schema — a new variant/field without
    // a schema def fails here (emitter evidence the schema must
    // accept, never silently reject via additionalProperties or
    // an unmatched anyOf).
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let oracle = std::fs::read_to_string(root.join("src/scan/oracle.rs")).unwrap();
    let evidence = std::fs::read_to_string(root.join("src/evidence.rs")).unwrap();
    let schema = std::fs::read_to_string(root.join("schemas/observed-crypto-v2.json")).unwrap();
    for (ty, names) in [
        ("Outcome", enum_variants(&oracle, "Outcome")),
        ("TrueT", enum_variants(&oracle, "TrueT")),
        (
            "PartialReason",
            enum_variants(&oracle, "PartialReason"),
        ),
        (
            "AbandonReason",
            enum_variants(&oracle, "AbandonReason"),
        ),
    ] {
        assert!(
            !names.is_empty(),
            "{ty}: no variants parsed (scanner broke?)"
        );
        for v in &names {
            assert!(
                schema.contains(&format!("\"{v}\"")),
                "{ty}::{v} missing from the shipped schema"
            );
        }
    }
    let fields = struct_fields(&evidence, "TraversalRecord");
    assert!(!fields.is_empty(), "no TraversalRecord fields parsed");
    for f in &fields {
        assert!(
            schema.contains(&format!("\"{f}\"")),
            "TraversalRecord::{f} missing from the shipped schema"
        );
    }
}

// ---------------------------------------------------------------- privacy sweep

fn assert_no_forbidden_keys(v: &Value, path: &str) {
    // Single vocabulary: the lib constant (schema + semantics +
    // this sweep can never drift apart).
    assert!(!FORBIDDEN_V2_KEYS.is_empty());
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                assert!(
                    !FORBIDDEN_V2_KEYS.contains(&key.as_str()),
                    "{path}: forbidden key {key:?}"
                );
                assert_no_forbidden_keys(value, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                assert_no_forbidden_keys(item, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn rendered_artifacts_contain_no_forbidden_keys() {
    for (name, doc) in [
        ("complete", complete_doc()),
        ("partial", partial_doc()),
        ("fatal", fatal_doc()),
        ("violation", violation_doc()),
        ("inconclusive", inconclusive_doc()),
        ("pass", pass_doc()),
        ("traversal", traversal_doc()),
    ] {
        let json_bytes = render_json(&doc).unwrap();
        let v: Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_no_forbidden_keys(&v, &format!("{name}.json"));
        // argv_redacted rides every report; no raw argv exists to leak.
        assert_eq!(v["target"]["argv_redacted"], true, "{name}");
        let cbom: Value = serde_json::from_slice(&render_cbom(&doc).unwrap()).unwrap();
        assert_no_forbidden_keys(&cbom, &format!("{name}.cdx.json"));
        assert!(
            !contains_hex_address(&String::from_utf8(json_bytes).unwrap()),
            "{name}.json contains address-shaped bytes"
        );
    }
}

// ---------------------------------------------------------------- generated artifacts

#[test]
fn record_consistency_helpers() {
    // Constructor-maintained invariants (the JSON validator
    // enforces the same shapes on the wire).
    use osslscope::evidence::{DispositionOutcome, OpensslVersionState};
    assert!(OpensslVersion::verified("3.0.14".to_string()).is_consistent());
    assert!(OpensslVersion::unknown().is_consistent());
    assert!(
        !OpensslVersion {
            state: OpensslVersionState::Verified,
            version: None,
        }
        .is_consistent()
    );
    assert!(
        !OpensslVersion {
            state: OpensslVersionState::Unknown,
            version: Some("9.9.9".to_string()),
        }
        .is_consistent()
    );
    assert!(DispositionRecord::exited(0).is_consistent());
    assert!(DispositionRecord::detached_running(7).is_consistent());
    assert!(
        !DispositionRecord {
            outcome: DispositionOutcome::Exited,
            code: None,
            pid: None,
        }
        .is_consistent()
    );
    assert!(
        !DispositionRecord {
            outcome: DispositionOutcome::DetachedRunning,
            code: None,
            pid: None,
        }
        .is_consistent()
    );
}

fn unresolved_doc() -> CaptureDocument {
    // Complete candidate sets with unresolvable algorithm classes:
    // certain provider/op/funcid, unknowable algorithm.
    let mut input = input_base();
    input.sites = vec![
        site_at(
            FP_A,
            8,
            100,
            0x1000,
            0,
            100,
            vec![cand(FP_A, "default", 2, 21, &["other"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            FP_B,
            8,
            200,
            0x1000,
            0,
            100,
            vec![
                cand(FP_A, "default", 2, 21, &["other"], false),
                cand(FP_B, "default", 2, 21, &["other"], false),
            ],
            CandidateCoverage::Complete,
        ),
    ];
    input.coverage = vec![ScopeCoverage {
        scope: "provider/default".to_string(),
        expected: ExpectedScope::Applicable { sites: 2 },
        discovered: 2,
        attached: 2,
    }];
    let doc = finalize_honest(input);
    assert!(
        matches!(doc.status, Completeness::Complete),
        "unresolved classes are not gaps: {:?}",
        doc.status
    );
    doc
}

#[test]
fn human_marks_unresolved_classes_not_definite() {
    // The `other` bucket is never a definite asset (F2): it renders
    // UNRESOLVED with its certain provider/op/funcid, never
    // "definite: other".
    let doc = unresolved_doc();
    validate_v2(&json_of(&doc)).expect("unresolved doc validates");
    check_v2_semantics(&json_of(&doc)).expect("unresolved doc is consistent");
    let text = render_human(&doc);
    assert!(text.contains("UNRESOLVED"), "{text}");
    assert!(text.contains("algorithm class unresolvable"), "{text}");
    assert!(text.contains("1 candidate"), "{text}");
    assert!(text.contains("2 candidates"), "{text}");
    assert!(!text.contains("definite: other"), "{text}");
    assert!(!text.contains("definite:"), "{text}");
}

#[test]
fn cbom_omits_unresolved_classes() {
    let cbom = cbom_of(&unresolved_doc());
    assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "2");
    assert_eq!(meta["osslscope:omitted-ambiguous-calls"], "200");
}

#[test]
fn h3_t4_mixed_site_lands_in_cbom_omitted_unknown() {
    // H3 (design T4): a mixed-shaped site (Unknown coverage +
    // min label + weak, as H3-T2 produces) exports NO component
    // — the collapsed min label must never become a definite
    // asset — and lands in omitted-unknown, not
    // omitted-ambiguous (coverage-unknown short-circuits before
    // the definite-asset check).
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_A,
        8,
        100,
        0x1000,
        0,
        7,
        vec![cand(FP_A, "default", 1, 7, &["SHA-256"], true)],
        CandidateCoverage::Unknown,
    )];
    let doc = finalize_honest(input);
    let cbom = cbom_of(&doc);
    assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-unknown-coverage-sites"], "1");
    assert_eq!(meta["osslscope:omitted-unknown-coverage-calls"], "7");
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
    assert_eq!(meta["osslscope:omitted-ambiguous-calls"], "0");
}

#[test]
fn delivery_same_file_path_refuses_cbom() {
    // F1: primary and CBOM to one file would overwrite the primary;
    // the CBOM side is refused and the primary bytes survive.
    let path = temp_path("same.json");
    remove_quiet(&path);
    let doc = complete_doc();
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(path.clone()),
        cbom: Some(OutputDest::File(path.clone())),
    };
    let res = write_artifacts(&doc, &req);
    assert!(res.primary.ok, "primary must deliver: {res:?}");
    let cbom = res.cbom.as_ref().expect("cbom outcome recorded");
    assert!(!cbom.ok, "same-file CBOM must be refused");
    assert!(
        cbom.error.as_deref().unwrap().contains("same sink"),
        "unexpected error: {cbom:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        render_json(&doc).unwrap(),
        "primary bytes must survive (no overwrite)"
    );
    assert!(res.failed());
    assert_diagnostics_bounded(&res.diagnostics);
    remove_quiet(&path);
}

#[test]
fn semantics_rejects_status_reasons_mismatch() {
    // F3: COMPLETE lists no gaps; PARTIAL always names one.
    let mut v = json_of(&complete_doc());
    v["completeness"]["reasons"] = json!([{"kind": "signal-cut"}]);
    assert!(
        check_v2_semantics(&v).is_err(),
        "COMPLETE with reasons accepted"
    );
    let mut v = json_of(&partial_doc());
    assert!(!v["completeness"]["reasons"].as_array().unwrap().is_empty());
    v["completeness"]["reasons"] = json!([]);
    assert!(
        check_v2_semantics(&v).is_err(),
        "PARTIAL without reasons accepted"
    );
}

#[test]
fn semantics_rejects_inconsistent_policy_verdict() {
    // F4: the verdict is the AND of its rules.
    let mut v = json_of(&violation_doc());
    v["policy"]["verdict"] = json!("pass");
    assert!(
        check_v2_semantics(&v).is_err(),
        "pass verdict with a violation rule accepted"
    );
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["result"] = json!("pass");
    assert!(
        check_v2_semantics(&v).is_err(),
        "violation verdict with all-pass rules accepted"
    );
    let mut v = json_of(&violation_doc());
    v["policy"]["verdict"] = json!("no-verdict");
    assert!(
        check_v2_semantics(&v).is_err(),
        "no-verdict on a non-fatal document accepted"
    );
    // FATAL documents with policy carry exactly no-verdict.
    let mut v = json_of(&fatal_doc());
    v["policy"] = json!({"verdict": "pass", "rules": []});
    assert!(
        check_v2_semantics(&v).is_err(),
        "pass verdict on a FATAL document accepted"
    );
    let mut v = json_of(&fatal_doc());
    v["policy"] = json!({"verdict": "no-verdict", "rules": []});
    validate_v2(&v).expect("fatal no-verdict shape validates");
    check_v2_semantics(&v).expect("fatal no-verdict is consistent");
}

#[test]
fn semantics_accepts_evaluated_runtime_verdicts() {
    // R02: a FATAL/runtime doc carries an evaluated verdict (the AND
    // of its rules) — violation, pass and inconclusive shapes all
    // validate; no-verdict on usable evidence is rejected, as is any
    // verdict contradicting its rules.
    let v = json_of(&runtime_violation_doc());
    validate_v2(&v).expect("runtime violation shape validates");
    check_v2_semantics(&v).expect("runtime violation is consistent");
    assert_eq!(v["policy"]["verdict"], "violation");
    // Pass and inconclusive verdicts with matching rules validate too.
    let mut pass = v.clone();
    pass["policy"]["verdict"] = json!("pass");
    pass["policy"]["rules"][0]["result"] = json!("pass");
    pass["policy"]["rules"][0]["definite"] = json!(0);
    pass["policy"]["rules"][0]["possible"] = json!(0);
    pass["policy"]["rules"][0]["evidence"] = json!([]);
    check_v2_semantics(&pass).expect("runtime pass is consistent");
    let mut inconclusive = v.clone();
    inconclusive["policy"]["verdict"] = json!("inconclusive");
    inconclusive["policy"]["rules"][0]["result"] = json!("inconclusive");
    inconclusive["policy"]["rules"][0]["definite"] = json!(0);
    inconclusive["policy"]["rules"][0]["evidence"] = json!([]);
    check_v2_semantics(&inconclusive).expect("runtime inconclusive is consistent");
    // No-verdict on usable evidence is rejected (it would mask the
    // retained sites), as is a verdict contradicting its rules.
    let mut masked = v.clone();
    masked["policy"]["verdict"] = json!("no-verdict");
    assert!(
        check_v2_semantics(&masked).is_err(),
        "no-verdict on usable Runtime evidence accepted"
    );
    let mut contradicted = v.clone();
    contradicted["policy"]["verdict"] = json!("pass");
    assert!(
        check_v2_semantics(&contradicted).is_err(),
        "pass verdict with a violation rule accepted on a Runtime doc"
    );
}

#[test]
fn cbom_runtime_retains_definite_assets() {
    // R02: the CBOM enumerates definite assets on usable Runtime
    // docs (per-site accounting still applies) with an accurate
    // disclaimer — no silent emptying, no false "no usable evidence".
    let cbom = cbom_of(&runtime_violation_doc());
    let comps = cbom["components"].as_array().unwrap();
    assert_eq!(comps.len(), 1);
    let props = cbom_props(&comps[0]);
    assert_eq!(props["osslscope:algorithm"], "DES");
    assert_eq!(props["osslscope:calls"], "500");
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
    assert_eq!(meta["osslscope:omitted-unknown-coverage-sites"], "0");
    assert_eq!(meta["osslscope:policy-verdict"], "violation");
    let disclaimer = &meta["osslscope:completeness-disclaimer"];
    assert!(disclaimer.contains("FATAL"), "{disclaimer}");
    assert!(disclaimer.contains("salvaged"), "{disclaimer}");
    assert!(!disclaimer.contains("no usable evidence"), "{disclaimer}");
}

#[test]
fn semantics_rejects_bad_policy_bounds_and_evidence() {
    // F5: definite never exceeds possible; evidence cannot
    // double-claim one site's calls within a rule.
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["definite"] = json!(551);
    assert!(
        check_v2_semantics(&v).is_err(),
        "definite above possible accepted"
    );
    // Unknown upper bounds skip the comparison.
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["possible"] = Value::Null;
    check_v2_semantics(&v).expect("null possible skips the bound check");
    // Same site cited twice, splitting 500 calls into 400 + 100:
    // legal (summed within the site total).
    let mut v = json_of(&violation_doc());
    let dup = v["policy"]["rules"][0]["evidence"][0].clone();
    v["policy"]["rules"][0]["evidence"][0]["calls"] = json!(400);
    let mut second = dup.clone();
    second["calls"] = json!(100);
    v["policy"]["rules"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(second);
    check_v2_semantics(&v).expect("split citation within the total is legal");
    // Same site cited twice claiming 500 + 500: double-claim.
    let mut v = json_of(&violation_doc());
    let dup = v["policy"]["rules"][0]["evidence"][0].clone();
    v["policy"]["rules"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(dup);
    assert!(
        check_v2_semantics(&v).is_err(),
        "evidence double-claim accepted"
    );
}

#[test]
fn semantics_rejects_site_object_mismatch() {
    // F6: site (device, inode) must match a record of its claimed
    // fingerprint, not just resolve the fingerprint.
    let mut v = json_of(&complete_doc());
    v["sites"][0]["device"] = json!(9);
    assert!(
        check_v2_semantics(&v).is_err(),
        "contradicting device accepted"
    );
    let mut v = json_of(&complete_doc());
    v["sites"][0]["inode"] = json!(999);
    assert!(
        check_v2_semantics(&v).is_err(),
        "contradicting inode accepted"
    );
    let mut v = json_of(&violation_doc());
    v["policy"]["rules"][0]["evidence"][0]["inode"] = json!(999);
    assert!(
        check_v2_semantics(&v).is_err(),
        "evidence with contradicting inode accepted"
    );
}

#[test]
fn semantics_rejects_fenced_generation_mismatch() {
    // F8: bucket members carry the bucket generation.
    let mut v = json_of(&violation_doc());
    v["fenced"][0]["sites"][0]["generation"] = json!(0);
    assert!(
        check_v2_semantics(&v).is_err(),
        "member generation disagreeing with its bucket accepted"
    );
}

#[test]
fn write_generated_v2_artifacts() {
    // Fresh generated artifacts for the auditor explicitly-supplied
    // run and for test-derived doc examples. Paths print on stderr;
    // the auditor v2 story test consumes them via
    // OSSLSCOPE_AUDITOR_STORY_V2.
    let dir = std::env::temp_dir().join("osslscope-output-contract-v2");
    std::fs::create_dir_all(&dir).unwrap();
    let cases = [
        ("complete", complete_doc()),
        ("violation", violation_doc()),
        ("inconclusive", inconclusive_doc()),
    ];
    for (name, doc) in cases {
        let json_path = dir.join(format!("{name}.json"));
        let cbom_path = dir.join(format!("{name}.cdx.json"));
        let human_path = dir.join(format!("{name}.txt"));
        std::fs::write(&json_path, render_json(&doc).unwrap()).unwrap();
        std::fs::write(&cbom_path, render_cbom(&doc).unwrap()).unwrap();
        std::fs::write(&human_path, render_human(&doc)).unwrap();
        eprintln!("OSSLSCOPE_GENERATED_ARTIFACT json={}", json_path.display());
        eprintln!("OSSLSCOPE_GENERATED_ARTIFACT cbom={}", cbom_path.display());
        eprintln!(
            "OSSLSCOPE_GENERATED_ARTIFACT human={}",
            human_path.display()
        );
    }
}

#[test]
fn site_installed_at_renders_and_validates_v2() {
    // P6 installed-at: a stamped site renders its wall, an
    // unstamped site omits the key (minors add optional keys
    // only), the document validates and stamps the v2.1 minor.
    let mut doc = complete_doc();
    assert!(doc.sites.len() >= 4);
    doc.sites[0].installed_at = Some(5);
    assert_eq!(doc.sites[3].installed_at, None);
    let v = json_of(&doc);
    assert_eq!(v["schema_version"], "observed-crypto-v2.1");
    validate_v2(&v).expect("installed_at doc fails schema");
    check_v2_semantics(&v).expect("installed_at doc fails semantics");
    assert_eq!(v["sites"][0]["installed_at"], 5);
    assert!(
        v["sites"][3].get("installed_at").is_none(),
        "unstamped site must omit the key"
    );
    // A v2.0-shaped document (no installed_at anywhere) keeps
    // validating: stored evidence survives the minor bump.
    let mut old = v.clone();
    old["schema_version"] = Value::from("observed-crypto-v2.0");
    let strip = |sites: &mut Value| {
        if let Some(list) = sites.as_array_mut() {
            for site in list {
                if let Some(m) = site.as_object_mut() {
                    m.remove("installed_at");
                }
            }
        }
    };
    strip(&mut old["sites"]);
    if let Some(buckets) = old["fenced"].as_array_mut() {
        for bucket in buckets {
            strip(&mut bucket["sites"]);
        }
    }
    validate_v2(&old).expect("v2.0-shaped doc must keep validating");
}

// ---------------------------------------------------------------- R05 (F06)

fn engine_obs_at(
    offset: u64,
    generation: u64,
    entrypoint: &str,
    calls: u64,
    window: EngineWindow,
) -> EngineObservation {
    EngineObservation {
        key: SiteKey {
            object: obj(FP_A),
            device: 8,
            inode: 100,
            offset,
        },
        generation,
        entrypoint: engine_index(entrypoint).expect("frozen ENGINE registry name"),
        calls,
        window,
    }
}

/// COMPLETE document with provider sites plus five in-window typed
/// ENGINE observations and an evaluated deny-engine policy.
fn engine_doc_fixture() -> CaptureDocument {
    let mut input = input_base();
    input.sites = vec![site_at(
        FP_A,
        8,
        100,
        0x1000,
        0,
        500,
        vec![cand(FP_A, "default", 2, 21, &["AES-128-GCM"], false)],
        CandidateCoverage::Complete,
    )];
    input.engine_observations = vec![
        engine_obs_at(0x100, 0, "ENGINE_by_id", 1, EngineWindow::InWindow),
        engine_obs_at(0x200, 0, "ENGINE_init", 1, EngineWindow::InWindow),
        engine_obs_at(0x300, 0, "ENGINE_finish", 1, EngineWindow::InWindow),
        engine_obs_at(0x400, 0, "ENGINE_free", 1, EngineWindow::InWindow),
        engine_obs_at(0x500, 0, "ENGINE_ctrl", 1, EngineWindow::InWindow),
    ];
    let doc = finalize_honest(input);
    assert!(matches!(doc.status, Completeness::Complete));
    let verdict = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    let mut doc = doc;
    doc.policy = Some(policy_record(&verdict));
    doc
}

#[test]
fn engine_observations_render_validate_and_replay() {
    let doc = engine_doc_fixture();
    let v = json_of(&doc);
    validate_v2(&v).expect("engine doc fails schema");
    check_v2_semantics(&v).expect("engine doc fails semantics");
    // Rendered observations carry index + registry name + window.
    let obs = v["engine_observations"]
        .as_array()
        .expect("observations render");
    assert_eq!(obs.len(), 5);
    assert_eq!(obs[0]["entrypoint_name"], "ENGINE_by_id");
    assert_eq!(obs[0]["window"], "in-window");
    assert_eq!(obs[0]["calls"], 1);
    // Policy engine evidence resolves to the listed observations.
    let rule = &v["policy"]["rules"][0];
    assert_eq!(rule["rule"], "deny-engine");
    assert_eq!(rule["result"], "violation");
    assert_eq!(rule["definite"], 5);
    let refs = rule["engine_evidence"]
        .as_array()
        .expect("engine evidence renders");
    assert_eq!(refs.len(), 5);
    // Provider conservation excludes ENGINE calls everywhere.
    assert_eq!(doc.total_calls(), 500);
    let part = &v["legacy_partition"];
    let buckets: u64 = [
        "legacy_exclusive_calls",
        "non_legacy_exclusive_calls",
        "shared_ambiguous_calls",
        "unfenced_tail_calls",
    ]
    .iter()
    .map(|k| part[k].as_u64().unwrap())
    .sum();
    assert_eq!(buckets, 500);
    // CBOM carries engine metadata beside definite assets.
    let cbom = cbom_of(&doc);
    let meta = cbom_metadata(&cbom);
    assert_eq!(meta["osslscope:engine-observations"], "5");
    assert_eq!(meta["osslscope:engine-in-window-calls"], "5");
    // Human render names the observation plane honestly.
    let human = render_human(&doc);
    assert!(
        human.contains("engine observations (5, 5 in-window calls)"),
        "{human}"
    );
    assert!(human.contains("ENGINE_init"), "{human}");
    // Replay consumes the RENDERED artifact (not the Rust model):
    // re-derive ENGINE bounds from the rendered JSON observations
    // and require agreement with the model's evaluation plus the
    // rendered policy section. Certainty/window limits and counts
    // must survive rendering.
    let bytes = render_json(&doc).expect("rendered artifact serializes");
    let rendered: Value = serde_json::from_slice(&bytes).expect("rendered artifact parses");
    validate_v2(&rendered).expect("rendered replay fails schema");
    check_v2_semantics(&rendered).expect("rendered replay fails semantics");
    let robs = rendered["engine_observations"]
        .as_array()
        .expect("rendered observations");
    assert_eq!(robs.len(), 5);
    let mut definite = 0u64;
    let mut untimed = false;
    for o in robs {
        let calls = o["calls"].as_u64().expect("rendered calls");
        match o["window"].as_str().expect("rendered window") {
            "in-window" => definite = definite.saturating_add(calls),
            "pre-window" => {}
            "untimed" => {
                if calls > 0 {
                    untimed = true;
                }
            }
            w => panic!("unknown rendered window {w}"),
        }
    }
    let possible = if untimed { None } else { Some(definite) };
    let v2 = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v2.rules[0].bounds.definite, definite);
    assert_eq!(v2.rules[0].bounds.possible, possible);
    let rrule = &rendered["policy"]["rules"][0];
    assert_eq!(rrule["definite"].as_u64().unwrap(), definite);
    assert_eq!(rrule["possible"].as_u64(), possible);
    // Every rendered ref resolves to a rendered observation with
    // no over-claim (mirrors the semantic check, over the artifact
    // bytes a downstream consumer actually reads).
    let rrefs = rrule["engine_evidence"].as_array().unwrap();
    assert_eq!(rrefs.len(), 5);
    for r in rrefs {
        let key = (
            r["object"].as_str().unwrap(),
            r["device"].as_u64().unwrap(),
            r["inode"].as_u64().unwrap(),
            r["offset"].as_u64().unwrap(),
            r["generation"].as_u64().unwrap(),
            r["entrypoint"].as_u64().unwrap(),
        );
        let have = robs
            .iter()
            .find(|o| {
                (
                    o["object"].as_str().unwrap(),
                    o["device"].as_u64().unwrap(),
                    o["inode"].as_u64().unwrap(),
                    o["offset"].as_u64().unwrap(),
                    o["generation"].as_u64().unwrap(),
                    o["entrypoint"].as_u64().unwrap(),
                ) == key
            })
            .unwrap_or_else(|| panic!("rendered ref resolves: {r}"));
        assert_eq!(have["window"], "in-window");
        assert!(have["calls"].as_u64().unwrap() >= r["calls"].as_u64().unwrap());
    }
}

#[test]
fn engine_documents_read_old_shape() {
    // Docs without observations omit every engine key (golden
    // stability) and old-shaped JSON still deserializes.
    let old = complete_doc();
    let v = json_of(&old);
    assert!(v.get("engine_observations").is_none());
    validate_v2(&v).expect("old-shaped doc fails new schema");
    check_v2_semantics(&v).expect("old-shaped doc fails new semantics");
    // New code reads old serde documents: missing engine fields
    // default to empty, never to fabricated observations.
    let mut stripped = serde_json::to_value(engine_doc_fixture()).expect("document serializes");
    stripped
        .as_object_mut()
        .unwrap()
        .remove("engine_observations");
    if let Some(policy) = stripped.get_mut("policy") {
        for rule in policy["rules"].as_array_mut().unwrap() {
            rule.as_object_mut().unwrap().remove("engine_evidence");
        }
    }
    let back: CaptureDocument = serde_json::from_value(stripped).expect("old shape parses");
    assert!(back.engine_observations.is_empty());
    assert!(
        back.policy.as_ref().unwrap().rules[0]
            .engine_evidence
            .is_empty()
    );
}

#[test]
fn engine_semantics_rejects_bad_engine_refs() {
    let good = json_of(&engine_doc_fixture());
    // Ref to no listed observation.
    let mut bad = good.clone();
    bad["policy"]["rules"][0]["engine_evidence"][0]["offset"] = json!(0x9999);
    assert!(check_v2_semantics(&bad).is_err());
    // Double-claim across refs exceeds the observed calls.
    let mut bad = good.clone();
    bad["policy"]["rules"][0]["engine_evidence"][1] =
        bad["policy"]["rules"][0]["engine_evidence"][0].clone();
    assert!(check_v2_semantics(&bad).is_err());
    // Entrypoint outside the frozen registry.
    let mut bad = good.clone();
    bad["engine_observations"][0]["entrypoint"] = json!(9999);
    assert!(check_v2_semantics(&bad).is_err());
    // Name contradicting the indexed entrypoint.
    let mut bad = good.clone();
    bad["engine_observations"][0]["entrypoint_name"] = json!("ENGINE_init");
    assert!(check_v2_semantics(&bad).is_err());
    // Observation keyed to an unlisted object.
    let mut bad = good.clone();
    bad["engine_observations"][0]["object"] = json!("build:deadbeef");
    assert!(check_v2_semantics(&bad).is_err());
    // definite can never exceed possible on engine rules either.
    let mut bad = good.clone();
    bad["policy"]["rules"][0]["definite"] = json!(6);
    bad["policy"]["rules"][0]["possible"] = json!(5);
    assert!(check_v2_semantics(&bad).is_err());
}

#[test]
fn engine_semantics_rejects_pre_window_definite_refs() {
    // F-R05-4 RED: definite ENGINE refs must resolve to InWindow
    // observations. All five fixture observations flipped to
    // pre-window must invalidate the definite violation refs.
    let good = json_of(&engine_doc_fixture());
    let mut bad = good.clone();
    let obs = bad["engine_observations"].as_array_mut().unwrap();
    assert_eq!(obs.len(), 5);
    for o in obs.iter_mut() {
        o["window"] = json!("pre-window");
    }
    assert!(
        check_v2_semantics(&bad).is_err(),
        "definite refs to pre-window observations must be rejected"
    );
}

#[test]
fn engine_semantics_rejects_untimed_definite_refs() {
    // F-R05-4 RED: definite ENGINE refs must resolve to InWindow
    // observations. All five fixture observations flipped to
    // untimed must invalidate the definite violation refs.
    let good = json_of(&engine_doc_fixture());
    let mut bad = good.clone();
    let obs = bad["engine_observations"].as_array_mut().unwrap();
    assert_eq!(obs.len(), 5);
    for o in obs.iter_mut() {
        o["window"] = json!("untimed");
    }
    assert!(
        check_v2_semantics(&bad).is_err(),
        "definite refs to untimed observations must be rejected"
    );
}

// ---------------------------------------------------------------- R12 report context + display neutralization

/// R12 fixture context: deterministic kernel + wall edges for
/// golden fixtures (attached post-finalize; live captures carry
/// the real uname release and window wall edges instead).
fn fixture_context() -> CaptureContext {
    CaptureContext {
        kernel_release: "6.9.0-test".to_string(),
        wall_start_unix_ns: Some(1_700_000_000_000_000_000),
        wall_end_unix_ns: Some(1_700_000_030_000_000_000),
    }
}

/// F14 counterexample, verbatim: an actual Linux-permitted short
/// comm (TASK_COMM_LEN - 1 = 15 bytes: NUL is the only byte the
/// kernel refuses) carrying ESC + newline + a fake status line.
const EVIL_COMM_SHORT: &str = "a\x1b[2J\nstatus=OK";

/// Extended target-controlled comm: tab, OSC title sequence, BEL,
/// bidi overrides, C1 NEL, zero-width space, U+2028 line
/// separator and BOM — every class `safe_display` must neutralize.
const EVIL_COMM_WIDE: &str =
    "x\t\x1b]0;pwned\x07\u{202E}RTL\u{202C}\u{0085}\u{200B}\u{2028}\u{FEFF}y";

/// Actual short tab/bidi comms (Linux-permitted: at most 15 bytes):
/// a tab-split comm with a bidi override, and a bare bidi-override
/// comm. Lengths pinned in the test.
const EVIL_COMM_TAB_SHORT: &str = "a\tb\u{202E}c";
const EVIL_COMM_BIDI_SHORT: &str = "\u{202E}RTL\u{202C}";

/// Omitted invisible format controls (U+2060–U+2064): WORD JOINER,
/// FUNCTION APPLICATION, INVISIBLE TIMES, INVISIBLE SEPARATOR,
/// INVISIBLE PLUS. General_Category=Cf, outside `is_control`, so a
/// renderer matching only C0/C1 passes them through. Each `x{c}y`
/// comm below is 5 bytes — Linux-permitted.
fn evil_comm_invisible() -> Vec<String> {
    (0x2060..=0x2064)
        .map(|cp| format!("x{}y", char::from_u32(cp).unwrap()))
        .collect()
}

/// Independent oracle: characters that must never reach human output
/// active. The expected set is derived INDEPENDENTLY of the
/// renderer's `is_display_control` match arms: it is the COMPLETE
/// General_Category=Cf set plus Zl/Zp from the Unicode Character
/// Database (UCD 16.0.0, classified by CPython's `unicodedata`
/// property tables — a different codebase's classification, not a
/// copy of the renderer list), frozen as codepoint ranges below. Cc
/// controls are covered by `char::is_control` (the std Cc property).
/// Because the oracle embeds the whole category — 172 codepoints,
/// including 145 the renderer does NOT neutralize (e.g. deprecated
/// U+206A-U+206F, U+180E, TAGs) — a renderer omission cannot hide by
/// shared selection: any Cf/Zl/Zp char in test inputs fails here
/// unless neutralized.
///
/// Regenerate (must reproduce these ranges exactly; exact command in
/// the R12 report): classify every scalar value with
/// `unicodedata.category`, keep Cf/Zl/Zp, compress to ranges.
///
/// Scope note: the renderer covers 27 of these 172 (see
/// `is_display_control`); the remainder pass through today. No
/// fixture scanned below contains them, so the suite is green;
/// feeding any uncovered Cf through the renderer now FAILS the
/// oracle (proven by probe — see report).
const UCD_FORMAT_CONTROL_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),   // SOFT HYPHEN (Cf)
    (0x0600, 0x0605),   // ARABIC NUMBER SIGN..ARABIC NUMBER MARK ABOVE (Cf)
    (0x061C, 0x061C),   // ARABIC LETTER MARK (Cf)
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH (Cf)
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK (Cf)
    (0x0890, 0x0891),   // ARABIC POUND MARK ABOVE..ARABIC PIASTRE MARK ABOVE (Cf)
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH (Cf)
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR (Cf)
    (0x200B, 0x200F),   // ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK (Cf)
    (0x2028, 0x202E),   // LINE SEPARATOR..RIGHT-TO-LEFT OVERRIDE (Zl+Zp+Cf, contiguous)
    (0x2060, 0x2064),   // WORD JOINER..INVISIBLE PLUS (Cf)
    (0x2066, 0x206F),   // bidi isolates + deprecated U+206A..U+206F (Cf; U+2065 is Cn)
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE (Cf)
    (0xFFF9, 0xFFFB),   // interlinear annotation (Cf)
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN (Cf)
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE (Cf)
    (0x13430, 0x1343F), // EGYPTIAN HIEROGLYPH joiners/enclosure (Cf)
    (0x1BCA0, 0x1BCA3), // SHORTHAND FORMAT LETTER OVERLAP..UP STEP (Cf)
    (0x1D173, 0x1D17A), // MUSICAL SYMBOL BEGIN BEAM..END PHRASE (Cf)
    (0xE0001, 0xE0001), // LANGUAGE TAG (Cf; U+E0000 is Cn)
    (0xE0020, 0xE007F), // TAG SPACE..CANCEL TAG (Cf)
];

/// Frozen UCD 16.0.0 Cf+Zl+Zp population (pins the table above
/// against row erosion; see the self-pin test).
const UCD_FORMAT_CONTROL_COUNT: usize = 172;

/// True when `c` is Cf/Zl/Zp per the independent UCD table (Cc is
/// handled by `char::is_control` at the call site).
fn ucd_is_format_control(c: char) -> bool {
    let cp = c as u32;
    UCD_FORMAT_CONTROL_RANGES
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&cp))
}

/// No active display controls outside the renderer's own `\n` line
/// separators: no C0/C1/DEL, no bidi controls, no invisible/zero-
/// width format characters, no U+2028/2029 line breaks.
fn assert_no_active_display_controls(text: &str) {
    for c in text.chars() {
        if c == '\n' {
            continue;
        }
        assert!(!c.is_control(), "active control {c:?} in human output");
        assert!(
            !ucd_is_format_control(c),
            "active UCD format/line control {c:?} (U+{:04X}) in human output",
            c as u32
        );
    }
}

#[test]
fn r12_context_renders_in_json_with_exact_values() {
    // R12 RED: the finalized document retains execution context
    // (kernel + wall edges) in JSON with exact values, and the
    // extended document validates end to end.
    let mut doc = complete_doc();
    doc.context = Some(fixture_context());
    let v = json_of(&doc);
    assert_eq!(
        v["context"],
        json!({
            "kernel_release": "6.9.0-test",
            "wall_start_unix_ns": 1_700_000_000_000_000_000u64,
            "wall_end_unix_ns": 1_700_000_030_000_000_000u64,
        }),
        "context must render exactly"
    );
    validate_v2(&v).expect("context doc fails schema");
    check_v2_semantics(&v).expect("context doc fails semantics");
}

#[test]
fn r12_oracle_covers_invisible_format_controls() {
    // The oracle guards itself: it must forbid the omitted-format
    // range (U+2060-U+2064) plus one representative of every other
    // forbidden class — and it must NOT be a copy of the renderer
    // list, so it additionally forbids Cf controls the renderer
    // passes through (U+206A-U+206F, U+180E, ...), proves
    // category-precision on unassigned neighbors (U+2065, U+E0000
    // are Cn, not forbidden), and pins the frozen UCD 16.0
    // population (172) against row erosion. Ordinary printable
    // Unicode must NOT appear.
    let population: usize = UCD_FORMAT_CONTROL_RANGES
        .iter()
        .map(|(lo, hi)| (hi - lo + 1) as usize)
        .sum();
    assert_eq!(
        population, UCD_FORMAT_CONTROL_COUNT,
        "UCD table population must match the frozen UCD 16.0 Cf+Zl+Zp count"
    );
    // Table integrity: sorted, disjoint ranges (guards the
    // transcription from the generator output).
    for pair in UCD_FORMAT_CONTROL_RANGES.windows(2) {
        assert!(
            pair[0].1 < pair[1].0,
            "UCD ranges must be sorted and disjoint: {pair:?}"
        );
    }
    let forbidden = |c: char| c.is_control() || ucd_is_format_control(c);
    for cp in 0x2060..=0x2064 {
        let c = char::from_u32(cp).unwrap();
        assert!(!c.is_control(), "U+{cp:04X} must be outside is_control");
        assert!(forbidden(c), "oracle must forbid U+{cp:04X}");
    }
    // One representative of every other forbidden class.
    for cp in [
        0x00ADu32, 0x061C, 0x200B, 0x200E, 0x2028, 0x2029, 0x202A, 0x202E, 0x2066, 0xFEFF, 0xFFF9,
    ] {
        let c = char::from_u32(cp).unwrap();
        assert!(forbidden(c), "oracle must forbid U+{cp:04X}");
    }
    // Non-copy proof: the oracle forbids Cf controls the renderer
    // does NOT neutralize (none of these appear in
    // `is_display_control`), so the oracle cannot be a copy of the
    // renderer list.
    for cp in [
        0x206Au32, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0x180E, 0x0600, 0xE0020,
    ] {
        let c = char::from_u32(cp).unwrap();
        assert!(!c.is_control(), "U+{cp:04X} must be outside is_control");
        assert!(
            ucd_is_format_control(c),
            "oracle must forbid U+{cp:04X} although the renderer passes it"
        );
    }
    // Category precision: unassigned neighbors are Cn, not Cf —
    // the table came from category data, not from padded ranges.
    for cp in [0x2065u32, 0xE0000] {
        let c = char::from_u32(cp).unwrap();
        assert!(!c.is_control(), "U+{cp:04X} must be outside is_control");
        assert!(
            !ucd_is_format_control(c),
            "U+{cp:04X} is Cn and must not be forbidden"
        );
    }
    for c in ['é', '日', '🎉', 'Ω', 'م', 'ß', ' '] {
        assert!(!c.is_control(), "printable {c:?} must not be control");
        assert!(!forbidden(c), "printable {c:?} must not be forbidden");
    }
    let nbsp = char::from_u32(0x00A0).unwrap();
    assert!(!forbidden(nbsp), "NBSP (Zs) must not be forbidden");
}

#[test]
fn r12_human_neutralizes_target_controlled_comm() {
    // R12/F14 RED: Linux-permitted comm controls (ESC/newline/tab/
    // bidi) plus Unicode controls never reach the terminal active;
    // the genuine status/policy footer stays intact and singular.
    assert_eq!(EVIL_COMM_SHORT.len(), 15, "short-comm shape must hold");
    assert!(
        EVIL_COMM_TAB_SHORT.len() <= 15 && EVIL_COMM_BIDI_SHORT.len() <= 15,
        "tab/bidi comms must be short"
    );
    let invisible = evil_comm_invisible();
    assert_eq!(invisible.len(), 5, "one comm per U+2060–U+2064");
    for comm in &invisible {
        assert_eq!(comm.len(), 5, "invisible-format comm must be 5 bytes");
    }
    let mut evils: Vec<&str> = vec![
        EVIL_COMM_SHORT,
        EVIL_COMM_WIDE,
        EVIL_COMM_TAB_SHORT,
        EVIL_COMM_BIDI_SHORT,
    ];
    evils.extend(invisible.iter().map(String::as_str));
    for evil in evils {
        let mut doc = violation_doc();
        doc.target.comm = evil.to_string();
        let text = render_human(&doc);
        assert_no_active_display_controls(&text);
        // The injected fake status line is inert: no line of its
        // own, and the genuine footer appears exactly once.
        assert!(
            !text.lines().any(|l| l == "status=OK"),
            "fake status line survived neutralization:\n{text}"
        );
        assert_eq!(
            text.lines().filter(|l| l.starts_with("status=")).count(),
            1,
            "genuine status footer must be singular:\n{text}"
        );
        assert!(text.contains("status=COMPLETE"), "{text}");
        assert!(text.contains("policy: violation"), "{text}");
        assert!(text.contains("absence = not-observed in window"), "{text}");
    }
}

#[test]
fn r12_json_round_trips_target_controlled_comm() {
    // R12/F14: JSON keeps the reversible original — neutralization
    // happens at human rendering only, never in the model or JSON.
    let invisible = evil_comm_invisible();
    let mut evils: Vec<&str> = vec![
        EVIL_COMM_SHORT,
        EVIL_COMM_WIDE,
        EVIL_COMM_TAB_SHORT,
        EVIL_COMM_BIDI_SHORT,
    ];
    evils.extend(invisible.iter().map(String::as_str));
    for evil in evils {
        let mut doc = complete_doc();
        doc.target.comm = evil.to_string();
        let v = json_of(&doc);
        assert_eq!(v["target"]["comm"], evil, "JSON must round-trip comm");
        validate_v2(&v).expect("evil-comm doc fails schema");
        check_v2_semantics(&v).expect("evil-comm doc fails semantics");
    }
}

#[test]
fn r12_human_preserves_printable_unicode() {
    // Neutralization targets display controls, not text: ordinary
    // printable Unicode (accents, CJK, emoji, Greek, an Arabic
    // letter, NBSP) passes through human rendering verbatim.
    let comm = "café-日本-🎉-Ω-م-\u{00A0}x";
    let mut doc = violation_doc();
    doc.target.comm = comm.to_string();
    let text = render_human(&doc);
    assert_no_active_display_controls(&text);
    assert!(
        text.contains(comm),
        "printable Unicode must survive verbatim:\n{text}"
    );
}

#[test]
fn r12_human_shows_duration_kernel_and_wall() {
    // R12/G08 RED: the human header carries explicit requested/
    // effective durations plus kernel and wall context, with clock
    // domains labeled so monotonic and wall are never conflated.
    let mut doc = complete_doc();
    doc.context = Some(fixture_context());
    let text = render_human(&doc);
    assert!(
        text.contains("duration: requested=100ns effective=100ns (monotonic; authoritative)"),
        "{text}"
    );
    assert!(text.contains("kernel: 6.9.0-test"), "{text}");
    assert!(
        text.contains(
            "wall: start=1700000000000000000 end=1700000030000000000 (unix-ns; context only)"
        ),
        "{text}"
    );
    // PARTIAL fixture: narrowed effective window shows its own
    // explicit durations (requested 100ns, effective 90ns).
    let mut doc = partial_doc();
    doc.context = Some(fixture_context());
    let text = render_human(&doc);
    assert!(
        text.contains("duration: requested=100ns effective=90ns (monotonic; authoritative)"),
        "{text}"
    );
}

#[test]
fn r12_wall_backward_adjustment_never_rewrites_monotonic() {
    // R12 RED: a backward wall-clock adjustment (end < start) is
    // legal context — it validates, keeps its exact values, and
    // never rewrites the authoritative monotonic durations.
    let mut doc = complete_doc();
    doc.context = Some(CaptureContext {
        kernel_release: "6.9.0-test".to_string(),
        wall_start_unix_ns: Some(2_000),
        wall_end_unix_ns: Some(1_000),
    });
    let v = json_of(&doc);
    assert_eq!(v["context"]["wall_start_unix_ns"], 2_000);
    assert_eq!(v["context"]["wall_end_unix_ns"], 1_000);
    validate_v2(&v).expect("backward wall fails schema");
    check_v2_semantics(&v).expect("backward wall fails semantics");
    let text = render_human(&doc);
    assert!(
        text.contains("duration: requested=100ns effective=100ns (monotonic; authoritative)"),
        "wall adjustment must not rewrite monotonic durations:\n{text}"
    );
    assert!(
        text.contains("wall: start=2000 end=1000 (unix-ns; context only)"),
        "{text}"
    );
    // The monotonic window itself is untouched by wall context.
    assert_eq!(v["window"]["requested_start_ns"], 0);
    assert_eq!(v["window"]["requested_end_ns"], 100);
    assert_eq!(v["window"]["effective_start_ns"], 0);
    assert_eq!(v["window"]["effective_end_ns"], 100);
}

#[test]
fn r12_unknown_kernel_and_wall_stay_explicit() {
    // R12 RED: missing context omits the JSON section and renders
    // human unknown; present-but-unknown context renders explicit
    // nulls (never fabricated zeros).
    let mut doc = complete_doc();
    doc.context = None;
    let v = json_of(&doc);
    assert!(v.get("context").is_none(), "absent context must omit");
    validate_v2(&v).expect("context-less doc fails schema");
    check_v2_semantics(&v).expect("context-less doc fails semantics");
    let text = render_human(&doc);
    assert!(text.contains("kernel: unknown"), "{text}");
    assert!(
        text.contains("wall: start=unknown end=unknown (unix-ns; context only)"),
        "{text}"
    );

    doc.context = Some(CaptureContext {
        kernel_release: String::new(),
        wall_start_unix_ns: None,
        wall_end_unix_ns: None,
    });
    let v = json_of(&doc);
    assert_eq!(
        v["context"],
        json!({
            "kernel_release": "",
            "wall_start_unix_ns": Value::Null,
            "wall_end_unix_ns": Value::Null,
        }),
        "unknown wall times must be explicit null"
    );
    validate_v2(&v).expect("null-wall doc fails schema");
    check_v2_semantics(&v).expect("null-wall doc fails semantics");
    let text = render_human(&doc);
    assert!(text.contains("kernel: unknown"), "{text}");
    assert!(
        text.contains("wall: start=unknown end=unknown (unix-ns; context only)"),
        "{text}"
    );
}

#[test]
fn r12_no_window_fatal_carries_explicit_unknown() {
    // R12 RED: the no-window setup-failure document (nothing was
    // observed) validates with zero durations and explicit unknown
    // kernel/wall — no invented context.
    let doc = setup_failure_document(FatalKind::Environment("boom".to_string()));
    let v = json_of(&doc);
    assert!(v.get("context").is_none());
    validate_v2(&v).expect("no-window fatal fails schema");
    check_v2_semantics(&v).expect("no-window fatal fails semantics");
    let text = render_human(&doc);
    assert!(
        text.contains("duration: requested=0ns effective=0ns (monotonic; authoritative)"),
        "{text}"
    );
    assert!(text.contains("kernel: unknown"), "{text}");
    assert!(
        text.contains("wall: start=unknown end=unknown (unix-ns; context only)"),
        "{text}"
    );
}

/// Pre-R12 wire-reader shape: the supported-evidence subset an old
/// (pre-context) reader parses from the PUBLISHED artifact layout
/// (`render_json` bytes) — `completeness.status` string, wire
/// `target`/`window`/`sites`/`objects`/`coverage` objects, and R05
/// ENGINE observations. No `context` field; serde ignores that
/// unknown key by default — exactly like a real old field reader.
/// Inner objects deny unknown fields, so the shape provably matches
/// the published layout instead of loosely parsing it.
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct PreR12WireDocument {
    schema_version: String,
    target: PreR12WireTarget,
    window: PreR12WireWindow,
    completeness: PreR12WireCompleteness,
    sites: Vec<PreR12WireSite>,
    objects: Vec<PreR12WireObject>,
    coverage: Vec<PreR12WireCoverage>,
    engine_observations: Vec<PreR12WireEngineObs>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireTarget {
    pid: u32,
    comm: String,
    container_id: String,
    image_digest: String,
    argv_redacted: bool,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireWindow {
    requested_start_ns: u64,
    requested_end_ns: u64,
    effective_start_ns: u64,
    effective_end_ns: u64,
    signal_cut: bool,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireCounter {
    name: String,
    kind: String,
    units: String,
    source: String,
    value: u64,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireCompleteness {
    status: String,
    fatal_kind: Value,
    reasons: Vec<Value>,
    counters: Vec<PreR12WireCounter>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireCandidate {
    provider: String,
    provider_class: String,
    op: u32,
    funcid: u32,
    algorithm_classes: Vec<String>,
    weak_alias: bool,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireSite {
    object: String,
    device: u64,
    inode: u64,
    offset: u64,
    generation: u32,
    candidates: Vec<PreR12WireCandidate>,
    candidates_coverage: String,
    calls: u64,
    first_ns: u64,
    last_ns: u64,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireObject {
    id: String,
    device: u64,
    inode: u64,
    display_locator: String,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireExpected {
    state: String,
    sites: Option<u64>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireCoverage {
    scope: String,
    expected: PreR12WireExpected,
    discovered: u64,
    attached: u64,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
struct PreR12WireEngineObs {
    object: String,
    device: u64,
    inode: u64,
    offset: u64,
    generation: u64,
    entrypoint: u16,
    entrypoint_name: String,
    window: String,
    calls: u64,
}

#[test]
fn r12_old_reader_ignores_context() {
    // Correct direction: the UNCHANGED context-bearing RENDERED
    // artifact (`render_json` bytes — with R05 ENGINE observations)
    // feeds a pre-R12 wire-reader shape (no `context` field). The
    // old reader parses the published layout and its supported
    // evidence survives intact; the unknown key is ignored.
    let doc = engine_doc_fixture();
    assert!(doc.context.is_some(), "fixture must carry context");
    let bytes = render_json(&doc).expect("rendered artifact serializes");
    let rendered: Value = serde_json::from_slice(&bytes).expect("rendered artifact parses");
    validate_v2(&rendered).expect("rendered artifact fails schema");
    check_v2_semantics(&rendered).expect("rendered artifact fails semantics");
    assert!(
        rendered.get("context").is_some(),
        "artifact must carry context into the old reader"
    );
    assert_eq!(
        rendered["engine_observations"].as_array().unwrap().len(),
        5,
        "artifact must carry ENGINE observations into the old reader"
    );
    let back: PreR12WireDocument =
        serde_json::from_value(rendered).expect("old reader parses new bytes");
    assert_eq!(back.schema_version, "observed-crypto-v2.1");
    assert_eq!(back.completeness.status, "COMPLETE");
    assert_eq!(
        back.window.requested_start_ns,
        doc.window.requested_start_ns
    );
    assert_eq!(back.window.requested_end_ns, doc.window.requested_end_ns);
    assert_eq!(
        back.window.effective_start_ns,
        doc.window.effective_start_ns
    );
    assert_eq!(back.window.effective_end_ns, doc.window.effective_end_ns);
    assert_eq!(back.window.signal_cut, doc.window.signal_cut);
    assert_eq!(back.target.pid, doc.target.pid);
    assert_eq!(back.target.comm, doc.target.comm);
    assert_eq!(back.target.container_id, doc.target.container_id);
    assert_eq!(back.target.image_digest, doc.target.image_digest);
    assert!(back.target.argv_redacted, "wire target redacts argv");
    assert_eq!(back.sites.len(), doc.sites.len());
    let site = &back.sites[0];
    let model = &doc.sites[0];
    assert_eq!(site.object, model.site.object.0);
    assert_eq!(site.device, model.site.device);
    assert_eq!(site.inode, model.site.inode);
    assert_eq!(site.offset, model.site.offset);
    assert_eq!(site.generation, model.generation);
    assert_eq!(site.candidates_coverage, "complete");
    assert_eq!(site.calls, model.calls);
    assert_eq!(site.first_ns, model.first_ns);
    assert_eq!(site.last_ns, model.last_ns);
    assert_eq!(site.candidates.len(), model.candidates.len());
    assert_eq!(site.candidates[0].provider, FP_A);
    assert_eq!(site.candidates[0].provider_class, "default");
    assert_eq!(site.candidates[0].op, 2);
    assert_eq!(site.candidates[0].funcid, 21);
    assert_eq!(site.candidates[0].algorithm_classes, ["AES-128-GCM"]);
    assert!(!site.candidates[0].weak_alias);
    assert_eq!(back.objects.len(), doc.objects.len());
    for (wire, model) in back.objects.iter().zip(doc.objects.iter()) {
        assert_eq!(wire.id, model.id.0);
        assert_eq!(wire.device, model.device);
        assert_eq!(wire.inode, model.inode);
        assert_eq!(wire.display_locator, model.display_locator);
    }
    assert_eq!(back.coverage.len(), doc.coverage.len());
    assert_eq!(back.completeness.counters.len(), doc.counters.len());
    assert_eq!(back.engine_observations.len(), 5);
    let names: Vec<&str> = back
        .engine_observations
        .iter()
        .map(|o| o.entrypoint_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "ENGINE_by_id",
            "ENGINE_init",
            "ENGINE_finish",
            "ENGINE_free",
            "ENGINE_ctrl"
        ]
    );
    for (wire, model) in back
        .engine_observations
        .iter()
        .zip(doc.engine_observations.iter())
    {
        assert_eq!(wire.object, model.key.object.0);
        assert_eq!(wire.device, model.key.device);
        assert_eq!(wire.inode, model.key.inode);
        assert_eq!(wire.offset, model.key.offset);
        assert_eq!(wire.generation, model.generation);
        assert_eq!(wire.entrypoint, model.entrypoint);
        assert_eq!(wire.window, "in-window");
        assert_eq!(wire.calls, model.calls);
    }
    let calls: u64 = back.sites.iter().map(|s| s.calls).sum();
    assert_eq!(calls, 500, "calls conserved through the old reader");
    assert_eq!(calls, doc.total_calls());
}

#[test]
fn r12_new_reader_defaults_missing_context() {
    // New code still reads old bytes: a document without the
    // optional context section validates, and a missing context
    // defaults to None — never to fabricated kernel/wall values.
    let mut doc = complete_doc();
    doc.context = Some(fixture_context());
    let mut v = json_of(&doc);
    assert!(v.get("context").is_some());
    v.as_object_mut().unwrap().remove("context");
    validate_v2(&v).expect("old-shaped doc fails schema");
    check_v2_semantics(&v).expect("old-shaped doc fails semantics");
    let mut stripped = serde_json::to_value(&doc).expect("document serializes");
    stripped.as_object_mut().unwrap().remove("context");
    let back: CaptureDocument = serde_json::from_value(stripped).expect("old shape parses");
    assert!(back.context.is_none());
    assert_eq!(back.total_calls(), 900);
}

#[test]
fn r12_context_carries_no_forbidden_keys() {
    // R12: the new section holds kernel + two timestamps only — no
    // raw argv, pointers or payloads under any name.
    let mut doc = complete_doc();
    doc.context = Some(fixture_context());
    let v = json_of(&doc);
    let context = v["context"].as_object().expect("context renders");
    for key in context.keys() {
        assert!(
            ["kernel_release", "wall_start_unix_ns", "wall_end_unix_ns"].contains(&key.as_str()),
            "unexpected context key {key:?}"
        );
        assert!(
            !FORBIDDEN_V2_KEYS.contains(&key.as_str()),
            "forbidden context key {key:?}"
        );
    }
    assert_no_forbidden_keys(&v, "context-doc.json");
}
