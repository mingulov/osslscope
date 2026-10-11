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
//! inconclusive/violation artifacts from one document — no second
//! capture). v2 goldens pin bytes; examples in docs come from these
//! fixtures, never invented.

use osslscope::check::policy_record;
use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, Completeness,
    CounterKind, CounterSource, CounterUnits, DispositionRecord, ExpectedScope, FatalKind,
    FencedGeneration, FinalizeInput, GapCounter, ObjectId, ObjectRecord, OpensslVersion,
    PolicyRecord, PolicyRuleResult, PolicyVerdict, RuleVerdict, ScopeCoverage, SiteExecution,
    SiteKey, TargetRecord, finalize,
};
use osslscope::policy::{PolicyRule, evaluate_document};
use osslscope::report::{
    OutputDest, OutputFormat, OutputRequest, render_cbom, render_human, render_json,
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
    }
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
    let doc = finalize(input);
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
    let doc = finalize(input);
    assert!(matches!(doc.status, Completeness::Partial { .. }));
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
    let doc = finalize(input);
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
            },
            PolicyRuleResult {
                rule: "deny-weak".to_string(),
                predicate: "weak-alias".to_string(),
                result: RuleVerdict::Pass,
                definite: 0,
                possible: Some(0),
                evidence: Vec::new(),
            },
        ],
    });
    let doc = finalize(input);
    assert!(matches!(doc.status, Completeness::Complete));
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
        }],
    });
    finalize(input)
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
        }],
    });
    finalize(input)
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
    ] {
        let v = json_of(&doc);
        validate_v2(&v).unwrap_or_else(|e| panic!("{name} fails schema: {e}"));
        check_v2_semantics(&v).unwrap_or_else(|e| panic!("{name} fails semantics: {e}"));
    }
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
        assert_eq!(json_of(&doc)["schema_version"], "observed-crypto-v2.0");
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
                        },
                        PolicyRuleResult {
                            rule: "deny-weak".to_string(),
                            predicate: "weak-alias".to_string(),
                            result: RuleVerdict::Pass,
                            definite: 0,
                            possible: Some(0),
                            evidence: Vec::new(),
                        },
                    ],
                    0xdef + round,
                ),
            });
            finalize(input)
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
        assert_eq!(meta["osslscope:schema-version"], "observed-crypto-v2.0");
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
    // Fatal/partial/inconclusive/violation/pass artifacts from one
    // document each: delivered bytes equal direct renders and
    // validate (schema + semantics).
    for (name, doc) in [
        ("fatal", fatal_doc()),
        ("partial", partial_doc()),
        ("inconclusive", inconclusive_doc()),
        ("violation", violation_doc()),
        ("pass", pass_doc()),
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
    let doc = finalize(input);
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
