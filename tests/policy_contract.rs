//! SPDX-License-Identifier: GPL-3.0-or-later
//! T10 policy integration contract (spec R06/R08).
//!
//! Table-driven coverage for every R06 rule/outcome over finalized
//! [`CaptureDocument`] fixtures: unknown candidates, relevant vs
//! unrelated gaps, weak alias, renamed provider, FIPS/parameter
//! ambiguity, child failure, interruption, fatal capture and no rules.
//! Integration tests pin the exit table (2/4/10/1/11/3/0), the
//! all-artifacts-attempted delivery rule, and the same-window guarantee
//! across primary and CBOM artifacts. Possible use never becomes a
//! definite violation: inconclusive rows assert zero violations.
//!
//! No live capture here: all documents are built with
//! [`evidence::finalize`], so these tests run on the host (C3).

use osslscope::capture::EngineCollector;
use osslscope::check::{exit_for, policy_json, policy_record};
use osslscope::discovery::legacy;
use osslscope::discovery::maps;
use osslscope::discovery::session::{
    DiscoveryDelta, MapSnapshots, PollBudget, SessionCore, SessionEnv, TripModulePin,
};
use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, Completeness,
    CounterKind, CounterSource, CounterUnits, EngineObservation, EngineWindow, ExpectedScope,
    FatalKind, FencedGeneration, FinalizeInput, GapCounter, LegacyCallPartition, MatchBounds,
    ObjectId, ObjectRecord, OpensslVersion, RuleVerdict, ScopeCoverage, SiteExecution, SiteKey,
    TargetRecord, engine_index, finalize,
};
use osslscope::policy::{ENGINE_PROVIDER_CLASS, PolicyOutcome, PolicyRule, evaluate_document};
use osslscope::report::{
    ArtifactOutcome, DeliveryResult, OutputDest, OutputFormat, OutputRequest, write_artifacts,
};
use std::process::ExitCode;

const DIGEST: u32 = 1;
const SIGNATURE: u32 = 12;

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
        algs.iter().map(|s| s.to_string()).collect(),
        weak,
    )
}

fn site_at(
    offset: u64,
    generation: u32,
    calls: u64,
    cands: Vec<CandidateIdentity>,
    cov: CandidateCoverage,
) -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: obj("exe-fingerprint"),
            device: 7,
            inode: 9,
            offset,
        },
        generation,
        candidates: cands,
        candidates_coverage: cov,
        calls,
        first_ns: 100,
        last_ns: 200,
        installed_at: None,
    }
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

#[allow(clippy::too_many_arguments)]
fn doc(
    sites: Vec<SiteExecution>,
    fenced: Vec<FencedGeneration>,
    coverage: Vec<ScopeCoverage>,
    counters: Vec<GapCounter>,
    window: CaptureWindow,
    fatal: Option<FatalKind>,
) -> CaptureDocument {
    finalize(FinalizeInput {
        window,
        sites,
        fenced,
        objects: Vec::new(),
        coverage,
        counters,
        fatal,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
    })
}

fn complete_doc(sites: Vec<SiteExecution>) -> CaptureDocument {
    doc(
        sites,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        None,
    )
}

fn loss_counter(name: &str) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind: CounterKind::Loss,
        units: CounterUnits::Events,
        source: CounterSource::Discovery,
        value: 3,
    }
}

fn activity_counter(name: &str, value: u64) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind: CounterKind::Activity,
        units: CounterUnits::Events,
        source: CounterSource::Discovery,
        value,
    }
}

fn coverage_gap(scope: &str) -> ScopeCoverage {
    ScopeCoverage {
        scope: scope.to_string(),
        expected: ExpectedScope::Applicable { sites: 2 },
        discovered: 1,
        attached: 1,
    }
}

fn ok_delivery() -> DeliveryResult {
    DeliveryResult {
        primary: ArtifactOutcome {
            dest: "stdout".to_string(),
            ok: true,
            bytes: 8,
            error: None,
        },
        cbom: None,
        diagnostics: Vec::new(),
    }
}

fn violations_of(doc: &CaptureDocument, rules: &[PolicyRule]) -> serde_json::Value {
    let v = evaluate_document(rules, doc);
    policy_json(doc, &v)["violations"].clone()
}

/// Every R06 truth-table row over conserved document bounds (DIGEST op,
/// so no parameter-ambiguity upgrade applies here).
#[test]
fn r06_rule_outcomes() {
    let exact = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["AES-256-GCM"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let clean_empty = complete_doc(Vec::new());
    let ambiguous = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![
            cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["AES-128-GCM"],
                false,
            ),
            cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["AES-256-GCM"],
                false,
            ),
        ],
        CandidateCoverage::Complete,
    )]);
    let unknown_cov = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["AES-128-GCM"],
                false,
            )],
            CandidateCoverage::Unknown,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        None,
    );
    assert!(matches!(unknown_cov.status, Completeness::Partial { .. }));
    let relevant_gap = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![loss_counter("discovery.table_aborted")],
        exact_window(),
        None,
    );

    struct Row {
        name: &'static str,
        rule: PolicyRule,
        doc: CaptureDocument,
        bounds: MatchBounds,
        expected: RuleVerdict,
        overall: PolicyOutcome,
    }
    let rows = vec![
        Row {
            name: "require definite use passes",
            rule: PolicyRule::require_executed("AES-256-GCM"),
            doc: exact.clone(),
            bounds: MatchBounds {
                definite: 7,
                possible: Some(7),
            },
            expected: RuleVerdict::Pass,
            overall: PolicyOutcome::Pass,
        },
        Row {
            name: "require clean absence violates",
            rule: PolicyRule::require_executed("AES-256-GCM"),
            doc: clean_empty.clone(),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(0),
            },
            expected: RuleVerdict::Violation,
            overall: PolicyOutcome::Violation,
        },
        Row {
            name: "require possible use is inconclusive",
            rule: PolicyRule::require_executed("AES-256-GCM"),
            doc: ambiguous.clone(),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(7),
            },
            expected: RuleVerdict::Inconclusive,
            overall: PolicyOutcome::Inconclusive,
        },
        Row {
            name: "require unknown use is inconclusive",
            rule: PolicyRule::require_executed("AES-256-GCM"),
            doc: unknown_cov.clone(),
            bounds: MatchBounds {
                definite: 0,
                possible: None,
            },
            expected: RuleVerdict::Inconclusive,
            overall: PolicyOutcome::Inconclusive,
        },
        Row {
            name: "deny definite use violates",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: exact.clone(),
            bounds: MatchBounds {
                definite: 7,
                possible: Some(7),
            },
            expected: RuleVerdict::Violation,
            overall: PolicyOutcome::Violation,
        },
        Row {
            name: "deny possible use is inconclusive",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: ambiguous.clone(),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(7),
            },
            expected: RuleVerdict::Inconclusive,
            overall: PolicyOutcome::Inconclusive,
        },
        Row {
            name: "deny relevant blind coverage is inconclusive",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: relevant_gap.clone(),
            bounds: MatchBounds {
                definite: 0,
                // F-E/B5: relevant loss makes the upper bound
                // unknown; the old Some(0) was the false certainty.
                possible: None,
            },
            expected: RuleVerdict::Inconclusive,
            overall: PolicyOutcome::Inconclusive,
        },
        Row {
            name: "deny clean absence passes",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: clean_empty.clone(),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(0),
            },
            expected: RuleVerdict::Pass,
            overall: PolicyOutcome::Pass,
        },
    ];
    for row in &rows {
        let v = evaluate_document(std::slice::from_ref(&row.rule), &row.doc);
        assert_eq!(v.rules.len(), 1, "{}", row.name);
        assert_eq!(v.rules[0].bounds, row.bounds, "{}", row.name);
        assert_eq!(v.rules[0].verdict, row.expected, "{}", row.name);
        assert_eq!(v.overall(), row.overall, "{}", row.name);
        let p = policy_json(&row.doc, &v);
        let expect_verdict = match row.expected {
            RuleVerdict::Pass => "pass",
            RuleVerdict::Violation => "violation",
            RuleVerdict::Inconclusive => "inconclusive",
        };
        assert_eq!(p["verdict"], expect_verdict, "{}", row.name);
        if row.expected == RuleVerdict::Inconclusive {
            assert_eq!(
                p["violations"].as_array().unwrap().len(),
                0,
                "{}: possible use is never a definite violation",
                row.name
            );
        }
    }
    // AND semantics across rules: violation dominates inconclusive dominates pass.
    let mixed = evaluate_document(
        &[
            PolicyRule::deny_algorithm("AES-256-GCM"),
            PolicyRule::require_executed("AES-256-GCM"),
        ],
        &ambiguous,
    );
    assert_eq!(mixed.overall(), PolicyOutcome::Inconclusive);
    let mixed = evaluate_document(
        &[
            PolicyRule::deny_algorithm("AES-128-GCM"),
            PolicyRule::deny_algorithm("AES-256-GCM"),
        ],
        &exact,
    );
    assert_eq!(mixed.overall(), PolicyOutcome::Violation);
}

/// F-E/B5: an empty observation with an unknown denominator reports
/// an unknown upper bound (None), never a finite `possible: 0`.
/// Relevant coverage/loss shapes the bound, not just the verdict.
#[test]
fn empty_observation_with_unknown_denominator_has_unknown_possible() {
    let d = doc(
        Vec::new(),
        Vec::new(),
        vec![ScopeCoverage {
            scope: "provider/default".to_string(),
            expected: ExpectedScope::Unknown,
            discovered: 0,
            attached: 0,
        }],
        Vec::new(),
        exact_window(),
        None,
    );
    assert!(matches!(d.status, Completeness::Partial { .. }));
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_algorithm("DES")), &d);
    assert_eq!(v.rules.len(), 1);
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(v.rules[0].bounds.possible, None);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    let rec = policy_record(&v);
    assert_eq!(rec.rules[0].possible, None);
}

/// F-E/B6: a resolved non-weak HMAC identity does not establish a
/// strong unseen digest — deny-weak is inconclusive at
/// parameter-blind ops, never a clean pass.
#[test]
fn deny_weak_is_inconclusive_for_resolved_hmac_with_unseen_digest() {
    let mac = osslscope::kinds::op_id("OSSL_OP_MAC").expect("MAC op id");
    let d = complete_doc(vec![site_at(
        1,
        0,
        5,
        vec![cand("prov-default", "default", mac, 5, &["HMAC"], false)],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &d);
    assert_eq!(v.rules.len(), 1);
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(v.rules[0].bounds.possible, Some(5));
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
}

#[test]
fn h3_t3_mixed_sites_never_yield_definite_verdicts() {
    // H3: a mixed-shaped site (Unknown coverage + min label +
    // weak preserved, as H3-T2 produces) feeds no definite
    // verdict in either direction — neither require (present)
    // nor deny (weak label). Pins the coverage→exclusion link
    // (Complete-first gate); the status→coverage link is H3-T2's.
    let mixed = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["SHA-256"],
                true,
            )],
            CandidateCoverage::Unknown,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        None,
    );
    for rule in [
        PolicyRule::require_executed("SHA-256"),
        PolicyRule::deny_algorithm("SHA-256"),
        PolicyRule::deny_weak(),
    ] {
        let v = evaluate_document(std::slice::from_ref(&rule), &mixed);
        assert_eq!(v.rules[0].bounds.definite, 0, "{}", rule.name);
        assert_eq!(
            v.rules[0].verdict,
            RuleVerdict::Inconclusive,
            "{}",
            rule.name
        );
    }
}

/// Unknown candidate sets make the upper bound unknown and prevent any
/// absence proof; zero-call unknown sites stay known-zero.
#[test]
fn unknown_candidates_are_unbounded() {
    let unknown = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["AES-128-GCM"],
                false,
            )],
            CandidateCoverage::Unknown,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        None,
    );
    for rule in [
        PolicyRule::require_executed("AES-256-GCM"),
        PolicyRule::deny_algorithm("AES-256-GCM"),
        PolicyRule::require_provider("default"),
        PolicyRule::deny_provider("fips"),
    ] {
        let v = evaluate_document(std::slice::from_ref(&rule), &unknown);
        assert_eq!(v.rules[0].bounds.definite, 0, "{}", rule.name);
        assert_eq!(v.rules[0].bounds.possible, None, "{}", rule.name);
        assert_eq!(
            v.rules[0].verdict,
            RuleVerdict::Inconclusive,
            "{}",
            rule.name
        );
    }
    assert_eq!(
        violations_of(
            &unknown,
            std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM"))
        )
        .as_array()
        .unwrap()
        .len(),
        0
    );
    // Zero calls with unknown attribution: known-zero, gaps stay empty.
    let quiet_unknown = complete_doc(vec![site_at(
        1,
        0,
        0,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["AES-128-GCM"],
            false,
        )],
        CandidateCoverage::Unknown,
    )]);
    assert_eq!(quiet_unknown.status, Completeness::Complete);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &quiet_unknown,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
}

/// Relevant loss blocks absence proofs; unrelated gaps neither erase
/// positive evidence nor poison disjoint rules.
#[test]
fn relevant_vs_unrelated_gaps() {
    let with_gap = |coverage: Vec<ScopeCoverage>, counters: Vec<GapCounter>| {
        doc(
            Vec::new(),
            Vec::new(),
            coverage,
            counters,
            exact_window(),
            None,
        )
    };
    struct Row {
        name: &'static str,
        rule: PolicyRule,
        doc: CaptureDocument,
        expected: RuleVerdict,
    }
    let rows = vec![
        Row {
            name: "provider loss is relevant to deny-algorithm",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: with_gap(Vec::new(), vec![loss_counter("discovery.table_aborted")]),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "engine-internal loss is unrelated to deny-algorithm",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: with_gap(
                Vec::new(),
                vec![loss_counter("legacy.engine_uninstrumented")],
            ),
            expected: RuleVerdict::Pass,
        },
        Row {
            name: "provider coverage gap is relevant to require-provider",
            rule: PolicyRule::require_provider("default"),
            doc: with_gap(vec![coverage_gap("default")], Vec::new()),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "engine coverage gap is unrelated to require-provider",
            rule: PolicyRule::require_provider("default"),
            doc: with_gap(vec![coverage_gap("legacy.engine")], Vec::new()),
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "engine loss is relevant to deny-engine",
            rule: PolicyRule::deny_engine(),
            doc: with_gap(Vec::new(), vec![loss_counter("legacy.meth_uninstrumented")]),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "generic loss is relevant to deny-engine (tripwire shares the path)",
            rule: PolicyRule::deny_engine(),
            doc: with_gap(Vec::new(), vec![loss_counter("discovery.table_aborted")]),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "unrecognized coverage gaps fail engine rules closed",
            rule: PolicyRule::deny_engine(),
            doc: with_gap(vec![coverage_gap("default")], Vec::new()),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "engine coverage gap is relevant to deny-engine",
            rule: PolicyRule::deny_engine(),
            doc: with_gap(vec![coverage_gap("engine.tripwire")], Vec::new()),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "startup gap is relevant to every rule",
            rule: PolicyRule::deny_algorithm("AES-256-GCM"),
            doc: doc(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                CaptureWindow {
                    requested_start_ns: 1_000,
                    requested_end_ns: 2_000,
                    effective_start_ns: 1_500,
                    effective_end_ns: 2_000,
                    signal_cut: false,
                },
                None,
            ),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "signal cut is relevant to deny-engine too",
            rule: PolicyRule::deny_engine(),
            doc: doc(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                CaptureWindow {
                    signal_cut: true,
                    ..exact_window()
                },
                None,
            ),
            expected: RuleVerdict::Inconclusive,
        },
    ];
    for row in &rows {
        assert!(
            matches!(row.doc.status, Completeness::Partial { .. }),
            "{}: fixture must be PARTIAL",
            row.name
        );
        let v = evaluate_document(std::slice::from_ref(&row.rule), &row.doc);
        assert_eq!(v.rules[0].verdict, row.expected, "{}", row.name);
    }
    // Positive evidence survives unrelated and relevant gaps alike.
    let gappy = with_gap(Vec::new(), vec![loss_counter("discovery.table_aborted")]);
    let mut gappy = gappy;
    gappy.sites = vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["AES-256-GCM"],
            false,
        )],
        CandidateCoverage::Complete,
    )];
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("AES-256-GCM")),
        &gappy,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &gappy,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
}

/// A weak alias can neither disappear (mixed candidates stay possible)
/// nor fabricate a violation; unresolved classes could be weak.
#[test]
fn weak_alias_matching() {
    let all_weak = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
        CandidateCoverage::Complete,
    )]);
    let mixed = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![
            cand("prov-default", "default", DIGEST, 7, &["SHA2-256"], false),
            cand("prov-default", "default", DIGEST, 7, &["MD5"], true),
        ],
        CandidateCoverage::Complete,
    )]);
    let strong = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["SHA2-256"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let unresolved = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["other"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    struct Row {
        name: &'static str,
        doc: CaptureDocument,
        expected: RuleVerdict,
    }
    for row in [
        Row {
            name: "all-weak executed violates",
            doc: all_weak,
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "mixed weak/strong is possible, never definite",
            doc: mixed,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "strong only passes",
            doc: strong,
            expected: RuleVerdict::Pass,
        },
        Row {
            name: "unresolved class could be weak",
            doc: unresolved,
            expected: RuleVerdict::Inconclusive,
        },
    ] {
        let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &row.doc);
        assert_eq!(v.rules[0].verdict, row.expected, "{}", row.name);
        if row.expected == RuleVerdict::Inconclusive {
            assert_eq!(
                policy_json(&row.doc, &v)["violations"]
                    .as_array()
                    .unwrap()
                    .len(),
                0,
                "{}",
                row.name
            );
        }
    }
    // The definite weak violation carries object and generation refs.
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_weak()),
        &complete_doc(vec![site_at(
            0x40,
            0,
            7,
            vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )]),
    );
    let x = &policy_json(
        &complete_doc(vec![site_at(
            0x40,
            0,
            7,
            vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )]),
        &v,
    )["violations"][0];
    assert_eq!(x["rule"], "deny-weak");
    assert_eq!(x["site"]["object"], "exe-fingerprint");
    assert_eq!(x["site"]["offset"], 0x40);
    assert_eq!(x["generation"], 0);
    assert_eq!(x["calls"], 7);
}

/// Provider class is pinned metadata, never a filename guess: renames
/// match by class, and FIPS-shaped filenames without the class do not.
#[test]
fn renamed_provider_matches_by_class() {
    // Same class, renamed backing file: require still passes.
    let renamed = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "renamed-blob-object",
            "default",
            DIGEST,
            7,
            &["SHA2-256"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_provider("default")),
        &renamed,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    // FIPS-shaped filename, third-party class: deny-fips passes, require-fips violates.
    let lookalike = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "some-renamed-fips.so-object",
            "third-party:deadbeef",
            DIGEST,
            7,
            &["SHA2-256"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_provider("fips")),
        &lookalike,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_provider("fips")),
        &lookalike,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    // Between-candidate class ambiguity stays possible.
    let mixed_class = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![
            cand("prov-a", "default", DIGEST, 7, &["SHA2-256"], false),
            cand(
                "prov-b",
                "third-party:deadbeef",
                DIGEST,
                7,
                &["SHA2-256"],
                false,
            ),
        ],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_provider("default")),
        &mixed_class,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    // Existential require: one definite default execution among others passes.
    let multi = complete_doc(vec![
        site_at(
            1,
            0,
            5,
            vec![cand("prov-fips", "fips", DIGEST, 7, &["SHA2-256"], false)],
            CandidateCoverage::Complete,
        ),
        site_at(
            2,
            0,
            9,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["SHA2-256"],
                false,
            )],
            CandidateCoverage::Complete,
        ),
    ]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_provider("default")),
        &multi,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert_eq!(v.rules[0].bounds.definite, 9);
}

/// Parameter-only digest identity upgrades algorithm absence to
/// inconclusive at SIGN/MAC/KDF-family ops; unlabeled FIPS executions
/// fail closed (no KAT carve-out) and are counted, not hidden.
#[test]
fn fips_and_parameter_ambiguity() {
    let sign_rsa = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-default",
            "default",
            SIGNATURE,
            21,
            &["RSA"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    struct Row {
        name: &'static str,
        rule: PolicyRule,
        doc: CaptureDocument,
        expected: RuleVerdict,
    }
    let rows = vec![
        Row {
            name: "sign digest could be the denied digest",
            rule: PolicyRule::deny_algorithm("SHA2-256"),
            doc: sign_rsa.clone(),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "sign scheme itself is definite",
            rule: PolicyRule::deny_algorithm("RSA"),
            doc: sign_rsa.clone(),
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "require digest over sign-only use is unproven",
            rule: PolicyRule::require_executed("SHA2-256"),
            doc: sign_rsa.clone(),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "digest op stays exact",
            rule: PolicyRule::deny_algorithm("SHA2-256"),
            doc: complete_doc(vec![site_at(
                1,
                0,
                7,
                vec![cand(
                    "prov-default",
                    "default",
                    DIGEST,
                    7,
                    &["SHA2-256"],
                    false,
                )],
                CandidateCoverage::Complete,
            )]),
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "fips execution of denied algorithm violates (no KAT exclusion)",
            rule: PolicyRule::deny_algorithm("SHA2-256"),
            doc: complete_doc(vec![site_at(
                1,
                0,
                7,
                vec![cand("prov-fips", "fips", DIGEST, 7, &["SHA2-256"], false)],
                CandidateCoverage::Complete,
            )]),
            expected: RuleVerdict::Violation,
        },
    ];
    for row in &rows {
        let v = evaluate_document(std::slice::from_ref(&row.rule), &row.doc);
        assert_eq!(v.rules[0].verdict, row.expected, "{}", row.name);
    }
    // Require satisfied by a FIPS execution passes, with the unlabeled
    // count visible in machine-readable form.
    let fips_use = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand("prov-fips", "fips", DIGEST, 7, &["SHA2-256"], false)],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &fips_use,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    let p = policy_json(&fips_use, &v);
    assert_eq!(p["fips_unlabeled_executions"], 7);
    assert_eq!(p["kat_excluded"], 0);
    // The parameter caveat is raised exactly when algorithm rules meet
    // executed parameter-blind ops.
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("SHA2-256")),
        &sign_rsa,
    );
    assert_eq!(policy_json(&sign_rsa, &v)["param_blind"], true);
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &sign_rsa);
    assert_eq!(policy_json(&sign_rsa, &v)["param_blind"], false);
}

/// Query/load/activity counters never shape verdicts; only executed
/// sites and relevant loss do.
#[test]
fn no_policy_use_of_query_or_load_counts() {
    let busy = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![
            activity_counter("discovery.queries_issued", 500),
            activity_counter("provider.loads", 4),
            activity_counter("unseen_ops", 12),
        ],
        exact_window(),
        None,
    );
    assert_eq!(busy.status, Completeness::Complete);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &busy,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("SHA2-256")),
        &busy,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    // Queried-but-unexecuted (zero-call) sites are reported shape, not evidence.
    let queried = complete_doc(vec![site_at(
        1,
        0,
        0,
        vec![cand(
            "prov-default",
            "default",
            DIGEST,
            7,
            &["SHA2-256"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &queried,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
}

/// Fenced generations evaluate like current sites, with the fenced
/// generation on every violation record.
#[test]
fn fenced_counts_evaluated() {
    let fenced = doc(
        Vec::new(),
        vec![FencedGeneration {
            generation: 3,
            sites: vec![site_at(
                9,
                3,
                7,
                vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
                CandidateCoverage::Complete,
            )],
        }],
        Vec::new(),
        Vec::new(),
        exact_window(),
        None,
    );
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &fenced);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    let x = &policy_json(&fenced, &v)["violations"][0];
    assert_eq!(x["generation"], 3);
    assert_eq!(x["fenced"], true);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("MD5")),
        &fenced,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
}

/// Fatal capture yields no verdict at all, never a violation.
#[test]
fn fatal_capture_has_no_verdict() {
    let fatal = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        Some(FatalKind::AttachZero),
    );
    let v = evaluate_document(
        &[
            PolicyRule::deny_weak(),
            PolicyRule::require_executed("SHA2-256"),
        ],
        &fatal,
    );
    assert_eq!(v.overall(), PolicyOutcome::NoVerdict);
    assert!(v.rules.is_empty());
    assert_eq!(policy_json(&fatal, &v)["verdict"], "no-verdict");
    assert_eq!(exit_for(v.overall(), None, &fatal, &ok_delivery()), 4);
}

/// Exit precedence (PRD §14): violation(10) first, then
/// setup-no-verdict(4), child/artifact failure(1), inconclusive(11),
/// signal-cut/PARTIAL(3), clean(0); H7 inserts salvaged
/// `runtime`-fatal at 1 between violation and no-verdict (see
/// `h7_failure_fidelity`).
#[test]
fn exit_precedence() {
    let viol_doc = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
        CandidateCoverage::Complete,
    )]);
    let violation = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &viol_doc);
    assert_eq!(violation.overall(), PolicyOutcome::Violation);
    let clean_doc = complete_doc(Vec::new());
    let pass = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &clean_doc,
    );
    assert_eq!(pass.overall(), PolicyOutcome::Pass);
    let gappy_doc = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![loss_counter("discovery.table_aborted")],
        exact_window(),
        None,
    );
    let inconclusive = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &gappy_doc,
    );
    assert_eq!(inconclusive.overall(), PolicyOutcome::Inconclusive);
    struct Row {
        name: &'static str,
        outcome: PolicyOutcome,
        child: Option<i32>,
        doc: CaptureDocument,
        delivery: DeliveryResult,
        expected: u8,
    }
    let rows = vec![
        Row {
            name: "violation dominates child failure",
            outcome: violation.overall(),
            child: Some(1),
            doc: viol_doc.clone(),
            delivery: ok_delivery(),
            expected: 10,
        },
        Row {
            name: "violation dominates artifact failure",
            outcome: violation.overall(),
            child: Some(0),
            doc: viol_doc.clone(),
            delivery: failed_delivery_with("primary"),
            expected: 10,
        },
        Row {
            name: "failed child beats clean pass",
            outcome: pass.overall(),
            child: Some(2),
            doc: clean_doc.clone(),
            delivery: ok_delivery(),
            expected: 1,
        },
        Row {
            name: "failed child beats inconclusive",
            outcome: inconclusive.overall(),
            child: Some(7),
            doc: gappy_doc.clone(),
            delivery: ok_delivery(),
            expected: 1,
        },
        Row {
            name: "artifact failure beats inconclusive",
            outcome: inconclusive.overall(),
            child: Some(0),
            doc: gappy_doc.clone(),
            delivery: failed_delivery_with("cbom"),
            expected: 1,
        },
        Row {
            name: "inconclusive is 11",
            outcome: inconclusive.overall(),
            child: Some(0),
            doc: gappy_doc.clone(),
            delivery: ok_delivery(),
            expected: 11,
        },
        Row {
            name: "inconclusive without child status is 11",
            outcome: inconclusive.overall(),
            child: None,
            doc: gappy_doc.clone(),
            delivery: ok_delivery(),
            expected: 11,
        },
        Row {
            name: "clean pass is 0",
            outcome: pass.overall(),
            child: Some(0),
            doc: clean_doc.clone(),
            delivery: ok_delivery(),
            expected: 0,
        },
    ];
    for row in &rows {
        assert_eq!(
            exit_for(row.outcome, row.child, &row.doc, &row.delivery),
            row.expected,
            "{}",
            row.name
        );
    }
}

fn failed_delivery_with(which: &str) -> DeliveryResult {
    let ok = ArtifactOutcome {
        dest: "stdout".to_string(),
        ok: true,
        bytes: 8,
        error: None,
    };
    match which {
        "primary" => DeliveryResult {
            primary: ArtifactOutcome {
                dest: "stdout".to_string(),
                ok: false,
                bytes: 0,
                error: Some("primary failed".to_string()),
            },
            cbom: None,
            diagnostics: vec!["primary stdout: primary failed".to_string()],
        },
        _ => DeliveryResult {
            primary: ok,
            cbom: Some(ArtifactOutcome {
                dest: "cbom.json".to_string(),
                ok: false,
                bytes: 0,
                error: Some("cbom failed".to_string()),
            }),
            diagnostics: vec!["cbom cbom.json: cbom failed".to_string()],
        },
    }
}

/// Interruption alone is 3; it never suppresses a proved violation and
/// never fabricates one from an unproven rule.
#[test]
fn interruption_outcomes() {
    let cut_window = CaptureWindow {
        signal_cut: true,
        ..exact_window()
    };
    // Definite violation on a cut window stays a violation (exit 10).
    let cut_viol = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand("prov-default", "default", DIGEST, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cut_window,
        None,
    );
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &cut_viol);
    assert_eq!(v.overall(), PolicyOutcome::Violation);
    assert_eq!(
        exit_for(v.overall(), Some(0), &cut_viol, &ok_delivery()),
        10
    );
    // Unproven rule on a cut window is inconclusive (exit 11), not 3.
    let cut_unknown = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cut_window,
        None,
    );
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &cut_unknown,
    );
    assert_eq!(v.overall(), PolicyOutcome::Inconclusive);
    assert_eq!(
        exit_for(v.overall(), Some(0), &cut_unknown, &ok_delivery()),
        11
    );
    // Definite require-use on a cut window still passes the rule, but
    // the cut window degrades the exit to 3 (warning, not proof failure).
    let cut_pass = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["SHA2-256"],
                false,
            )],
            CandidateCoverage::Complete,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cut_window,
        None,
    );
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &cut_pass,
    );
    assert_eq!(v.overall(), PolicyOutcome::Pass);
    assert_eq!(exit_for(v.overall(), Some(0), &cut_pass, &ok_delivery()), 3);
    // Same degradation for a PARTIAL (non-cut) window with a passing verdict.
    let partial_pass = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["SHA2-256"],
                false,
            )],
            CandidateCoverage::Complete,
        )],
        Vec::new(),
        Vec::new(),
        vec![loss_counter("discovery.table_aborted")],
        exact_window(),
        None,
    );
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
        &partial_pass,
    );
    assert_eq!(v.overall(), PolicyOutcome::Pass);
    assert_eq!(
        exit_for(v.overall(), Some(0), &partial_pass, &ok_delivery()),
        3
    );
}

/// No rules, unknown algorithms and bad numerics are usage errors (exit
/// 2) raised before any capture side effect.
#[test]
fn usage_errors_exit2() {
    let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        osslscope::check::run(&v(vec!["--pid", "1"])),
        ExitCode::from(2)
    );
    assert_eq!(
        osslscope::check::run(&v(vec!["--deny-algorithm", "NOPE-NOT-REAL", "--pid", "1"])),
        ExitCode::from(2)
    );
    assert_eq!(
        osslscope::check::run(&v(vec!["--require-executed", "SHA257", "--pid", "1"])),
        ExitCode::from(2)
    );
    assert_eq!(
        osslscope::check::run(&v(vec!["--deny-weak", "--format", "yaml", "--pid", "1"])),
        ExitCode::from(2)
    );
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("osslscope-t10-{}-{name}", std::process::id()))
}

/// Primary and CBOM artifacts derive from the same finalized document:
/// both carry the exact capture window.
#[test]
fn artifacts_carry_same_window() {
    let window = CaptureWindow {
        requested_start_ns: 111_000,
        requested_end_ns: 222_000,
        effective_start_ns: 111_500,
        effective_end_ns: 222_000,
        signal_cut: false,
    };
    let mut d = doc(
        vec![site_at(
            1,
            0,
            7,
            vec![cand(
                "prov-default",
                "default",
                DIGEST,
                7,
                &["SHA2-256"],
                false,
            )],
            CandidateCoverage::Complete,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        window,
        None,
    );
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &d,
    );
    d.policy = Some(policy_record(&v));
    let primary = tmp_path("primary.json");
    let cbom = tmp_path("cbom.json");
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(primary.clone()),
        cbom: Some(OutputDest::File(cbom.clone())),
    };
    let delivery = write_artifacts(&d, &req);
    assert!(delivery.primary.ok);
    assert!(delivery.cbom.as_ref().is_some_and(|c| c.ok));
    assert!(!delivery.failed());
    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&primary).unwrap()).unwrap();
    let c: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cbom).unwrap()).unwrap();
    assert_eq!(p["window"]["requested_start_ns"], 111_000);
    assert_eq!(p["window"]["requested_end_ns"], 222_000);
    assert_eq!(p["window"]["effective_start_ns"], 111_500);
    assert_eq!(p["window"]["effective_end_ns"], 222_000);
    let meta = cbom_metadata(&c);
    assert_eq!(meta["osslscope:window-requested-start-ns"], "111000");
    assert_eq!(meta["osslscope:window-requested-end-ns"], "222000");
    assert_eq!(meta["osslscope:window-effective-start-ns"], "111500");
    assert_eq!(meta["osslscope:window-effective-end-ns"], "222000");
    // The startup gap makes the absence unproven: artifacts still
    // deliver, carrying the policy verdict with the same window.
    assert_eq!(p["policy"]["verdict"], "inconclusive");
    assert_eq!(meta["osslscope:policy-verdict"], "inconclusive");
    let _ = std::fs::remove_file(&primary);
    let _ = std::fs::remove_file(&cbom);
}

fn cbom_metadata(cbom: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
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

/// Every requested artifact is attempted even when another fails, and
/// each failure is reported without pretending delivery succeeded.
#[test]
fn all_artifacts_attempted_despite_failure() {
    let mut d = complete_doc(Vec::new());
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
        &d,
    );
    d.policy = Some(policy_record(&v));
    // Unwritable primary (missing parent), writable CBOM.
    let cbom = tmp_path("ok-cbom.json");
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(tmp_path("no-such-dir-5f2c/out.json")),
        cbom: Some(OutputDest::File(cbom.clone())),
    };
    let delivery = write_artifacts(&d, &req);
    assert!(!delivery.primary.ok);
    assert!(delivery.cbom.as_ref().is_some_and(|c| c.ok));
    assert!(delivery.failed());
    assert!(!delivery.diagnostics.is_empty());
    assert!(cbom.is_file(), "CBOM still attempted");
    let _ = std::fs::remove_file(&cbom);
    // Reverse: writable primary, unwritable CBOM.
    let primary = tmp_path("ok-primary.json");
    let req = OutputRequest {
        format: OutputFormat::Json,
        primary: OutputDest::File(primary.clone()),
        cbom: Some(OutputDest::File(tmp_path("no-such-dir-9d1a/cbom.json"))),
    };
    let delivery = write_artifacts(&d, &req);
    assert!(delivery.primary.ok);
    assert!(delivery.cbom.as_ref().is_some_and(|c| !c.ok));
    assert!(delivery.failed());
    assert!(!delivery.diagnostics.is_empty());
    assert!(primary.is_file(), "primary still attempted");
    let _ = std::fs::remove_file(&primary);
}

/// Unattributed provider identity ("unknown", synthesized until T09
/// pinned classification) proves neither a match nor an absence: both
/// rule directions go inconclusive, never a definite pass/violation.
#[test]
fn unknown_provider_class_is_not_absence() {
    let unattributed = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "prov-file",
            "unknown",
            DIGEST,
            7,
            &["SHA2-256"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    struct Row {
        name: &'static str,
        rule: PolicyRule,
        expected: RuleVerdict,
    }
    for row in [
        Row {
            name: "deny over unknown class is unproven (never a false pass)",
            rule: PolicyRule::deny_provider("default"),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "require over unknown class is unproven (never a false absence)",
            rule: PolicyRule::require_provider("default"),
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "unknown class could be engine use",
            rule: PolicyRule::deny_engine(),
            expected: RuleVerdict::Inconclusive,
        },
    ] {
        let v = evaluate_document(std::slice::from_ref(&row.rule), &unattributed);
        assert_eq!(v.rules[0].verdict, row.expected, "{}", row.name);
        assert_eq!(
            policy_json(&unattributed, &v)["violations"]
                .as_array()
                .unwrap()
                .len(),
            0,
            "{}",
            row.name
        );
    }
    // Mixed unknown/known between candidates stays possible too.
    let mixed = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![
            cand("prov-a", "unknown", DIGEST, 7, &["SHA2-256"], false),
            cand("prov-b", "default", DIGEST, 7, &["SHA2-256"], false),
        ],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::require_provider("default")),
        &mixed,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_provider("default")),
        &mixed,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
}

/// Pre-T08 transition: legacy ENGINE tripwire counts are real
/// in-window executions the document does not model yet. They upgrade
/// a silent deny-engine rule to a violation, never double-count
/// document hits, and never manufacture a pass.
#[test]
fn legacy_engine_tripwire_fallback() {
    use osslscope::policy::apply_legacy_engine_fallback;
    // Silent document + tripwire fire = definite violation (exit 10).
    let quiet = complete_doc(Vec::new());
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    apply_legacy_engine_fallback(&mut v, 4);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    assert_eq!(v.overall(), PolicyOutcome::Violation);
    assert_eq!(v.rules[0].legacy_engine_calls, 4);
    let x = &policy_json(&quiet, &v)["violations"][0];
    assert_eq!(x["rule"], "deny-engine");
    assert_eq!(x["legacy"], true);
    assert_eq!(x["timed"], false);
    assert_eq!(x["calls"], 4);
    assert!(x.get("site").is_none());
    assert_eq!(exit_for(v.overall(), Some(0), &quiet, &ok_delivery()), 10);
    // Zero tripwire calls: no-op on pass and inconclusive alike.
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
    apply_legacy_engine_fallback(&mut v, 0);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    let gappy = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![loss_counter("discovery.table_aborted")],
        exact_window(),
        None,
    );
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &gappy);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    apply_legacy_engine_fallback(&mut v, 0);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    // Document hits win: the tripwire does not double-display.
    let engine_use = complete_doc(vec![site_at(
        1,
        0,
        7,
        vec![cand(
            "libcrypto-object",
            "engine",
            0,
            3,
            &["ENGINE_init"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let mut v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_engine()),
        &engine_use,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    apply_legacy_engine_fallback(&mut v, 9);
    assert_eq!(v.rules[0].hits.len(), 1);
    assert_eq!(v.rules[0].legacy_engine_calls, 0);
    // Other rules are never touched.
    let mut v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_algorithm("SHA2-256")),
        &quiet,
    );
    apply_legacy_engine_fallback(&mut v, 9);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert_eq!(v.rules[0].legacy_engine_calls, 0);
    // No verdict stays no verdict.
    let fatal = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        Some(FatalKind::AttachZero),
    );
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &fatal);
    apply_legacy_engine_fallback(&mut v, 9);
    assert_eq!(v.overall(), PolicyOutcome::NoVerdict);
    assert!(v.rules.is_empty());
}

fn engine_obs(
    offset: u64,
    generation: u64,
    entrypoint: &str,
    calls: u64,
    window: EngineWindow,
) -> EngineObservation {
    EngineObservation {
        key: SiteKey {
            object: obj("libcrypto-fingerprint"),
            device: 8,
            inode: 11,
            offset,
        },
        generation,
        entrypoint: engine_index(entrypoint).expect("frozen ENGINE registry name"),
        calls,
        window,
    }
}

/// COMPLETE document carrying typed ENGINE observations (no sites).
fn engine_doc(obs: Vec<EngineObservation>) -> CaptureDocument {
    finalize(FinalizeInput {
        window: exact_window(),
        sites: Vec::new(),
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
        engine_observations: obs,
    })
}

fn engine_ref_resolves(doc: &CaptureDocument, r: &osslscope::evidence::EngineEvidenceRef) -> bool {
    doc.engine_observations.iter().any(|o| {
        o.key.object == r.object
            && o.key.device == r.device
            && o.key.inode == r.inode
            && o.key.offset == r.offset
            && o.generation == r.generation
            && o.entrypoint == r.entrypoint
            && o.calls >= r.calls
    })
}

// ---------------------------------------------------------------- R05 real-transition harness (F-R05-5)
//
// Acceptance observations come from REAL transitions: a real
// `SessionCore` joins scripted `TRIP` maps into per-generation
// counter deltas (real cookie join, real replacement fence, real
// pins), and the production `EngineCollector` joins them into
// observations. Nothing here hand-builds an `EngineObservation`.

struct ScriptEnv {
    maps: Vec<maps::Mapping>,
    plan: Option<legacy::ProbeSet>,
    pins: Vec<TripModulePin>,
    trip: Vec<(u64, u64)>,
}

impl ScriptEnv {
    fn new() -> Self {
        Self {
            maps: Vec::new(),
            plan: None,
            pins: Vec::new(),
            trip: Vec::new(),
        }
    }
}

impl SessionEnv for ScriptEnv {
    fn next_event(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn current_maps(&mut self) -> Option<Vec<maps::Mapping>> {
        Some(self.maps.clone())
    }
    fn join_maps(&mut self) -> MapSnapshots {
        MapSnapshots {
            trip: self.trip.clone(),
            ..MapSnapshots::default()
        }
    }
    fn install_stage2(
        &mut self,
        _cookie: u64,
        _offset: u64,
        _path: &std::path::Path,
        _pid: u32,
        _expected: Option<(u64, u64)>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn install_trips(
        &mut self,
        _set: &legacy::ProbeSet,
        _pid: u32,
        _maps: &[maps::Mapping],
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
    fn last_trip_pins(&self) -> Vec<TripModulePin> {
        self.pins.clone()
    }
    fn plan_trips(&mut self, _maps: &[maps::Mapping]) -> anyhow::Result<Option<legacy::ProbeSet>> {
        Ok(self.plan.clone())
    }
    fn pretouch(&mut self, _cookie: u64, _addr: u64) {}
    fn evict_array_state(&mut self, _arr: u64) -> anyhow::Result<()> {
        Ok(())
    }
    fn install_generation(&mut self, _arr: u64, _gen: u64) -> anyhow::Result<()> {
        Ok(())
    }
    fn verify_pin(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn quiesce(&mut self) {}
    fn link_counts(&self) -> (u64, u64) {
        (0, 0)
    }
    fn detach_trips(&mut self) {}
    fn detach_dispatch_anchors(&mut self) {}
    fn detach_stage2(&mut self, _cookie: u64) {}
    fn reinstall_dispatch(
        &mut self,
    ) -> anyhow::Result<osslscope::discovery::session::DispatchReinstall> {
        anyhow::bail!("no reinstall scripted")
    }
    fn provider_stat(&self) -> Option<(String, u64)> {
        None
    }
}

fn lc_map(ino: u64) -> maps::Mapping {
    maps::Mapping {
        start: 0x1000,
        end: 0x2000,
        x: true,
        offset: 0,
        dev: "08:01".to_string(),
        ino,
        path: "/lib/libcrypto.so.3".to_string(),
    }
}

fn engine_probe(cookie: u64, symbol: &str, offset: u64, module: &str) -> legacy::Probe {
    legacy::Probe {
        cookie,
        symbol: symbol.to_string(),
        offset,
        module: module.to_string(),
        family: None,
        str_arg: None,
        program: "trip_count",
    }
}

fn engine_plan(lc_ino: u64, probes: Vec<legacy::Probe>) -> legacy::ProbeSet {
    legacy::ProbeSet {
        probes,
        by_id_cookies: std::collections::HashSet::new(),
        load_cookies: std::collections::HashSet::new(),
        libcrypto: Some((
            "/lib/libcrypto.so.3".to_string(),
            "08:01".to_string(),
            lc_ino,
        )),
        ..legacy::ProbeSet::default()
    }
}

fn caller_pin(module: &str, program: &str, ino: u64) -> TripModulePin {
    TripModulePin {
        module: module.to_string(),
        program: program.to_string(),
        dev: "08:01".to_string(),
        ino,
    }
}

fn caller_object(id: &str, ino: u64, path: &str) -> ObjectRecord {
    ObjectRecord {
        id: ObjectId(id.to_string()),
        device: osslscope::plan::device_id_of_dev_str("08:01").unwrap(),
        inode: ino,
        display_locator: path.to_string(),
    }
}

/// One scripted poll: maps + plan + pins + cumulative TRIP map.
struct PollScript {
    maps: Vec<maps::Mapping>,
    plan: Option<legacy::ProbeSet>,
    pins: Vec<TripModulePin>,
    trip: Vec<(u64, u64)>,
}

/// Drive real `SessionCore::poll` transitions through the production
/// `EngineCollector`, then finalize a COMPLETE document carrying the
/// resulting observations (plus `objects` for the join). Returns the
/// document. Panics on unkeyed loss (every scripted hit must key).
fn real_engine_doc(scripts: Vec<PollScript>, objects: Vec<ObjectRecord>) -> CaptureDocument {
    let mut core = SessionCore::new(
        std::path::PathBuf::from("/p/provider.so"),
        "/canon/provider.so".to_string(),
        true,
        4242,
    );
    let mut env = ScriptEnv::new();
    let mut collector = EngineCollector::new();
    let budget = PollBudget::new(65536, 64);
    for s in scripts {
        env.maps = s.maps;
        env.plan = s.plan;
        env.pins = s.pins;
        env.trip = s.trip;
        let delta: DiscoveryDelta = core.poll(&mut env, budget.clone()).unwrap();
        collector.snapshot_binding(
            delta.trip_generation,
            core.snapshot().legacy.set,
            &delta.trip_module_pins,
        );
        collector.accumulate(
            delta.trip_generation,
            &delta.tripwire.counter_deltas,
            &delta.retired_trip_deltas,
        );
    }
    let (obs, unkeyed) = collector.build(&objects);
    assert_eq!(unkeyed, 0, "scripted hits must key: {unkeyed} unkeyed");
    let mut doc = finalize(FinalizeInput {
        window: exact_window(),
        sites: Vec::new(),
        fenced: Vec::new(),
        objects,
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: obs,
    });
    assert!(matches!(doc.status, Completeness::Complete));
    // Attach the evaluated policy record, as `check` does.
    let rules = vec![PolicyRule::deny_engine()];
    let v = evaluate_document(&rules, &doc);
    doc.policy = Some(policy_record(&v));
    doc
}

/// `--deny-engine` matches the engine provider class, not file stems.
#[test]
fn deny_engine_matches_class() {
    assert_eq!(ENGINE_PROVIDER_CLASS, "engine");
    let engine_use = complete_doc(vec![site_at(
        1,
        0,
        4,
        vec![cand(
            "libcrypto-object",
            "engine",
            0,
            3,
            &["ENGINE_init"],
            false,
        )],
        CandidateCoverage::Complete,
    )]);
    let v = evaluate_document(
        std::slice::from_ref(&PolicyRule::deny_engine()),
        &engine_use,
    );
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    assert_eq!(v.rules[0].bounds.definite, 4);
    let quiet = complete_doc(Vec::new());
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
}

// ---------------------------------------------------------------- R05 (F06)

/// R05: five in-window typed ENGINE observations drive the source
/// check verdict, and independent serialized-document replay agrees
/// with all evidence references resolving on both sides. The
/// observations come from REAL transitions (real `SessionCore`
/// cookie join + production `EngineCollector`), never from
/// hand-built fixtures.
#[test]
fn engine_policy_replays_from_document() {
    let syms = [
        "ENGINE_by_id",
        "ENGINE_init",
        "ENGINE_finish",
        "ENGINE_free",
        "ENGINE_ctrl",
    ];
    let probes: Vec<legacy::Probe> = syms
        .iter()
        .enumerate()
        .map(|(i, s)| engine_probe(10 + i as u64, s, 0x100 + i as u64 * 0x100, "/app/caller.so"))
        .collect();
    let plan = engine_plan(100, probes);
    let pins = vec![caller_pin("/app/caller.so", "trip_count", 200)];
    let objects = vec![caller_object("build:caller", 200, "/app/caller.so")];
    // Poll 1 installs gen 0; poll 2 joins one hit per cookie.
    let trip: Vec<(u64, u64)> = (10..15).map(|c| (c, 1)).collect();
    let doc = real_engine_doc(
        vec![
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan.clone()),
                pins: pins.clone(),
                trip: Vec::new(),
            },
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan),
                pins,
                trip,
            },
        ],
        objects,
    );
    assert_eq!(doc.engine_observations.len(), 5);
    for o in &doc.engine_observations {
        assert_eq!(o.calls, 1);
        assert_eq!(o.window, EngineWindow::InWindow);
        assert_eq!(o.generation, 0);
    }
    let rules = vec![PolicyRule::deny_engine()];
    let v = evaluate_document(&rules, &doc);
    assert_eq!(v.overall(), PolicyOutcome::Violation);
    assert_eq!(v.rules[0].bounds.definite, 5);
    assert_eq!(v.rules[0].bounds.possible, Some(5));
    assert_eq!(v.rules[0].engine_hits.len(), 5);
    assert_eq!(v.rules[0].legacy_engine_calls, 0);
    let rec = doc.policy.clone().expect("harness attaches the record");
    assert_eq!(rec.rules[0].engine_evidence.len(), 5);
    assert!(rec.rules[0].evidence.is_empty());
    for r in &rec.rules[0].engine_evidence {
        assert!(engine_ref_resolves(&doc, r), "ref resolves: {r:?}");
    }
    // Independent replay from the serialized document alone: no
    // side input, same verdict, same bounds, same record.
    let bytes = serde_json::to_string(&doc).expect("document serializes");
    let replayed: CaptureDocument = serde_json::from_str(&bytes).expect("document parses");
    assert_eq!(replayed.engine_observations, doc.engine_observations);
    let v2 = evaluate_document(&rules, &replayed);
    assert_eq!(v2.overall(), PolicyOutcome::Violation);
    assert_eq!(v2.rules[0].bounds, v.rules[0].bounds);
    assert_eq!(v2.rules[0].engine_hits, v.rules[0].engine_hits);
    assert_eq!(policy_record(&v2), rec);
    for r in &policy_record(&v2).rules[0].engine_evidence {
        assert!(engine_ref_resolves(&replayed, r), "replay ref resolves");
    }
    // Conserved provider unit: ENGINE calls never join site totals.
    assert_eq!(doc.total_calls(), 0);
    assert_eq!(replayed.total_calls(), 0);
    // Certainty/window limits survive the round trip.
    for o in &replayed.engine_observations {
        assert_eq!(o.window, EngineWindow::InWindow);
    }
}

#[test]
fn engine_pre_window_only_passes() {
    let doc = engine_doc(vec![engine_obs(
        0x100,
        0,
        "ENGINE_init",
        9,
        EngineWindow::PreWindow,
    )]);
    assert!(matches!(doc.status, Completeness::Complete));
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(v.rules[0].bounds.possible, Some(0));
    assert!(v.rules[0].engine_hits.is_empty());
}

#[test]
fn engine_untimed_is_inconclusive() {
    let doc = engine_doc(vec![engine_obs(
        0x100,
        0,
        "ENGINE_init",
        9,
        EngineWindow::Untimed,
    )]);
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    // Never a violation without in-window evidence, never a pass
    // over evidence the window cannot place: fail closed.
    assert_eq!(v.rules[0].verdict, RuleVerdict::Inconclusive);
    assert_eq!(v.rules[0].bounds.definite, 0);
    assert_eq!(v.rules[0].bounds.possible, None);
    assert!(v.rules[0].engine_hits.is_empty());
    // Untimed evidence still replays with its limits intact.
    let bytes = serde_json::to_string(&doc).unwrap();
    let replayed: CaptureDocument = serde_json::from_str(&bytes).unwrap();
    let v2 = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &replayed);
    assert_eq!(v2.rules[0].verdict, RuleVerdict::Inconclusive);
    assert_eq!(v2.rules[0].bounds, v.rules[0].bounds);
}

#[test]
fn engine_mixed_document_and_tripwire_no_double_count() {
    use osslscope::policy::apply_legacy_engine_fallback;
    // The typed document already proves the violation: the legacy
    // side input must not double-count (document hits win).
    let doc = engine_doc(vec![engine_obs(
        0x100,
        0,
        "ENGINE_init",
        5,
        EngineWindow::InWindow,
    )]);
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    apply_legacy_engine_fallback(&mut v, 5);
    assert_eq!(v.rules[0].bounds.definite, 5);
    assert_eq!(v.rules[0].legacy_engine_calls, 0);
    assert_eq!(policy_record(&v).rules[0].engine_evidence.len(), 1);
    // And the fallback still fires when the document is silent
    // (transitional parity until every caller uses typed input).
    let quiet = complete_doc(Vec::new());
    let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
    apply_legacy_engine_fallback(&mut v, 5);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    assert_eq!(v.rules[0].bounds.definite, 5);
    assert_eq!(v.rules[0].legacy_engine_calls, 5);
    assert!(policy_record(&v).rules[0].engine_evidence.is_empty());
}

#[test]
fn engine_setup_failure_has_no_verdict() {
    let doc = doc(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        exact_window(),
        Some(FatalKind::Environment("setup failed".to_string())),
    );
    // Evidence-free fatal documents never reach per-rule
    // evaluation, however the evaluator is invoked.
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.overall(), PolicyOutcome::NoVerdict);
    assert!(v.rules.is_empty());
}

#[test]
fn engine_zero_hits_passes() {
    let quiet = complete_doc(Vec::new());
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert_eq!(v.rules[0].bounds.possible, Some(0));
    // A zero-call observation is evidence of nothing.
    let silent = engine_doc(vec![engine_obs(
        0x100,
        0,
        "ENGINE_init",
        0,
        EngineWindow::InWindow,
    )]);
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &silent);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert!(v.rules[0].engine_hits.is_empty());
}

#[test]
fn engine_duplicate_cookie_joins_sum() {
    // Same entrypoint probed in two caller modules: a REAL cookie
    // join (two TRIP cookies → two counts → two observations, one
    // entrypoint) — both definite, summed once, never collapsed.
    let plan = engine_plan(
        100,
        vec![
            engine_probe(7, "ENGINE_init", 0x100, "/app/a.so"),
            engine_probe(8, "ENGINE_init", 0x100, "/app/b.so"),
        ],
    );
    let pins = vec![
        caller_pin("/app/a.so", "trip_count", 201),
        caller_pin("/app/b.so", "trip_count", 202),
    ];
    let objects = vec![
        caller_object("build:a", 201, "/app/a.so"),
        caller_object("build:b", 202, "/app/b.so"),
    ];
    let doc = real_engine_doc(
        vec![
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan.clone()),
                pins: pins.clone(),
                trip: Vec::new(),
            },
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan),
                pins,
                trip: vec![(7, 3), (8, 5)],
            },
        ],
        objects,
    );
    assert_eq!(doc.engine_observations.len(), 2);
    assert_ne!(
        doc.engine_observations[0].key,
        doc.engine_observations[1].key
    );
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    assert_eq!(v.rules[0].bounds.definite, 8);
    assert_eq!(v.rules[0].bounds.possible, Some(8));
    assert_eq!(v.rules[0].engine_hits.len(), 2);
    let bytes = serde_json::to_string(&doc).unwrap();
    let replayed: CaptureDocument = serde_json::from_str(&bytes).unwrap();
    let v2 = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &replayed);
    assert_eq!(v2.rules[0].bounds, v.rules[0].bounds);
}

#[test]
fn engine_retired_binding_replays_per_generation() {
    // REAL replacement transition: gen 0 binds and observes 2 hits,
    // libcrypto is replaced (same path, new inode, identical cookie
    // mapping), gen 1 binds and observes 4 fresh hits. Both
    // generations observed in-window under a live binding, so both
    // are definite; replay preserves the per-generation split and
    // the retired fence keeps gen-0 hits off gen-1 meanings.
    let g0 = engine_plan(
        100,
        vec![engine_probe(7, "ENGINE_init", 0x100, "/app/caller.so")],
    );
    let g1 = engine_plan(
        200,
        vec![engine_probe(7, "ENGINE_init", 0x140, "/app/caller.so")],
    );
    let pins = vec![caller_pin("/app/caller.so", "trip_count", 300)];
    let objects = vec![caller_object("build:caller", 300, "/app/caller.so")];
    let doc = real_engine_doc(
        vec![
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(g0),
                pins: pins.clone(),
                trip: Vec::new(),
            },
            PollScript {
                maps: vec![lc_map(100)],
                plan: None,
                pins: pins.clone(),
                trip: vec![(7, 2)],
            },
            PollScript {
                maps: vec![lc_map(200)],
                plan: Some(g1),
                pins: pins.clone(),
                trip: vec![(7, 2)],
            },
            PollScript {
                maps: vec![lc_map(200)],
                plan: None,
                pins,
                trip: vec![(7, 6)],
            },
        ],
        objects,
    );
    assert_eq!(doc.engine_observations.len(), 2);
    let mut by_gen: Vec<(u64, u64)> = doc
        .engine_observations
        .iter()
        .map(|o| (o.generation, o.calls))
        .collect();
    by_gen.sort();
    assert_eq!(by_gen, vec![(0, 2), (1, 4)]);
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Violation);
    assert_eq!(v.rules[0].bounds.definite, 6);
    let rec = doc.policy.clone().expect("harness attaches the record");
    assert_eq!(rec.rules[0].engine_evidence.len(), 2);
    let mut gens: Vec<u64> = rec.rules[0]
        .engine_evidence
        .iter()
        .map(|r| r.generation)
        .collect();
    gens.sort_unstable();
    assert_eq!(gens, vec![0, 1]);
    let bytes = serde_json::to_string(&doc).unwrap();
    let replayed: CaptureDocument = serde_json::from_str(&bytes).unwrap();
    assert_eq!(replayed.engine_observations, doc.engine_observations);
    let v2 = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &replayed);
    assert_eq!(v2.rules[0].bounds, v.rules[0].bounds);
    assert_eq!(policy_record(&v2), rec);
}

#[test]
fn engine_runtime_salvage_evaluates() {
    // Salvaged Runtime docs carry REAL observations (joined through
    // the production collector from real `SessionCore` polls): a
    // proved ENGINE violation still evaluates (exit 10 via check).
    // The salvage ASSEMBLY itself (close failure → fatal-Runtime
    // capture preserving collected observations) runs really in
    // `capture::tests::stub_runner::engine_runtime_salvage_keeps_real_observations`;
    // this control pins the salvaged SHAPE's policy evaluation.
    let plan = engine_plan(
        100,
        vec![engine_probe(7, "ENGINE_init", 0x100, "/app/caller.so")],
    );
    let pins = vec![caller_pin("/app/caller.so", "trip_count", 200)];
    let mut core = SessionCore::new(
        std::path::PathBuf::from("/p/provider.so"),
        "/canon/provider.so".to_string(),
        true,
        4242,
    );
    let mut env = ScriptEnv::new();
    let mut collector = EngineCollector::new();
    let budget = PollBudget::new(65536, 64);
    for (i, trip) in [Vec::new(), vec![(7, 7)]].into_iter().enumerate() {
        env.maps = vec![lc_map(100)];
        env.plan = Some(plan.clone());
        env.pins = pins.clone();
        env.trip = trip;
        let delta = core.poll(&mut env, budget.clone()).unwrap();
        collector.snapshot_binding(
            delta.trip_generation,
            core.snapshot().legacy.set,
            &delta.trip_module_pins,
        );
        collector.accumulate(
            delta.trip_generation,
            &delta.tripwire.counter_deltas,
            &delta.retired_trip_deltas,
        );
        let _ = i;
    }
    let objects = vec![caller_object("build:caller", 200, "/app/caller.so")];
    let (obs, unkeyed) = collector.build(&objects);
    assert_eq!(unkeyed, 0);
    assert_eq!(obs.len(), 1);
    let doc = finalize(FinalizeInput {
        window: exact_window(),
        sites: Vec::new(),
        fenced: Vec::new(),
        objects,
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: Some(FatalKind::Runtime("drain failed".to_string())),
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: obs,
    });
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.overall(), PolicyOutcome::Violation);
    assert_eq!(v.rules[0].bounds.definite, 7);
    assert_eq!(v.rules[0].bounds.possible, None);
    assert_eq!(v.rules[0].engine_hits.len(), 1);
    assert_eq!(exit_for(v.overall(), Some(0), &doc, &ok_delivery()), 10);
}

#[test]
fn engine_fallback_replay_agreement_on_typed_provenance() {
    // Fix-round-2 F4: GENUINE missing-provenance RED→GREEN
    // control (replaces the retired both-paths-passing
    // characterization). Five real ENGINE executions flow
    // through real `SessionCore` polls + the production
    // collector into typed document observations. Source
    // (document evidence; the side-input fallback stands down —
    // document hits win) and independent serialized-document
    // replay AGREE: violation, definite 5. Pre-fix this
    // agreement assertion FAILS: old finalization produced a
    // quiet document, so the fallback (positive evidence the
    // document lacks) reported violation while replay passed
    // (recorded RED: `left: Violation, right: Pass` — see the
    // task report). Stripping the typed observations flips this
    // control red again (coupling proof in the report).
    use osslscope::policy::apply_legacy_engine_fallback;
    let plan = engine_plan(
        100,
        vec![engine_probe(7, "ENGINE_init", 0x100, "/app/caller.so")],
    );
    let pins = vec![caller_pin("/app/caller.so", "trip_count", 200)];
    let objects = vec![caller_object("build:caller", 200, "/app/caller.so")];
    let doc = real_engine_doc(
        vec![
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan.clone()),
                pins: pins.clone(),
                trip: Vec::new(),
            },
            PollScript {
                maps: vec![lc_map(100)],
                plan: Some(plan),
                pins,
                trip: vec![(7, 5)],
            },
        ],
        objects,
    );
    assert_eq!(doc.engine_observations.len(), 1);
    assert_eq!(doc.engine_observations[0].calls, 5);
    let rules = vec![PolicyRule::deny_engine()];
    // Source verdict: document evidence plus the side input —
    // the fallback must stand down (the document already proves
    // the executions).
    let mut v_src = evaluate_document(&rules, &doc);
    apply_legacy_engine_fallback(&mut v_src, 5);
    assert_eq!(
        v_src.rules[0].legacy_engine_calls, 0,
        "fallback must stand down on typed evidence"
    );
    assert_eq!(v_src.overall(), PolicyOutcome::Violation);
    // Independent replay from the serialized document alone (no
    // side input) — and the agreement that closes F06.
    let bytes = serde_json::to_string(&doc).unwrap();
    let replayed: CaptureDocument = serde_json::from_str(&bytes).unwrap();
    let v_re = evaluate_document(&rules, &replayed);
    assert_eq!(v_src.overall(), v_re.overall());
    assert_eq!(v_src.rules[0].bounds, v_re.rules[0].bounds);
    assert_eq!(v_src.rules[0].bounds.definite, 5);
    assert_eq!(policy_record(&v_re), policy_record(&v_src));
}

#[test]
fn engine_unrelated_provider_calls_pass_and_conserve() {
    // Provider-dispatch executions are not ENGINE evidence, and
    // ENGINE observations never join provider totals.
    let doc = finalize(FinalizeInput {
        window: exact_window(),
        sites: vec![site_at(
            1,
            0,
            12,
            vec![cand("p", "default", DIGEST, 7, &["SHA2-256"], false)],
            CandidateCoverage::Complete,
        )],
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition {
            legacy_exclusive: 0,
            non_legacy_exclusive: 12,
            shared_ambiguous: 0,
            unfenced_tails: 0,
        },
        engine_observations: vec![engine_obs(
            0x100,
            0,
            "ENGINE_init",
            5,
            EngineWindow::PreWindow,
        )],
    });
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &doc);
    assert_eq!(v.rules[0].verdict, RuleVerdict::Pass);
    assert_eq!(doc.total_calls(), 12);
}
