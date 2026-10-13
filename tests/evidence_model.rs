//! SPDX-License-Identifier: GPL-3.0-or-later
//! T01 conserved-evidence model tests (spec R01/R02/R06).
//!
//! Pins: physical site counts conserved across shared candidates, no
//! lower-bound proof from ambiguous attribution, weak-alias survival,
//! fence preservation, quiet-but-attached coverage, unknown coverage
//! blocking COMPLETE, total input-order independence, and the full R06
//! require/deny truth table at 0/7 calls.

use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureWindow, Completeness, CounterKind, CounterSource,
    CounterUnits, ExpectedScope, FatalKind, FencedGeneration, FinalizeInput, GapCounter, GapReason,
    LegacyCallPartition, MatchBounds, ObjectId, OpensslVersion, PredicateMatch, RuleVerdict,
    ScopeCoverage, SiteExecution, SiteKey, TargetRecord, finalize, match_bounds,
};
use osslscope::policy::{Predicate, Rule, evaluate_rule};

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
            device: 1,
            inode: 2,
            offset,
        },
        generation,
        candidates: cands,
        candidates_coverage: cov,
        calls,
        first_ns: 10,
        last_ns: 20,
        installed_at: None,
    }
}

fn site(calls: u64, cands: Vec<CandidateIdentity>, cov: CandidateCoverage) -> SiteExecution {
    site_at(0x1000, 0, calls, cands, cov)
}

fn clean_window() -> CaptureWindow {
    CaptureWindow {
        requested_start_ns: 0,
        requested_end_ns: 100,
        effective_start_ns: 0,
        effective_end_ns: 100,
        signal_cut: false,
    }
}

fn clean_input(sites: Vec<SiteExecution>) -> FinalizeInput {
    FinalizeInput {
        window: clean_window(),
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
        engine_observations: Vec::new(),
    }
}

fn alg_pred(name: &str) -> Predicate {
    Predicate::Algorithm(name.to_string())
}

fn bounds_for(sites: &[SiteExecution], pred: &Predicate) -> MatchBounds {
    match_bounds(sites, &|c| pred.eval(c))
}

/// Two algorithms sharing one site with 7 calls produce 7 site calls,
/// not 14 algorithm calls (R01).
#[test]
fn shared_site_conserves_calls() {
    let s = site(
        7,
        vec![
            cand("prov-default", "default", 1, 7, &["AES-128-GCM"], false),
            cand("prov-default", "default", 1, 7, &["AES-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    );
    let sites = [s];
    assert_eq!(SiteExecution::sum_calls(&sites), 7);
    // Candidate-only algorithm: no lower-bound proof, upper bound is 7.
    let b = bounds_for(&sites, &alg_pred("AES-256-GCM"));
    assert_eq!(b.definite, 0);
    assert_eq!(b.possible, Some(7));
    // Predicate true of every candidate proves all 7.
    let op = bounds_for(&sites, &Predicate::Op(1));
    assert_eq!(op.definite, 7);
    assert_eq!(op.possible, Some(7));
    // Nothing anywhere sums to 14.
    assert!(b.possible.unwrap() + op.possible.unwrap() <= 14);
    assert_eq!(SiteExecution::sum_calls(&sites), 7);
}

/// A require rule over an ambiguous candidate-only algorithm is unproven:
/// neither pass nor violation (R06 row 3).
#[test]
fn ambiguous_require_is_unproven() {
    let s = site(
        7,
        vec![
            cand("prov-default", "default", 1, 7, &["AES-128-GCM"], false),
            cand("prov-default", "default", 1, 7, &["AES-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    );
    let sites = [s];
    let b = bounds_for(&sites, &alg_pred("AES-256-GCM"));
    let verdict = evaluate_rule(&Rule::Require(alg_pred("AES-256-GCM")), &b, true);
    assert!(matches!(verdict, RuleVerdict::Inconclusive));
}

/// Weak-alias metadata survives finalization and still shapes bounds (R01).
#[test]
fn weak_alias_survives() {
    let s = site(
        7,
        vec![
            cand("prov-default", "default", 1, 7, &["AES-128-GCM"], true),
            cand("prov-default", "default", 1, 7, &["AES-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    );
    let doc = finalize(clean_input(vec![s]));
    let weak: Vec<_> = doc.sites[0]
        .candidates
        .iter()
        .filter(|c| c.weak_alias)
        .collect();
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].algorithm_classes, vec!["AES-128-GCM".to_string()]);
    let b = bounds_for(&doc.sites, &Predicate::WeakAlias);
    assert_eq!(b.definite, 0);
    assert_eq!(b.possible, Some(7));
}

/// Moving sites across a fence preserves candidate meaning and counts.
#[test]
fn fence_preserves_candidates() {
    let s = site(
        7,
        vec![
            cand("prov-default", "default", 1, 7, &["AES-128-GCM"], true),
            cand("prov-default", "default", 1, 7, &["AES-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    );
    let current = finalize(clean_input(vec![s.clone()]));
    let mut fenced_input = clean_input(Vec::new());
    fenced_input.fenced = vec![FencedGeneration {
        generation: 0,
        sites: vec![s],
    }];
    let fenced = finalize(fenced_input);
    assert_eq!(current.total_calls(), 7);
    assert_eq!(fenced.total_calls(), 7);
    assert_eq!(
        current.sites[0].candidates,
        fenced.fenced[0].sites[0].candidates
    );
    for pred in [alg_pred("AES-256-GCM"), Predicate::WeakAlias] {
        assert_eq!(
            bounds_for(&current.sites, &pred).definite,
            bounds_for(&fenced.fenced[0].sites, &pred).definite
        );
        assert_eq!(
            bounds_for(&current.sites, &pred).possible,
            bounds_for(&fenced.fenced[0].sites, &pred).possible
        );
    }
}

/// A quiet but fully instrumented scope is covered, not a gap (R04).
#[test]
fn quiet_attached_op_is_covered() {
    let scope = ScopeCoverage {
        scope: "default/digest".to_string(),
        expected: ExpectedScope::Applicable { sites: 1 },
        discovered: 1,
        attached: 1,
    };
    assert!(scope.is_complete());
    assert!(scope.gaps().is_empty());
    let mut input = clean_input(vec![site(
        0,
        vec![cand("prov-default", "default", 1, 7, &["SHA2-256"], false)],
        CandidateCoverage::Complete,
    )]);
    input.coverage = vec![scope];
    let doc = finalize(input);
    assert!(matches!(doc.status, Completeness::Complete));
}

/// Unknown denominator blocks COMPLETE even with exact counts (R04/R06).
#[test]
fn unknown_coverage_is_not_complete() {
    let scope = ScopeCoverage {
        scope: "default/digest".to_string(),
        expected: ExpectedScope::Unknown,
        discovered: 1,
        attached: 1,
    };
    assert!(!scope.is_complete());
    let mut input = clean_input(vec![site(
        7,
        vec![cand("prov-default", "default", 1, 7, &["SHA2-256"], false)],
        CandidateCoverage::Complete,
    )]);
    input.coverage = vec![scope];
    let doc = finalize(input);
    assert!(matches!(doc.status, Completeness::Partial { .. }));
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::UnknownDenominator { .. }))
    );
}

/// Reversed arrival/insertion order preserves bytes and bounds (R01/R08).
#[test]
fn ordering_is_total() {
    let mk = || {
        vec![
            site_at(
                0x3000,
                1,
                3,
                vec![
                    cand("prov-b", "third-party:x", 2, 9, &["SHA2-256"], false),
                    cand("prov-a", "default", 1, 7, &["AES-256-GCM"], true),
                ],
                CandidateCoverage::Complete,
            ),
            site_at(
                0x1000,
                0,
                7,
                vec![cand("prov-a", "default", 1, 7, &["AES-128-GCM"], false)],
                CandidateCoverage::Complete,
            ),
            site_at(
                0x2000,
                0,
                0,
                vec![cand("prov-a", "default", 1, 8, &["other"], false)],
                CandidateCoverage::Complete,
            ),
        ]
    };
    let mut reversed = mk();
    reversed.reverse();
    for s in &mut reversed {
        s.candidates.reverse();
    }
    let doc_a = finalize(clean_input(mk()));
    let doc_b = finalize(clean_input(reversed));
    let bytes_a = serde_json::to_vec(&doc_a).unwrap();
    let bytes_b = serde_json::to_vec(&doc_b).unwrap();
    assert_eq!(bytes_a, bytes_b);
    for pred in [alg_pred("AES-256-GCM"), Predicate::Op(1)] {
        let a = bounds_for(&doc_a.sites, &pred);
        let b = bounds_for(&doc_b.sites, &pred);
        assert_eq!((a.definite, a.possible), (b.definite, b.possible));
    }
}

/// Full R06 require/deny truth table at 0/7 calls.
#[test]
fn r06_truth_table() {
    let pred = alg_pred("AES-256-GCM");
    // Definite use: 7 calls, every candidate matches.
    let exact = [site(
        7,
        vec![cand(
            "prov-default",
            "default",
            1,
            7,
            &["AES-256-GCM"],
            false,
        )],
        CandidateCoverage::Complete,
    )];
    // Clean absence: 0 calls, complete attribution, nothing matches.
    let zero = [site(
        0,
        vec![cand(
            "prov-default",
            "default",
            1,
            7,
            &["AES-128-GCM"],
            false,
        )],
        CandidateCoverage::Complete,
    )];
    // Ambiguous use: 7 calls shared by a matching and a nonmatching candidate.
    let ambiguous = [site(
        7,
        vec![
            cand("prov-default", "default", 1, 7, &["AES-128-GCM"], false),
            cand("prov-default", "default", 1, 7, &["AES-256-GCM"], false),
        ],
        CandidateCoverage::Complete,
    )];
    // Unbounded use: 7 calls with an incomplete candidate set.
    let unknown = [site(
        7,
        vec![cand(
            "prov-default",
            "default",
            1,
            7,
            &["AES-128-GCM"],
            false,
        )],
        CandidateCoverage::Unknown,
    )];
    let b_exact = bounds_for(&exact, &pred);
    let b_zero = bounds_for(&zero, &pred);
    let b_ambiguous = bounds_for(&ambiguous, &pred);
    let b_unknown = bounds_for(&unknown, &pred);
    assert_eq!((b_exact.definite, b_exact.possible), (7, Some(7)));
    assert_eq!((b_zero.definite, b_zero.possible), (0, Some(0)));
    assert_eq!((b_ambiguous.definite, b_ambiguous.possible), (0, Some(7)));
    assert_eq!((b_unknown.definite, b_unknown.possible), (0, None));

    struct Row {
        name: &'static str,
        rule: Rule,
        bounds: MatchBounds,
        relevant_complete: bool,
        expected: RuleVerdict,
    }
    let rows = [
        Row {
            name: "require definite use passes",
            rule: Rule::Require(alg_pred("AES-256-GCM")),
            bounds: b_exact,
            relevant_complete: true,
            expected: RuleVerdict::Pass,
        },
        Row {
            name: "require clean absence violates",
            rule: Rule::Require(alg_pred("AES-256-GCM")),
            bounds: b_zero,
            relevant_complete: true,
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "require possible use is inconclusive",
            rule: Rule::Require(alg_pred("AES-256-GCM")),
            bounds: b_ambiguous,
            relevant_complete: true,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "require unknown use is inconclusive",
            rule: Rule::Require(alg_pred("AES-256-GCM")),
            bounds: b_unknown,
            relevant_complete: true,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "require incomplete coverage is inconclusive",
            rule: Rule::Require(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(0),
            },
            relevant_complete: false,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "deny definite use violates",
            rule: Rule::Deny(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 7,
                possible: Some(7),
            },
            relevant_complete: true,
            expected: RuleVerdict::Violation,
        },
        Row {
            name: "deny possible use is inconclusive",
            rule: Rule::Deny(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(7),
            },
            relevant_complete: true,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "deny unknown use is inconclusive",
            rule: Rule::Deny(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 0,
                possible: None,
            },
            relevant_complete: true,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "deny incomplete coverage is inconclusive",
            rule: Rule::Deny(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(0),
            },
            relevant_complete: false,
            expected: RuleVerdict::Inconclusive,
        },
        Row {
            name: "deny clean absence passes",
            rule: Rule::Deny(alg_pred("AES-256-GCM")),
            bounds: MatchBounds {
                definite: 0,
                possible: Some(0),
            },
            relevant_complete: true,
            expected: RuleVerdict::Pass,
        },
    ];
    for row in rows {
        let got = evaluate_rule(&row.rule, &row.bounds, row.relevant_complete);
        assert_eq!(got, row.expected, "row: {}", row.name);
    }
}

/// Ambiguity inside one alias list: mixed matching/nonmatching classes
/// yield Unknown, never a first-alias boolean (R01/R06).
#[test]
fn within_alias_mixed_classes_are_unknown() {
    let c = cand(
        "prov-default",
        "default",
        1,
        7,
        &["AES-128-GCM", "AES-256-GCM"],
        false,
    );
    assert!(matches!(
        alg_pred("AES-256-GCM").eval(&c),
        PredicateMatch::Unknown
    ));
    assert!(matches!(
        alg_pred("AES-128-GCM").eval(&c),
        PredicateMatch::Unknown
    ));
    let sites = [site(7, vec![c], CandidateCoverage::Complete)];
    let b = bounds_for(&sites, &alg_pred("AES-256-GCM"));
    assert_eq!((b.definite, b.possible), (0, Some(7)));
}

/// An unresolved algorithm class proves neither match nor absence.
#[test]
fn unresolved_class_is_unknown() {
    let c = cand("prov-default", "default", 1, 7, &["other"], false);
    assert!(matches!(
        alg_pred("AES-256-GCM").eval(&c),
        PredicateMatch::Unknown
    ));
    let sites = [site(7, vec![c], CandidateCoverage::Complete)];
    let b = bounds_for(&sites, &alg_pred("AES-256-GCM"));
    assert_eq!((b.definite, b.possible), (0, Some(7)));
}

/// Provider/op predicates stay certain when only the algorithm is unknown.
#[test]
fn provider_predicate_certain_despite_unknown_algorithm() {
    let c = cand("prov-default", "default", 1, 7, &["other"], false);
    assert!(matches!(
        Predicate::ProviderClass("default".to_string()).eval(&c),
        PredicateMatch::Yes
    ));
    assert!(matches!(Predicate::Op(1).eval(&c), PredicateMatch::Yes));
    let sites = [site(7, vec![c], CandidateCoverage::Complete)];
    let b = bounds_for(&sites, &Predicate::ProviderClass("default".to_string()));
    assert_eq!((b.definite, b.possible), (7, Some(7)));
}

/// Loss forces PARTIAL; positive activity counters do not (R06).
#[test]
fn loss_vs_activity_counters() {
    let loss = GapCounter {
        name: "ring_reserve_fail".to_string(),
        kind: CounterKind::Loss,
        units: CounterUnits::Events,
        source: CounterSource::KernelRing,
        value: 1,
    };
    assert!(loss.forces_partial());
    let activity = GapCounter {
        name: "quiet_sites_observed".to_string(),
        kind: CounterKind::Activity,
        units: CounterUnits::Sites,
        source: CounterSource::Discovery,
        value: 999,
    };
    assert!(!activity.forces_partial());

    let mut with_loss = clean_input(Vec::new());
    with_loss.counters = vec![loss, activity.clone()];
    let doc = finalize(with_loss);
    assert!(matches!(doc.status, Completeness::Partial { .. }));
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::Loss { .. }))
    );

    let mut activity_only = clean_input(Vec::new());
    activity_only.counters = vec![activity];
    let doc = finalize(activity_only);
    assert!(matches!(doc.status, Completeness::Complete));
}

/// Requested/effective window mismatches are typed gaps (R05/R06).
#[test]
fn window_gaps_are_partial() {
    let mut late_start = clean_input(Vec::new());
    late_start.window.effective_start_ns = 5;
    let doc = finalize(late_start);
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::StartupGap { missing_ns: 5 }))
    );

    let mut early_end = clean_input(Vec::new());
    early_end.window.effective_end_ns = 90;
    let doc = finalize(early_end);
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::TailGap { missing_ns: 10 }))
    );

    let mut cut = clean_input(Vec::new());
    cut.window.signal_cut = true;
    let doc = finalize(cut);
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::SignalCut))
    );
}

/// Zero calls with an incomplete candidate set: the upper bound is known
/// zero (no activity to attribute), and the window stays complete.
#[test]
fn zero_call_unknown_candidates_bound_known_zero() {
    let sites = [site(
        0,
        vec![cand(
            "prov-default",
            "default",
            1,
            7,
            &["AES-128-GCM"],
            false,
        )],
        CandidateCoverage::Unknown,
    )];
    let b = bounds_for(&sites, &alg_pred("AES-256-GCM"));
    assert_eq!((b.definite, b.possible), (0, Some(0)));
    let doc = finalize(clean_input(sites.to_vec()));
    assert!(matches!(doc.status, Completeness::Complete));
}

/// Executed calls with an incomplete candidate set force PARTIAL.
#[test]
fn unattributed_calls_force_partial() {
    let doc = finalize(clean_input(vec![site(
        7,
        vec![cand(
            "prov-default",
            "default",
            1,
            7,
            &["AES-128-GCM"],
            false,
        )],
        CandidateCoverage::Unknown,
    )]));
    assert!(
        doc.reasons()
            .iter()
            .any(|r| matches!(r, GapReason::UnattributedCalls { sites: 1, calls: 7 }))
    );
}

/// Identical candidates dedupe; classes sort (R01).
#[test]
fn candidates_dedupe_and_sort() {
    let c = cand(
        "prov-default",
        "default",
        1,
        7,
        &["SHA2-256", "AES-256-GCM"],
        false,
    );
    assert_eq!(c.algorithm_classes, vec!["AES-256-GCM", "SHA2-256"]);
    let doc = finalize(clean_input(vec![site(
        7,
        vec![c.clone(), c],
        CandidateCoverage::Complete,
    )]));
    assert_eq!(doc.sites[0].candidates.len(), 1);
}

/// Records sharing a primary key still serialize deterministically:
/// full-record tie-breaks make every document order total (R08).
#[test]
fn ordering_tiebreaks_are_total() {
    let counters = vec![
        GapCounter {
            name: "dropped".to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Events,
            source: CounterSource::KernelRing,
            value: 1,
        },
        GapCounter {
            name: "dropped".to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Calls,
            source: CounterSource::KernelMap,
            value: 2,
        },
    ];
    let coverage = vec![
        ScopeCoverage {
            scope: "default/digest".to_string(),
            expected: ExpectedScope::Applicable { sites: 1 },
            discovered: 1,
            attached: 1,
        },
        ScopeCoverage {
            scope: "default/digest".to_string(),
            expected: ExpectedScope::Applicable { sites: 2 },
            discovered: 1,
            attached: 1,
        },
    ];
    let mut forward = clean_input(Vec::new());
    forward.counters = counters;
    forward.coverage = coverage;
    let mut backward = clean_input(Vec::new());
    backward.counters = forward.counters.clone();
    backward.counters.reverse();
    backward.coverage = forward.coverage.clone();
    backward.coverage.reverse();
    let a = serde_json::to_vec(&finalize(forward)).unwrap();
    let b = serde_json::to_vec(&finalize(backward)).unwrap();
    assert_eq!(a, b);
}

/// Fatal input finalizes as fatal, retaining collected reasons.
#[test]
fn fatal_input_is_fatal() {
    let mut input = clean_input(Vec::new());
    input.fatal = Some(FatalKind::AttachZero);
    let doc = finalize(input);
    assert!(matches!(doc.status, Completeness::Fatal { .. }));
}
