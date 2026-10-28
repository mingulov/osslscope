// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::{
    evidence::*,
    focused_capture::{FocusedConfig, batch_requires_retirement, project},
    focused_count::CountSample,
    policy::{self, PolicyRule},
    provider_observation::{
        ApiOutcome, Cacheability, ObservationBatch, ObservationFact, ObservationGap,
        ObservationPayload,
    },
    report, schema,
};
use std::time::Duration;

fn window() -> CaptureWindow {
    CaptureWindow {
        requested_start_ns: 10,
        requested_end_ns: 100,
        effective_start_ns: 10,
        effective_end_ns: 100,
        signal_cut: false,
        count_admission: Some(CountAdmissionWindow {
            start_ns: 10,
            deadline_ns: 100,
        }),
    }
}
fn site(calls: u64, labels: &[&str]) -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: ObjectId("a".repeat(64)),
            device: 1,
            inode: 2,
            offset: 3,
        },
        generation: 1,
        candidates: labels
            .iter()
            .map(|label| {
                CandidateIdentity::new(
                    ObjectId("b".repeat(64)),
                    "unknown".into(),
                    1,
                    1,
                    vec![(*label).into()],
                    false,
                )
            })
            .collect(),
        candidates_coverage: CandidateCoverage::Unknown,
        calls,
        first_ns: if calls == 0 { 0 } else { 30 },
        last_ns: if calls == 0 { 0 } else { 40 },
        installed_at: Some(20),
    }
}
fn check_open(doc: &CaptureDocument) {
    assert!(matches!(doc.status, Completeness::Partial { .. }));
    assert!(
        doc.coverage
            .iter()
            .all(|s| s.expected == ExpectedScope::Unknown)
    );
    let value = serde_json::from_slice(&report::render_json(doc).unwrap()).unwrap();
    schema::validate_v2(&value).unwrap();
    schema::check_v2_semantics(&value).unwrap();
    let result = policy::evaluate_document(
        &[
            PolicyRule::require_executed("sha256"),
            PolicyRule::deny_algorithm("sha256"),
            PolicyRule::require_provider("legacy"),
            PolicyRule::deny_provider("legacy"),
        ],
        doc,
    );
    for rule in &result.rules {
        assert_eq!(rule.bounds.definite, 0);
        assert_eq!(rule.bounds.possible, None);
        assert_eq!(rule.verdict, RuleVerdict::Inconclusive);
    }
    let cbom: serde_json::Value =
        serde_json::from_slice(&report::render_cbom(doc).unwrap()).unwrap();
    assert!(cbom["components"].as_array().unwrap().is_empty());
    assert_eq!(doc.legacy_partition.total(), doc.total_calls());
    assert_eq!(doc.target.comm, "unknown");
    assert!(doc.objects.iter().all(|o| o.display_locator == "unknown"));
}
#[test]
fn advertisements_without_calls_never_become_execution_assets() {
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(0, &["sha256"])],
            ..Default::default()
        },
        &[],
    );
    check_open(&doc);
    assert_eq!(doc.total_calls(), 0);
    assert!(
        doc.counters
            .iter()
            .any(|g| g.name == "focused.finality_unknown")
    );
}
#[test]
fn known_algorithm_with_unknown_candidates_has_no_definite_calls() {
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(7, &["sha256"])],
            ..Default::default()
        },
        &[],
    );
    check_open(&doc);
    assert_eq!(doc.legacy_partition.shared_ambiguous, 7);
    assert_eq!(doc.legacy_partition.non_legacy_exclusive, 0);
}
#[test]
fn shared_candidates_conserve_one_physical_count() {
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(11, &["sha256", "sha384"])],
            ..Default::default()
        },
        &[],
    );
    check_open(&doc);
    assert_eq!(doc.total_calls(), 11);
    assert_eq!(doc.sites.len(), 1);
    assert_eq!(doc.sites[0].candidates.len(), 2);
}
#[test]
fn empty_and_zero_hit_documents_remain_useful_partial() {
    for sites in [vec![], vec![site(0, &[])]] {
        let doc = project(
            42,
            window(),
            CountSample {
                sites,
                ..Default::default()
            },
            &[ObservationGap::BpfUnavailable],
        );
        check_open(&doc);
        assert!(doc.has_usable_evidence());
    }
}
fn invalidation() -> ObservationFact {
    serde_json::from_value(serde_json::json!({
        "pid":42,"starttime":99,"object_sha256":"a".repeat(64),"generation":1,
        "context":{"state":"unknown"},"source":"provider_query","api":"provider_query_callback",
        "operation":"digest","class":"digest","monotonic_ns":30,"confidence":"unknown",
        "payload":{"kind":"invalidation","cause":"unquery"}
    }))
    .unwrap()
}
#[test]
fn unquery_preserves_backed_physical_count_lifetime() {
    let batch = ObservationBatch {
        facts: vec![invalidation()],
        ..Default::default()
    };
    assert!(!batch_requires_retirement(&batch, 42));
    assert!(!batch_requires_retirement(&batch, 43));
}
#[test]
fn unscoped_loss_and_identity_churn_require_later_advertisements() {
    for gap in [
        ObservationGap::NamespaceChanged,
        ObservationGap::ProcessChanged,
        ObservationGap::MembershipUnknown,
        ObservationGap::ObjectChanged,
        ObservationGap::BpfUnavailable,
    ] {
        let batch = ObservationBatch {
            gaps: vec![gap],
            ..Default::default()
        };
        assert!(batch_requires_retirement(&batch, 42), "{gap:?}");
        let doc = project(42, window(), CountSample::default(), &[gap]);
        check_open(&doc);
        assert!(doc.engine_observations.is_empty());
    }
}
#[test]
fn ordinary_coverage_and_finite_alias_gaps_do_not_retire_sites() {
    for gap in [
        ObservationGap::QueueLoss,
        ObservationGap::InvalidWire,
        ObservationGap::TargetReadFailed,
        ObservationGap::FactLimit,
        ObservationGap::StateLimit,
        ObservationGap::FirstQueryUnknown,
        ObservationGap::IntervalUnknown,
        ObservationGap::SamplingPartial,
        ObservationGap::AmbiguousSite,
        ObservationGap::DispatchPartial,
    ] {
        assert!(!batch_requires_retirement(
            &ObservationBatch {
                gaps: vec![gap],
                ..Default::default()
            },
            42
        ));
    }
}
#[test]
fn partition_serialization_conserves_current_and_fenced_physical_rows_only() {
    let mut old = site(5, &["sha256"]);
    old.generation = 2;
    old.site.offset = 4;
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![
                site(7, &["sha256"]),
                SiteExecution {
                    site: SiteKey {
                        offset: 5,
                        ..site(0, &[]).site
                    },
                    ..site(3, &[])
                },
            ],
            fenced: vec![old],
            unattributed: 200,
            admitted: 999,
            ..Default::default()
        },
        &[],
    );
    check_open(&doc);
    let json: serde_json::Value =
        serde_json::from_slice(&report::render_json(&doc).unwrap()).unwrap();
    assert_eq!(
        json["legacy_partition"],
        serde_json::json!({
            "legacy_exclusive_calls":0,"non_legacy_exclusive_calls":0,
            "shared_ambiguous_calls":12,"unfenced_tail_calls":3
        })
    );
    assert_eq!(doc.total_calls(), 15);
}
#[test]
fn config_defaults_and_positive_bounded_validation() {
    let config = FocusedConfig::default();
    assert_eq!(
        (config.duration, config.timeout, config.grace),
        (
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(5)
        )
    );
    assert!(config.validate().is_ok());
    for config in [
        FocusedConfig {
            duration: Duration::ZERO,
            ..config
        },
        FocusedConfig {
            timeout: Duration::ZERO,
            ..config
        },
        FocusedConfig {
            grace: Duration::ZERO,
            ..config
        },
        FocusedConfig {
            timeout: Duration::from_secs(121),
            ..config
        },
    ] {
        assert!(config.validate().is_err());
    }
}

#[test]
fn only_zero_call_zero_timestamp_sentinel_bypasses_activity_bounds() {
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(0, &[])],
            ..Default::default()
        },
        &[],
    );
    let value: serde_json::Value =
        serde_json::from_slice(&report::render_json(&doc).unwrap()).unwrap();
    schema::check_v2_semantics(&value).unwrap();
    for (calls, first, last) in [(1, 0, 0), (0, 0, 40), (0, 5, 5), (1, 30, 100)] {
        let mut bad = value.clone();
        bad["sites"][0]["calls"] = calls.into();
        bad["sites"][0]["first_ns"] = first.into();
        bad["sites"][0]["last_ns"] = last.into();
        // Keep conservation independent of the timestamp oracle.
        bad["legacy_partition"]["unfenced_tail_calls"] = calls.into();
        assert!(
            schema::check_v2_semantics(&bad).is_err(),
            "{calls}/{first}/{last}"
        );
    }
}

#[test]
fn projection_never_promotes_upstream_candidate_coverage() {
    let mut row = site(7, &["sha256"]);
    row.candidates_coverage = CandidateCoverage::Complete;
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![row],
            ..Default::default()
        },
        &[],
    );
    check_open(&doc);
    assert_eq!(doc.sites[0].candidates_coverage, CandidateCoverage::Unknown);
}

#[test]
fn zero_hit_row_does_not_skip_a_later_invalid_execution_row() {
    let mut zero = site(0, &[]);
    zero.site.offset = 1;
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![zero, site(7, &["sha256"])],
            ..Default::default()
        },
        &[],
    );
    let mut value: serde_json::Value =
        serde_json::from_slice(&report::render_json(&doc).unwrap()).unwrap();
    schema::check_v2_semantics(&value).unwrap();
    assert_eq!(value["sites"][0]["calls"], 0);
    value["sites"][1]["first_ns"] = 0.into();
    value["sites"][1]["last_ns"] = 0.into();
    assert!(schema::check_v2_semantics(&value).is_err());
}

#[test]
fn query_cacheability_does_not_retire_verified_code_lifetime() {
    for (cacheability, retire) in [
        (Cacheability::Cacheable, false),
        (Cacheability::Volatile, false),
        (Cacheability::Unknown, false),
    ] {
        let mut fact = invalidation();
        fact.payload = ObservationPayload::QueryResult {
            outcome: ApiOutcome::Success,
            cacheability,
        };
        let batch = ObservationBatch {
            facts: vec![fact],
            ..Default::default()
        };
        assert_eq!(
            batch_requires_retirement(&batch, 42),
            retire,
            "{cacheability:?}"
        );
        assert!(
            !batch_requires_retirement(&batch, 43),
            "unrelated PID {cacheability:?}"
        );
    }
}

#[test]
fn association_handoff_keeps_fenced_identity_without_another_count() {
    use osslscope::focused_count::{CandidateAssociation, MetadataOrigin, SiteAssociations};
    let physical = site(37, &[]);
    let association = SiteAssociations {
        site: physical.site.clone(),
        count_generation: 1,
        associations: vec![CandidateAssociation {
            origin: MetadataOrigin::StaticPublicTableCandidate,
            algorithm: None,
            known_algorithm: None,
            alias_quality: Default::default(),
            operation: None,
            function_id: 70001,
            advertisers: Vec::new(),
            static_provenance: Some(osslscope::provider_observation::static_tables::StaticTableProvenance::DispatchTableShape),
            storage: Some(osslscope::provider_observation::static_tables::TableStorage::ReadOnly),
            partial: true,
            observed_ns: 20,
            observation_generation: 9,
        }],
    };
    let doc = project(
        42,
        window(),
        CountSample {
            fenced: vec![physical],
            associations: vec![association.clone()],
            ..Default::default()
        },
        &[],
    );
    assert_eq!(doc.total_calls(), 37);
    assert_eq!(doc.candidate_associations, vec![association]);
    assert_eq!(
        doc.fenced[0].generation,
        doc.candidate_associations[0].count_generation
    );
    assert!(
        !serde_json::to_value(&doc)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("candidate_associations")
    );
    check_open(&doc);
}

#[test]
fn advertisement_invalidation_alone_preserves_physical_lifetime_but_identity_loss_retires() {
    for advertisement in [
        ObservationGap::RegistrationRace,
        ObservationGap::Invalidated,
    ] {
        let mut batch = ObservationBatch {
            gaps: vec![advertisement],
            ..Default::default()
        };
        assert!(
            !batch_requires_retirement(&batch, 42),
            "{advertisement:?} is not code custody loss"
        );
        for identity in [
            ObservationGap::ProcessChanged,
            ObservationGap::NamespaceChanged,
            ObservationGap::ObjectChanged,
            ObservationGap::MembershipUnknown,
        ] {
            batch.gaps.push(identity);
            assert!(
                batch_requires_retirement(&batch, 42),
                "{advertisement:?} must not mask {identity:?}"
            );
            batch.gaps.pop();
        }
        let doc = project(
            42,
            window(),
            CountSample {
                sites: vec![site(37, &[])],
                ..Default::default()
            },
            &[advertisement],
        );
        assert_eq!(doc.total_calls(), 37);
        check_open(&doc);
    }
}

#[test]
fn candidate_output_budget_refuses_metadata_without_losing_physical_counts() {
    use osslscope::focused_count::{CandidateAssociation, MetadataOrigin, SiteAssociations};
    let physical = site(37, &[]);
    let association = CandidateAssociation {
        origin: MetadataOrigin::StaticPublicTableCandidate, algorithm: None, known_algorithm: None, alias_quality: Default::default(), operation: None, function_id: 7, advertisers: Vec::new(),
        static_provenance: Some(osslscope::provider_observation::static_tables::StaticTableProvenance::DispatchTableShape), storage: Some(osslscope::provider_observation::static_tables::TableStorage::ReadOnly), partial: true, observed_ns: 20, observation_generation: 9,
    };
    let doc = project(
        42,
        window(),
        CountSample {
            fenced: vec![physical.clone()],
            associations: vec![SiteAssociations {
                site: physical.site,
                count_generation: 1,
                associations: vec![association; 131072],
            }],
            ..Default::default()
        },
        &[],
    );
    assert_eq!(doc.total_calls(), 37);
    assert!(doc.site_provenance.is_empty());
    assert!(
        doc.counters
            .iter()
            .any(|c| c.name == "focused.metadata_output_limit" && c.value == 1)
    );
    check_open(&doc);
}
