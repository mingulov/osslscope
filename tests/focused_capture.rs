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
fn project_leaves_attribution_projection_to_finish() {
    // project() assembles the physical/candidate document only:
    // v2.5 sections stay empty and the schema stays v2.4 until
    // finish() projects a certified closed result (or records
    // the typed gap when the collect refuses).
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(37, &["SHA2-256"])],
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    check_open(&doc);
    assert_eq!(doc.schema, CAPTURE_SCHEMA_V2);
    assert!(doc.execution_attributions.is_empty());
    assert!(doc.algorithm_selectors.is_empty());
    assert_eq!(doc.attribution_bounds, None);
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
        &std::collections::BTreeSet::new(),
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
        &std::collections::BTreeSet::new(),
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
        &std::collections::BTreeSet::new(),
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
            &std::collections::BTreeSet::new(),
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
        let doc = project(
            42,
            window(),
            CountSample::default(),
            &[gap],
            &std::collections::BTreeSet::new(),
        );
        check_open(&doc);
        assert!(doc.engine_observations.is_empty());
    }
}
#[test]
fn inventory_upgrade_does_not_mask_actual_identity_loss() {
    let mut batch = ObservationBatch {
        refreshed_processes: vec![42],
        gaps: vec![ObservationGap::IdentityUnverified],
        ..Default::default()
    };
    // This classification is followed by independent retained-custody
    // validation in process_batch; it is never attachment authority.
    assert!(!batch_requires_retirement(&batch, 42));
    for loss in [
        ObservationGap::ProcessChanged,
        ObservationGap::NamespaceChanged,
        ObservationGap::ObjectChanged,
        ObservationGap::BackingUnavailable,
        ObservationGap::MembershipUnknown,
    ] {
        batch.gaps.push(loss);
        assert!(batch_requires_retirement(&batch, 42), "{loss:?}");
        batch.gaps.pop();
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
        &std::collections::BTreeSet::new(),
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
            ..config.clone()
        },
        FocusedConfig {
            timeout: Duration::ZERO,
            ..config.clone()
        },
        FocusedConfig {
            grace: Duration::ZERO,
            ..config.clone()
        },
        FocusedConfig {
            timeout: Duration::from_secs(121),
            ..config.clone()
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
        &std::collections::BTreeSet::new(),
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
        &std::collections::BTreeSet::new(),
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
        &std::collections::BTreeSet::new(),
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
        &std::collections::BTreeSet::new(),
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
            &std::collections::BTreeSet::new(),
        );
        assert_eq!(doc.total_calls(), 37);
        check_open(&doc);
    }
}

fn usite(calls: u64, offset: u64) -> SiteExecution {
    let mut row = site(calls, &[]);
    row.site.offset = offset;
    row
}

fn static_assoc() -> osslscope::focused_count::CandidateAssociation {
    use osslscope::focused_count::MetadataOrigin;
    osslscope::focused_count::CandidateAssociation {
        origin: MetadataOrigin::StaticPublicTableCandidate,
        algorithm: None,
        known_algorithm: None,
        alias_quality: Default::default(),
        operation: None,
        function_id: 7,
        advertisers: Vec::new(),
        static_provenance: Some(
            osslscope::provider_observation::static_tables::StaticTableProvenance::DispatchTableShape,
        ),
        storage: Some(
            osslscope::provider_observation::static_tables::TableStorage::ReadOnly,
        ),
        partial: true,
        observed_ns: 20,
        observation_generation: 9,
    }
}

#[test]
fn bounded_projection_retains_used_site_metadata_under_pressure() {
    use osslscope::focused_count::SiteAssociations;
    // One executed (positive) site plus huge unknown candidate sets that
    // overflow the frozen 64MiB ceiling: bounded projection must retain
    // the used site's metadata, conserve physical calls, and emit
    // explicit omission counts instead of dropping everything.
    let used = usite(37, 100);
    let used_row = SiteAssociations {
        site: used.site.clone(),
        count_generation: 1,
        associations: vec![static_assoc()],
    };
    let mut sites = vec![used];
    let mut rows = vec![used_row];
    for offset in [200, 300, 400] {
        let idle = usite(0, offset);
        rows.push(SiteAssociations {
            site: idle.site.clone(),
            count_generation: 1,
            associations: vec![static_assoc(); 8000],
        });
        sites.push(idle);
    }
    let doc = project(
        42,
        window(),
        CountSample {
            sites,
            associations: rows,
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(doc.total_calls(), 37);
    assert!(
        doc.site_provenance.iter().any(|row| row.site.offset == 100),
        "used site metadata must be retained under pressure"
    );
    assert!(
        doc.counters
            .iter()
            .any(|c| c.name == "focused.metadata_output_limit" && c.value == 1)
    );
    let omitted_sites = doc
        .counters
        .iter()
        .find(|c| c.name == "focused.metadata_omitted_sites")
        .map(|c| c.value)
        .unwrap_or(0);
    let omitted_associations = doc
        .counters
        .iter()
        .find(|c| c.name == "focused.metadata_omitted_associations")
        .map(|c| c.value)
        .unwrap_or(0);
    assert!(omitted_sites > 0, "omitted site rows must be counted");
    assert!(
        omitted_associations > 0,
        "omitted association rows must be counted"
    );
    check_open(&doc);
}

#[test]
fn bounded_projection_counts_omitted_rows_exactly() {
    use osslscope::focused_count::SiteAssociations;
    // Frozen byte model: each row costs 2048 + 64 (object hex) plus
    // 4096 per advertiser-free association. Three 8000-association
    // rows cost 3 * 32_770_112 bytes; the 64MiB ceiling retains the
    // first two in stable input order and omits exactly the third.
    let mut sites = Vec::new();
    let mut rows = Vec::new();
    for offset in [11, 22, 33] {
        let idle = usite(0, offset);
        rows.push(SiteAssociations {
            site: idle.site.clone(),
            count_generation: 1,
            associations: vec![static_assoc(); 8000],
        });
        sites.push(idle);
    }
    let doc = project(
        42,
        window(),
        CountSample {
            sites,
            associations: rows,
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(doc.total_calls(), 0);
    assert_eq!(doc.site_provenance.len(), 2);
    assert_eq!(doc.site_provenance[0].site.offset, 11);
    assert_eq!(doc.site_provenance[1].site.offset, 22);
    for (name, expected) in [
        ("focused.metadata_omitted_sites", 1),
        ("focused.metadata_omitted_associations", 8000),
    ] {
        let value = doc
            .counters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{name} must be emitted"))
            .value;
        assert_eq!(value, expected, "{name}");
    }
    check_open(&doc);
}

#[test]
fn bounded_projection_keeps_stable_input_order_when_everything_fits() {
    use osslscope::focused_count::SiteAssociations;
    // Characterization pin (passes before and after): fitting rows
    // project in stable input order, never sorted or dropped.
    let mut sites = Vec::new();
    let mut rows = Vec::new();
    for offset in [30, 10, 20] {
        let row = usite(3, offset);
        rows.push(SiteAssociations {
            site: row.site.clone(),
            count_generation: 1,
            associations: vec![static_assoc()],
        });
        sites.push(row);
    }
    let doc = project(
        42,
        window(),
        CountSample {
            sites,
            associations: rows,
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(doc.total_calls(), 9);
    let offsets: Vec<u64> = doc
        .site_provenance
        .iter()
        .map(|row| row.site.offset)
        .collect();
    assert_eq!(offsets, vec![30, 10, 20]);
    assert!(
        !doc.counters
            .iter()
            .any(|c| c.name == "focused.metadata_output_limit")
    );
    check_open(&doc);
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
        &std::collections::BTreeSet::new(),
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

#[test]
fn project_carries_attach_diagnostics_sorted_capped() {
    let diags: std::collections::BTreeSet<String> = [
        "backing-denied:permission-denied",
        "attach:link count_entry@0x1a2b failed (kind=PermissionDenied)",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(37, &["SHA2-256"])],
            ..Default::default()
        },
        &[],
        &diags,
    );
    check_open(&doc);
    assert_eq!(
        doc.attach_diagnostics,
        vec![
            "attach:link count_entry@0x1a2b failed (kind=PermissionDenied)".to_string(),
            "backing-denied:permission-denied".to_string(),
        ]
    );
    // Past the cap, the take keeps the first sorted sixteen.
    let many: std::collections::BTreeSet<String> = (0u64..20)
        .map(|i| format!("attach:link count_entry@0x{i:x} failed (kind=NotFound)"))
        .collect();
    let doc = project(
        42,
        window(),
        CountSample {
            sites: vec![site(37, &["SHA2-256"])],
            ..Default::default()
        },
        &[],
        &many,
    );
    assert_eq!(doc.attach_diagnostics.len(), 16);
    assert_eq!(
        doc.attach_diagnostics[0],
        "attach:link count_entry@0x0 failed (kind=NotFound)"
    );
}

#[test]
fn six_trace_counters_force_partial_through_shared_finalizer() {
    // P2fix1 item 1c/22: the six frozen trace counters project as
    // Loss-kind GapCounters (computed once, projected twice) and
    // force PARTIAL via the shared finalize — trace loss can never
    // hide in a COMPLETE window. The fold below is the REAL
    // production fold (every counter tripped for real).
    use osslscope::focused_capture::trace_loss_counters;
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    for i in 0..5000u64 {
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 1000 + i,
            invocation: i + 1,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i * 10,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1005 + i * 10,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    // One backward pair (nonmonotonic) + one orphan attempt + one
    // orphan result + one decode reject.
    let kb = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 99991,
        invocation: 6000,
    };
    p.attempt(t::AttemptEdge {
        key: kb,
        api: 20,
        monotonic_ns: 999000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: kb,
        api: 20,
        monotonic_ns: 999000,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let ko = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 99992,
        invocation: 6001,
    };
    p.attempt(t::AttemptEdge {
        key: ko,
        api: 22,
        monotonic_ns: 999010,
        start_time_ns: 1,
        seed: 1,
    });
    let kr = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 99993,
        invocation: 6002,
    };
    p.result(t::ResultEdge {
        key: kr,
        api: 22,
        monotonic_ns: 999020,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    p.reject_unknown();
    p.finalize(2_000_000);
    let w = p.close_window(0, 2_000_000, [0, 0, 3, 0, 0, 0, 0, 0]);
    assert!(w.dropped > 0, "detail must overflow");
    assert_eq!(w.nonmonotonic_pairs, 1);
    assert_eq!(w.unpaired_entries, 1);
    assert_eq!(w.unpaired_results, 1);
    assert_eq!(w.rejected_unknown_api, 1);
    assert_eq!(w.depth_exceeded, 3);
    let counters = trace_loss_counters(&w);
    assert_eq!(counters.len(), 6);
    for c in &counters {
        assert!(c.forces_partial(), "{} must force PARTIAL", c.name);
    }
    let doc = project(
        42,
        window(),
        CountSample {
            gaps: counters,
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    let reasons = match &doc.status {
        Completeness::Partial { reasons } => reasons.clone(),
        s => panic!("lossy trace window must be PARTIAL, got {s:?}"),
    };
    for name in [
        "trace_dropped",
        "trace_unpaired_entries",
        "trace_unpaired_results",
        "trace_depth_exceeded",
        "trace_nonmonotonic_pairs",
        "trace_rejected_unknown_api",
    ] {
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, GapReason::Loss { counter, .. } if counter == name)),
            "missing reason for {name}: {reasons:?}"
        );
    }
    // Clean window: no counters, no trace-loss reasons (still
    // PARTIAL via the focused unknowns — the pin is the ABSENCE of
    // trace loss, never a silent zero).
    let mut q = t::TraceProducer::new();
    q.set_mode(t::TRACE_MODE_LATENCY);
    for i in 0..10u64 {
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 2000 + i,
            invocation: i + 1,
        };
        q.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i * 10,
            start_time_ns: 1,
            seed: 1,
        });
        q.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1005 + i * 10,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    q.finalize(2_000_000);
    let clean = q.close_window(0, 2_000_000, [0; 8]);
    assert!(trace_loss_counters(&clean).is_empty());
    let clean_doc = project(
        42,
        window(),
        CountSample {
            gaps: trace_loss_counters(&clean),
            ..Default::default()
        },
        &[],
        &std::collections::BTreeSet::new(),
    );
    let clean_reasons = match &clean_doc.status {
        Completeness::Partial { reasons } => reasons.clone(),
        s => panic!("focused project is always PARTIAL here, got {s:?}"),
    };
    assert!(
        !clean_reasons.iter().any(|r| matches!(
            r,
            GapReason::Loss { counter, .. } if counter.starts_with("trace_")
        )),
        "clean window must carry no trace-loss reasons: {clean_reasons:?}"
    );
}

#[test]
fn newp2e_taint_only_cut_degrades_focused_completeness_and_exit() {
    // P2fix3 NEW-P2e: a taint-only late cut (every counted loss
    // zero — the fold holds out-of-interval pairs it cannot
    // exclude) still degrades focused completeness + exit: the
    // seal uncertainty rides the seal-gap word through the shared
    // finalizer (mirrors the standalone degrade rule), while the
    // six `trace_*` counters stay exactly six.
    use osslscope::focused_capture::{trace_loss_counters, trace_seal_uncertainty_gap};
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    // Late cut (below the consumed pair) + terminal seal.
    p.note_global_cut(50);
    p.finalize(2_000_000);
    let w = p.close_window(0, 2_000_000, [0; 8]);
    let totals = p.totals();
    assert!(w.late_cut, "seal marks the late cut");
    assert!(w.pairing_uncertain);
    // Taint-only: every counted loss is zero.
    assert!(trace_loss_counters(&w).is_empty(), "taint-only seal");
    // ... yet the seal uncertainty rides the seal gap.
    assert_eq!(
        trace_seal_uncertainty_gap(&w, &totals),
        Some(ObservationGap::SamplingPartial)
    );
    let doc = project(
        42,
        window(),
        CountSample {
            gaps: trace_loss_counters(&w),
            ..Default::default()
        },
        &[ObservationGap::SamplingPartial],
        &std::collections::BTreeSet::new(),
    );
    let reasons = match &doc.status {
        Completeness::Partial { reasons } => reasons.clone(),
        s => panic!("taint-only cut must be PARTIAL, got {s:?}"),
    };
    assert!(
        reasons.iter().any(
            |r| matches!(r, GapReason::Loss { counter, .. } if counter == "focused.interval_unknown")
        ),
        "seal gap reason present: {reasons:?}"
    );
    let delivery = report::DeliveryResult {
        primary: report::ArtifactOutcome {
            dest: "stdout".to_string(),
            ok: true,
            bytes: 8,
            error: None,
        },
        cbom: None,
        diagnostics: vec![],
    };
    assert_eq!(
        report::exit_for(policy::PolicyOutcome::Pass, None, &doc, &delivery),
        3,
        "taint-only cut exits 3"
    );
    // Clean seal: no gap, no interval reason.
    let mut q = t::TraceProducer::new();
    q.set_mode(t::TRACE_MODE_LATENCY);
    q.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    q.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    q.note_global_cut(10_000);
    q.finalize(2_000_000);
    let clean = q.close_window(0, 2_000_000, [0; 8]);
    let clean_totals = q.totals();
    assert!(!clean.late_cut);
    assert_eq!(
        trace_seal_uncertainty_gap(&clean, &clean_totals),
        None,
        "clean seal rides no gap"
    );
}

#[test]
fn trace_feed_cut_uses_the_effective_end() {
    // P2fix3 TRACE: the feed cut IS the reported effective end
    // (observed now clamped to the requested deadline, never
    // before start) — never the requested deadline alone. One
    // binding feeds the cut and the published window, so the two
    // cannot drift.
    use osslscope::focused_capture::effective_end_ns;
    // Early finish: now before the deadline clamps the cut.
    assert_eq!(effective_end_ns(50, 100, 10), 50);
    // Full-duration finish: now past the deadline clamps to it.
    assert_eq!(effective_end_ns(150, 100, 10), 100);
    // Degenerate clock (now before start): never before start.
    assert_eq!(effective_end_ns(5, 100, 10), 10);
}
