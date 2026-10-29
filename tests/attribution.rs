// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::{attribution::*, evidence::*};

fn physical() -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: ObjectId("a".repeat(64)),
            device: 7,
            inode: 9,
            offset: 16,
        },
        generation: 3,
        candidates: vec![],
        candidates_coverage: CandidateCoverage::Unknown,
        calls: 100,
        first_ns: 10,
        last_ns: 100,
        installed_at: Some(8),
    }
}
fn record(segment: u64, calls: u64) -> AttributionRecord {
    let site = physical().site;
    AttributionRecord {
        algorithm: AlgorithmSelector::ObjectBound {
            object: site.object.clone(),
            id: [7; 32],
        },
        site,
        generation: 3,
        segment,
        start_ns: 20,
        end_ns: 80,
        calls,
        provider_definition: None,
        provider_instance: 8,
        operation: 3,
        function: 5,
        algorithm_scope:
            AlgorithmScope::ObservedSuccessfulRequestForConsumedMethodAtCallbackObjectV1,
    }
}
#[test]
fn attribution_conserves_shared_physical_calls() {
    let result = validate_attribution_rows(&[physical()], &[record(1, 37), record(2, 11)]).unwrap();
    assert_eq!(result.unresolved_calls, 52);
    assert_eq!(result.definite.len(), 2);
    assert!(
        result
            .definite
            .iter()
            .all(|r| r.provider_definition.is_none())
    );
}
#[test]
fn concurrent_context_intervals_may_overlap() {
    assert!(validate_attribution_rows(&[physical()], &[record(1, 37), record(2, 11)]).is_ok());
}
#[test]
fn attribution_rejects_duplicate_partition_and_old_generation() {
    assert_eq!(
        validate_attribution_rows(&[physical()], &[record(1, 37), record(1, 11)]),
        Err(AttributionError::DuplicatePartition)
    );
    let mut old = record(1, 37);
    old.generation = 2;
    assert_eq!(
        validate_attribution_rows(&[physical()], &[old]),
        Err(AttributionError::Generation)
    );
}
#[test]
fn late_identity_never_relabels_prior_calls() {
    let mut late = record(1, 11);
    late.start_ns = 80;
    late.end_ns = 100;
    let result = validate_attribution_rows(&[physical()], &[late]).unwrap();
    assert_eq!(result.unresolved_calls, 89);
}
#[test]
fn rejects_overcount_overflow_duplicate_physical_and_bad_identity() {
    assert_eq!(
        validate_attribution_rows(&[physical()], &[record(1, 101)]),
        Err(AttributionError::CountExceeded)
    );
    assert_eq!(
        validate_attribution_rows(&[physical(), physical()], &[]),
        Err(AttributionError::Identity)
    );
    let mut wrong = record(1, 1);
    wrong.provider_instance = 0;
    assert_eq!(
        validate_attribution_rows(&[physical()], &[wrong]),
        Err(AttributionError::Identity)
    );
    let mut huge = physical();
    huge.calls = u64::MAX;
    let mut other = huge.clone();
    other.site.offset += 1;
    assert_eq!(
        validate_attribution_rows(&[huge, other], &[]),
        Err(AttributionError::Resource)
    );
}
#[test]
fn inclusive_extrema_and_actual_code_scope_are_checked() {
    let mut row = record(1, 1);
    row.start_ns = 100;
    row.end_ns = 100;
    assert!(validate_attribution_rows(&[physical()], &[row.clone()]).is_ok());
    row.end_ns = 101;
    assert_eq!(
        validate_attribution_rows(&[physical()], &[row.clone()]),
        Err(AttributionError::Window)
    );
    row.end_ns = 100;
    row.algorithm = AlgorithmSelector::ObjectBound {
        object: ObjectId("b".repeat(64)),
        id: [7; 32],
    };
    assert_eq!(
        validate_attribution_rows(&[physical()], &[row]),
        Err(AttributionError::Identity)
    );
}
