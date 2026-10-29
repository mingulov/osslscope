// SPDX-License-Identifier: GPL-3.0-or-later
//! Conserved execution partitions. Public row validation checks mathematics;
//! it cannot certify acquisition or manufacture a production finalized result.
use crate::evidence::{ObjectId, SiteExecution, SiteKey};
#[allow(dead_code)]
#[path = "../crates/bpf-contract/src/attribution.rs"]
pub(crate) mod wire;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlgorithmSelector {
    Known(u16),
    ObjectBound { object: ObjectId, id: [u8; 32] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmScope {
    ObservedSuccessfulRequestForConsumedMethodAtCallbackObjectV1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionRecord {
    pub site: SiteKey,
    pub generation: u32,
    pub segment: u64,
    /// Inclusive actual-hit extrema, not exclusive ownership intervals.
    pub start_ns: u64,
    pub end_ns: u64,
    pub calls: u64,
    pub provider_definition: Option<ObjectId>,
    /// A proved reference continuity interval, not allocation birth/cardinality.
    pub provider_instance: u64,
    pub operation: u32,
    pub function: u32,
    pub algorithm: AlgorithmSelector,
    pub algorithm_scope: AlgorithmScope,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionSummary {
    pub definite: Vec<AttributionRecord>,
    pub unresolved_calls: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributionError {
    UnknownSite,
    Generation,
    Window,
    DuplicatePartition,
    CountExceeded,
    Resource,
    Identity,
    Cut,
}
/// Noncertifying validation. Only finalizer-owned acquisition can establish
/// that partitions and physical counts share the same actual closed owners.
pub fn validate_attribution_rows(
    physical: &[SiteExecution],
    records: &[AttributionRecord],
) -> Result<AttributionSummary, AttributionError> {
    use AttributionError::*;
    use std::collections::{BTreeMap, BTreeSet};
    let mut rows = BTreeMap::new();
    let mut total = 0u64;
    for row in physical {
        if rows
            .insert((&row.site, row.generation), (row, 0u64))
            .is_some()
        {
            return Err(Identity);
        }
        total = total.checked_add(row.calls).ok_or(Resource)?;
    }
    let mut segments = BTreeSet::new();
    let mut assigned = 0u64;
    for record in records {
        if record.segment == 0
            || record.provider_instance == 0
            || record.calls == 0
            || record.operation == 0
            || record.function == 0
        {
            return Err(Identity);
        }
        if !segments.insert(record.segment) {
            return Err(DuplicatePartition);
        }
        if !rows.contains_key(&(&record.site, record.generation)) {
            return Err(if physical.iter().any(|row| row.site == record.site) {
                Generation
            } else {
                UnknownSite
            });
        }
        let (physical, count) = rows.get_mut(&(&record.site, record.generation)).unwrap();
        if record.start_ns == 0
            || record.start_ns > record.end_ns
            || record.start_ns < physical.first_ns
            || record.end_ns > physical.last_ns
        {
            return Err(Window);
        }
        match &record.algorithm {
            AlgorithmSelector::ObjectBound { object, .. } if *object == record.site.object => (),
            _ => return Err(Identity),
        }
        *count = count.checked_add(record.calls).ok_or(Resource)?;
        if *count > physical.calls {
            return Err(CountExceeded);
        }
        assigned = assigned.checked_add(record.calls).ok_or(Resource)?;
    }
    let mut definite = records.to_vec();
    definite.sort_by(|a, b| {
        (&a.site, a.generation, a.segment).cmp(&(&b.site, b.generation, b.segment))
    });
    Ok(AttributionSummary {
        definite,
        unresolved_calls: total.checked_sub(assigned).ok_or(CountExceeded)?,
    })
}
