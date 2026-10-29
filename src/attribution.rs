// SPDX-License-Identifier: GPL-3.0-or-later
//! Conserved execution partitions. Public row validation checks mathematics;
//! it cannot certify acquisition or manufacture a production finalized result.
//! The private certifying core below (closed snapshot, partition decode,
//! shard reduction, one-shot collection, fold) is the host half of the
//! phase-1 MAC/KDF producer; its kernel emission half and finalizer call
//! site land with the producer. Staged items carry their consumer in docs.
use crate::evidence::{CaptureWindow, CountAdmissionWindow, ObjectId, SiteExecution, SiteKey};
use std::num::NonZeroU64;
#[allow(dead_code)]
#[path = "../crates/bpf-contract/src/attribution.rs"]
pub(crate) mod wire;
pub use wire::TypedRoleId;

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
        checked_conserve(count, physical.calls, &mut assigned, record.calls)?;
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

/// Single conservation step shared by the public validator and the private
/// certifying fold: checked per-key accumulation against its physical cap,
/// then checked total accumulation. One algorithm, two callers; the fold
/// adds custody/coordinate/window/identity checks around these same sums.
fn checked_conserve(
    spent: &mut u64,
    cap: u64,
    assigned: &mut u64,
    calls: u64,
) -> Result<(), AttributionError> {
    *spent = spent.checked_add(calls).ok_or(AttributionError::Resource)?;
    if *spent > cap {
        return Err(AttributionError::CountExceeded);
    }
    *assigned = assigned
        .checked_add(calls)
        .ok_or(AttributionError::Resource)?;
    Ok(())
}

/// Session-local result coordinate, assigned before immutable admission
/// opens. The cut is this result's scheduled final-snapshot label, not proof
/// of closure; closure is proved by the retained closed gate owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CutCoordinate {
    session_id: NonZeroU64,
    cut_id: NonZeroU64,
    admission_epoch: NonZeroU64,
}

/// Window evidence for one closed result: the fixed kernel admission
/// interval both physical and partition recording shared, the completeness
/// report window (policy, never a cut credential), and the monotonic
/// bracket of the first successful close of the retained gate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotWindow {
    admission: CountAdmissionWindow,
    report: CaptureWindow,
    close_before_ns: u64,
    close_after_ns: u64,
}

/// One final physical row with its observer dictionary identity. The
/// `site_id` resolves only through this result's retained rows: equal
/// cookies from different counters never alias. `source_epoch` is the
/// retained source custody epoch for this site; partitions must match it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClosedPhysicalRow {
    site_id: NonZeroU64,
    source_epoch: NonZeroU64,
    execution: SiteExecution,
}

/// One retained safe-dictionary entry, host-resolved from the exact
/// 64-byte `SelectorDictionaryValue` projection. The object is the
/// independently retained artifact containing the actual firing callback;
/// the digest is the opaque encoding-2 request identity scoped to that
/// object, family and exact spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedSelector {
    selector_id: NonZeroU64,
    dictionary_epoch: NonZeroU64,
    object: ObjectId,
    operation: u32,
    digest: [u8; 32],
}

/// Immutable key half of one decoded 128-byte partition row: the 104-byte
/// map key. Shards group by full-tuple equality; reusing a segment identity
/// for changed tuple fields is a duplicate-partition failure, never a merge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PartitionKeyTuple {
    session_id: u64,
    cut_id: u64,
    site_id: u64,
    segment_id: u64,
    provider_definition: u64,
    provider_continuity: u64,
    selector_id: u64,
    dictionary_epoch: u64,
    relation_epoch: u64,
    source_epoch: u64,
    count_generation: u32,
    operation: u32,
    function: u32,
}

/// One decoded 128-byte internal row: explicit fixed-width fields, never
/// Rust struct serialization. Multibyte integers use the agreed native
/// fixed-width map ABI, matching existing host map readers. Decoded by the
/// finalizer's strict partition-map read when the kernel producer lands.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Partition128 {
    key: PartitionKeyTuple,
    calls: u64,
    first_ns: u64,
    last_ns: u64,
}

#[allow(dead_code)]
fn map_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[allow(dead_code)]
fn map_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[allow(dead_code)]
impl Partition128 {
    /// Strict fixed-layout decode of one 104-byte key plus one 24-byte
    /// per-CPU aggregate. Structural violations fail closed as identity
    /// errors; window/conservation checks belong to the fold, which sees
    /// the retained physical rows the producer stored first.
    fn decode(key: &[u8], value: &[u8]) -> Result<Self, AttributionError> {
        use AttributionError::Identity;
        if key.len() != 104 || value.len() != 24 {
            return Err(Identity);
        }
        if map_u32(key, 0) != 1 || map_u32(key, 4) != 128 || map_u32(key, 100) != 2 {
            return Err(Identity);
        }
        let tuple = PartitionKeyTuple {
            session_id: map_u64(key, 8),
            cut_id: map_u64(key, 16),
            site_id: map_u64(key, 24),
            segment_id: map_u64(key, 32),
            provider_definition: map_u64(key, 40),
            provider_continuity: map_u64(key, 48),
            selector_id: map_u64(key, 56),
            dictionary_epoch: map_u64(key, 64),
            relation_epoch: map_u64(key, 72),
            source_epoch: map_u64(key, 80),
            count_generation: map_u32(key, 88),
            operation: map_u32(key, 92),
            function: map_u32(key, 96),
        };
        // Except the provider definition (0 = Unknown origin), every
        // identity coordinate is nonzero; operation/function name the exact
        // admitted public pair and are never zero in a positive row.
        if tuple.session_id == 0
            || tuple.cut_id == 0
            || tuple.site_id == 0
            || tuple.segment_id == 0
            || tuple.provider_continuity == 0
            || tuple.selector_id == 0
            || tuple.dictionary_epoch == 0
            || tuple.relation_epoch == 0
            || tuple.source_epoch == 0
            || tuple.operation == 0
            || tuple.function == 0
        {
            return Err(Identity);
        }
        Ok(Self {
            key: tuple,
            calls: map_u64(value, 0),
            first_ns: map_u64(value, 8),
            last_ns: map_u64(value, 16),
        })
    }
}

/// One partition after per-CPU shard reduction: the immutable key tuple
/// plus the checked cumulative aggregate. The producer stored the physical
/// hit first in this same count generation; a failed physical insert has
/// no partition, and a failed attribution insert leaves stored physical
/// counts unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReducedPartition {
    key: PartitionKeyTuple,
    calls: u64,
    first_ns: u64,
    last_ns: u64,
}

/// Reduce per-CPU shards exactly once. Shards sharing a segment identity
/// must carry one identical key tuple; changed fields are a duplicate
/// reuse, never a second partition. Empty shards contribute nothing to
/// the extrema, following the physical fold's contributing-shard rule;
/// an all-empty segment reduces to zero calls and the fold rejects it.
#[allow(dead_code)]
fn reduce_partition_shards(
    shards: &[Partition128],
) -> Result<Vec<ReducedPartition>, AttributionError> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<u64, (PartitionKeyTuple, u64, u64, u64)> = BTreeMap::new();
    for shard in shards {
        match groups.get_mut(&shard.key.segment_id) {
            None => {
                groups.insert(
                    shard.key.segment_id,
                    (
                        shard.key.clone(),
                        shard.calls,
                        shard.first_ns,
                        shard.last_ns,
                    ),
                );
            }
            Some((tuple, calls, first, last)) => {
                if *tuple != shard.key {
                    return Err(AttributionError::DuplicatePartition);
                }
                let had = *calls > 0;
                *calls = calls
                    .checked_add(shard.calls)
                    .ok_or(AttributionError::Resource)?;
                if shard.calls > 0 {
                    if !had || shard.first_ns < *first {
                        *first = shard.first_ns;
                    }
                    if !had || shard.last_ns > *last {
                        *last = shard.last_ns;
                    }
                }
            }
        }
    }
    Ok(groups
        .into_iter()
        .map(|(_, (key, calls, first_ns, last_ns))| ReducedPartition {
            key,
            calls,
            first_ns,
            last_ns,
        })
        .collect())
}

/// Finite loss evidence folded with the snapshot. Foreign physical counts
/// stay in the unresolved remainder; they never become definite rows.
/// Poison/withholding detail grows here with the kernel producer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ClosedAttributionLosses {
    foreign_calls: u64,
}

/// Retained custody for one closed result. The closed gate is the actual
/// shared owner, not a numeric map identity: only `matches` against the
/// live gate proves the snapshot closed over this domain. Map, source and
/// dictionary owners stay retained by the finalizer, which outlives the
/// consuming fold.
#[allow(dead_code)]
struct RetainedAttributionOwners {
    closed_gate: crate::writer_gate::OwnedClosedGate,
}

/// One-shot result-acquisition state, owned once per logical result by the
/// focused finalizer. Gate close stays idempotent; snapshot acquisition
/// does not: a second collection from the same state is unavailable.
#[derive(Debug, PartialEq, Eq)]
enum CollectionState {
    Unclaimed,
    Completed,
}

/// Per-result acquisition claim. The finalizer owns exactly one and calls
/// `collect` once after the actual gate close and strict final reads.
#[allow(dead_code)]
struct AttributionCollection {
    state: CollectionState,
}

/// Strictly read final evidence, without custody. The finalizer builds
/// this from sequential post-close reads through its retained owners;
/// `collect` binds it to the actual closed gate and one-shot claim.
#[allow(dead_code)]
struct CollectedEvidence {
    coordinate: CutCoordinate,
    window: SnapshotWindow,
    physical: Vec<ClosedPhysicalRow>,
    partitions: Vec<ReducedPartition>,
    selectors: Vec<ResolvedSelector>,
    losses: ClosedAttributionLosses,
}

/// One private, non-Clone closed snapshot bundle per logical result. Its
/// sole constructor owns the retained gate proof, the one-shot claim, the
/// coordinate, the window and every strictly read final row. A copied
/// sample, a map ID, matching timestamps or a caller-supplied cut number
/// cannot construct it.
#[allow(dead_code)]
struct ClosedAttributionSnapshot {
    coordinate: CutCoordinate,
    window: SnapshotWindow,
    owners: RetainedAttributionOwners,
    physical: Vec<ClosedPhysicalRow>,
    partitions: Vec<ReducedPartition>,
    selectors: Vec<ResolvedSelector>,
    losses: ClosedAttributionLosses,
}

#[allow(dead_code)]
impl AttributionCollection {
    fn unclaimed() -> Self {
        Self {
            state: CollectionState::Unclaimed,
        }
    }

    /// Bind strictly read evidence to the actual closed gate. Swapped
    /// owners fail even with equal map IDs, timestamps and claimed cut
    /// numbers: only the retained gate owner matches. The window bracket
    /// must equal this close's actual receipt bracket, and the admission
    /// configuration must be well-formed. Consumes the one-shot claim.
    fn collect(
        &mut self,
        closed_gate: crate::writer_gate::OwnedClosedGate,
        gate: &crate::writer_gate::WriterGate,
        evidence: CollectedEvidence,
    ) -> Result<ClosedAttributionSnapshot, AttributionError> {
        if self.state != CollectionState::Unclaimed {
            return Err(AttributionError::Cut);
        }
        if !closed_gate.matches(gate) {
            return Err(AttributionError::Cut);
        }
        let receipt = closed_gate.receipt();
        if evidence.window.close_before_ns != receipt.close_before_ns
            || evidence.window.close_after_ns != receipt.close_after_ns
        {
            return Err(AttributionError::Cut);
        }
        if evidence.window.admission.start_ns == 0
            || evidence.window.admission.start_ns >= evidence.window.admission.deadline_ns
        {
            return Err(AttributionError::Cut);
        }
        self.state = CollectionState::Completed;
        Ok(ClosedAttributionSnapshot {
            coordinate: evidence.coordinate,
            window: evidence.window,
            owners: RetainedAttributionOwners { closed_gate },
            physical: evidence.physical,
            partitions: evidence.partitions,
            selectors: evidence.selectors,
            losses: evidence.losses,
        })
    }
}

/// Production definite result, privately constructed by the certifying
/// fold only. Task 3 projects `definite` plus the unresolved bound into
/// the finalized document; the public validator's summary is explicitly
/// never accepted in place of this type.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
struct FinalizedAttribution {
    coordinate: CutCoordinate,
    definite: Vec<AttributionRecord>,
    unresolved_calls: u64,
    withheld_uncertain: u64,
}

#[allow(dead_code)]
impl FinalizedAttribution {
    /// Task 3 projection seam: local result coordinate, definite rows,
    /// conserved unresolved remainder and withheld-uncertain count.
    pub(crate) fn coordinate(&self) -> (u64, u64, u64) {
        (
            self.coordinate.session_id.get(),
            self.coordinate.cut_id.get(),
            self.coordinate.admission_epoch.get(),
        )
    }
    pub(crate) fn definite(&self) -> &[AttributionRecord] {
        &self.definite
    }
    pub(crate) fn unresolved_calls(&self) -> u64 {
        self.unresolved_calls
    }
    pub(crate) fn withheld_uncertain(&self) -> u64 {
        self.withheld_uncertain
    }
}

/// Certifying fold: consumes one privately collected closed snapshot and
/// creates the privately constructed production result. Structural
/// inconsistency (duplicate identities, overcount, coordinate, window or
/// binding mismatch, torn evidence) fails the fold; an unproved optional
/// identity (nonzero provider definition without its independent proof
/// channel) withholds that segment only, leaving its stored physical
/// calls unresolved. Nothing is ever relabeled; valid earlier segments
/// survive ordinary later retirement because the snapshot carries their
/// immutable epochs, and the historical relation epoch is accepted as
/// captured rather than compared to a live value.
#[allow(dead_code)]
fn fold_attribution(
    snapshot: ClosedAttributionSnapshot,
) -> Result<FinalizedAttribution, AttributionError> {
    use AttributionError::*;
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_site: BTreeMap<u64, usize> = BTreeMap::new();
    let mut by_row: BTreeMap<(&SiteKey, u32), usize> = BTreeMap::new();
    let mut totals: Vec<u64> = Vec::with_capacity(snapshot.physical.len());
    let mut known = 0u64;
    for (index, row) in snapshot.physical.iter().enumerate() {
        if by_site.insert(row.site_id.get(), index).is_some() {
            return Err(Identity);
        }
        if by_row
            .insert((&row.execution.site, row.execution.generation), index)
            .is_some()
        {
            return Err(Identity);
        }
        totals.push(row.execution.calls);
        known = known.checked_add(row.execution.calls).ok_or(Resource)?;
    }
    let mut selectors: BTreeMap<(u64, u64), &ResolvedSelector> = BTreeMap::new();
    for selector in &snapshot.selectors {
        if selectors
            .insert(
                (selector.selector_id.get(), selector.dictionary_epoch.get()),
                selector,
            )
            .is_some()
        {
            return Err(Identity);
        }
    }
    let mut spent = vec![0u64; snapshot.physical.len()];
    let mut assigned = 0u64;
    let mut seen_segments = BTreeSet::new();
    let mut definite = Vec::new();
    let mut withheld_uncertain = 0u64;
    for partition in &snapshot.partitions {
        let key = &partition.key;
        if key.session_id != snapshot.coordinate.session_id.get()
            || key.cut_id != snapshot.coordinate.cut_id.get()
        {
            return Err(Cut);
        }
        if !seen_segments.insert(key.segment_id) {
            return Err(DuplicatePartition);
        }
        let index = *by_site.get(&key.site_id).ok_or(UnknownSite)?;
        let row = &snapshot.physical[index];
        // Host-verifiable half of same-handler coupling: the partition
        // was recorded in exactly this physical row's count generation,
        // from the same retained source custody.
        if key.count_generation != row.execution.generation {
            return Err(Generation);
        }
        if key.source_epoch != row.source_epoch.get() {
            return Err(Identity);
        }
        // Positive rows carry inclusive actual-hit extrema inside the
        // admission interval and the matching physical extrema, no later
        // than the early close-after bound. Concurrent contexts may
        // overlap; intervals are extrema, not exclusive ownership.
        if partition.calls == 0
            || partition.first_ns == 0
            || partition.first_ns > partition.last_ns
            || partition.first_ns < snapshot.window.admission.start_ns
            || partition.last_ns >= snapshot.window.admission.deadline_ns
            || partition.first_ns < row.execution.first_ns
            || partition.last_ns > row.execution.last_ns
            || partition.last_ns > snapshot.window.close_after_ns
        {
            return Err(Window);
        }
        // Selector binding: the retained dictionary entry must name this
        // family and the actual firing site's retained code object.
        let selector = selectors
            .get(&(key.selector_id, key.dictionary_epoch))
            .ok_or(Identity)?;
        if selector.operation != key.operation || selector.object != row.execution.site.object {
            return Err(Identity);
        }
        // Unproved provider origin withholds the segment: phase-1
        // evidence never proves a defining artifact, so a nonzero
        // definition identity cannot certify. Its stored physical calls
        // stay unresolved; no other segment is affected.
        if key.provider_definition != 0 {
            withheld_uncertain = withheld_uncertain.saturating_add(1);
            continue;
        }
        checked_conserve(
            &mut spent[index],
            totals[index],
            &mut assigned,
            partition.calls,
        )?;
        definite.push(AttributionRecord {
            site: row.execution.site.clone(),
            generation: row.execution.generation,
            segment: key.segment_id,
            start_ns: partition.first_ns,
            end_ns: partition.last_ns,
            calls: partition.calls,
            provider_definition: None,
            provider_instance: key.provider_continuity,
            operation: key.operation,
            function: key.function,
            algorithm: AlgorithmSelector::ObjectBound {
                object: selector.object.clone(),
                id: selector.digest,
            },
            algorithm_scope:
                AlgorithmScope::ObservedSuccessfulRequestForConsumedMethodAtCallbackObjectV1,
        });
    }
    definite.sort_by(|a, b| {
        (&a.site, a.generation, a.segment).cmp(&(&b.site, b.generation, b.segment))
    });
    let unresolved = known
        .checked_add(snapshot.losses.foreign_calls)
        .ok_or(Resource)?
        .checked_sub(assigned)
        .ok_or(CountExceeded)?;
    Ok(FinalizedAttribution {
        coordinate: snapshot.coordinate,
        definite,
        unresolved_calls: unresolved,
        withheld_uncertain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::CandidateCoverage;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn object() -> ObjectId {
        ObjectId("a".repeat(64))
    }

    fn site() -> SiteKey {
        SiteKey {
            object: object(),
            device: 7,
            inode: 9,
            offset: 16,
        }
    }

    fn execution(calls: u64, first: u64, last: u64) -> SiteExecution {
        SiteExecution {
            site: site(),
            generation: 3,
            candidates: vec![],
            candidates_coverage: CandidateCoverage::Unknown,
            calls,
            first_ns: first,
            last_ns: last,
            installed_at: Some(8),
        }
    }

    fn row() -> ClosedPhysicalRow {
        ClosedPhysicalRow {
            site_id: nz(21),
            source_epoch: nz(41),
            execution: execution(100, 10, 100),
        }
    }

    fn coordinate() -> CutCoordinate {
        CutCoordinate {
            session_id: nz(11),
            cut_id: nz(12),
            admission_epoch: nz(13),
        }
    }

    fn window(close_before_ns: u64, close_after_ns: u64) -> SnapshotWindow {
        SnapshotWindow {
            admission: CountAdmissionWindow {
                start_ns: 10,
                deadline_ns: 200,
            },
            report: CaptureWindow {
                requested_start_ns: 10,
                requested_end_ns: 200,
                effective_start_ns: 10,
                effective_end_ns: 200,
                signal_cut: false,
                count_admission: None,
            },
            close_before_ns,
            close_after_ns,
        }
    }

    fn selector() -> ResolvedSelector {
        ResolvedSelector {
            selector_id: nz(31),
            dictionary_epoch: nz(32),
            object: object(),
            operation: 3,
            digest: [7; 32],
        }
    }

    fn tuple(segment: u64) -> PartitionKeyTuple {
        PartitionKeyTuple {
            session_id: 11,
            cut_id: 12,
            site_id: 21,
            segment_id: segment,
            provider_definition: 0,
            provider_continuity: 8,
            selector_id: 31,
            dictionary_epoch: 32,
            relation_epoch: 33,
            source_epoch: 41,
            count_generation: 3,
            operation: 3,
            function: 5,
        }
    }

    fn reduced(segment: u64, calls: u64, first: u64, last: u64) -> ReducedPartition {
        ReducedPartition {
            key: tuple(segment),
            calls,
            first_ns: first,
            last_ns: last,
        }
    }

    fn raw_key(edit: impl FnOnce(&mut [u8; 104])) -> [u8; 104] {
        let mut key = [0u8; 104];
        key[0..4].copy_from_slice(&1u32.to_ne_bytes());
        key[4..8].copy_from_slice(&128u32.to_ne_bytes());
        for (offset, value) in [
            (8, 11u64),
            (16, 12),
            (24, 21),
            (32, 22),
            (40, 0),
            (48, 8),
            (56, 31),
            (64, 32),
            (72, 33),
            (80, 41),
        ] {
            key[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        key[88..92].copy_from_slice(&3u32.to_ne_bytes());
        key[92..96].copy_from_slice(&3u32.to_ne_bytes());
        key[96..100].copy_from_slice(&5u32.to_ne_bytes());
        key[100..104].copy_from_slice(&2u32.to_ne_bytes());
        edit(&mut key);
        key
    }

    fn raw_value(calls: u64, first: u64, last: u64) -> [u8; 24] {
        let mut value = [0u8; 24];
        value[0..8].copy_from_slice(&calls.to_ne_bytes());
        value[8..16].copy_from_slice(&first.to_ne_bytes());
        value[16..24].copy_from_slice(&last.to_ne_bytes());
        value
    }

    fn closed_pair() -> (
        crate::writer_gate::WriterGate,
        crate::writer_gate::OwnedClosedGate,
    ) {
        let pool =
            crate::observation_memory::MemoryPool::new(2 * crate::writer_gate::RESERVATION_BYTES);
        crate::writer_gate::fake_closed_for_shape_tests(&pool).unwrap()
    }

    fn evidence(window: SnapshotWindow) -> CollectedEvidence {
        CollectedEvidence {
            coordinate: coordinate(),
            window,
            physical: vec![row()],
            partitions: vec![reduced(1, 37, 20, 80), reduced(2, 11, 25, 70)],
            selectors: vec![selector()],
            losses: ClosedAttributionLosses { foreign_calls: 0 },
        }
    }

    fn snapshot(
        window: SnapshotWindow,
        physical: Vec<ClosedPhysicalRow>,
        partitions: Vec<ReducedPartition>,
        selectors: Vec<ResolvedSelector>,
        losses: ClosedAttributionLosses,
    ) -> ClosedAttributionSnapshot {
        let (_, closed_gate) = closed_pair();
        ClosedAttributionSnapshot {
            coordinate: coordinate(),
            window,
            owners: RetainedAttributionOwners { closed_gate },
            physical,
            partitions,
            selectors,
            losses,
        }
    }

    #[test]
    fn partition_decode_accepts_a_valid_row() {
        let row = Partition128::decode(&raw_key(|_| {}), &raw_value(37, 20, 80)).unwrap();
        assert_eq!(row.key, tuple(22));
        assert_eq!((row.calls, row.first_ns, row.last_ns), (37, 20, 80));
    }

    #[test]
    fn partition_decode_rejects_bad_layout_and_zero_identity() {
        let good_key = raw_key(|_| {});
        let good_value = raw_value(37, 20, 80);
        assert_eq!(
            Partition128::decode(&good_key[..103], &good_value),
            Err(AttributionError::Identity)
        );
        assert_eq!(
            Partition128::decode(&good_key, &good_value[..23]),
            Err(AttributionError::Identity)
        );
        for (offset, width) in [(0, 4), (4, 4), (100, 4)] {
            let mut key = good_key;
            key[offset..offset + width].copy_from_slice(&9u32.to_ne_bytes()[..width]);
            assert_eq!(
                Partition128::decode(&key, &good_value),
                Err(AttributionError::Identity),
                "header word at {offset}"
            );
        }
        for offset in [8, 16, 24, 32, 48, 56, 64, 72, 80] {
            let mut key = good_key;
            key[offset..offset + 8].copy_from_slice(&0u64.to_ne_bytes());
            assert_eq!(
                Partition128::decode(&key, &good_value),
                Err(AttributionError::Identity),
                "zero identity at {offset}"
            );
        }
        for offset in [92, 96] {
            let mut key = good_key;
            key[offset..offset + 4].copy_from_slice(&0u32.to_ne_bytes());
            assert_eq!(
                Partition128::decode(&key, &good_value),
                Err(AttributionError::Identity),
                "zero operation/function at {offset}"
            );
        }
        // Provider definition 0 is Unknown origin, accepted at decode.
        assert!(Partition128::decode(&good_key, &good_value).is_ok());
    }

    #[test]
    fn shard_reduction_sums_once_and_takes_contributing_extrema() {
        let key = tuple(22);
        let shards = [
            Partition128 {
                key: key.clone(),
                calls: 0,
                first_ns: 0,
                last_ns: 0,
            },
            Partition128 {
                key: key.clone(),
                calls: 30,
                first_ns: 40,
                last_ns: 60,
            },
            Partition128 {
                key: key.clone(),
                calls: 7,
                first_ns: 20,
                last_ns: 80,
            },
        ];
        let reduced = reduce_partition_shards(&shards).unwrap();
        assert_eq!(reduced.len(), 1);
        assert_eq!(reduced[0].key, key);
        assert_eq!(
            (reduced[0].calls, reduced[0].first_ns, reduced[0].last_ns),
            (37, 20, 80)
        );
    }

    #[test]
    fn shard_reduction_rejects_changed_tuple_and_overflow() {
        let mut other = tuple(22);
        other.provider_continuity = 9;
        let shards = [
            Partition128 {
                key: tuple(22),
                calls: 1,
                first_ns: 20,
                last_ns: 20,
            },
            Partition128 {
                key: other,
                calls: 1,
                first_ns: 20,
                last_ns: 20,
            },
        ];
        assert_eq!(
            reduce_partition_shards(&shards),
            Err(AttributionError::DuplicatePartition)
        );
        let wide = [
            Partition128 {
                key: tuple(22),
                calls: u64::MAX,
                first_ns: 20,
                last_ns: 20,
            },
            Partition128 {
                key: tuple(22),
                calls: 1,
                first_ns: 20,
                last_ns: 20,
            },
        ];
        assert_eq!(
            reduce_partition_shards(&wide),
            Err(AttributionError::Resource)
        );
    }

    #[test]
    fn collect_binds_evidence_to_the_actual_closed_gate() {
        let (gate, closed) = closed_pair();
        let receipt = closed.receipt();
        assert!(receipt.close_before_ns > 0);
        assert!(receipt.close_after_ns >= receipt.close_before_ns);
        let mut collection = AttributionCollection::unclaimed();
        let snapshot = collection
            .collect(
                closed,
                &gate,
                evidence(window(receipt.close_before_ns, receipt.close_after_ns)),
            )
            .unwrap();
        assert_eq!(snapshot.coordinate, coordinate());
        assert_eq!(snapshot.partitions.len(), 2);
    }

    #[test]
    fn collect_rejects_swapped_owners_with_equal_map_ids() {
        let (gate_a, closed_a) = closed_pair();
        let (gate_b, _) = closed_pair();
        // Both fake pairs share the diagnostic map id; custody still differs.
        assert_eq!(closed_a.receipt().map_id, gate_b.receipt().unwrap().map_id);
        assert!(!closed_a.matches(&gate_b));
        let receipt = closed_a.receipt();
        let mut collection = AttributionCollection::unclaimed();
        assert_eq!(
            collection
                .collect(
                    closed_a,
                    &gate_b,
                    evidence(window(receipt.close_before_ns, receipt.close_after_ns)),
                )
                .err(),
            Some(AttributionError::Cut)
        );
        // The refused claim is not consumed: the rightful owner still binds
        // with a freshly minted capability from its retained gate.
        let closed_a = gate_a.owned_closed().unwrap();
        let receipt = closed_a.receipt();
        collection
            .collect(
                closed_a,
                &gate_a,
                evidence(window(receipt.close_before_ns, receipt.close_after_ns)),
            )
            .unwrap();
    }

    #[test]
    fn collect_rejects_foreign_bracket_replay_and_malformed_admission() {
        let (gate, closed) = closed_pair();
        let receipt = closed.receipt();
        let mut collection = AttributionCollection::unclaimed();
        assert_eq!(
            collection
                .collect(
                    closed,
                    &gate,
                    evidence(window(receipt.close_before_ns, receipt.close_after_ns + 1)),
                )
                .err(),
            Some(AttributionError::Cut)
        );
        let (gate, closed) = closed_pair();
        let receipt = closed.receipt();
        let mut malformed = window(receipt.close_before_ns, receipt.close_after_ns);
        malformed.admission.start_ns = 0;
        assert_eq!(
            collection.collect(closed, &gate, evidence(malformed)).err(),
            Some(AttributionError::Cut)
        );
        let (gate, closed) = closed_pair();
        let receipt = closed.receipt();
        collection
            .collect(
                closed,
                &gate,
                evidence(window(receipt.close_before_ns, receipt.close_after_ns)),
            )
            .unwrap();
        let (gate, closed) = closed_pair();
        let receipt = closed.receipt();
        assert_eq!(
            collection
                .collect(
                    closed,
                    &gate,
                    evidence(window(receipt.close_before_ns, receipt.close_after_ns)),
                )
                .err(),
            Some(AttributionError::Cut)
        );
    }

    #[test]
    fn fold_conserves_100_with_37_and_11_definite() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        let finalized = fold_attribution(snapshot(
            window(receipt.close_before_ns, receipt.close_after_ns),
            vec![row()],
            vec![reduced(1, 37, 20, 80), reduced(2, 11, 25, 70)],
            vec![selector()],
            ClosedAttributionLosses { foreign_calls: 0 },
        ))
        .unwrap();
        assert_eq!(finalized.coordinate(), (11, 12, 13));
        assert_eq!(finalized.unresolved_calls(), 52);
        assert_eq!(finalized.withheld_uncertain(), 0);
        let definite = finalized.definite();
        assert_eq!(definite.len(), 2);
        assert_eq!((definite[0].segment, definite[0].calls), (1, 37));
        assert_eq!((definite[1].segment, definite[1].calls), (2, 11));
        for record in definite {
            assert_eq!(record.site, site());
            assert_eq!(record.generation, 3);
            assert_eq!(record.provider_definition, None);
            assert_eq!(record.provider_instance, 8);
            assert_eq!((record.operation, record.function), (3, 5));
            assert_eq!(
                record.algorithm,
                AlgorithmSelector::ObjectBound {
                    object: object(),
                    id: [7; 32],
                }
            );
            assert_eq!(
                record.algorithm_scope,
                AlgorithmScope::ObservedSuccessfulRequestForConsumedMethodAtCallbackObjectV1
            );
        }
        // The public validator agrees on the projected rows: one algorithm.
        let summary = validate_attribution_rows(&[row().execution], definite).unwrap();
        assert_eq!(summary.unresolved_calls, 52);
    }

    #[test]
    fn fold_rejects_duplicate_segment_and_old_generation() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        let win = || window(receipt.close_before_ns, receipt.close_after_ns);
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![reduced(1, 37, 20, 80), reduced(1, 11, 25, 70)],
                vec![selector()],
                ClosedAttributionLosses { foreign_calls: 0 },
            )),
            Err(AttributionError::DuplicatePartition)
        );
        let mut old = reduced(1, 37, 20, 80);
        old.key.count_generation = 2;
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![old],
                vec![selector()],
                ClosedAttributionLosses { foreign_calls: 0 },
            )),
            Err(AttributionError::Generation)
        );
    }

    #[test]
    fn fold_rejects_window_violations_and_accepts_boundaries() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        // Physical 10..=100, admission [10, 200), close bound is the receipt.
        let bad: Vec<(u64, u64, u64)> = vec![
            (0, 20, 80),  // no positive without a hit
            (1, 0, 80),   // zero first
            (1, 80, 20),  // inverted extrema
            (1, 9, 80),   // before admission and physical
            (1, 20, 200), // deadline is exclusive
            (1, 20, 101), // past the physical last
            (1, 11, 10),  // inverted within physical
        ];
        for (calls, first, last) in bad {
            assert_eq!(
                fold_attribution(snapshot(
                    window(receipt.close_before_ns, receipt.close_after_ns),
                    vec![row()],
                    vec![reduced(1, calls, first, last)],
                    vec![selector()],
                    ClosedAttributionLosses { foreign_calls: 0 },
                )),
                Err(AttributionError::Window),
                "calls={calls} first={first} last={last}"
            );
        }
        // Past the early close-after bound fails even inside admission.
        assert_eq!(
            fold_attribution(snapshot(
                window(10, 50),
                vec![row()],
                vec![reduced(1, 11, 25, 70)],
                vec![selector()],
                ClosedAttributionLosses { foreign_calls: 0 },
            )),
            Err(AttributionError::Window)
        );
        // Boundaries: single-hit equality, physical edges, close edge.
        let ok = vec![
            (1, 50, 50),
            (1, 10, 100),
            (11, 25, 70),
            (1, 10, 10),
            (1, 100, 100),
        ];
        for (calls, first, last) in ok {
            assert!(
                fold_attribution(snapshot(
                    window(receipt.close_before_ns, receipt.close_after_ns),
                    vec![row()],
                    vec![reduced(1, calls, first, last)],
                    vec![selector()],
                    ClosedAttributionLosses { foreign_calls: 0 },
                ))
                .is_ok(),
                "calls={calls} first={first} last={last}"
            );
        }
    }

    #[test]
    fn fold_rejects_unknown_site_and_identity_breaks() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        let win = || window(receipt.close_before_ns, receipt.close_after_ns);
        let losses = || ClosedAttributionLosses { foreign_calls: 0 };
        let mut nowhere = reduced(1, 11, 25, 70);
        nowhere.key.site_id = 99;
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![nowhere],
                vec![selector()],
                losses(),
            )),
            Err(AttributionError::UnknownSite)
        );
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row(), row()],
                vec![],
                vec![],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        let mut second_id = row();
        second_id.site_id = nz(23);
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row(), second_id],
                vec![],
                vec![],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        let mut epoch = reduced(1, 11, 25, 70);
        epoch.key.source_epoch = 42;
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![epoch],
                vec![selector()],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![reduced(1, 11, 25, 70)],
                vec![],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        let mut family = selector();
        family.operation = 4;
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![reduced(1, 11, 25, 70)],
                vec![family],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        let mut foreign = selector();
        foreign.object = ObjectId("b".repeat(64));
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![reduced(1, 11, 25, 70)],
                vec![foreign],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![],
                vec![selector(), selector()],
                losses(),
            )),
            Err(AttributionError::Identity)
        );
    }

    #[test]
    fn fold_rejects_coordinate_mismatch_overcount_and_overflow() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        let win = || window(receipt.close_before_ns, receipt.close_after_ns);
        let losses = || ClosedAttributionLosses { foreign_calls: 0 };
        let mut cut = reduced(1, 11, 25, 70);
        cut.key.cut_id = 13;
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![cut],
                vec![selector()],
                losses(),
            )),
            Err(AttributionError::Cut)
        );
        assert_eq!(
            fold_attribution(snapshot(
                win(),
                vec![row()],
                vec![reduced(1, 101, 20, 80)],
                vec![selector()],
                losses(),
            )),
            Err(AttributionError::CountExceeded)
        );
        let mut huge = row();
        huge.execution.calls = u64::MAX;
        let mut other = huge.clone();
        other.site_id = nz(23);
        other.execution.site.offset = 17;
        assert_eq!(
            fold_attribution(snapshot(win(), vec![huge, other], vec![], vec![], losses(),)),
            Err(AttributionError::Resource)
        );
    }

    #[test]
    fn fold_withholds_unproved_definition_and_keeps_remainder() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        let mut unproved = reduced(9, 11, 25, 70);
        unproved.key.provider_definition = 77;
        let finalized = fold_attribution(snapshot(
            window(receipt.close_before_ns, receipt.close_after_ns),
            vec![row()],
            vec![reduced(1, 37, 20, 80), unproved],
            vec![selector()],
            ClosedAttributionLosses { foreign_calls: 5 },
        ))
        .unwrap();
        // Only the proved segment is definite; the unproved segment's
        // stored physical calls stay unresolved with the foreign remainder.
        assert_eq!(finalized.definite().len(), 1);
        assert_eq!(finalized.definite()[0].segment, 1);
        assert_eq!(finalized.withheld_uncertain(), 1);
        assert_eq!(finalized.unresolved_calls(), 100 + 5 - 37);
    }

    #[test]
    fn concurrent_overlaps_and_fenced_rows_fold_cleanly() {
        let (_, closed) = closed_pair();
        let receipt = closed.receipt();
        drop(closed);
        // Same row, overlapping extrema: valid concurrent contexts.
        let finalized = fold_attribution(snapshot(
            window(receipt.close_before_ns, receipt.close_after_ns),
            vec![row()],
            vec![reduced(1, 37, 20, 80), reduced(2, 11, 20, 80)],
            vec![selector()],
            ClosedAttributionLosses { foreign_calls: 0 },
        ))
        .unwrap();
        assert_eq!(finalized.unresolved_calls(), 52);
        // A fenced earlier generation is separate physical evidence,
        // retained once with its own partition.
        let mut fenced = row();
        fenced.site_id = nz(23);
        fenced.execution.generation = 2;
        fenced.execution.calls = 40;
        let mut old_partition = reduced(3, 13, 20, 80);
        old_partition.key.site_id = 23;
        old_partition.key.count_generation = 2;
        let finalized = fold_attribution(snapshot(
            window(receipt.close_before_ns, receipt.close_after_ns),
            vec![row(), fenced],
            vec![reduced(1, 37, 20, 80), old_partition],
            vec![selector()],
            ClosedAttributionLosses { foreign_calls: 0 },
        ))
        .unwrap();
        assert_eq!(finalized.definite().len(), 2);
        assert_eq!(finalized.unresolved_calls(), 100 + 40 - 37 - 13);
    }
}
