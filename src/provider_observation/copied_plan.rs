//! U1 copied-role staging plans: join live query observations to retained
//! dispatch bytes.
//!
//! A copied-role site (constructor 258/259, lifecycle 274/275, dup
//! 290/291, operational 304-308) stages only from an observed callback:
//! a live query the observer actually saw return, content-matched to a
//! retained algorithm array, yielding (operation, function, file offset)
//! triples grounded in retained bytes plus the live (op, function)
//! identity. Nothing here guesses: ambiguous or unmatched observations
//! refuse (fail closed), and staged sites still need kernel CODE_ROLE
//! authorization plus the chain's family checks before any read.
//!
//! Pass 1 (legacy-only run) drains validated ring records; [`collect_live_queries`]
//! groups them per query and per op. [`generate_plan`] parses the same
//! retained descriptors and exact-matches each live op shape against the
//! static arrays. Pass 2 (staged run) verifies every plan entry against
//! its retained file's parsed dispatch candidates (membership, exact
//! function, non-partial) before attach.

use std::collections::{BTreeMap, BTreeSet};

use super::wire::contract as c;

use super::schema::ObjectHash;

/// One live query's observed dispatch shape: per algorithm index, the
/// sorted function-ID set the kernel walker saw returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQuery {
    pub operation: u32,
    /// (algorithm index, sorted function IDs), index order.
    pub algos: Vec<(u32, Vec<u32>)>,
}

/// Group validated ring records into kept live queries: cacheable
/// (`cacheability == 1`), successful (`outcome == 1`) MAC/KDF queries
/// whose repeated observations agree exactly. Queries are delimited per
/// (pid, tid, invocation) so interleaved threads never merge. Anything
/// else (no-store, failed, unreadable, out-of-slice op, disagreeing
/// repeat) is dropped, never manufactured.
#[allow(dead_code)] // Wired by U1 native drivers; product orchestration is a U5 carryover.
pub(crate) fn collect_live_queries(records: &[c::Record]) -> Vec<LiveQuery> {
    struct Open {
        operation: u32,
        algos: BTreeMap<u32, BTreeSet<u32>>,
    }
    let mut queries: BTreeMap<(u32, u32, u64), Open> = BTreeMap::new();
    let mut order: Vec<(u32, u32, u64)> = Vec::new();
    for record in records {
        if record.api != c::PUBLIC_QUERY {
            continue;
        }
        let key = (record.pid, record.tid, record.invocation);
        if record.kind == c::QUERY {
            if record.outcome == 1
                && record.cacheability == 1
                && matches!(record.operation, 3 | 4)
                && queries
                    .insert(
                        key,
                        Open {
                            operation: record.operation,
                            algos: BTreeMap::new(),
                        },
                    )
                    .is_none()
            {
                order.push(key);
            }
            continue;
        }
        if record.kind != c::IMPLEMENTATION || record.outcome != 0 {
            continue;
        }
        // The kernel template carries the query's op/cacheability onto
        // every entry; entries that disagree with an open kept query are
        // not that query's (stale interleave) and stay out.
        if let Some(open) = queries.get_mut(&key) {
            if record.operation == open.operation && record.cacheability == 1 {
                open.algos
                    .entry(record.algorithm_index)
                    .or_default()
                    .insert(record.function);
            }
        }
    }
    // Per-op agreement: repeated queries for one op must observe the
    // identical shape, else the op refuses (fail closed).
    let mut per_op: BTreeMap<u32, Vec<LiveQuery>> = BTreeMap::new();
    for key in order {
        let open = &queries[&key];
        if open.algos.is_empty() {
            continue;
        }
        let algos = open
            .algos
            .iter()
            .map(|(index, funs)| (*index, funs.iter().copied().collect()))
            .collect();
        per_op.entry(open.operation).or_default().push(LiveQuery {
            operation: open.operation,
            algos,
        });
    }
    let mut kept = Vec::new();
    for (operation, shapes) in per_op {
        if shapes.iter().all(|shape| shape.algos == shapes[0].algos) {
            kept.push(LiveQuery {
                operation,
                algos: shapes
                    .into_iter()
                    .next()
                    .map(|s| s.algos)
                    .unwrap_or_default(),
            });
        }
    }
    kept.sort_by_key(|query| query.operation);
    kept
}

/// Per-file array-grouping inputs, carried from discovery (no re-parse):
/// the retained file's hash plus one (record address, (function ID, code
/// file offset) rows) pair per parsed algorithm record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileArrays {
    pub hash: ObjectHash,
    pub inputs: Vec<(u64, Vec<(u32, u64)>)>,
}

/// One statically grouped algorithm array: maximal stride-32 run of
/// records with their dispatch rows.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StaticArray {
    records: Vec<StaticRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StaticRecord {
    functions: Vec<u32>,
    entries: Vec<(u32, u64)>,
}

/// Group parsed algorithms into arrays by record-address contiguity
/// (OSSL_ALGORITHM records are 32 bytes; the scan finds them at stride
/// 8, so only exact stride-32 runs form an array). Records sort by
/// address; the live index is the position in the run.
fn group_arrays(inputs: &[(u64, Vec<(u32, u64)>)]) -> Vec<StaticArray> {
    let mut sorted: Vec<(u64, Vec<(u32, u64)>)> = inputs.to_vec();
    sorted.sort_by_key(|(address, _)| *address);
    sorted.dedup_by_key(|(address, _)| *address);
    let mut arrays = Vec::new();
    let mut current: Vec<(u64, Vec<(u32, u64)>)> = Vec::new();
    for (address, rows) in sorted {
        let contiguous = current
            .last()
            .is_some_and(|(prev, _)| prev.checked_add(32) == Some(address));
        if !contiguous && !current.is_empty() {
            arrays.push(std::mem::take(&mut current));
        }
        current.push((address, rows));
    }
    if !current.is_empty() {
        arrays.push(current);
    }
    arrays
        .into_iter()
        .map(|run| StaticArray {
            records: run
                .into_iter()
                .map(|(_, mut rows)| {
                    rows.sort_by_key(|(id, _)| *id);
                    rows.dedup_by_key(|(id, _)| *id);
                    let functions = rows.iter().map(|(id, _)| *id).collect();
                    StaticRecord {
                        functions,
                        entries: rows,
                    }
                })
                .collect(),
        })
        .collect()
}

/// Exact content match: same record count, live indices dense from 0
/// (a live table is one contiguous array, so any gap means a truncated
/// observation), and identical per-index function-ID sets in order. No
/// fuzzy matching, no subset matching.
fn array_matches(array: &StaticArray, live: &LiveQuery) -> bool {
    if array.records.len() != live.algos.len() {
        return false;
    }
    if !live
        .algos
        .iter()
        .enumerate()
        .all(|(position, (index, _))| *index as usize == position)
    {
        return false;
    }
    array
        .records
        .iter()
        .zip(live.algos.iter())
        .all(|(record, (_, funs))| record.functions == *funs)
}

/// First-slice (operation, function) to copied-role map. Pinned against
/// [`admission_parts`](osslscope_bpf_contract::attribution::TypedAdmission::admission_parts)
/// by `copied_role_matches_admission_table` below: any skew fails loud.
pub(crate) fn copied_role(operation: u32, function: u32) -> Option<u32> {
    match (operation, function) {
        (3, 1) => Some(258),
        (4, 1) => Some(259),
        (3, 3) => Some(274),
        (4, 3) => Some(275),
        (3, 2) => Some(290),
        (4, 2) => Some(291),
        (3, 4) => Some(304),
        (3, 5) => Some(305),
        (3, 6) => Some(306),
        (4, 5) => Some(307),
        (4, 4) => Some(308),
        _ => None,
    }
}

/// One staged copied-role site: role plus retained file offset. The
/// operation rides the role (see [`copied_role`]); pass 2 verifies
/// (offset, function) membership against the retained file before attach.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PlannedSite {
    pub file_hash: ObjectHash,
    pub role_id: u32,
    pub offset: u64,
}

/// Staging plan: verified (role, offset) sites from observed callbacks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CopiedPlan {
    pub sites: Vec<PlannedSite>,
}

impl CopiedPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    pub(crate) fn sites_for(&self, hash: &ObjectHash) -> Vec<&PlannedSite> {
        self.sites
            .iter()
            .filter(|site| &site.file_hash == hash)
            .collect()
    }
}

/// Unique-or-refuse across all files: an op stages only on exactly one
/// matching array. Ambiguous (two arrays match) or unmatched ops refuse.
fn match_op(
    arrays: &[(ObjectHash, StaticArray)],
    query: &LiveQuery,
) -> Option<(ObjectHash, StaticArray)> {
    let mut matches = arrays
        .iter()
        .filter(|(_, array)| array_matches(array, query))
        .map(|(hash, array)| (hash.clone(), array.clone()));
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first)
}

/// Generate a staging plan: exact-match each kept live query against the
/// retained files' static arrays. An op stages only on exactly one
/// matching array (unique-or-refuse across all files); within a matched
/// array only in-slice (role-mapped) entries stage. Partial tables never
/// match (their row sets are incomplete by construction).
#[allow(dead_code)] // Wired by U1 native drivers; product orchestration is a U5 carryover.
pub(crate) fn generate_plan(
    files: &[FileArrays],
    live: &[LiveQuery],
    budget: &crate::provider_observation::ObservationBudget,
) -> Result<CopiedPlan, crate::provider_observation::ObservationGap> {
    let mut arrays: Vec<(ObjectHash, StaticArray)> = Vec::new();
    for file in files {
        for array in group_arrays(&file.inputs) {
            arrays.push((file.hash.clone(), array));
        }
    }
    let mut sites = BTreeSet::new();
    for query in live {
        let Some((hash, array)) = match_op(&arrays, query) else {
            continue;
        };
        for record in &array.records {
            for (function, offset) in &record.entries {
                if let Some(role_id) = copied_role(query.operation, *function) {
                    budget.state(std::mem::size_of::<PlannedSite>())?;
                    sites.insert(PlannedSite {
                        file_hash: hash.clone(),
                        role_id,
                        offset: *offset,
                    });
                }
            }
        }
    }
    Ok(CopiedPlan {
        sites: sites.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::wire::{TypedAdmission, TypedRoleId};

    #[test]
    fn copied_role_matches_admission_table() {
        // Every matcher role maps to its contract (api, op, fun) triple,
        // and every copied triple in the contract maps back. Any skew
        // between matcher and contract fails here, loudly.
        let pairs = [
            (3u32, 1u32, 258u32),
            (4, 1, 259),
            (3, 3, 274),
            (4, 3, 275),
            (3, 2, 290),
            (4, 2, 291),
            (3, 4, 304),
            (3, 5, 305),
            (3, 6, 306),
            (4, 5, 307),
            (4, 4, 308),
        ];
        for (op, fun, role) in pairs {
            assert_eq!(copied_role(op, fun), Some(role));
            let (_, admit_op, admit_fun) = TypedAdmission::admission_parts(role).unwrap();
            assert_eq!((admit_op, admit_fun), (op, fun));
        }
        for op in [3, 4] {
            for fun in 0..64 {
                let role = copied_role(op, fun);
                if pairs.iter().any(|(o, f, _)| (*o, *f) == (op, fun)) {
                    assert!(role.is_some());
                } else {
                    assert_eq!(role, None, "op {op} fun {fun} must not map");
                }
            }
        }
        for role in [258u32, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308] {
            let id = TypedRoleId::from_u32(role).unwrap();
            assert_eq!(id.public_export(), None);
        }
    }

    fn record(kind: u32, pid: u32, tid: u32, invocation: u64) -> c::Record {
        let mut record = c::Record::default();
        record.kind = kind;
        record.api = c::PUBLIC_QUERY;
        record.pid = pid;
        record.tid = tid;
        record.invocation = invocation;
        record
    }

    fn query(pid: u32, tid: u32, invocation: u64, op: u32, outcome: u32, cache: u32) -> c::Record {
        let mut record = record(c::QUERY, pid, tid, invocation);
        record.operation = op;
        record.outcome = outcome;
        record.cacheability = cache;
        record
    }

    fn implementation(
        pid: u32,
        tid: u32,
        invocation: u64,
        op: u32,
        index: u32,
        fun: u32,
    ) -> c::Record {
        let mut record = record(c::IMPLEMENTATION, pid, tid, invocation);
        record.operation = op;
        record.algorithm_index = index;
        record.function = fun;
        record.outcome = 0;
        record.cacheability = 1;
        record
    }

    #[test]
    fn collect_groups_per_query_and_op() {
        let records = vec![
            query(7, 7, 1, 3, 1, 1),
            implementation(7, 7, 1, 3, 0, 1),
            implementation(7, 7, 1, 3, 0, 2),
            implementation(7, 7, 1, 3, 1, 1),
            query(7, 7, 2, 4, 1, 1),
            implementation(7, 7, 2, 4, 0, 5),
        ];
        let live = collect_live_queries(&records);
        assert_eq!(live.len(), 2);
        assert_eq!(live[0].operation, 3);
        assert_eq!(live[0].algos, vec![(0, vec![1, 2]), (1, vec![1])]);
        assert_eq!(live[1].operation, 4);
        assert_eq!(live[1].algos, vec![(0, vec![5])]);
    }

    #[test]
    fn collect_drops_no_store_failed_and_empty() {
        let records = vec![
            query(7, 7, 1, 3, 1, 2),
            implementation(7, 7, 1, 3, 0, 1),
            query(7, 7, 2, 3, 2, 1),
            implementation(7, 7, 2, 3, 0, 1),
            query(7, 7, 3, 5, 1, 1),
            implementation(7, 7, 3, 5, 0, 1),
            query(7, 7, 4, 3, 1, 1),
        ];
        assert!(collect_live_queries(&records).is_empty());
    }

    #[test]
    fn collect_refuses_disagreeing_repeats() {
        let same = vec![
            query(7, 7, 1, 3, 1, 1),
            implementation(7, 7, 1, 3, 0, 1),
            query(7, 8, 1, 3, 1, 1),
            implementation(7, 8, 1, 3, 0, 1),
        ];
        assert_eq!(collect_live_queries(&same).len(), 1);
        let disagree = vec![
            query(7, 7, 1, 3, 1, 1),
            implementation(7, 7, 1, 3, 0, 1),
            query(7, 8, 1, 3, 1, 1),
            implementation(7, 8, 1, 3, 0, 2),
        ];
        assert!(collect_live_queries(&disagree).is_empty());
    }

    #[test]
    fn arrays_group_by_stride_32_runs() {
        let inputs = vec![
            (0x1000u64, vec![(1u32, 0x100u64)]),
            (0x1020, vec![(1u32, 0x200u64)]),
            (0x1040, vec![(1u32, 0x300u64)]),
            (0x1060, vec![(1u32, 0x400u64)]),
            (0x2000, vec![(2u32, 0x500u64)]),
            // A stride-8 neighbor is not array-contiguous: it splits runs.
            (0x1008, vec![(9u32, 0x900u64)]),
        ];
        let arrays = group_arrays(&inputs);
        assert_eq!(arrays.len(), 4);
        assert_eq!(arrays[0].records.len(), 1);
        assert_eq!(arrays[0].records[0].functions, vec![1]);
        assert_eq!(arrays[1].records.len(), 1);
        assert_eq!(arrays[1].records[0].functions, vec![9]);
        assert_eq!(arrays[2].records.len(), 3);
        assert_eq!(arrays[2].records[0].functions, vec![1]);
        assert_eq!(arrays[3].records.len(), 1);
    }

    fn hash(byte: u8) -> ObjectHash {
        ObjectHash::try_from(format!("{:02x}", byte).repeat(32)).unwrap()
    }

    #[test]
    fn match_op_is_unique_or_refuse() {
        let array = || StaticArray {
            records: vec![StaticRecord {
                functions: vec![1, 2],
                entries: vec![(1, 0x100), (2, 0x200)],
            }],
        };
        let live = LiveQuery {
            operation: 3,
            algos: vec![(0, vec![1, 2])],
        };
        let arrays = vec![(hash(0xaa), array())];
        assert!(match_op(&arrays, &live).is_some());
        assert!(match_op(&[], &live).is_none());
        let ambiguous = vec![(hash(0xaa), array()), (hash(0xbb), array())];
        assert!(match_op(&ambiguous, &live).is_none());
        let other = StaticArray {
            records: vec![StaticRecord {
                functions: vec![1, 3],
                entries: vec![(1, 0x100), (3, 0x300)],
            }],
        };
        let distinct = vec![(hash(0xaa), array()), (hash(0xbb), other)];
        let matched = match_op(&distinct, &live).unwrap();
        assert_eq!(matched.0, hash(0xaa));
    }

    #[test]
    fn array_match_is_exact_and_dense() {
        let array = StaticArray {
            records: vec![
                StaticRecord {
                    functions: vec![1, 2],
                    entries: vec![(1, 0x100), (2, 0x200)],
                },
                StaticRecord {
                    functions: vec![1],
                    entries: vec![(1, 0x300)],
                },
            ],
        };
        let live = LiveQuery {
            operation: 3,
            algos: vec![(0, vec![1, 2]), (1, vec![1])],
        };
        assert!(array_matches(&array, &live));
        let subset = LiveQuery {
            operation: 3,
            algos: vec![(0, vec![1])],
        };
        assert!(!array_matches(&array, &subset));
        let gapped = LiveQuery {
            operation: 3,
            algos: vec![(0, vec![1, 2]), (2, vec![1])],
        };
        assert!(!array_matches(&array, &gapped));
        let reordered = LiveQuery {
            operation: 3,
            algos: vec![(0, vec![1]), (1, vec![1, 2])],
        };
        assert!(!array_matches(&array, &reordered));
    }
}
