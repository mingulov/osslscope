// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded joins of finite alias metadata. No target address or opaque handle.
use super::{AlgorithmId, AliasQuality, ObservationBudget, ObservationGap, wire::contract as c};
use std::collections::BTreeMap;

type Thread = (u32, u32, u64);
struct Sequence {
    identity: [u64; 6],
    evidence: c::FiniteEvidence,
    next: u32,
    valid: bool,
    ended: bool,
    algorithm: Option<(AlgorithmId, AliasQuality)>,
}
#[derive(Default)]
pub(crate) struct Sequences(BTreeMap<Thread, Sequence>);
fn thread(r: &c::Record) -> Thread {
    (r.pid, r.tid, r.generation)
}
fn identity(r: &c::Record) -> [u64; 6] {
    [
        r.cookie,
        r.invocation,
        r.api as u64,
        r.operation as u64,
        r.cacheability as u64,
        r.algorithm_index as u64,
    ]
}
pub(crate) fn other() -> AlgorithmId {
    AlgorithmId::try_from(u16::MAX).unwrap()
}
impl Sequences {
    pub(crate) fn begin(
        &mut self,
        r: &c::Record,
        budget: &ObservationBudget,
    ) -> Result<(), ObservationGap> {
        let key = thread(r);
        if r.outcome != 1 {
            self.0.remove(&key);
            return Ok(());
        }
        if let Some(previous) = self.0.get_mut(&key) {
            if previous.identity == identity(r) {
                previous.valid = false;
                previous.algorithm = None;
                return Err(ObservationGap::InvalidWire);
            }
        } else {
            if self.0.len() >= budget.limits.max_pending_calls {
                return Err(ObservationGap::PendingLimit);
            }
            // Covers key/value and BTree node overhead; reserved before insertion.
            budget.state(256)?;
        }
        let old = self.0.insert(
            key,
            Sequence {
                identity: identity(r),
                evidence: c::FiniteEvidence::new(),
                next: 0,
                valid: true,
                ended: false,
                algorithm: None,
            },
        );
        if old.is_some_and(|s| !s.ended) {
            Err(ObservationGap::IntervalUnknown)
        } else {
            Ok(())
        }
    }
    fn get(&mut self, r: &c::Record) -> Result<&mut Sequence, ObservationGap> {
        let s = self
            .0
            .get_mut(&thread(r))
            .ok_or(ObservationGap::IntervalUnknown)?;
        if s.identity != identity(r) || !s.valid {
            s.valid = false;
            s.algorithm = None;
            return Err(ObservationGap::IntervalUnknown);
        }
        Ok(s)
    }
    pub(crate) fn alias(&mut self, r: &c::Record) -> Result<(), ObservationGap> {
        let s = self.get(r)?;
        if s.ended || s.next != r.status || s.next >= 8 {
            s.valid = false;
            s.algorithm = None;
            return Err(ObservationGap::InvalidWire);
        }
        s.evidence
            .include(r.algorithm as u16, r.outcome as u8, r.function as u16);
        s.next += 1;
        Ok(())
    }
    pub(crate) fn end(&mut self, r: &c::Record) -> Result<(AlgorithmId, u8, bool), ObservationGap> {
        let s = self.get(r)?;
        if s.ended || s.next != r.function {
            s.valid = false;
            s.algorithm = None;
            return Err(ObservationGap::InvalidWire);
        }
        let (class, weak, status) = if r.status == 2 || r.status == 4 {
            (u16::MAX, false, r.status as u8)
        } else {
            s.evidence.finish(r.status == 3)
        };
        let algorithm = AlgorithmId::try_from(class).map_err(|_| ObservationGap::InvalidWire)?;
        s.ended = true;
        s.algorithm = Some((algorithm, AliasQuality::from_fold(status, weak)));
        Ok((algorithm, status, weak))
    }
    pub(crate) fn implementation(
        &mut self,
        r: &c::Record,
    ) -> Result<(AlgorithmId, AliasQuality), ObservationGap> {
        let s = self.get(r)?;
        if !s.ended {
            s.valid = false;
        }
        s.algorithm.ok_or(ObservationGap::IntervalUnknown)
    }
    pub(crate) fn retire(&mut self, pid: u32) {
        self.0.retain(|&(p, _, _), _| p != pid);
    }
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
    pub(crate) fn incomplete(&self) -> bool {
        self.0.values().any(|s| !s.ended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_observation::{ObservationLimits, wire};
    fn query() -> c::Record {
        c::Record {
            version: c::VERSION,
            size: 96,
            kind: c::QUERY,
            api: c::QUERY_CALLBACK,
            pid: 1,
            tid: 2,
            cookie: 3,
            generation: 4,
            invocation: 5,
            outcome: 1,
            operation: 1,
            cacheability: 1,
            ..c::Record::default()
        }
    }
    fn known(mut r: c::Record, index: u32) -> c::Record {
        let label = crate::kinds::ALG_NAMES[0].name;
        r.kind = c::ALIAS;
        r.status = index;
        r.algorithm = 0;
        r.function = crate::kinds::algorithm_semantic_id(label).unwrap() as u32;
        r.outcome = u32::from(crate::kinds::is_weak_alg(label));
        r
    }
    fn end(mut r: c::Record, count: u32, status: u32) -> c::Record {
        r.kind = c::ALIAS_END;
        r.algorithm = c::OTHER;
        r.function = count;
        r.outcome = 0;
        r.status = status;
        r
    }
    fn decode(r: c::Record) -> Result<wire::Transport, ObservationGap> {
        let bytes = unsafe { std::slice::from_raw_parts((&r as *const c::Record).cast(), 96) };
        wire::decode_transport(bytes)
    }
    #[test]
    fn adjacent_algorithms_in_one_return_have_separate_alias_boundaries() {
        let q = query();
        let mut s = Sequences::default();
        let b = ObservationBudget::default();
        s.begin(&q, &b).unwrap();
        s.alias(&known(q, 0)).unwrap();
        s.end(&end(q, 1, 0)).unwrap();
        let mut next = q;
        next.algorithm_index = 1;
        s.begin(&next, &b)
            .expect("a different bounded algorithm ordinal starts its own sequence");
        assert!(
            s.implementation(&next).is_err(),
            "previous algorithm cannot label the next one"
        );
    }
    #[test]
    fn complete_sequence_labels_only_matching_implementation() {
        let q = query();
        let mut s = Sequences::default();
        let b = ObservationBudget::default();
        s.begin(&q, &b).unwrap();
        s.alias(&decode(known(q, 0)).unwrap().record()).unwrap();
        assert_eq!(
            u16::from(s.end(&decode(end(q, 1, 0)).unwrap().record()).unwrap().0),
            0
        );
        assert_eq!(u16::from(s.implementation(&q).unwrap().0), 0);
        let mut stale = q;
        stale.invocation += 1;
        assert!(s.implementation(&stale).is_err());
        assert!(s.implementation(&q).is_err());
    }
    #[test]
    fn missing_duplicate_out_of_order_and_mismatched_end_fail_closed() {
        let q = query();
        let b = ObservationBudget::default();
        for index in [1, 7] {
            let mut s = Sequences::default();
            s.begin(&q, &b).unwrap();
            assert!(s.alias(&known(q, index)).is_err());
            assert!(s.end(&end(q, 1, 0)).is_err());
        }
        let mut s = Sequences::default();
        s.begin(&q, &b).unwrap();
        s.alias(&known(q, 0)).unwrap();
        assert!(s.implementation(&q).is_err());
        assert!(s.end(&end(q, 1, 0)).is_err());
        let mut s = Sequences::default();
        s.begin(&q, &b).unwrap();
        assert!(s.end(&end(q, 1, 0)).is_err());
        assert!(s.implementation(&q).is_err());
        let mut s = Sequences::default();
        s.begin(&q, &b).unwrap();
        s.alias(&known(q, 0)).unwrap();
        assert!(s.alias(&known(q, 0)).is_err());
        assert!(s.end(&end(q, 1, 0)).is_err());
        let mut s = Sequences::default();
        s.begin(&q, &b).unwrap();
        s.alias(&known(q, 0)).unwrap();
        s.end(&end(q, 1, 0)).unwrap();
        assert!(s.end(&end(q, 1, 0)).is_err());
    }
    #[test]
    fn finite_fold_preserves_mixed_weak_unknown_and_truncation() {
        let mut e = c::FiniteEvidence::new();
        e.include(7, 0, 10);
        e.include(2, 1, 11);
        assert_eq!(e.finish(false), (2, true, 5));
        assert_eq!(e.finish(true), (2, true, 3));
        let mut e = c::FiniteEvidence::new();
        e.include(7, 0, 10);
        e.include(2, 0, 10);
        assert_eq!(e.finish(false), (2, false, 0));
        let mut e = c::FiniteEvidence::new();
        e.include(u16::MAX, 1, u16::MAX);
        assert_eq!(e.finish(false), (u16::MAX, true, 1));
        let q = query();
        let mut s = Sequences::default();
        s.begin(&q, &ObservationBudget::default()).unwrap();
        for i in 0..8 {
            s.alias(&known(q, i)).unwrap();
        }
        assert_eq!(s.end(&end(q, 8, 3)).unwrap().1, 3);
        for status in [2, 4] {
            let mut s = Sequences::default();
            s.begin(&q, &ObservationBudget::default()).unwrap();
            let out = s.end(&end(q, 0, status)).unwrap();
            assert_eq!(out, (other(), status as u8, false));
        }
    }
    #[test]
    fn loss_retirement_caps_and_new_invocation_cannot_reuse_evidence() {
        let q = query();
        let b = ObservationBudget::new(ObservationLimits {
            max_pending_calls: 1,
            ..Default::default()
        });
        let mut s = Sequences::default();
        s.begin(&q, &b).unwrap();
        s.alias(&known(q, 0)).unwrap();
        s.end(&end(q, 1, 0)).unwrap();
        let mut next = q;
        next.tid += 1;
        assert_eq!(s.begin(&next, &b), Err(ObservationGap::PendingLimit));
        next = q;
        next.invocation += 1;
        s.begin(&next, &b).unwrap();
        assert!(s.end(&end(q, 1, 0)).is_err());
        assert!(s.implementation(&next).is_err());
        s.clear();
        assert!(s.implementation(&q).is_err());
        s.begin(&q, &b).unwrap();
        s.retire(q.pid);
        assert!(s.end(&end(q, 1, 0)).is_err());
        let b = ObservationBudget::new(ObservationLimits {
            max_state_bytes: 255,
            ..Default::default()
        });
        assert_eq!(
            Sequences::default().begin(&q, &b),
            Err(ObservationGap::StateLimit)
        );
    }
    #[test]
    fn internal_wire_rejects_unregistered_metadata_and_code() {
        let q = query();
        assert!(decode(known(q, 0)).is_ok());
        let r = known(q, 0);
        let bytes = unsafe { std::slice::from_raw_parts((&r as *const c::Record).cast(), 96) };
        assert!(
            wire::decode(bytes).is_err(),
            "internal aliases are not public facts"
        );
        let mut old = r;
        old.version = 1;
        assert!(decode(old).is_err());
        assert!(decode(end(q, 1, 0)).is_ok());
        for field in [0, 1, 2, 3, 4, 5, 6] {
            let mut r = known(q, 0);
            match field {
                0 => r.algorithm = 65534,
                1 => r.function ^= 1,
                2 => r.outcome ^= 1,
                3 => r.status = 8,
                4 => r.code = 4096,
                5 => r.reserved = 1,
                _ => r.api = c::LOAD,
            }
            assert!(decode(r).is_err(), "field {field}");
        }
        assert!(decode(end(q, 0, 0)).is_err());
        assert!(decode(end(q, 7, 3)).is_err());
        let mut r = q;
        r.kind = c::IMPLEMENTATION;
        r.algorithm = 0;
        r.outcome = 0;
        assert!(
            decode(r).is_err(),
            "implementation cannot guess its algorithm"
        );
    }
}
