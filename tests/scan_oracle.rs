//! SPDX-License-Identifier: GPL-3.0-or-later
//! Oracle stream scenarios (item 4): multi-invocation batches,
//! attribution, guard/TRUNC dispositions, and cross-batch
//! closure through the public `scan::oracle` API. Unit rules
//! live in `src/scan/oracle.rs`; live producer legs live in
//! `tests/members_probe.rs` (lane-gated).

use osslscope::scan::oracle::*;
use osslscope_ebpf_common as wire;

const TIDA: u32 = 1111;
const TIDB: u32 = 2222;
const ARR: u64 = 0x7000;
const OP: u32 = 7;

fn call(tid: u32, seq: u64, hint: bool, cause: u8) -> wire::ScanCallEvent {
    wire::ScanCallEvent {
        kind: wire::KIND_SCAN_CALL,
        op: OP,
        tid,
        flags: wire::make_call_flags(hint, cause),
        seq,
    }
}

fn ret(tid: u32, seq: u64, generation: u64) -> wire::ScanRetEvent {
    wire::ScanRetEvent {
        kind: wire::KIND_SCAN_RET,
        op: OP,
        flags: 0,
        tid,
        seq,
        arr: ARR,
        generation,
    }
}

fn alg(tid: u32, seq: u64, idx: u64, status: u8) -> wire::ScanAlgEvent {
    wire::ScanAlgEvent {
        kind: wire::KIND_SCAN_ALG,
        op: OP,
        class: 1,
        status,
        weak: 0,
        _pad: 0,
        arr: ARR,
        idx,
        generation: 0,
        tid,
        _pad2: 0,
        seq,
    }
}

fn guard(tid: u32, seq: u64, verdict: u32) -> wire::GuardEvent {
    wire::GuardEvent {
        kind: wire::KIND_GUARD,
        op: OP,
        verdict,
        tid,
        seq,
        arr: ARR,
        generation: 0,
    }
}

fn quiesced_idle(tids: &[u32]) -> ScanBatch {
    let mut b = ScanBatch {
        quiesced: true,
        ..ScanBatch::default()
    };
    for t in tids {
        b.rcount.insert(*t, (0, wire::RCOUNT_STATE_IDLE));
    }
    b
}

/// Two interleaved tids, each cold-complete: joins stay per-tid.
#[test]
fn stream_two_tids_cold_complete() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA, TIDB]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.calls.push(call(TIDB, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    b.rets.push(ret(TIDB, 0, 0));
    for j in 0..2 {
        b.algs.push(alg(TIDA, 0, j, wire::ALG_OK));
    }
    for j in 0..5 {
        b.algs.push(alg(TIDB, 0, j, wire::ALG_OK));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 2);
    let a = o.done().iter().find(|w| w.tid == TIDA).unwrap();
    let bb = o.done().iter().find(|w| w.tid == TIDB).unwrap();
    assert_eq!(a.true_t, TrueT::Proven(2));
    assert_eq!(bb.true_t, TrueT::Proven(5));
    assert!(matches!(a.outcome, Outcome::Complete { .. }));
    assert!(matches!(bb.outcome, Outcome::Complete { .. }));
    assert!(o.findings().is_empty());
}

/// 512-live cold table: all slots covered + GUARD EMPTY ⟹
/// Proven(512), Complete (the guard read slot 512 empty —
/// clean-full proof).
#[test]
fn stream_full_table_guard_empty() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.algs.push(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.guards.push(guard(TIDA, 0, wire::GUARD_EMPTY));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(512));
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
}

/// GUARD VALID (slot 512 live — 513-live contract violation) ⟹
/// PARTIAL with Overfull + TRUE-T Candidate(512) (the table
/// extends beyond observation; TRUNC_ALGS corroborates).
#[test]
fn stream_guard_valid_overfull() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.algs.push(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.guards.push(guard(TIDA, 0, wire::GUARD_VALID));
    b.trunc.insert(OP, wire::TRUNC_ALGS);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(512));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Overfull)
    ));
}

/// GUARD ERROR ⟹ PARTIAL (guard disposition inconsistent).
#[test]
fn stream_guard_error_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.algs.push(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.guards.push(guard(TIDA, 0, wire::GUARD_ERROR));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::GuardError)
    ));
}

/// UNREADABLE slots ⟹ PARTIAL with the explicit set.
#[test]
fn stream_unreadable_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    b.algs.push(alg(TIDA, 0, 0, wire::ALG_OK));
    b.algs.push(alg(TIDA, 0, 1, wire::ALG_UNREADABLE));
    b.algs.push(alg(TIDA, 0, 2, wire::ALG_OK));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Unreadable(vec![1]))
    ));
}

/// Structural TRUNC bits ⟹ PARTIAL; observation bits
/// (WALK_EMPTY/WALK_NOIMP/NO_STORE) stay Complete-compatible.
#[test]
fn stream_trunc_structural_vs_observation() {
    // Structural: TRUNC_DISPATCH ⟹ PARTIAL.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    b.algs.push(alg(TIDA, 0, 0, wire::ALG_OK));
    b.trunc.insert(OP, wire::TRUNC_DISPATCH);
    o.ingest(&b);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(wire::TRUNC_DISPATCH))
    ));
    // Observation: NOIMP + EMPTY + NO_STORE ⟹ Complete.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    b.algs.push(alg(TIDA, 0, 0, wire::ALG_OK));
    b.trunc.insert(
        OP,
        wire::TRUNC_WALK_NOIMP | wire::TRUNC_WALK_EMPTY | wire::TRUNC_NO_STORE,
    );
    o.ingest(&b);
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
}

/// Warm + walked beyond the cached T ⟹ stale belief ⟹
/// Candidate (the walkers prove the members ran cold).
#[test]
fn stream_warm_stale_candidate() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 5));
    for j in 0..6 {
        b.algs.push(alg(TIDA, 0, j, wire::ALG_OK));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    // Table runs to 6 (all covered, first absence 6) but the
    // belief said 2 ⟹ Candidate(6), still Complete (no holes
    // in the evidenced range).
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(6));
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
}

/// Churn attribution: a hinted take + LOSS_SCAN_CHURNED with a
/// single candidate tid converts the taint into Churned.
#[test]
fn stream_churn_attributed() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.calls.push(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    b2.loss.insert(wire::LOSS_SCAN_CHURNED, 1);
    o.ingest(&b2);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Abandoned {
            reason: AbandonReason::Churned
        }
    ));
    assert!(o.findings().is_empty());
}

/// Two candidate tids ⟹ the LOSS delta stays unattributed
/// (explicit finding, never guessed).
#[test]
fn stream_loss_unattributed_two_candidates() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.calls.push(call(TIDB, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.calls.push(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    b2.calls.push(call(TIDB, 1, true, wire::SKIP_ADMITTED));
    b2.loss.insert(wire::LOSS_SCAN_EVICTED, 1);
    o.ingest(&b2);
    // Both predecessors stay Tainted; the delta is an explicit
    // unattributed-loss finding.
    assert!(
        o.done()
            .iter()
            .all(|w| matches!(w.outcome, Outcome::Tainted { .. }))
    );
    assert!(o.findings().contains(&Finding::UnattributedLoss {
        id: wire::LOSS_SCAN_EVICTED,
        delta: 1
    }));
}

/// Ring loss corroborates holes (DrainLoss reason).
#[test]
fn stream_drain_loss_corroborates_holes() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.rets.push(ret(TIDA, 0, 0));
    b.algs.push(alg(TIDA, 0, 0, wire::ALG_OK));
    b.algs.push(alg(TIDA, 0, 2, wire::ALG_OK)); // hole at 1
    b.loss.insert(wire::LOSS_RING_ALG, 1);
    o.ingest(&b);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::DrainLoss)
            && reasons.iter().any(|r| matches!(r, PartialReason::Holes(_)))
    ));
}

/// Cross-batch: RET split across a drain boundary still joins
/// (opens persist until a sound close fires).
#[test]
fn stream_ret_across_drain_boundary() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.algs.push(alg(TIDA, 0, 0, wire::ALG_OK));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    let mut b2 = quiesced_idle(&[TIDA]);
    b2.rets.push(ret(TIDA, 0, 0));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
}

/// Worst-scan recompute is exported consistently (the const
/// asserts in the module are the re-verification; this pins
/// the headline numbers for the report).
#[test]
fn stream_worst_scan_numbers() {
    assert_eq!(ONRING_CALL, 32);
    assert_eq!(ONRING_RET, 48);
    assert_eq!(ONRING_GUARD, 48);
    assert_eq!(ONRING_SCAN_ALG, 64);
    assert_eq!(ONRING_SCAN_ROW, 72);
    assert_eq!(WORST_SCAN_BYTES, 4_751_488);
    // (The two-way-race fit itself is a compile-time const-assert
    // in the module — the re-verification that cannot drift.)
}

/// OracleScope double-checks EXPECTED == attached.len().
#[test]
#[should_panic(expected = "EXPECTED matches")]
fn stream_scope_expected_mismatch_panics() {
    let mut scope = OracleScope::full();
    scope.expected = 4; // attached still 512
    let _ = Oracle::new(scope);
}

#[test]
fn stream_drain_stats_accumulate() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = quiesced_idle(&[TIDA]);
    b1.calls.push(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = quiesced_idle(&[TIDA]);
    b2.calls.push(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    let s = o.stats();
    assert_eq!(s.batches, 2);
    assert_eq!(s.calls, 2);
    assert_eq!(s.records, 2);
    assert_eq!(s.bytes, 2 * ONRING_CALL);
}
