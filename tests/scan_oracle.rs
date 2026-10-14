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

fn alg_arr(
    tid: u32,
    seq: u64,
    idx: u64,
    status: u8,
    arr: u64,
    generation: u64,
) -> wire::ScanAlgEvent {
    wire::ScanAlgEvent {
        kind: wire::KIND_SCAN_ALG,
        op: OP,
        class: if status == wire::ALG_OK {
            1
        } else {
            wire::OTHER_CLASS
        },
        status,
        weak: 0,
        _pad: 0,
        arr,
        idx,
        generation,
        tid,
        _pad2: 0,
        seq,
    }
}

fn row(tid: u32, seq: u64, idx: u64) -> wire::ScanRowEvent {
    wire::ScanRowEvent {
        kind: wire::KIND_SCAN_ROW,
        op: OP,
        funcid: 300,
        _pad: 0,
        addr: 0x4400,
        aux: 0,
        idx,
        generation: 0,
        tid,
        _pad2: 0,
        seq,
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_call(call(TIDB, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_ret(ret(TIDB, 0, 0));
    for j in 0..2 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
    for j in 0..5 {
        b.push_alg(alg(TIDB, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDB, 0, 5, wire::ALG_EMPTY, ARR, 0));
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_guard(guard(TIDA, 0, wire::GUARD_EMPTY));
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_guard(guard(TIDA, 0, wire::GUARD_VALID));
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_guard(guard(TIDA, 0, wire::GUARD_ERROR));
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg(TIDA, 0, 1, wire::ALG_UNREADABLE));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Unreadable(vec![1]))
    ));
}

/// Structural TRUNC bits ⟹ PARTIAL; observation bits
/// (WALK_EMPTY/WALK_NOIMP) stay Complete-compatible; NO_STORE is
/// never Complete-compatible (wire contract).
#[test]
fn stream_trunc_structural_vs_observation() {
    // Structural: TRUNC_DISPATCH ⟹ PARTIAL.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_DISPATCH);
    o.ingest(&b);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(wire::TRUNC_DISPATCH))
    ));
    // Observation: NOIMP + EMPTY ⟹ Complete.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc
        .insert(OP, wire::TRUNC_WALK_NOIMP | wire::TRUNC_WALK_EMPTY);
    o.ingest(&b);
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
    // NO_STORE ⟹ PARTIAL (never Complete-compatible).
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_NO_STORE);
    o.ingest(&b);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(wire::TRUNC_NO_STORE))
    ));
}

/// Warm + walked beyond the cached T ⟹ stale belief ⟹ fresh
/// terminator proven + CacheStale PARTIAL (the backend
/// invalidates from the reason; cold re-probe heals).
#[test]
fn stream_warm_stale_candidate() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    for j in 0..6 {
        b.push_alg(alg_arr(TIDA, 0, j, wire::ALG_OK, ARR, 5));
    }
    b.push_alg(alg_arr(TIDA, 0, 6, wire::ALG_EMPTY, ARR, 5));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    // Fresh EMPTY@6 proves T=6, contradicting the cached 2.
    assert_eq!(o.done()[0].true_t, TrueT::Proven(6));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheStale { cached: 2 })
    ));
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
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, true, wire::SKIP_ADMITTED));
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
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_call(call(TIDB, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    b2.push_call(call(TIDB, 1, true, wire::SKIP_ADMITTED));
    b2.loss.insert(wire::LOSS_SCAN_EVICTED, 1);
    o.ingest(&b2);
    // Hints alone never taint (all four stay open); the delta is
    // an explicit unattributed-loss finding.
    assert_eq!(o.open_count(), 4);
    assert!(o.done().is_empty());
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
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK)); // hole at 1
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
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    let mut b2 = quiesced_idle(&[TIDA]);
    b2.push_ret(ret(TIDA, 0, 0));
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

/// Finding 2: silence is not a terminator. Cold slots 0..2 with
/// no explicit EMPTY must NOT prove T=3 — the terminator is
/// unobserved (holes beyond the evidence + unproven T).
#[test]
fn fix1_cold_requires_explicit_terminator() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg(TIDA, 0, 1, wire::ALG_OK));
    assert!(b.order_sound());
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        !matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "silence must never complete: {:?}",
        o.done()[0]
    );
    assert!(
        !matches!(o.done()[0].true_t, TrueT::Proven(_)),
        "silence must never prove T: {:?}",
        o.done()[0]
    );
}

/// Finding 2: an explicit EMPTY record IS the terminator proof
/// (min-EMPTY over explicit records; beyond-T discarded).
#[test]
fn fix1_cold_explicit_empty_proves() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg(TIDA, 0, 1, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(2));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Complete {
            true_t: 2,
            cached: false
        }
    ));
}

/// Finding 2: 512 covered slots prove nothing without GUARD EMPTY
/// (the guard is the 512-terminator evidence).
#[test]
fn fix1_512_requires_guard_empty() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..512 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(512));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::GuardMissing)
    ));
}

/// Finding 2: NOIMP slots are stable walk observations (explicit
/// records) — compatible with a proven terminator, never a
/// shorter-table proof.
#[test]
fn fix1_noimp_slot_compatible() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_NOIMP, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
}

/// Findings 2+8: a fully-covered selective window proves the
/// window, not the terminator — Candidate + explicit PARTIAL for
/// the unobserved slots beyond the window.
#[test]
fn fix1_selective_edge_partial() {
    let mut scope = OracleScope::full();
    scope.attached = (0..4).collect();
    scope.expected = 4;
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..4 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(4));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons
            .iter()
            .any(|r| matches!(r, PartialReason::UnobservedSlots(_)))
    ));
}

/// Finding 3: ring loss observed mid-invocation is retained — a
/// quiet closing batch does not wash it away.
#[test]
fn fix1_loss_retained_across_drains() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg(TIDA, 0, 2, wire::ALG_OK)); // hole at 1
    b1.loss.insert(wire::LOSS_RING_ALG, 1);
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::DrainLoss)
            && reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Holes(h) if h.contains(&1)))
    ));
}

/// Finding 3: structural TRUNC observed mid-invocation is retained
/// across the drain boundary.
#[test]
fn fix1_trunc_retained_across_drains() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.trunc.insert(OP, wire::TRUNC_DISPATCH);
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons
            .contains(&PartialReason::Trunc(wire::TRUNC_DISPATCH))
    ));
}

/// Finding 3: ring loss with no evaluable invocation is a window
/// finding, never dropped.
#[test]
fn fix1_window_loss_finding() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b.loss.insert(wire::LOSS_RING_ALG, 3);
    o.ingest(&b);
    assert!(o.done().is_empty());
    assert!(o.findings().contains(&Finding::WindowLoss { delta: 3 }));
}

/// Finding 4: a skip AFTER the RET in the same drain leaves the
/// RET-joined invocation closable (CALLs-before-RETs processing
/// would abandon it before its earlier RET joins).
#[test]
fn fix1_causal_close_before_skip() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_call(call(TIDA, 0, false, wire::SKIP_RING_PRESSURE));
    assert!(b.order_sound());
    o.ingest(&b);
    // (Skipped records also carry seq 0 — select the admitted key.)
    let seq0 = o
        .done()
        .iter()
        .find(|w| w.seq == 0 && !matches!(w.outcome, Outcome::Skipped { .. }))
        .unwrap();
    assert!(matches!(seq0.outcome, Outcome::Complete { .. }), "{seq0:?}");
    assert!(o.done().iter().any(|w| matches!(
        w.outcome,
        Outcome::Skipped { cause } if cause == wire::SKIP_RING_PRESSURE
    )));
}

/// Finding 4: a kernel hint alone never taints (hint +
/// rule-hit = nested certain; hint alone = stale-retire race,
/// ignored when the evidence closes clean).
#[test]
fn fix1_hint_alone_no_taint() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.open_count(), 2, "hint alone keeps both open");
    assert!(o.done().is_empty());
    let mut b3 = quiesced_idle(&[TIDA]);
    b3.push_ret(ret(TIDA, 0, 0));
    b3.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b3.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b3.push_ret(ret(TIDA, 1, 0));
    b3.push_alg(alg(TIDA, 1, 0, wire::ALG_OK));
    b3.push_alg(alg_arr(TIDA, 1, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b3);
    assert_eq!(o.done().len(), 2);
    assert!(
        o.done()
            .iter()
            .all(|w| matches!(w.outcome, Outcome::Complete { .. })),
        "{:?}",
        o.done()
    );
}

/// Finding 4: a duplicate slot taints BOTH invocations, keeps the
/// first record, and raises explicit findings.
#[test]
fn fix1_duplicate_slot_taints_both() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    b2.push_ret(ret(TIDA, 0, 0));
    b2.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b2.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_OK, ARR, 0)); // same slot again
    o.ingest(&b2);
    // Predecessor taints immediately; the successor carries the
    // sticky taint to its close.
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Tainted { by_seq: 1 }
    ));
    assert_eq!(o.done()[0].op, UNKNOWN_OP);
    assert_eq!(o.done()[0].alg_count, 1, "first record kept");
    assert!(o.findings().contains(&Finding::DuplicateSlot {
        tid: TIDA,
        seq: 0,
        idx: 0
    }));
    assert!(o.findings().contains(&Finding::Nested {
        tid: TIDA,
        seq: 0,
        by_seq: 1
    }));
    let mut b3 = quiesced_idle(&[TIDA]);
    b3.push_ret(ret(TIDA, 1, 0));
    b3.push_alg(alg(TIDA, 1, 0, wire::ALG_OK));
    b3.push_alg(alg_arr(TIDA, 1, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b3);
    let s1 = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(matches!(s1.outcome, Outcome::Tainted { .. }), "{s1:?}");
    assert_eq!(s1.op, UNKNOWN_OP);
}

/// Finding 4: slot evidence from a second array under one key
/// taints both invocations (multi-array rule).
#[test]
fn fix1_multi_array_taints_both() {
    const ARRB: u64 = 0x8000;
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, true, wire::SKIP_ADMITTED));
    b2.push_ret(ret(TIDA, 0, 0));
    b2.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b2.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_OK, ARRB, 0));
    o.ingest(&b2);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Tainted { by_seq: 1 }
    ));
    assert_eq!(o.done()[0].op, UNKNOWN_OP);
    assert!(o.findings().contains(&Finding::Nested {
        tid: TIDA,
        seq: 0,
        by_seq: 1
    }));
    let mut b3 = quiesced_idle(&[TIDA]);
    b3.push_ret(ret(TIDA, 1, 0));
    b3.push_alg(alg(TIDA, 1, 0, wire::ALG_OK));
    b3.push_alg(alg_arr(TIDA, 1, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b3);
    let s1 = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(matches!(s1.outcome, Outcome::Tainted { .. }), "{s1:?}");
}

/// Finding 4: slot evidence generations must agree with the RET
/// generation (cross-epoch joins are explicit PARTIAL).
#[test]
fn fix1_gen_mismatch_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    b.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_OK, ARR, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::GenMixed)
    ));
}

/// Finding 5: NO_STORE is never Complete-compatible (wire doc:
/// "never COMPLETE") and blocks warming.
#[test]
fn fix1_no_store_never_complete() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_NO_STORE);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(wire::TRUNC_NO_STORE))
    ));
}

/// Finding 5: a fresh terminator below the cached T proves a
/// shrink — PARTIAL with the observed T (the backend updates the
/// cache from this reason).
#[test]
fn fix1_shrink_partial_updates() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (9, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 3, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 3, 5));
    for j in 0..4 {
        b.push_alg(alg(TIDA, 3, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 3, 4, wire::ALG_EMPTY, ARR, 5));
    // Generations must agree with the RET (else GenMixed).
    for a in b.algs.iter_mut() {
        a.generation = 5;
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(4));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheShrink {
            cached: 9,
            observed: 4
        })
    ));
}

/// Finding 5: walked evidence beyond the cached T proves staleness
/// (grow) — PARTIAL with the fresh terminator (the backend
/// invalidates the cache from this reason; cold re-probe heals).
#[test]
fn fix1_grow_partial_invalidates() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    for j in 0..6 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 0, 6, wire::ALG_EMPTY, ARR, 5));
    // Generations must agree with the RET (else GenMixed): the
    // helper above pins gen 0, so rewrite gens for this fixture.
    for a in b.algs.iter_mut() {
        a.generation = 5;
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(6));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheStale { cached: 2 })
    ));
}

/// Finding 5: a generation turnover against a cached entry falls
/// back to cold rules and flags the stale row for invalidation.
#[test]
fn fix1_gen_turnover_cold_plus_stale() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (9, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 6));
    b.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_OK, ARR, 6));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_OK, ARR, 6));
    b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_OK, ARR, 6));
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 6));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::GenStale {
            expected: 5,
            observed: 6
        })
    ));
}

/// Finding 5 (live-lane race): a scan stamped generation 0 fired
/// before its array's epoch was recorded (GEN install happens at
/// the first close — the successor always fires pre-close — so
/// every window's second query stamps 0 and closes against epoch
/// 1). Turnover-spanning opens cannot close normally (turnover
/// abandons them), so observed 0 is unrecorded-at-fire, never a
/// superseded epoch: no GenStale, cold rules re-prove from the
/// scan's own full evidence (cached:false — it never consulted
/// the cache; cached:true keeps meaning "this scan rode the
/// cache").
#[test]
fn fix1_gen_zero_never_stale() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (3, 1));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_OK, ARR, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_OK, ARR, 0));
    b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_OK, ARR, 0));
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Complete {
            true_t: 3,
            cached: false
        }
    ));
}

/// Finding 4: ROWs for slots with no walked classifier verdict are
/// explicit findings (EMPTY/NOIMP/UNREADABLE slots emit no rows).
#[test]
fn fix1_stray_row_finding() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_row(row(TIDA, 0, 1)); // no rows should follow an EMPTY slot
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
    assert!(o.findings().contains(&Finding::StrayRow {
        tid: TIDA,
        seq: 0,
        idx: 1
    }));
}

#[test]
fn stream_drain_stats_accumulate() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = quiesced_idle(&[TIDA]);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    let mut b2 = quiesced_idle(&[TIDA]);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    let s = o.stats();
    assert_eq!(s.batches, 2);
    assert_eq!(s.calls, 2);
    assert_eq!(s.records, 2);
    assert_eq!(s.bytes, 2 * ONRING_CALL);
}
