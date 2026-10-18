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
        // Round 3, fixtures-wire: producer-admissible class per
        // status (the wire parser's combo rule — OK/MIXED carry
        // a real class, every other status carries OTHER_CLASS).
        class: if status == wire::ALG_OK || status == wire::ALG_MIXED {
            1
        } else {
            wire::OTHER_CLASS
        },
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
        // Round 3, fixtures-wire: same producer-admissible rule
        // as `alg` (OK/MIXED carry a real class).
        class: if status == wire::ALG_OK || status == wire::ALG_MIXED {
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
    row_full(tid, seq, idx, ARR, 0, 300, 0x4400)
}

fn row_full(
    tid: u32,
    seq: u64,
    idx: u64,
    aux: u64,
    generation: u64,
    funcid: u32,
    addr: u64,
) -> wire::ScanRowEvent {
    wire::ScanRowEvent {
        kind: wire::KIND_SCAN_ROW,
        op: OP,
        funcid,
        _pad: 0,
        addr,
        aux,
        idx,
        generation,
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

/// Round-4 F3: TRUNC-subsystem map pressure (LOSS_MAP_TRUNC —
/// a flag bit or its generation bump lost to a full map)
/// degrades spanned opens (fail-closed) and surfaces
/// window-level with no opens (never silently dropped).
#[test]
fn fix3_map_pressure_loss_degrades() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.loss.insert(wire::LOSS_MAP_TRUNC, 1);
    o.ingest(&b);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::DrainLoss)
        ),
        "map-pressure loss must degrade: {:?}",
        o.done()[0].outcome
    );
    // Window-level with no opens (never dropped).
    let mut o2 = Oracle::new(OracleScope::full());
    let mut w = quiesced_idle(&[TIDA]);
    w.loss.insert(wire::LOSS_MAP_TRUNC, 2);
    o2.ingest(&w);
    assert!(
        o2.findings()
            .iter()
            .any(|f| matches!(f, Finding::WindowLoss { delta: 2 })),
        "map-pressure loss surfaces window-level: {:?}",
        o2.findings()
    );
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
    // R35 quiescence: the take marks, the quiet batch closes (the
    // taint verdict is unchanged — only its delivery waits out one
    // drain for the batch's faults).
    o.ingest(&ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    });
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
    // R35 quiescence: the take marks, the quiet batch closes (the
    // taint verdict is unchanged — only its delivery waits out one
    // drain for the batch's faults).
    o.ingest(&ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    });
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
/// (grow) — PARTIAL with the lowest consistent terminator (the
/// backend invalidates the cache from this reason; cold re-probe
/// heals). Models production exactly: grown-by-N members
/// cold-walk (probe-nonzero) while the fresh terminator member
/// probe-skips silently (only cached_T + 1 emits its boundary
/// EMPTY) — no EMPTY record arrives.
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
    // Generations must agree with the RET (else GenMixed): the
    // helper above pins gen 0, so rewrite gens for this fixture.
    for a in b.algs.iter_mut() {
        a.generation = 5;
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(6));
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

/// Round-2 F2: a dispatch read failure behind a readable ALG
/// prefix closes PARTIAL, never COMPLETE (the producer emits ALG
/// before walking dispatch, so the bit is the only signal — it
/// must not be discarded for lack of ALG-prefix gaps).
#[test]
fn fix2_walk_read_behind_clean_prefix_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..3 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_WALK_READ != 0))
        ),
        "dispatch-read failure must degrade completion: {:?}",
        o.done()[0].outcome
    );
}

/// Round-2 F2: beyond-terminator name noise still discards (the
/// UNREADABLE sits past the evidenced terminator, so the walk
/// failure explains nothing below T).
#[test]
fn fix2_walk_name_beyond_terminator_still_complete() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..3 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 5, wire::ALG_UNREADABLE));
    b.trunc.insert(OP, wire::TRUNC_WALK_NAME);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "past-terminator name noise must not degrade: {:?}",
        o.done()[0].outcome
    );
}

/// Round-2 F3: dropped ROWs with intact ALG coverage degrade
/// completion (no holes — the loss itself is the evidence).
#[test]
fn fix2_row_loss_intact_prefix_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    for j in 0..3 {
        b1.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b1.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b1.push_row(row(TIDA, 0, 0));
    b1.loss.insert(wire::LOSS_RING_ROW, 2);
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::DrainLoss)
                && !reasons.iter().any(|r| matches!(r, PartialReason::Holes(_)))
        ),
        "ROW loss with intact ALGs must surface without holes: {:?}",
        o.done()[0].outcome
    );
}
/// Round-2 F4: the nesting rule-set taints stickily — the current
/// open keeps accumulating positive evidence and closes Tainted
/// with all of it (nothing is dropped at fire time).
#[test]
fn fix2_nesting_keeps_accumulating() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_OK, ARR, 0));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_OK, ARR + 0x1000, 0)); // multi-array: nesting fires
    b1.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_OK, ARR, 0)); // post-fire positive evidence
    b1.push_row(row(TIDA, 0, 0));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1, "fire must not drop the open");
    assert!(o.done().is_empty());
    assert!(o.findings().iter().any(|f| matches!(
        f,
        Finding::Nested {
            tid: TIDA,
            seq: 0,
            ..
        }
    )));
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Tainted { .. }),
        "sticky taint closes Tainted: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].alg_count, 3, "post-fire ALG retained");
    assert_eq!(o.done()[0].row_count, 1, "post-fire ROW retained");
    assert_eq!(o.done()[0].op, UNKNOWN_OP);
}

/// Round-2 F4: a dangling CALL taints both correlated sequences
/// (its own close carries UNKNOWN op; the correlated record is
/// tainted too, never left standing on mixed evidence).
#[test]
fn fix2_dangling_taints_both() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor marks 0; trails RET-less
    o.ingest(&b);
    // R35 quiescence: the take marks, the quiet batch retires seq 0
    // (verdicts below unchanged — the backstop still taints both).
    o.ingest(&nonquiesced(1_500));
    assert_eq!(o.open_count(), 1);
    o.finish(2_000);
    assert_eq!(o.open_count(), 0);
    assert_eq!(o.done().len(), 2);
    let dangle = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(
        matches!(dangle.outcome, Outcome::Tainted { .. }),
        "dangling CALL closes Tainted: {:?}",
        dangle.outcome
    );
    assert_eq!(dangle.op, UNKNOWN_OP);
    let pair = o.done().iter().find(|w| w.seq == 0).unwrap();
    assert!(
        matches!(pair.outcome, Outcome::Tainted { .. }),
        "correlated sequence tainted too: {:?}",
        pair.outcome
    );
}

/// Round-3 F4: a consumed (drained) Complete is CORRECTED when a
/// later dangling close taints it — the standing Complete must
/// not survive (a Nested finding alone leaves a false Complete
/// in every downstream copy). The correction channel carries
/// the rewrite to the backend/capture holders.
#[test]
fn fix3_consumed_taint_corrects() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor closes 0
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1, "inner closes first");
    let drained = o.take_done();
    assert!(
        matches!(drained[0].outcome, Outcome::Complete { .. }),
        "inner drains Complete: {:?}",
        drained[0].outcome
    );
    o.finish(3_000); // seq 1 dangles (RET-less) → taints consumed seq 0
    let dangle = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(
        matches!(dangle.outcome, Outcome::Tainted { .. }),
        "dangling close is Tainted: {:?}",
        dangle.outcome
    );
    let corrections = o.take_corrections();
    assert_eq!(corrections.len(), 1, "one post-drain correction");
    assert_eq!(corrections[0].tid, TIDA);
    assert_eq!(corrections[0].seq, 0);
    assert!(
        matches!(corrections[0].outcome, Outcome::Tainted { by_seq: 1 }),
        "consumed verdict corrected to Tainted: {:?}",
        corrections[0].outcome
    );
    assert_eq!(corrections[0].op, UNKNOWN_OP);
}

/// Round-4 F4: foreign closes never evict a nesting pair —
/// per-tid recent queues (an outer open on tid A keeps its
/// consumed inner correctable past 5000 closes on tid B).
#[test]
fn fix4_recent_survives_foreign_flood() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor closes 0
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    let _ = o.take_done(); // consume the inner (outer still open)
    // 5000 foreign closes via successor-takes (would evict a 4096
    // global FIFO; quiesced batches would close the outer early,
    // so each batch carries evidence(N) + call(N+1)).
    let mut bf0 = ScanBatch {
        quiesced: false,
        now_ns: 3_000,
        ..ScanBatch::default()
    };
    bf0.push_call(call(TIDB, 0, false, wire::SKIP_ADMITTED));
    o.ingest(&bf0);
    let mut flooded = 0usize;
    for seq in 0..5000u64 {
        let mut bf = ScanBatch {
            quiesced: false,
            now_ns: 4_000 + seq,
            ..ScanBatch::default()
        };
        bf.push_ret(ret(TIDB, seq, 0));
        bf.push_alg(alg(TIDB, seq, 0, wire::ALG_OK));
        bf.push_alg(alg_arr(TIDB, seq, 1, wire::ALG_EMPTY, ARR, 0));
        bf.push_call(call(TIDB, seq + 1, false, wire::SKIP_ADMITTED));
        o.ingest(&bf);
        flooded += o.take_done().len();
        let _ = o.take_findings();
    }
    // R35 quiescence: same-batch ring + take holds one quiet batch,
    // so each flood batch retires its predecessor (one-batch lag) —
    // flush the trailing open before counting (verdicts unchanged).
    o.ingest(&nonquiesced(9_000));
    flooded += o.take_done().len();
    let _ = o.take_findings();
    assert_eq!(
        flooded, 5000,
        "the flood must actually close (else vacuous)"
    );
    // Close the trailing foreign open quiesced (RET-joined —
    // the RET-less outer must stay open for the finish dangle).
    let mut bq = quiesced_idle(&[TIDB]);
    bq.push_ret(ret(TIDB, 5000, 0));
    bq.push_alg(alg(TIDB, 5000, 0, wire::ALG_OK));
    bq.push_alg(alg_arr(TIDB, 5000, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&bq);
    let _ = o.take_done();
    let _ = o.take_findings();
    assert_eq!(o.open_count(), 1, "only the outer stays open");
    o.finish(10_000_000); // outer dangles → must still correct the inner
    let corrections = o.take_corrections();
    assert_eq!(corrections.len(), 1, "flood must not evict the pair");
    assert_eq!((corrections[0].tid, corrections[0].seq), (TIDA, 0));
}

/// Round-4 F6: late REQUIRED-prefix data for a consumed key is
/// preserved as findings (a hole-filling ALG/ROW skewed past
/// its Partial close — positive recovery evidence); past-T
/// stragglers stay silent (beyond-terminator observations are
/// meaningless); late control (RET) for a non-hung consumed key
/// stays absorbed (redundant).
#[test]
fn fix4_late_prefix_data_preserved_beyond_t_silent() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg(TIDA, 0, 2, wire::ALG_OK)); // hole at 1
    b1.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0)); // terminator at 3
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor closes 0
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Partial { .. }),
        "holed close is Partial: {:?}",
        o.done()[0].outcome
    );
    let _ = o.take_done(); // consume seq 0
    let _ = o.take_findings();
    // Stragglers: hole-filling prefix pair (recovery!) + a
    // past-terminator ALG (meaningless) + a redundant RET.
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 3_000,
        ..ScanBatch::default()
    };
    b3.push_alg(alg(TIDA, 0, 1, wire::ALG_OK));
    b3.push_row(row_full(TIDA, 0, 1, ARR, 0, 301, 0x4401));
    b3.push_alg(alg(TIDA, 0, 9, wire::ALG_OK));
    b3.push_ret(ret(TIDA, 0, 0));
    o.ingest(&b3);
    assert!(
        o.findings().contains(&Finding::LateAlg {
            tid: TIDA,
            seq: 0,
            idx: 1,
            status: wire::ALG_OK,
            class: 1,
        }),
        "late hole-filling ALG preserved: {:?}",
        o.findings()
    );
    assert!(
        o.findings().contains(&Finding::LateRow {
            tid: TIDA,
            seq: 0,
            idx: 1,
            funcid: 301,
        }),
        "late hole-filling ROW preserved: {:?}",
        o.findings()
    );
    assert!(
        !o.findings().iter().any(|f| matches!(
            f,
            Finding::LateAlg { idx: 9, .. }
                | Finding::LateRet { seq: 0, .. }
                | Finding::DoubleRet { seq: 0, .. }
                | Finding::OrphanRet { seq: 0, .. }
        )),
        "past-T stragglers and redundant RET stay silent: {:?}",
        o.findings()
    );
}

/// Round-4 F1: every retained ALG identity carries its event
/// generation (copied at join), and the record derives its
/// agreed incarnation — a NOIMP-only record with no ROW or
/// guard keeps its generation (nothing to lose it through).
#[test]
fn fix4_slot_identities_carry_generation() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.generation = 7;
    b.push_ret(r);
    let mut a0 = alg(TIDA, 0, 0, wire::ALG_NOIMP);
    a0.generation = 7;
    b.push_alg(a0);
    let mut a1 = alg_arr(TIDA, 0, 1, wire::ALG_NOIMP, ARR, 0);
    a1.generation = 7;
    b.push_alg(a1);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    let w = &o.done()[0];
    assert!(
        w.algs.iter().all(|a| a.generation == 7),
        "every identity carries its event generation: {:?}",
        w.algs
    );
    assert_eq!(
        w.generation(),
        Some(7),
        "agreed incarnation derives from unanimous slots"
    );
}

/// Round-4 F1: mixed-generation evidence degrades (GenMixed)
/// and the record derives no agreed incarnation (per-slot
/// generations name the disagreeing slots instead).
#[test]
fn fix4_mixed_generation_derives_none() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.generation = 7;
    b.push_ret(r);
    let mut a0 = alg(TIDA, 0, 0, wire::ALG_OK);
    a0.generation = 7;
    b.push_alg(a0);
    let mut a1 = alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0);
    a1.generation = 9;
    b.push_alg(a1);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    let w = &o.done()[0];
    assert!(
        matches!(
            w.outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::GenMixed)
        ),
        "mixed generations degrade: {:?}",
        w.outcome
    );
    assert_eq!(w.generation(), None, "no agreed incarnation when mixed");
    assert_eq!(w.algs.iter().find(|a| a.idx == 0).unwrap().generation, 7);
    assert_eq!(w.algs.iter().find(|a| a.idx == 1).unwrap().generation, 9);
}

/// Round-4 reg3, flipped in round 2 (premise change, justified —
/// the review established this pin's premise is unattributed): a
/// ROW-bearing below-T prefix (ALG_OK + ROWs) + live T+1 + fault
/// bits used to mask to Complete. ROW presence proves neither
/// dispatch termination nor fault origin (a below-T walk may have
/// aborted mid-walk; the per-op bits are unattributable to
/// slots), so the walked prefix vetoes the filter and the bits
/// stay Partial. The T+1 filter survives only for provably
/// non-walking below-T prefixes (NOIMP — see
/// `r36_nowalk_prefix_with_live_t1_filters`) and vacuous T=0
/// prefixes (see `fix5_t1_filter_allows_t_zero`).
#[test]
fn fix4_t1_garbage_filtered_prefix_exact() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (3, 0));
    let mut o = Oracle::new(scope);
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.generation = 0;
    b.push_ret(r);
    for j in 0..3u64 {
        let mut a = alg(TIDA, 0, j, wire::ALG_OK);
        a.generation = 0;
        b.push_alg(a);
        let mut row = row(TIDA, 0, j);
        row.generation = 0;
        b.push_row(row);
    }
    let mut t = alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0);
    t.generation = 0;
    b.push_alg(t);
    // T+1 garbage walk (readable nonzero past the verified
    // terminator) + its fault bits.
    let mut g = alg(TIDA, 0, 4, wire::ALG_OK);
    g.generation = 0;
    b.push_alg(g);
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(
                wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ
            ))
        ),
        "walked below-T prefix vetoes the T+1 filter (bits kept): {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
}

/// Round-4 reg3 (F5 preserved): no verified terminator (stale
/// cache, slot T live) keeps the T+1 walk surfacing growth —
/// the filter never fires without its terminator.
#[test]
fn fix4_t1_filter_needs_verified_terminator() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (3, 0));
    let mut o = Oracle::new(scope);
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.generation = 0;
    b.push_ret(r);
    for j in 0..5u64 {
        let mut a = alg(TIDA, 0, j, wire::ALG_OK);
        a.generation = 0;
        b.push_alg(a);
        let mut row = row(TIDA, 0, j);
        row.generation = 0;
        b.push_row(row);
    }
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::CacheStale { .. }))
        ),
        "stale cache still surfaces via T+1 walk: {:?}",
        o.done()[0].outcome
    );
}

/// Round-4 reg3 (F2 preserved): a below-T hole keeps the
/// DISPATCH/READ bits (attribution needs a fully-evidenced
/// prefix — gaps fail closed).
#[test]
fn fix4_t1_filter_needs_clean_prefix() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (3, 0));
    let mut o = Oracle::new(scope);
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.generation = 0;
    b.push_ret(r);
    // Hole at 1 (prefix NOT fully evidenced).
    for j in [0u64, 2] {
        let mut a = alg(TIDA, 0, j, wire::ALG_OK);
        a.generation = 0;
        b.push_alg(a);
        let mut row = row(TIDA, 0, j);
        row.generation = 0;
        b.push_row(row);
    }
    let mut t = alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0);
    t.generation = 0;
    b.push_alg(t);
    let mut g = alg(TIDA, 0, 4, wire::ALG_OK);
    g.generation = 0;
    b.push_alg(g);
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(
                wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ
            ))
        ),
        "holed prefix keeps the bits (F2): {:?}",
        o.done()[0].outcome
    );
}

/// Round-2 F4: ROWs retain array/generation/callback data — a row
/// for a foreign array degrades the close explicitly.
#[test]
fn fix2_row_array_mismatch_partial() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_row(row_full(TIDA, 0, 0, ARR + 0x5000, 0, 300, 0x4400)); // foreign array
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::RowArrayMismatch)
        ),
        "foreign-array ROW must degrade: {:?}",
        o.done()[0].outcome
    );
}

/// Round-2 F4: retained ROWs ride the record for consistency
/// checks and callback relocation (full callback data, not
/// count+index).
#[test]
fn fix2_rows_retained_for_relocation() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_row(row_full(TIDA, 0, 0, ARR, 0, 301, 0x4500));
    b.push_row(row_full(TIDA, 0, 0, ARR, 0, 302, 0x4600));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(o.done()[0].outcome, Outcome::Complete { .. }));
    let rows = &o.done()[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].funcid, 301);
    assert_eq!(rows[0].addr, 0x4500);
    assert_eq!(rows[1].funcid, 302);
    assert_eq!(rows[1].addr, 0x4600);
}

/// Round-2 F5: warm growth the producer skips silently still
/// invalidates — no EMPTY, no beyond-T evidence, terminator slot
/// walked live: the cached Proven(T) cannot stand.
#[test]
fn fix2_warm_silent_growth_stale() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    // Production warm scan of a grown table: members 0..=2 walk
    // (slot 2 now live), members 3..=511 probe-skip silently —
    // no EMPTY anywhere, nothing beyond T.
    for j in 0..3 {
        b.push_alg(alg_arr(TIDA, 0, j, wire::ALG_OK, ARR, 5));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(2));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheStale { cached: 2 })
    ));
}

/// Round-2 F5: a hole where the cached terminator should be
/// re-proven invalidates (holes trigger invalidation).
#[test]
fn fix2_warm_terminator_hole_stale() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    for j in 0..2 {
        b.push_alg(alg_arr(TIDA, 0, j, wire::ALG_OK, ARR, 5));
    }
    // Slot 2 (the cached terminator) faulted silently; members
    // 3..=511 probe-skipped. No EMPTY, no beyond-T evidence.
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheStale { cached: 2 })
            && reasons.iter().any(|r| matches!(r, PartialReason::Holes(_)))
    ));
}

/// Round-2 F5: growth by exactly one slot carries the boundary
/// EMPTY the producer emits (first would-skip member proves
/// termination) — stale with the fresh proven T.
#[test]
fn fix2_grow_by_one_boundary_empty() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    for j in 0..3 {
        b.push_alg(alg_arr(TIDA, 0, j, wire::ALG_OK, ARR, 5));
    }
    // Member 3 == cached_T + 1: probe-zero proves the fresh
    // terminator explicitly (production would-skip emission).
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 5));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::CacheStale { cached: 2 })
    ));
}

/// Round-2 F5: selective scope keeps the belief when the
/// terminator slot is outside the attached set (unobservable —
/// the UnobservedSlots reason already partials).
#[test]
fn fix2_selective_unattached_terminator_keeps_belief() {
    let mut scope = OracleScope::full();
    scope.attached = (0..2).collect();
    scope.expected = 2;
    scope.known_t.insert(ARR, (2, 5));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 5));
    for j in 0..2 {
        b.push_alg(alg_arr(TIDA, 0, j, wire::ALG_OK, ARR, 5));
    }
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(2));
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Partial { ref reasons } if reasons
            .iter()
            .any(|r| matches!(r, PartialReason::UnobservedSlots(_)))
    ));
}

/// Round-5 F2 (rereview counterexample): slot 0 emits ALG_OK +
/// one ROW, then the next dispatch-entry read fails
/// (TRUNC_WALK_READ); slot 1 is a valid terminator. ROW
/// presence does not prove dispatch termination (the producer
/// emits ROWs before a later entry read can abort), and
/// vacuous beyond-T silence is not T+1 evidence — the
/// invocation stays PARTIAL, never Complete.
#[test]
fn fix5_f2_row_then_abort_not_masked() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_WALK_READ != 0))
        ),
        "aborted dispatch behind a ROW-bearing prefix must stay Partial: {:?}",
        o.done()[0].outcome
    );
}

/// Round-5 F2 (warm variant): the same abort under a standing
/// warm belief still degrades — warmth does not turn vacuous
/// beyond-T silence into T+1 noise evidence.
#[test]
fn fix5_f2_row_then_abort_warm_not_masked() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.trunc.insert(OP, wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_WALK_READ != 0))
        ),
        "warmth without T+1 activity must not mask a below-T abort: {:?}",
        o.done()[0].outcome
    );
}

/// R36/I3 (premise change, justified: round 5 admitted
/// zero-ROW prefixes into the T+1 filter, so a below-T
/// first-dispatch-read failure masked to Complete whenever live
/// T+1 activity coincided — the F2 regression. Base rejected
/// zero-ROW first-read failure; restored here): a verified
/// terminator + prefix whose OK slots carry no ROWs +
/// fault bits + actual T+1 live evidence stays PARTIAL — the
/// bits are unattributable (below-T abort vs T+1 noise), so the
/// filter must not fire. Zero-ROW prefixes stay valid (Complete)
/// absent fault bits (the cold-complete pins carry no ROWs and
/// no bits).
#[test]
fn fix5_t1_filter_rejects_zero_row_prefix_with_faults() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (3, 0));
    let mut o = Oracle::new(scope);
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..3u64 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 4, wire::ALG_OK));
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(
                wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ
            ))
        ),
        "zero-ROW prefix with faults must not filter: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::Proven(3));
}

/// Round-5 warm seam (T=0 inclusion): an empty prefix under a
/// verified T=0 terminator + actual T+1 live evidence filters
/// like any other T — T=0 is a valid warm table.
#[test]
fn fix5_t1_filter_allows_t_zero() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (0, 0));
    let mut o = Oracle::new(scope);
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 0, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 1, wire::ALG_OK));
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "T=0 with T+1 evidence must filter: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::Proven(0));
}

/// R36/I3 warm counterexample: warm T=1, ALG_OK@0 with ZERO
/// ROWs (its dispatch walk may have aborted on the first entry
/// read), EMPTY@1, independently readable ALG_OK@2 (live T+1),
/// TRUNC WALK_READ. The bit is unattributable to a slot
/// (below-T first-read failure vs T+1 noise) → fail closed,
/// never masked to Complete.
#[test]
fn r36_warm_below_t_fault_with_live_t1_not_masked() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b.trunc.insert(OP, wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_WALK_READ != 0))
        ),
        "warm below-T fault coinciding with live T+1 must stay Partial: {:?}",
        o.done()[0].outcome
    );
}

/// Round-5 warm seam (cold exclusion): without a standing warm
/// belief there is no T+1 verification walk, so T+1-looking
/// evidence + fault bits on a cold scan stay PARTIAL
/// (unattributable — fail closed).
#[test]
fn fix5_t1_filter_needs_warm_belief() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..3u64 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
        b.push_row(row(TIDA, 0, j));
    }
    b.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 4, wire::ALG_OK));
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(
                wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ
            ))
        ),
        "cold scan must not mask fault bits as T+1 noise: {:?}",
        o.done()[0].outcome
    );
}

/// Round-5 F6: Candidate termination is unproven, so late
/// valid evidence beyond the candidate still belongs to the
/// required prefix — a selective Candidate(4) close followed by
/// skewed ALG/ROW at 5 preserves both as recovery findings.
#[test]
fn fix5_late_beyond_candidate_preserved() {
    let mut scope = OracleScope::full();
    scope.attached = (0..4).collect();
    scope.expected = 4;
    let mut o = Oracle::new(scope);
    let mut b1 = quiesced_idle(&[TIDA]);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    for j in 0..4 {
        b1.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    o.ingest(&b1);
    assert_eq!(o.done().len(), 1);
    assert_eq!(o.done()[0].true_t, TrueT::Candidate(4));
    let _ = o.take_done();
    let _ = o.take_findings();
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_alg(alg(TIDA, 0, 5, wire::ALG_OK));
    b2.push_row(row_full(TIDA, 0, 5, ARR, 0, 301, 0x4401));
    o.ingest(&b2);
    assert!(
        o.findings().contains(&Finding::LateAlg {
            tid: TIDA,
            seq: 0,
            idx: 5,
            status: wire::ALG_OK,
            class: 1,
        }),
        "late valid ALG beyond an unproven candidate is recovery: {:?}",
        o.findings()
    );
    assert!(
        o.findings().contains(&Finding::LateRow {
            tid: TIDA,
            seq: 0,
            idx: 5,
            funcid: 301,
        }),
        "late valid ROW beyond an unproven candidate is recovery: {:?}",
        o.findings()
    );
}

/// Round-5 F6: sticky taint keeps slots and forces op UNKNOWN —
/// it never discards positive array/index evidence. Late ALG/ROW
/// for a tainted close are recovery findings, not silence.
#[test]
fn fix5_late_tainted_prefix_preserved() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK)); // duplicate slot: nesting fires
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor closes 0
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Tainted { .. }),
        "duplicate slot closes Tainted: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].op, UNKNOWN_OP);
    let _ = o.take_done();
    let _ = o.take_findings();
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 3_000,
        ..ScanBatch::default()
    };
    b3.push_alg(alg(TIDA, 0, 1, wire::ALG_OK));
    b3.push_row(row_full(TIDA, 0, 1, ARR, 0, 302, 0x4402));
    o.ingest(&b3);
    assert!(
        o.findings().contains(&Finding::LateAlg {
            tid: TIDA,
            seq: 0,
            idx: 1,
            status: wire::ALG_OK,
            class: 1,
        }),
        "taint must keep late slot evidence: {:?}",
        o.findings()
    );
    assert!(
        o.findings().contains(&Finding::LateRow {
            tid: TIDA,
            seq: 0,
            idx: 1,
            funcid: 302,
        }),
        "taint must keep late callback evidence: {:?}",
        o.findings()
    );
}

/// Round-5 F6 (correlated-rewrite variant): a consumed Complete
/// rewritten to Tainted by a later dangling close still keeps
/// late in-prefix evidence — the correction changes the
/// verdict, never the retention rule.
#[test]
fn fix5_late_tainted_rewrite_preserved() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED)); // successor closes 0
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    let drained = o.take_done();
    assert!(matches!(drained[0].outcome, Outcome::Complete { .. }));
    o.finish(3_000); // seq 1 dangles → taints consumed seq 0
    assert_eq!(o.take_corrections().len(), 1);
    let _ = o.take_done();
    let _ = o.take_findings();
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 4_000,
        ..ScanBatch::default()
    };
    b3.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b3.push_row(row_full(TIDA, 0, 2, ARR, 0, 303, 0x4403));
    o.ingest(&b3);
    assert!(
        o.findings().contains(&Finding::LateAlg {
            tid: TIDA,
            seq: 0,
            idx: 2,
            status: wire::ALG_OK,
            class: 1,
        }),
        "corrected-tainted close must keep late slot evidence: {:?}",
        o.findings()
    );
    assert!(
        o.findings().contains(&Finding::LateRow {
            tid: TIDA,
            seq: 0,
            idx: 2,
            funcid: 303,
        }),
        "corrected-tainted close must keep late callback evidence: {:?}",
        o.findings()
    );
}

/// Round-5 F1: census loss (CALLS map pressure) degrades
/// spanning verdicts — a failed admitted-increment hides an
/// admission exactly like a ring drop hides a record, so the
/// retained-loss rule (R18: nonzero loss ⟹ PARTIAL) covers it.
#[test]
fn fix5_calls_loss_degrades_open() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    for j in 0..3 {
        b1.push_alg(alg(TIDA, 0, j, wire::ALG_OK));
    }
    b1.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    b1.push_row(row(TIDA, 0, 0));
    b1.loss.insert(wire::LOSS_MAP_CALLS, 1);
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    let mut b2 = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::DrainLoss)
                && !reasons.iter().any(|r| matches!(r, PartialReason::Holes(_)))
        ),
        "census loss with intact ALGs must surface without holes: {:?}",
        o.done()[0].outcome
    );
}

/// Round-5 F1: census loss with no evaluable invocation is a
/// window finding, never dropped (same rule as ring loss).
#[test]
fn fix5_calls_loss_window_finding() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        ..ScanBatch::default()
    };
    b.loss.insert(wire::LOSS_MAP_CALLS, 2);
    o.ingest(&b);
    assert!(
        o.done().is_empty(),
        "loss alone closes nothing: {:?}",
        o.done()
    );
    assert!(
        o.findings().contains(&Finding::WindowLoss { delta: 2 }),
        "census loss with no opens must surface window-level: {:?}",
        o.findings()
    );
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

/// K2: unknown RCOUNT lifecycle states must not retire (an
/// invalid state is corrupt content, never an absent/retired
/// record): state 2 stalls exactly like ACTIVE (open held +
/// Stall finding at ingest), never Complete — with otherwise
/// complete evidence.
#[test]
fn k2_unknown_rcount_state_stalls_like_active() {
    for (state, tag) in [(wire::RCOUNT_STATE_ACTIVE, "active"), (2u32, "unknown-2")] {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = ScanBatch {
            quiesced: true,
            ..ScanBatch::default()
        };
        b.rcount.insert(TIDA, (0, state));
        b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(TIDA, 0, 0));
        b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
        b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
        o.ingest(&b);
        assert!(
            o.done().is_empty(),
            "{tag}: must not retire at ingest: {:?}",
            o.done()
        );
        assert!(
            o.findings().contains(&Finding::Stall { tid: TIDA, seq: 0 }),
            "{tag}: stall finding missing: {:?}",
            o.findings()
        );
    }
}

/// K1: the terminator-region consumer range is bounded
/// independently of the wire parser (synthetic batches bypass
/// it): a corrupted EMPTY idx inside a synthetic attached set
/// must not loop-allocate the unobserved list (the production
/// parser rejects idx >= 512 before joining; this pins the
/// consumer's own bound).
#[test]
fn k1_corrupt_idx_bounds_consumer_range() {
    let mut scope = OracleScope::full();
    scope.attached = [0u32, 100_000].into_iter().collect();
    scope.expected = 2;
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 100_000, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    let Outcome::Partial { reasons } = &o.done()[0].outcome else {
        panic!(
            "corrupt terminator must stay partial: {:?}",
            o.done()[0].outcome
        );
    };
    for r in reasons {
        if let PartialReason::UnobservedSlots(v) = r {
            assert!(
                v.len() <= wire::SCAN_SLOTS as usize,
                "unobserved list unbounded ({} slots): corrupt idx loop-allocated",
                v.len()
            );
        }
    }
}

/// Successor operation on the same thread (the R35 schedule's
/// later admitted query of another op — its take must not close
/// a predecessor whose fault data is still in flight).
const OP_SUCC: u32 = 9;
const ARR_SUCC: u64 = 0x8000;

fn call_op(tid: u32, seq: u64, op: u32) -> wire::ScanCallEvent {
    wire::ScanCallEvent {
        kind: wire::KIND_SCAN_CALL,
        op,
        tid,
        flags: wire::make_call_flags(false, wire::SKIP_ADMITTED),
        seq,
    }
}

fn nonquiesced(now_ns: u64) -> ScanBatch {
    ScanBatch {
        quiesced: false,
        now_ns,
        ..ScanBatch::default()
    }
}

/// Two-slot scope (terminator at 1, no holes below it): the shape
/// under which a fault-free predecessor honestly Completes, so a
/// stale-fault masking shows as Complete (the R35 NEW regression).
fn two_slot_scope() -> OracleScope {
    let mut scope = OracleScope::full();
    scope.attached = [0u32, 1].into_iter().collect();
    scope.expected = 2;
    scope
}

/// Round 2, residual B (R35 stale-snapshot race — the review's
/// exact schedule): ALG_OK@0, one ROW, dispatch-read abort,
/// EMPTY@1, then a successor admitted take of another op on the
/// same thread. The backend snapshots TRUNC before draining the
/// ring, so the first batch carries the ring evidence with stale
/// empty faults; the abort's flag lands in the NEXT drain. The
/// successor's take must NOT close the predecessor against the
/// stale snapshot (pre-fix: Complete); the predecessor holds one
/// quiet batch, the next poll's fault joins it, and it closes
/// Partial with the retained WALK_READ bit. The successor then
/// closes normally through the real backstop (`finish`).
#[test]
fn r35_successor_holds_predecessor_for_next_poll_fault() {
    let mut o = Oracle::new(two_slot_scope());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_row(row(TIDA, 0, 0));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.push_call(call_op(TIDA, 1, OP_SUCC));
    // No TRUNC in this batch: the pre-drain snapshot predates the
    // abort's flag write (stale empty faults — the race).
    o.ingest(&b1);
    assert!(
        o.done().is_empty(),
        "successor take must hold a predecessor with same-batch ring evidence \
         (fault data may be stale): {:?}",
        o.done().iter().map(|w| &w.outcome).collect::<Vec<_>>()
    );
    // Next poll: the abort's flag lands; the successor's own
    // evidence arrives (RET-joined, so the backstop evaluates it
    // instead of tainting the pair).
    let mut b2 = nonquiesced(2_000);
    b2.trunc.insert(OP, wire::TRUNC_WALK_READ);
    let mut succ_ret = ret(TIDA, 1, 0);
    succ_ret.op = OP_SUCC;
    succ_ret.arr = ARR_SUCC;
    b2.push_ret(succ_ret);
    let mut succ_empty = alg_arr(TIDA, 1, 0, wire::ALG_EMPTY, ARR_SUCC, 0);
    succ_empty.op = OP_SUCC;
    b2.push_alg(succ_empty);
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1, "predecessor closes on the quiet batch");
    let pred = &o.done()[0];
    assert_eq!((pred.tid, pred.seq), (TIDA, 0));
    assert!(
        matches!(
            pred.outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_WALK_READ != 0))
        ),
        "late fault must degrade the held predecessor: {:?}",
        pred.outcome
    );
    // The successor closes through the real backstop (RET-joined:
    // evaluated, never tainting its partner).
    o.finish(3_000);
    assert_eq!(o.done().len(), 2);
    assert_eq!((o.done()[1].tid, o.done()[1].seq), (TIDA, 1));
    assert!(
        !matches!(
            o.done()[1].outcome,
            Outcome::Tainted { .. } | Outcome::Abandoned { .. }
        ),
        "successor closes normally: {:?}",
        o.done()[1].outcome
    );
}

/// R35 battery: no fault anywhere — the deferral is purely timing
/// (verdict-preserving). Same-batch ring + successor holds, then
/// the quiet batch closes Complete.
#[test]
fn r35_hold_is_verdict_preserving_without_faults() {
    let mut o = Oracle::new(two_slot_scope());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_row(row(TIDA, 0, 0));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.push_call(call_op(TIDA, 1, OP_SUCC));
    o.ingest(&b1);
    assert!(
        o.done().is_empty(),
        "fault-free take still holds: {:?}",
        o.done()
    );
    o.ingest(&nonquiesced(2_000));
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "quiet batch closes the fault-free predecessor Complete: {:?}",
        o.done()[0].outcome
    );
}

/// R35 battery: settled evidence + a fresh successor take closes in
/// the SAME batch (no deferral when the ring predates the fault
/// snapshot — only same-batch ring waits out one drain).
#[test]
fn r35_settled_evidence_closes_on_fresh_take() {
    let mut o = Oracle::new(two_slot_scope());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    assert!(o.done().is_empty());
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call_op(TIDA, 1, OP_SUCC));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1, "fresh take closes settled evidence");
    assert_eq!((o.done()[0].tid, o.done()[0].seq), (TIDA, 0));
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "settled fault-free predecessor Completes: {:?}",
        o.done()[0].outcome
    );
}

/// R35 battery: a fault for the SUCCESSOR's op alone does not
/// degrade the held predecessor (per-op fault scoping survives
/// the deferral — the predecessor still Completes).
#[test]
fn r35_unrelated_op_fault_does_not_degrade_held_predecessor() {
    let mut o = Oracle::new(two_slot_scope());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.push_call(call_op(TIDA, 1, OP_SUCC));
    o.ingest(&b1);
    assert!(o.done().is_empty());
    let mut b2 = nonquiesced(2_000);
    b2.trunc.insert(OP_SUCC, wire::TRUNC_WALK_READ);
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "successor-op fault must not touch the predecessor: {:?}",
        o.done()[0].outcome
    );
}

/// Round 2, residual C (R36 fault class — the review's exact
/// fixture: `fix5_f2_row_then_abort_warm_not_masked` + ALG_OK@2):
/// warm T=1, ALG_OK@0 with one ROW (its dispatch walk may have
/// aborted on the second entry read), EMPTY@1, live ALG_OK@2
/// (T+1), TRUNC fault bits. ROW presence proves neither dispatch
/// termination (ROWs emit before a later entry read can abort)
/// nor fault origin (the per-op bits are unattributable to
/// slots) — a walked below-T slot vetoes the T+1 filter, and the
/// bits stay Partial. Pre-fix the 1..=127 ROW predicate passed
/// and the filter masked to Complete.
#[test]
fn r36_row_bearing_below_t_with_live_t1_not_masked() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Trunc(
                wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ
            ))
        ),
        "ROW-bearing below-T walk must veto the T+1 filter: {:?}",
        o.done()[0].outcome
    );
}

/// R36 battery: the veto is ROW-count-independent (0 and 128 are
/// pinned elsewhere; every walked count in between — short-clean
/// vs aborted-mid-walk are wire-indistinguishable — vetoes too).
#[test]
fn r36_walked_prefix_vetoes_at_any_row_count() {
    for n in [2u32, 64, 127] {
        let mut scope = OracleScope::full();
        scope.known_t.insert(ARR, (1, 0));
        let mut o = Oracle::new(scope);
        let mut b = quiesced_idle(&[TIDA]);
        b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(TIDA, 0, 0));
        b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
        for _ in 0..n {
            b.push_row(row(TIDA, 0, 0));
        }
        b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
        b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
        b.trunc.insert(OP, wire::TRUNC_WALK_READ);
        o.ingest(&b);
        assert_eq!(o.done().len(), 1);
        assert!(
            matches!(
                o.done()[0].outcome,
                Outcome::Partial { ref reasons } if reasons
                    .iter()
                    .any(|r| matches!(r, PartialReason::Trunc(_)))
            ),
            "{n} ROWs prove no termination — must veto the filter: {:?}",
            o.done()[0].outcome
        );
    }
}

/// R36 battery: 128 ROWs prove the below-T walk itself overflowed
/// (one ROW per entry over 128 slots) — its DISPATCH is genuine,
/// never T+1 noise.
#[test]
fn r36_full_walk_overflow_is_genuine_below_t_fault() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    for _ in 0..128 {
        b.push_row(row(TIDA, 0, 0));
    }
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b.trunc.insert(OP, wire::TRUNC_DISPATCH);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_DISPATCH != 0))
        ),
        "below-T overflow must keep its DISPATCH bit: {:?}",
        o.done()[0].outcome
    );
}

/// R36 battery: every walking below-T status vetoes (OK, UNKNOWN,
/// MIXED — each reaches the dispatch walk, so each may have
/// faulted); multi-slot below-T prefixes veto as a class.
#[test]
fn r36_every_walking_prefix_status_vetoes() {
    for status in [wire::ALG_OK, wire::ALG_UNKNOWN, wire::ALG_MIXED] {
        let mut scope = OracleScope::full();
        scope.known_t.insert(ARR, (2, 0));
        let mut o = Oracle::new(scope);
        let mut b = quiesced_idle(&[TIDA]);
        b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(TIDA, 0, 0));
        for j in 0..2u64 {
            b.push_alg(alg(TIDA, 0, j, status));
            b.push_row(row(TIDA, 0, j));
        }
        b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
        b.push_alg(alg(TIDA, 0, 3, wire::ALG_OK));
        b.trunc
            .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
        o.ingest(&b);
        assert_eq!(o.done().len(), 1);
        assert!(
            matches!(
                o.done()[0].outcome,
                Outcome::Partial { ref reasons } if reasons
                    .iter()
                    .any(|r| matches!(r, PartialReason::Trunc(_)))
            ),
            "walking status {status} below-T must veto the filter: {:?}",
            o.done()[0].outcome
        );
    }
}

/// R36 battery: a DISPATCH-only fault with a ROW-bearing below-T
/// prefix still vetoes (overflow may be below-T — 128 ROWs are
/// sufficient, never necessary, to prove it).
#[test]
fn r36_dispatch_only_fault_with_walked_prefix_not_masked() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_OK));
    b.trunc.insert(OP, wire::TRUNC_DISPATCH);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::Trunc(b) if b & wire::TRUNC_DISPATCH != 0))
        ),
        "DISPATCH with a walked below-T prefix must stay Partial: {:?}",
        o.done()[0].outcome
    );
}

/// R36 battery (the remaining positive pin): below-T slots that
/// provably NEVER walked (ALG_NOIMP — the producer classifies
/// without implementation and never reaches the dispatch walk)
/// cannot have faulted, so live-T+1 fault bits attribute to the
/// T+1 walk and the filter fires. This is the only masking shape:
/// every below-T slot non-walking, terminator verified, T+1
/// walked, beyond-T confined to T+1.
#[test]
fn r36_nowalk_prefix_with_live_t1_filters() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (2, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    for j in 0..2u64 {
        b.push_alg(alg(TIDA, 0, j, wire::ALG_NOIMP));
    }
    b.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 3, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 3));
    b.trunc
        .insert(OP, wire::TRUNC_DISPATCH | wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "non-walking below-T cannot explain the bits — T+1 noise filters: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::Proven(2));
}

/// R36 battery: a non-walking T+1 record (UNREADABLE never reaches
/// the dispatch walk) is not T+1 noise evidence — with a walked
/// below-T prefix the bits stay Partial on both halves.
#[test]
fn r36_nonwalking_t1_is_not_noise_evidence() {
    let mut scope = OracleScope::full();
    scope.known_t.insert(ARR, (1, 0));
    let mut o = Oracle::new(scope);
    let mut b = quiesced_idle(&[TIDA]);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_row(row(TIDA, 0, 0));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b.push_alg(alg(TIDA, 0, 2, wire::ALG_UNREADABLE));
    b.trunc.insert(OP, wire::TRUNC_WALK_READ);
    o.ingest(&b);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Partial { .. }),
        "non-walking T+1 + walked prefix must stay Partial: {:?}",
        o.done()[0].outcome
    );
}

/// R35 battery: successor take arriving BEFORE the predecessor's
/// RET no longer strands it to the backstop (sticky successor —
/// the pre-fix per-batch take scan forgot takes from older
/// batches; now the close lands one quiet batch after the RET).
#[test]
fn r35_take_before_ret_closes_after_quiet_batch() {
    let mut o = Oracle::new(two_slot_scope());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_call(call_op(TIDA, 1, OP_SUCC));
    o.ingest(&b1);
    assert!(o.done().is_empty());
    let mut b2 = nonquiesced(2_000);
    b2.push_ret(ret(TIDA, 0, 0));
    b2.push_alg(alg(TIDA, 0, 0, wire::ALG_NOIMP));
    b2.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b2);
    assert!(
        o.done().is_empty(),
        "RET batch is not quiet (fault data may lag the RET): {:?}",
        o.done()
    );
    o.ingest(&nonquiesced(3_000));
    assert_eq!(o.done().len(), 1, "quiet batch closes the take-marked open");
    assert_eq!((o.done()[0].tid, o.done()[0].seq), (TIDA, 0));
}

/// Round 3, residual B-2 (review's schedule): a dispatch read
/// faults during the drain and the post-drain re-read fails —
/// the batch carries an unavailable fault view. The terminal
/// backstop (no next batch to settle against) must retain the
/// drained evidence while treating the verdict as UNCERTAIN —
/// never silently Complete.
#[test]
fn r3_backstop_marks_unavailable_fault_view_uncertain() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = nonquiesced(1_000);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    // The post-drain LOSS/TRUNC re-read failed mid-drain faults
    // may be missing from this batch.
    b.fault_view_uncertain = true;
    o.ingest(&b);
    assert_eq!(o.open_count(), 1, "no successor: honestly open");
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "unavailable fault view must not silently Complete: {:?}",
        o.done()[0].outcome
    );
    // Drained evidence is retained (uncertain, never dropped).
    assert_eq!(o.done()[0].alg_count, 2);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
}

/// Round 3, fixtures-wire: every fixture ALG status the
/// battery uses must survive the wire parser — the positive
/// battery feeds producer-admissible records (no class/status
/// contradictions like class-1 NOIMP/UNKNOWN/UNREADABLE).
#[test]
fn r3_fixture_algs_are_wire_admissible() {
    fn alg_bytes(e: &wire::ScanAlgEvent) -> Vec<u8> {
        assert_eq!(std::mem::size_of::<wire::ScanAlgEvent>(), 56);
        let p = e as *const wire::ScanAlgEvent as *const u8;
        unsafe { std::slice::from_raw_parts(p, 56) }.to_vec()
    }
    for status in [
        wire::ALG_OK,
        wire::ALG_NOIMP,
        wire::ALG_UNKNOWN,
        wire::ALG_UNREADABLE,
        wire::ALG_MIXED,
        wire::ALG_EMPTY,
    ] {
        let e = alg(TIDA, 0, 3, status);
        let bytes = alg_bytes(&e);
        assert!(
            wire::parse_scan_alg_event(&bytes).is_ok(),
            "status-{status} fixture must be wire-admissible: {:?}",
            wire::parse_scan_alg_event(&bytes).unwrap_err()
        );
        let e = alg_arr(TIDA, 0, 3, status, ARR, 0);
        let bytes = alg_bytes(&e);
        assert!(
            wire::parse_scan_alg_event(&bytes).is_ok(),
            "status-{status} alg_arr fixture must be wire-admissible: {:?}",
            wire::parse_scan_alg_event(&bytes).unwrap_err()
        );
    }
}

/// Round 3, residual B-2 (control): the same shape with an
/// available fault view Completes — the uncertainty rule fires
/// only on the marked view, never by default.
#[test]
fn r3_backstop_completes_with_available_fault_view() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = nonquiesced(1_000);
    b.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(TIDA, 0, 0));
    b.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    assert!(!b.fault_view_uncertain, "default view is available");
    o.ingest(&b);
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "available fault view still Completes: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (review's 6-step schedule): member
/// 1 emits EMPTY before member 0; member 0 emits RET, ALG_OK
/// and one ROW; batch 1 drains those records; batch 2 reads
/// empty pre-drain fault snapshots, then the dispatch read
/// faults (WALK_READ, retires) and the same thread issues a
/// successor CALL consumed during batch 2; batch 2's
/// post-TRUNC read fails with no new predecessor ring. The
/// take selector accepts the fault-uncertain marked open —
/// closure through the TAKE path must downgrade exactly like
/// the terminal backstop, never silently Complete.
#[test]
fn r4_take_marks_review_schedule_uncertain() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_row(row(TIDA, 0, 0));
    assert!(b1.order_sound());
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1, "no successor: honestly open");
    // Batch 2: unavailable fault view + the successor CALL, no
    // new predecessor ring (last ring evidence precedes the
    // fault write).
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1, "successor take closes seq 0");
    assert_eq!((o.done()[0].tid, o.done()[0].seq), (TIDA, 0));
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "take-path close of a marked open must not silently Complete: {:?}",
        o.done()[0].outcome
    );
    // Drained evidence is retained (uncertain, never dropped).
    assert_eq!(o.done()[0].alg_count, 2);
    assert_eq!(o.done()[0].row_count, 1);
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
}

/// Round 4, residual B-2-take (sticky marking): the uncertain
/// batch only MARKS the open (same-batch ring holds the take
/// close); a later quiet batch closes it through the sticky
/// successor mark. The sticky mark must survive to that close
/// — the verdict cannot be Complete.
#[test]
fn r4_take_sticky_mark_closes_uncertain_later() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    // Batch 2 (uncertain): successor CALL plus same-batch
    // predecessor ring (beyond-terminator EMPTY — discarded,
    // but it holds the take close one quiet batch).
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 0, "same-batch ring holds the take");
    // Batch 3 (certain, quiet): the sticky successor mark
    // closes seq 0 — still marked, still uncertain.
    o.ingest(&nonquiesced(3_000));
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "sticky take close of a marked open must not silently Complete: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
}

/// Round 4, residual B-2-take (predecessor-chain order): two
/// RET-joined opens span the uncertain batch; one successor
/// CALL take-closes both. Every marked open downgrades —
/// closure order across the chain changes nothing.
#[test]
fn r4_take_marked_chain_downgrades_every_open() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    for seq in [0, 1] {
        b1.push_call(call(TIDA, seq, false, wire::SKIP_ADMITTED));
        b1.push_ret(ret(TIDA, seq, 0));
        b1.push_alg(alg(TIDA, seq, 0, wire::ALG_OK));
        b1.push_alg(alg_arr(TIDA, seq, 1, wire::ALG_EMPTY, ARR, 0));
    }
    o.ingest(&b1);
    assert_eq!(o.open_count(), 2);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 2, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 2, "one take closes both opens");
    for w in o.done() {
        assert!(
            matches!(
                w.outcome,
                Outcome::Partial { ref reasons } if reasons
                    .iter()
                    .any(|r| matches!(r, PartialReason::FaultViewUncertain))
            ),
            "marked seq {} must not silently Complete: {:?}",
            w.seq,
            w.outcome
        );
    }
}

/// Round 4, residual B-2-take (RET-first order variant): the
/// same uncertain take close with RET joined before the slot
/// records. Drain order within the settled batch changes
/// neither the marking nor the downgrade.
#[test]
fn r4_take_ret_first_order_closes_uncertain() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "RET-first take close of a marked open must not silently Complete: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (Partial preservation): a marked
/// open that already earns Partial keeps its evaluated
/// reasons — the uncertainty marker is APPENDED, never a
/// replacement.
#[test]
fn r4_take_marked_hole_preserves_reasons() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg(TIDA, 0, 2, wire::ALG_OK)); // slot 1: hole
    b1.push_alg(alg_arr(TIDA, 0, 3, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    match &o.done()[0].outcome {
        Outcome::Partial { reasons } => {
            assert!(
                reasons.contains(&PartialReason::Holes(vec![1])),
                "evaluated hole reason must survive: {reasons:?}"
            );
            assert!(
                reasons
                    .iter()
                    .any(|r| matches!(r, PartialReason::FaultViewUncertain)),
                "uncertainty marker must append: {reasons:?}"
            );
        }
        other => panic!("marked holed take close must stay Partial: {other:?}"),
    }
}

/// Round 4, residual B-2-take (quiesced route): the same
/// closable funnel serves take closes AND quiesced-cell
/// closes — a marked open closed on IDLE cells in an
/// uncertain batch downgrades identically (the uncertainty is
/// about the retained fault evidence, identical on both
/// routes).
#[test]
fn r4_quiesced_marked_close_downgrades() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = quiesced_idle(&[TIDA]);
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1, "IDLE cells close the open");
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "quiesced close of a marked open must not silently Complete: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (RET-EMPTY parity): the take path
/// mirrors the terminal rule EXACTLY — even a RET-EMPTY
/// marked open downgrades (the backstop's Complete arm fires
/// there too; parity, not precision, is the contract).
#[test]
fn r4_take_marked_ret_empty_downgrades() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    let mut r = ret(TIDA, 0, 0);
    r.flags = wire::RET_FLAG_EMPTY;
    b1.push_ret(r);
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(
            o.done()[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::FaultViewUncertain))
        ),
        "RET-EMPTY take close of a marked open must mirror the backstop: {:?}",
        o.done()[0].outcome
    );
    assert_eq!(o.done()[0].true_t, TrueT::EmptyTable);
}

/// Round 4, residual B-2-take (taint control): uncertainty
/// never rewrites a nesting verdict — a marked open carrying
/// a taint still closes Tainted (terminal rule parity for
/// non-evaluated outcomes).
#[test]
fn r4_take_marked_taint_stands() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK)); // duplicate slot: taint
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.fault_view_uncertain = true;
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Tainted { .. }),
        "marked tainted take close must stay Tainted: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (available-view control): the
/// review-schedule shape with a CERTAIN view take-closes
/// Complete — the uncertainty rule fires only on the marked
/// view, never by default.
#[test]
fn r4_take_certain_view_completes() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_row(row(TIDA, 0, 0));
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    assert!(!b2.fault_view_uncertain, "default view is available");
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "certain-view take close still Completes: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (sticky available-view control):
/// the sticky-hold shape with CERTAIN views throughout
/// take-closes Complete — stickiness alone never downgrades.
#[test]
fn r4_take_sticky_certain_view_completes() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    let mut b2 = nonquiesced(2_000);
    b2.push_call(call(TIDA, 1, false, wire::SKIP_ADMITTED));
    b2.push_alg(alg_arr(TIDA, 0, 2, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 0, "same-batch ring holds the take");
    o.ingest(&nonquiesced(3_000));
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "certain-view sticky take close still Completes: {:?}",
        o.done()[0].outcome
    );
}

/// Round 4, residual B-2-take (quiesced available-view
/// control): an IDLE-cell close with a CERTAIN view Completes
/// — the quiesced route downgrades only marked opens.
#[test]
fn r4_quiesced_certain_view_completes() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = nonquiesced(1_000);
    b1.push_call(call(TIDA, 0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(TIDA, 0, 0));
    b1.push_alg(alg(TIDA, 0, 0, wire::ALG_OK));
    b1.push_alg(alg_arr(TIDA, 0, 1, wire::ALG_EMPTY, ARR, 0));
    o.ingest(&b1);
    o.ingest(&quiesced_idle(&[TIDA]));
    assert_eq!(o.done().len(), 1);
    assert!(
        matches!(o.done()[0].outcome, Outcome::Complete { .. }),
        "certain-view quiesced close still Completes: {:?}",
        o.done()[0].outcome
    );
}
