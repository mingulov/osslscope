//! SPDX-License-Identifier: GPL-3.0-or-later
//! Trailing-closure controls (findings 6–7): window-edge finish,
//! hung-scan abandonment, and governor composition with the real
//! capture loop. These failed before the fix (opens stuck past
//! the window; zero attempt-rate at 250ms spacing; idle polls
//! never releasing the throttle).

use osslscope::scan::governor::{DutyThrottle, StormAction, StormDetector, ThrottleAction};
use osslscope::scan::oracle::*;
use osslscope_ebpf_common as wire;

const TID: u32 = 4242;
const ARR: u64 = 0x7000;
const OP: u32 = 7;

fn call(seq: u64, hint: bool, cause: u8) -> wire::ScanCallEvent {
    wire::ScanCallEvent {
        kind: wire::KIND_SCAN_CALL,
        op: OP,
        tid: TID,
        flags: wire::make_call_flags(hint, cause),
        seq,
    }
}

fn ret(seq: u64) -> wire::ScanRetEvent {
    wire::ScanRetEvent {
        kind: wire::KIND_SCAN_RET,
        op: OP,
        flags: 0,
        tid: TID,
        seq,
        arr: ARR,
        generation: 0,
    }
}

fn alg(seq: u64, idx: u64, status: u8) -> wire::ScanAlgEvent {
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
        arr: ARR,
        idx,
        generation: 0,
        tid: TID,
        _pad2: 0,
        seq,
    }
}

/// Finding 6: the window edge closes trailing queries — RET-joined
/// opens evaluate on retained evidence (backstop), RET-less opens
/// taint both correlated sequences (never dropped, never standing
/// on mixed evidence).
#[test]
fn fix1_finish_closes_trailing() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(0));
    b.push_alg(alg(0, 0, wire::ALG_OK));
    b.push_alg(alg(0, 1, wire::ALG_EMPTY));
    b.push_call(call(1, false, wire::SKIP_ADMITTED)); // no RET: dangling
    o.ingest(&b);
    // The quiet successor already retired seq 0 (successor close);
    // seq 1 trails with no RET.
    assert_eq!(o.open_count(), 1);
    assert_eq!(o.done().len(), 1);
    o.finish(2_000);
    assert_eq!(o.open_count(), 0);
    assert_eq!(o.done().len(), 2);
    let s0 = o.done().iter().find(|w| w.seq == 0).unwrap();
    assert!(
        matches!(s0.outcome, Outcome::Tainted { .. }),
        "dangling successor taints the correlated record: {s0:?}"
    );
    let s1 = o.done().iter().find(|w| w.seq == 1).unwrap();
    assert!(matches!(s1.outcome, Outcome::Tainted { .. }));
    assert_eq!(s1.op, UNKNOWN_OP);
    // A lone completed query with NO successor trails honestly
    // open mid-window, then the backstop evaluates it.
    let mut o = Oracle::new(OracleScope::full());
    let mut b = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b.push_call(call(0, false, wire::SKIP_ADMITTED));
    b.push_ret(ret(0));
    b.push_alg(alg(0, 0, wire::ALG_OK));
    b.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b);
    assert_eq!(o.open_count(), 1);
    assert!(o.done().is_empty());
    o.finish(2_000);
    assert_eq!(o.done().len(), 1);
    assert!(matches!(
        o.done()[0].outcome,
        Outcome::Complete { true_t: 1, .. }
    ));
    assert_eq!(o.done()[0].true_t, TrueT::Proven(1));
}

/// Finding 6: the 5s sticky abandonment fires on age (RET-less
/// opens only), cascades to same-tid RET-less outers, and a late
/// RET joins as LATE with the verdict standing.
#[test]
fn fix1_hung_abandonment_and_late_ret() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 0,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_call(call(1, true, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 2);
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: HUNG_NS + 1,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert_eq!(o.open_count(), 0, "aged RET-less opens abandon");
    assert!(
        o.done().iter().all(|w| matches!(
            w.outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Hung
            }
        )),
        "{:?}",
        o.done()
    );
    // A late RET joins as LATE (coverage noted, verdict stands —
    // no resurrection, no orphan either).
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: HUNG_NS + 2,
        ..ScanBatch::default()
    };
    b3.push_ret(ret(0));
    o.ingest(&b3);
    assert_eq!(o.done().len(), 2, "verdict stands");
    assert!(o.findings().contains(&Finding::LateRet {
        tid: TID,
        seq: 0,
        arr: ARR
    }));
}

/// Finding 6: RET-joined opens never hang-abandon (evidence in
/// hand closes on succession/finish, not on age).
#[test]
fn fix1_hung_spares_ret_joined() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 0,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(0));
    b1.push_alg(alg(0, 0, wire::ALG_OK));
    b1.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b1);
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: 2 * HUNG_NS,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert_eq!(o.open_count(), 1, "RET-joined opens survive aging");
    assert!(o.done().is_empty());
}

/// Finding 7: the storm detector trips at the real 250ms capture
/// spacing (1200/s over sparse polls — the trailing-100ms
/// first-sample rule reported zero).
#[test]
fn fix1_storm_detector_sparse_polls_trip() {
    let mut d = StormDetector::new();
    assert_eq!(d.observe(0, 0), None);
    // 200 over 250ms = 800/s: under the line.
    assert_eq!(d.observe(250_000_000, 200), None);
    // 300 more over the next 250ms = 1200/s: trips.
    assert_eq!(
        d.observe(500_000_000, 500),
        Some(StormAction::Detach),
        "300 attempts over 250ms = 1200/s must trip"
    );
    assert!(d.detached());
}

/// Round-2 F6: late-RET recovery survives production drains —
/// the RET for a hung-abandoned invocation joins as LATE even
/// after `take_done` consumed the verdict (no orphaning).
#[test]
fn fix2_late_ret_after_production_drain() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    o.ingest(&b1);
    assert_eq!(o.open_count(), 1);
    // Age past the 5s hung line, then drain like production
    // (every poll takes `done`).
    let b2 = ScanBatch {
        quiesced: false,
        now_ns: 6_000_000_001,
        ..ScanBatch::default()
    };
    o.ingest(&b2);
    assert!(o.done().iter().any(|w| w.seq == 0
        && matches!(
            w.outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Hung
            }
        )));
    let drained = o.take_done();
    assert_eq!(drained.len(), 1);
    assert!(o.done().is_empty());
    // The late RET arrives after the drain: LATE join, verdict
    // standing — never an orphan.
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 6_000_000_002,
        ..ScanBatch::default()
    };
    b3.push_ret(ret(0));
    o.ingest(&b3);
    assert!(
        o.findings().contains(&Finding::LateRet {
            tid: TID,
            seq: 0,
            arr: ARR
        }),
        "late RET after drain must join LATE: {:?}",
        o.findings()
    );
    assert!(
        !o.findings()
            .iter()
            .any(|f| matches!(f, Finding::OrphanRet { seq: 0, .. }))
    );
}

/// Round-2 F6: straggler records for consumed invocations are not
/// orphans (cross-CPU ring skew delivers them after the close;
/// the oracle retains the outcome evidence across drains).
#[test]
fn fix2_consumed_no_false_orphans() {
    let mut o = Oracle::new(OracleScope::full());
    let mut b1 = ScanBatch {
        quiesced: false,
        now_ns: 1_000,
        ..ScanBatch::default()
    };
    b1.push_call(call(0, false, wire::SKIP_ADMITTED));
    b1.push_ret(ret(0));
    b1.push_alg(alg(0, 0, wire::ALG_OK));
    b1.push_alg(alg(0, 1, wire::ALG_EMPTY));
    o.ingest(&b1);
    let mut b2 = ScanBatch {
        quiesced: false,
        now_ns: 2_000,
        ..ScanBatch::default()
    };
    b2.push_call(call(1, false, wire::SKIP_ADMITTED));
    o.ingest(&b2);
    assert_eq!(o.done().len(), 1);
    let _ = o.take_done();
    // Stragglers for the consumed key arrive late: absorbed, not
    // orphan findings.
    let mut b3 = ScanBatch {
        quiesced: false,
        now_ns: 3_000,
        ..ScanBatch::default()
    };
    b3.push_alg(alg(0, 2, wire::ALG_OK));
    b3.push_guard(wire::GuardEvent {
        kind: wire::KIND_GUARD,
        op: OP,
        verdict: wire::GUARD_EMPTY,
        tid: TID,
        seq: 0,
        arr: ARR,
        generation: 0,
    });
    o.ingest(&b3);
    assert!(
        !o.findings().iter().any(|f| matches!(
            f,
            Finding::OrphanAlg { seq: 0, .. } | Finding::OrphanGuard { seq: 0, .. }
        )),
        "consumed-key stragglers must not orphan: {:?}",
        o.findings()
    );
    // A truly unknown key still orphans.
    let mut b4 = ScanBatch {
        quiesced: false,
        now_ns: 4_000,
        ..ScanBatch::default()
    };
    b4.push_alg(alg(9, 0, wire::ALG_OK));
    o.ingest(&b4);
    assert!(
        o.findings()
            .iter()
            .any(|f| matches!(f, Finding::OrphanAlg { seq: 9, .. }))
    );
}

/// Finding 7: idle polls age the tier-2 window (an engaged
/// throttle releases once the trailing cost decays, without
/// needing a completion to trigger the recheck).
#[test]
fn fix1_tier2_idle_aging_releases() {
    let mut t = DutyThrottle::new();
    for i in 0..1000u64 {
        t.observe(i * 100_000, 511);
    }
    assert!(t.throttled());
    assert_eq!(t.age(3_000_000_000), Some(ThrottleAction::ReleaseSkipAll));
    assert!(!t.throttled());
}
