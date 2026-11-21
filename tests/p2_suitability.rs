// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 2 producer-suitability pins: the T8.2a producer (demux,
//! decoder, pairing, streaming folds) re-proved suitable for the
//! expanded API vocabulary (P1-A1 73..=80) on the selected 3.5.x
//! input. Host-side, unprivileged; live legs re-prove in the guest.
use osslscope::provider_observation::{trace, wire};

fn edge_bytes(kind: u32, api: u32, outcome: u32) -> Vec<u8> {
    let mut b = vec![0; wire::contract::EVENT_SIZE];
    for (at, v) in [
        (0, wire::contract::VERSION),
        (4, kind),
        (8, wire::contract::EVENT_SIZE as u32),
        (12, api),
        (16, 42),
        (20, 43),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    for at in [24, 32, 40, 48, 96] {
        b[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
    }
    b[56..60].copy_from_slice(&outcome.to_le_bytes());
    b
}

fn key(invocation: u64, cookie: u64) -> trace::PairKey {
    trace::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie,
        invocation,
    }
}

fn bearing() -> trace::TraceProducer {
    let mut p = trace::TraceProducer::new();
    p.set_mode(trace::TRACE_MODE_LATENCY);
    p
}

/// Suitability S1: decoder and demux agree on the full expanded
/// vocabulary. ATTEMPT decodes exactly on 1..=6|10..=15|20..=72|
/// 73..=80; demux accepts exactly 1..=80 (None ⟺ {0} ∪ {81+}).
#[test]
fn suitability_decoder_demux_agree_over_expanded_vocabulary() {
    for api in 0..=90u32 {
        let demuxed = trace::demux(api).is_some();
        assert_eq!(
            demuxed,
            (1..=80).contains(&api),
            "demux boundary at api {api}"
        );
        let decodable = matches!(api, 1..=6 | 10..=15 | 20..=72 | 73..=80);
        assert_eq!(
            wire::decode(&edge_bytes(1, api, 0)).is_ok(),
            decodable,
            "ATTEMPT decode at api {api}"
        );
        assert_eq!(
            wire::decode(&edge_bytes(2, api, 1)).is_ok(),
            decodable,
            "RESULT decode at api {api}"
        );
    }
    // Family assignment of the extension block.
    for api in 73..=80u32 {
        assert_eq!(trace::demux(api), Some(trace::TraceFamily::Fetch));
    }
}

/// Suitability S2: every extension fetch surface (73..=80) pairs
/// through the producer, folds class-0, skips histograms, and lands
/// in its own per-API slot.
#[test]
fn suitability_extension_fetch_pairs_fold_class_zero() {
    let mut p = bearing();
    for (i, api) in (73..=80u32).enumerate() {
        let k = key(i as u64 + 1, 100 + i as u64);
        let ns = 1000 + i as u64 * 100;
        p.attempt(trace::AttemptEdge {
            key: k,
            api,
            monotonic_ns: ns,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(trace::ResultEdge {
            key: k,
            api,
            monotonic_ns: ns + 50,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let w = p.close_window(0, 9000, [0; 8]);
    assert_eq!(w.paired, 8);
    assert_eq!(w.unpaired_entries, 0);
    assert_eq!(w.unpaired_results, 0);
    assert_eq!(w.class_counts, [8, 0, 0, 0, 0]);
    for (c, h) in w.histograms.iter().enumerate() {
        assert_eq!(
            (h.count, h.sum),
            (0, 0),
            "extension fetch never histogrammed: class {c}"
        );
    }
    for api in 73..=80u32 {
        assert_eq!(w.api_attempts[api as usize], 1, "attempt slot {api}");
        assert_eq!(w.api_results[api as usize], 1, "result slot {api}");
    }
    assert_eq!(w.received.attempts[trace::TraceFamily::Fetch.index()], 8);
}

/// Suitability S3: a mixed window (lifecycle + both fetch blocks +
/// operational) partitions exactly; class counts sum to paired.
#[test]
fn suitability_mixed_window_partition_exact() {
    let mut p = bearing();
    let mut inv = 0u64;
    let mut pair = |p: &mut trace::TraceProducer, api: u32, outcome: u32, ns: u64| {
        inv += 1;
        let k = key(inv, 500 + inv);
        p.attempt(trace::AttemptEdge {
            key: k,
            api,
            monotonic_ns: ns,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(trace::ResultEdge {
            key: k,
            api,
            monotonic_ns: ns + 10,
            outcome,
            start_time_ns: 1,
            seed: 1,
        });
    };
    // Lifecycle 1..=6, legacy fetch 10..=15, operational sample,
    // extension fetch 73..=80.
    for api in 1..=6u32 {
        pair(&mut p, api, 1, 1000 + api as u64);
    }
    for api in 10..=15u32 {
        pair(&mut p, api, 1, 2000 + api as u64);
    }
    for api in [20u32, 22, 23, 64, 69, 70] {
        pair(&mut p, api, 1, 3000 + api as u64);
    }
    for api in 73..=80u32 {
        pair(&mut p, api, 1, 4000 + api as u64);
    }
    // One orphan attempt (operational) + one orphan result.
    inv += 1;
    p.attempt(trace::AttemptEdge {
        key: key(inv, 900),
        api: 22,
        monotonic_ns: 5000,
        start_time_ns: 1,
        seed: 1,
    });
    inv += 1;
    p.result(trace::ResultEdge {
        key: key(inv, 901),
        api: 22,
        monotonic_ns: 5010,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    // N → N+1 carry: the two orphans expire at the second close.
    let w = p.close_window(0, 9000, [0; 8]);
    assert_eq!(w.paired, 26);
    assert_eq!(w.unpaired_entries, 0);
    assert_eq!(w.unpaired_results, 0);
    // Window 0 still holds the 2 orphans as live carry, so the
    // received == paired + unpaired partition does NOT hold here
    // (27 received vs 26 paired + 0 unpaired) — it holds once the
    // carry expires (window 1) or at finalize.
    let received_attempts: u64 = w.received.attempts.iter().sum();
    let received_results: u64 = w.received.results.iter().sum();
    assert_eq!(received_attempts, 27);
    assert_eq!(received_results, 27);
    let w1 = p.close_window(1, 9000, [0; 8]);
    assert_eq!(w1.paired, 0);
    assert_eq!(w1.unpaired_entries, 1);
    assert_eq!(w1.unpaired_results, 1);
    let totals = p.totals();
    assert_eq!(totals.paired, 26);
    assert_eq!(totals.unpaired_entries, 1);
    assert_eq!(totals.unpaired_results, 1);
    let total_attempts: u64 = totals.received.attempts.iter().sum();
    let total_results: u64 = totals.received.results.iter().sum();
    assert_eq!(total_attempts, totals.paired + totals.unpaired_entries);
    assert_eq!(total_results, totals.paired + totals.unpaired_results);
    assert_eq!(w.class_counts.iter().sum::<u64>(), w.paired);
    // 20 class-0 (6 lifecycle + 6 legacy fetch + 8 extension),
    // 6 operational successes.
    assert_eq!(w.class_counts, [20, 6, 0, 0, 0]);
    assert_eq!(w.api_attempts.iter().sum::<u64>(), received_attempts);
    assert_eq!(w.api_results.iter().sum::<u64>(), received_results);
    // Only the 6 operational pairs histogrammed.
    let hist_total: u64 = w.histograms.iter().map(|h| h.count).sum();
    assert_eq!(hist_total, 6);
}

/// Suitability S4 (off-mode twin): in off/metadata modes the
/// extension fetch edges count (ungated emission) but never pair.
#[test]
fn suitability_extension_off_mode_twin() {
    for mode in [trace::TRACE_MODE_OFF, trace::TRACE_MODE_METADATA] {
        let mut p = trace::TraceProducer::new();
        p.set_mode(mode);
        for (i, api) in (73..=80u32).enumerate() {
            let k = key(i as u64 + 1, 300 + i as u64);
            p.attempt(trace::AttemptEdge {
                key: k,
                api,
                monotonic_ns: 1000,
                start_time_ns: 1,
                seed: 1,
            });
            p.result(trace::ResultEdge {
                key: k,
                api,
                monotonic_ns: 1100,
                outcome: 1,
                start_time_ns: 1,
                seed: 1,
            });
        }
        let w = p.close_window(0, 9000, [0; 8]);
        assert_eq!(w.mode, mode);
        assert_eq!(w.paired, 0, "mode {mode}");
        assert_eq!(w.class_counts, [0; 5], "mode {mode}");
        assert!(
            w.histograms.iter().all(|h| h.count == 0 && h.sum == 0),
            "mode {mode}"
        );
        for api in 73..=80u32 {
            assert_eq!(w.api_attempts[api as usize], 1, "mode {mode} slot {api}");
        }
    }
}

/// Suitability S6 (pairing schedules through production
/// publication, P2fix1 item 3 as corrected by P2fix2 item 5 and
/// P2fix3 item 5): the R13, skip, and overflow schedules drive the
/// REAL fold → close → summarize → validate → JSON → presenter →
/// adapters/frame path. Overflow corrupts pairing trust
/// (uncertainty marked, interpreted distributions withheld in
/// every spelling, raw kept); skips land unpaired exactly
/// (certain zeros project, never withheld); the R13 schedule
/// carries the ACTUAL emitted schedule (quota units + rejected
/// return → seven Y-keyed emissions with (7,900) first, X1
/// absent) and pairs all 7 Y frames while orphaning X1 visibly —
/// certain throughout, with no operational duration folded.
#[test]
fn suitability_pairing_schedules_pin_through_publication() {
    use osslscope::presentation::{Presenter, snapshot};
    // --- Overflow schedule: 4100 concurrent attempts against the
    // 4096 pending cap (4 evicted), the 4096 survivors paired.
    let mut p = bearing();
    p.set_histogram_by_api(true);
    for i in 0..4100u64 {
        let k = key(i + 1, 10000 + i);
        p.attempt(trace::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i,
            start_time_ns: 1,
            seed: 1,
        });
    }
    for i in 0..4096u64 {
        // Results for the SURVIVORS only (invocations 5..=4100 —
        // FIFO evicted the first four).
        let k = key(i + 5, 10004 + i);
        p.result(trace::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 9000 + i,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let w = p.close_window(0, 20000, [0; 8]);
    assert_eq!(w.paired, 4096);
    assert_eq!(w.unpaired_entries, 4);
    assert_eq!(w.unpaired_results, 0);
    assert_eq!(w.pending_evicted_entries, 4);
    assert!(w.pairing_uncertain);
    assert!(
        w.pairing_uncertainty
            .contains(&"pending-eviction".to_string())
    );
    let t = p.totals();
    assert!(t.pairing_uncertain);
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 { "covered" } else { "not_attached" }.to_string(),
        );
    }
    let s = trace::summarize(&w, &t, "latency", Some(&avail));
    s.validate().expect("withheld overflow summary validates");
    assert!(s.class_epoch.is_none() && s.histograms.is_none() && s.by_api.is_none());
    // Through publication: JSON round-trip → presenter → adapters.
    let json = serde_json::to_value(&s).unwrap();
    let back: trace::TraceSummary = serde_json::from_value(json).unwrap();
    back.validate().expect("round-tripped summary validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&back).unwrap();
    // Coverage support (P2fix3 GATE29 — the covered-20 claim
    // needs a clean activity row).
    doc["api_activity"] = serde_json::json!([{
        "api": 20, "entries": 1,
        "observed_success": 1, "observed_failure": 0,
        "verification_mismatch": 0, "unsupported": 0,
        "gaps": {
            "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
            "unsupported_return": 0, "saturated": false,
            "not_attached": false, "read_receipt": true,
            "attachment": false, "finality": false,
        },
    }]);
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block kept");
    assert_eq!(trace.paired, 4096);
    assert!(trace.class_window.is_none() && trace.class_epoch.is_none());
    assert!(trace.pairing_uncertain);
    assert!(snap.histograms.is_none());
    assert!(snap.counts.by_outcome.is_none());
    let prom = osslscope::presentation::prometheus::render(&snap);
    assert!(!prom.contains("osslscope_trace_calls_total"), "{prom:?}");
    assert!(
        !prom.contains("osslscope_dispatch_duration_nanoseconds_bucket"),
        "{prom:?}"
    );
    let otel = osslscope::presentation::otel::render(&snap);
    assert!(!otel.contains("osslscope.trace.calls"), "{otel:?}");
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(frame.contains("class withheld"), "{frame:?}");
    // --- Skip schedule: orphan attempt + orphan result straddling
    // closes land unpaired exactly, never paired, staying certain —
    // through publication (the certain shape projects: zero
    // classes shown as observed zeros, never withheld).
    let mut p = bearing();
    p.attempt(trace::AttemptEdge {
        key: key(1, 501),
        api: 22,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(trace::ResultEdge {
        key: key(2, 502),
        api: 22,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let w0 = p.close_window(0, 9000, [0; 8]);
    assert_eq!(
        (w0.paired, w0.unpaired_entries, w0.unpaired_results),
        (0, 0, 0)
    );
    assert!(!w0.pairing_uncertain);
    let w1 = p.close_window(1, 9900, [0; 8]);
    assert_eq!(
        (w1.paired, w1.unpaired_entries, w1.unpaired_results),
        (0, 1, 1)
    );
    assert!(!w1.pairing_uncertain);
    let t = p.totals();
    let s = trace::summarize(&w1, &t, "latency", None);
    s.validate().expect("skip summary validates");
    let json = serde_json::to_value(&s).unwrap();
    let back: trace::TraceSummary = serde_json::from_value(json).unwrap();
    back.validate()
        .expect("round-tripped skip summary validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&back).unwrap();
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block kept");
    assert_eq!(
        (
            trace.paired,
            trace.trace_unpaired_entries,
            trace.trace_unpaired_results
        ),
        (0, 1, 1)
    );
    assert!(!trace.pairing_uncertain);
    // Certain zero classes project as observed zeros (present, all
    // zero — the honest absence, never withheld, never estimated).
    let cw = trace.class_window.as_ref().expect("certain zeros show");
    assert_eq!(
        (cw.success, cw.failure, cw.empty, cw.retry, cw.unknown),
        (0, 0, 0, 0, 0)
    );
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(!frame.contains("class withheld"), "{frame:?}");
    // --- R13 schedule (P2fix3 item 5 — the ACTUAL emitted
    // schedule, replacing the correctly-keyed fiction): quota
    // units A(Y) + B(X), window close MID-FLIGHT (pre-expiry
    // carry), B's rejected return stealing X1's frame, A's accept
    // emitting (7,900) against Y7's frame FIRST, X1's genuine
    // return consuming B's orphan — seven Y-keyed emissions, X1
    // absent. Key-exact matching pairs all 7 Y frames and orphans
    // X1 visibly, through publication. (The wire-driven pin lives
    // in-crate as
    // `trace::tests::r13_emitted_schedule_carries_through_publication`.)
    let mut p = bearing();
    for i in 1..=7u64 {
        let k = key(i, 700 + i);
        p.attempt(trace::AttemptEdge {
            key: k,
            api: 10,
            monotonic_ns: 1000 + 10 * i,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let xk = key(8, 708);
    p.attempt(trace::AttemptEdge {
        key: xk,
        api: 20,
        monotonic_ns: 1100,
        start_time_ns: 1,
        seed: 1,
    });
    let w0 = p.close_window(0, 1900, [0; 8]);
    assert_eq!(
        (w0.paired, w0.unpaired_entries, w0.unpaired_results),
        (0, 0, 0),
        "mid-flight close carries (pre-expiry)"
    );
    // ACTUAL emitted schedule (P2fix3 PAIRING — RED step): X1
    // emits nothing (consumed by the rejected arm); (7,900)
    // FIRST, then Y6..Y1 LIFO.
    p.result(trace::ResultEdge {
        key: key(7, 707),
        api: 10,
        monotonic_ns: 1970,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    for i in (1..=6u64).rev() {
        p.result(trace::ResultEdge {
            key: key(i, 700 + i),
            api: 10,
            monotonic_ns: 2080 - 10 * i,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let w1 = p.close_window(1, 9900, [0; 8]);
    assert_eq!(w1.paired, 7, "seven Y frames pair; X1 orphans");
    assert_eq!((w1.unpaired_entries, w1.unpaired_results), (1, 0));
    assert_eq!(w1.class_counts, [7, 0, 0, 0, 0]);
    assert_eq!(w1.histograms[1].count, 0, "no operational duration folds");
    assert_eq!(w1.histograms[1].sum, 0, "the 900 stays in fetch class-0");
    assert!(!w1.pairing_uncertain, "orphan expiry stays certain");
    let t = p.totals();
    assert_eq!(
        (t.paired, t.unpaired_entries, t.unpaired_results),
        (7, 1, 0)
    );
    let s = trace::summarize(&w1, &t, "latency", None);
    s.validate().expect("r13 summary validates");
    assert_eq!(s.window.class_window.as_ref().unwrap().success, 0);
    assert_eq!(s.window.class_window.as_ref().unwrap().unknown, 7);
    let json = serde_json::to_value(&s).unwrap();
    let back: trace::TraceSummary = serde_json::from_value(json).unwrap();
    back.validate()
        .expect("round-tripped r13 summary validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&back).unwrap();
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("trace block projects");
    assert_eq!(trace.paired, 7);
    assert_eq!(trace.trace_unpaired_entries, 1);
    let prom = osslscope::presentation::prometheus::render(&snap);
    assert!(prom.contains("osslscope_trace_calls_total"), "{prom:?}");
    let otel = osslscope::presentation::otel::render(&snap);
    assert!(otel.contains("osslscope.trace.calls"), "{otel:?}");
}

/// Suitability S5 (3.5.x input vocabulary): every expanded attach ID
/// carries a decodable surface — ATTEMPT/RESULT decode on the full
/// attach enumeration, and RESULT classes fold Failure ← {2,3,4}.
#[test]
fn suitability_attach_enumeration_decodes_and_folds() {
    use osslscope::provider_observation as po;
    let attach: Vec<u32> = (1..=16).chain(20..=72).chain(73..=80).collect();
    assert_eq!(attach.len(), 16 + 53 + 8);
    for api in attach {
        let attempt_ok = wire::decode(&edge_bytes(1, api, 0)).is_ok();
        // IDs 7,8,9,16 carry no ATTEMPT/RESULT edges (lifecycle
        // metadata only); everything else on the attach list does.
        let expect = !matches!(api, 7 | 8 | 9 | 16);
        assert_eq!(attempt_ok, expect, "ATTEMPT api {api}");
        if expect {
            for (raw, folded) in [
                (0u32, po::ApiOutcome::Unknown),
                (1, po::ApiOutcome::Success),
                (2, po::ApiOutcome::Failure),
                (3, po::ApiOutcome::Failure),
                (4, po::ApiOutcome::Failure),
            ] {
                let event = wire::decode(&edge_bytes(2, api, raw))
                    .unwrap_or_else(|g| panic!("RESULT api={api} raw={raw}: {g:?}"));
                assert!(
                    matches!(event.payload(), po::ObservationPayload::ApiResult { outcome: got, .. } if *got == folded),
                    "api {api} raw {raw}"
                );
            }
        }
    }
}
