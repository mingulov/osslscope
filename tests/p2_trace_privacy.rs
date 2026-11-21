// SPDX-License-Identifier: GPL-3.0-or-later
//! §6D-11 privacy pins with deliberate canary positive controls:
//! canary cookies/params flow through the real fold and every 6D
//! output carries only hashes/classes — the canary values are
//! provably exposed (positive control) yet never emitted.
use osslscope::provider_observation::trace as t;

// Canary cookie: distinctive in decimal (12648430), hex
// (0xc0ffee), and byte form — any raw crossing is greppable.
const CANARY_COOKIE: u64 = 0xC0FFEE;
const CANARY_DEC: &str = "12648430";
const CANARY_HEX: &str = "c0ffee";

fn fold_canary() -> (t::ClosedTraceWindow, t::TraceTotals) {
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    // Every raw outcome class (0..4) crosses pairing; only the
    // class may appear downstream (never an `rv` scalar).
    for (i, outcome) in [0u32, 1, 2, 3, 4].iter().enumerate() {
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: CANARY_COOKIE + i as u64,
            invocation: 100 + i as u64,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i as u64 * 100,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1050 + i as u64 * 100,
            outcome: *outcome,
            start_time_ns: 1,
            seed: 1,
        });
    }
    // One orphan for an exemplar (hashed key only).
    p.attempt(t::AttemptEdge {
        key: t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: CANARY_COOKIE + 99,
            invocation: 200,
        },
        api: 22,
        monotonic_ns: 2000,
        start_time_ns: 1,
        seed: 1,
    });
    // Terminal finalize lands the orphan unpaired WITH its
    // exemplar in window 0.
    p.finalize(9000);
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    assert_eq!(window.paired, 5);
    assert_eq!(window.unpaired_entries, 1);
    assert!(!window.exemplars.is_empty());
    (window, totals)
}

fn assert_no_raw_canary(name: &str, body: &str) {
    for needle in [CANARY_DEC, CANARY_HEX, "C0FFEE", "12648431", "12648429"] {
        assert!(!body.contains(needle), "{name} leaks raw canary {needle}");
    }
    // No raw-cookie key anywhere (hashes only).
    assert!(!body.contains("\"cookie\""), "{name} carries a cookie key");
    assert!(
        !body.contains("cookie="),
        "{name} carries a cookie fragment"
    );
}

#[test]
fn canary_cookies_never_cross_raw() {
    let (window, totals) = fold_canary();
    // POSITIVE CONTROL: the canary cookies entered pairing (5
    // pairs + hashed detail rows prove exposure).
    assert_eq!(window.detail.len(), 11);
    // Every output below must carry the HASH (proves the flow) and
    // never the raw canary.
    let expect_hash = t::key_hash16(CANARY_COOKIE, 1);
    let detail = t::detail_json(&window);
    let detail_text = serde_json::to_string(&detail).unwrap();
    assert!(detail_text.contains(&expect_hash), "hash flows to detail");
    assert_no_raw_canary("detail", &detail_text);
    // Detail rows carry the closed field set only.
    for row in detail.as_array().unwrap() {
        let keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for key in keys {
            assert!(
                [
                    "kind",
                    "api",
                    "pid",
                    "tid",
                    "generation",
                    "key_hash16",
                    "invocation",
                    "monotonic_ns",
                    "outcome"
                ]
                .contains(&key),
                "detail row carries non-allowlist key {key}"
            );
        }
        assert!(row["outcome"].as_u64().unwrap() <= 4);
    }
    // §6D-7 record + summary.
    let record = osslscope::provider_observation::cli::trace_record_json(&window, &totals, None);
    let record_text = serde_json::to_string(&record).unwrap();
    assert_no_raw_canary("6d7-record", &record_text);
    let summary = t::summarize(&window, &totals, "latency", None);
    let summary_text = serde_json::to_string(&summary).unwrap();
    assert_no_raw_canary("summary", &summary_text);
    // Paired canaries fold into counts (no per-pair identity —
    // honest absence); the orphan's hash proves exemplar flow.
    let orphan_hash = t::key_hash16(CANARY_COOKIE + 99, 1);
    assert!(summary_text.contains(&orphan_hash), "hash flows to summary");
    // Terminal sections.
    let mut human = Vec::new();
    osslscope::provider_observation::cli::trace_human(&window, &totals, None, &mut human).unwrap();
    let human = String::from_utf8(human).unwrap();
    assert_no_raw_canary("trace-human", &human);
    let mut detail_h = Vec::new();
    osslscope::provider_observation::cli::trace_detail_human(&window, &mut detail_h).unwrap();
    let detail_h = String::from_utf8(detail_h).unwrap();
    assert!(detail_h.contains(&expect_hash), "hash flows to -vv");
    assert_no_raw_canary("trace-detail-human", &detail_h);
}

#[test]
fn canary_never_reaches_exporters_or_frames() {
    use osslscope::presentation::{Presenter, snapshot};
    let (window, totals) = fold_canary();
    let summary = t::summarize(&window, &totals, "latency", None);
    let mut doc = snapshot::test_document(5, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let snap = Presenter::oneshot(&doc).unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    assert_no_raw_canary("snapshot", &json);
    let prom = osslscope::presentation::prometheus::render(&snap);
    assert_no_raw_canary("prometheus", &prom);
    let otel = osslscope::presentation::otel::render(&snap);
    assert_no_raw_canary("otel", &otel);
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert_no_raw_canary("frame", &frame);
    // The hashed exemplar still flows (positive control at the
    // presentation layer).
    let orphan_hash = t::key_hash16(CANARY_COOKIE + 99, 1);
    assert!(json.contains(&orphan_hash), "hash flows to snapshot");
}

#[test]
fn renderer_entry_points_omit_poisoned_labels_on_every_profile() {
    // P2fix1 item 6: persisted strings (by_api keys) reach label
    // values — the REAL renderer entry points must omit
    // off-vocabulary labels on EVERY profile (not debug-only),
    // while valid series flow (positive controls).
    use osslscope::presentation::{Presenter, snapshot};
    let (window, totals) = fold_canary();
    let summary = t::summarize(&window, &totals, "latency", None);
    let mut doc = snapshot::test_document(5, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let mut snap = Presenter::oneshot(&doc).unwrap();
    // Graft a by_api block: one valid unit + three poisoned keys
    // (algorithm-like, path-like, control-bearing).
    let entry = snapshot::ByApiEntry {
        success: snapshot::Distribution {
            buckets: [1; 19],
            sum: 50,
            count: 1,
        },
        failure: snapshot::Distribution::default(),
        empty: snapshot::Distribution::default(),
        retry: snapshot::Distribution::default(),
        unknown: snapshot::Distribution::default(),
    };
    let mut by_api = std::collections::BTreeMap::new();
    by_api.insert("20".to_string(), entry.clone());
    by_api.insert("EVP_Digest".to_string(), entry.clone());
    by_api.insert("../../..".to_string(), entry.clone());
    by_api.insert("20\x1b[31m".to_string(), entry);
    let hist = snap.histograms.as_mut().expect("histograms");
    hist.by_api = Some(by_api);
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(id.to_string(), "not_attached".to_string());
    }
    avail.insert("20".to_string(), "covered".to_string());
    hist.by_api_availability = Some(avail);
    // Prometheus: poison absent, valid present (both spellings of
    // the check — the api label never escapes the decimal form).
    let prom = osslscope::presentation::prometheus::render(&snap);
    for needle in ["EVP_Digest", "..", "\x1b"] {
        assert!(!prom.contains(needle), "prometheus leaks {needle:?}");
    }
    assert!(prom.contains("api=\"20\""), "valid unit flows");
    assert!(prom.contains("osslscope_trace_calls_total"), "P-16 flows");
    // OTel consumes the shared admission set: same rule.
    let otel = osslscope::presentation::otel::render(&snap);
    for needle in ["EVP_Digest", "..", "\x1b"] {
        assert!(!otel.contains(needle), "otel leaks {needle:?}");
    }
    assert!(otel.contains("\"key\":\"api\""), "valid unit flows to otel");
    // Frames never carry label vocabularies; canary rules hold.
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert_no_raw_canary("frame", &frame);
    for needle in ["EVP_Digest", "\x1b"] {
        assert!(!frame.contains(needle), "frame leaks {needle:?}");
    }
}

#[test]
fn otel_omits_malformed_distributions_without_disagreement() {
    // P2fix1 item 23: bucket/count conversion must agree — a
    // malformed distribution (non-cumulative buckets) omits its
    // OTLP point instead of emitting disagreeing counts; valid
    // points convert exactly (differences telescope to count).
    use osslscope::presentation::{Presenter, snapshot};
    let (window, totals) = fold_canary();
    let summary = t::summarize(&window, &totals, "latency", None);
    let mut doc = snapshot::test_document(5, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let mut snap = Presenter::oneshot(&doc).unwrap();
    let hist = snap.histograms.as_mut().expect("histograms");
    hist.success.buckets[0] = 9;
    hist.success.buckets[1] = 2;
    hist.success.count = 9;
    let otel = osslscope::presentation::otel::render(&snap);
    let v: serde_json::Value = serde_json::from_str(&otel).unwrap();
    let metrics = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
    let hist_metric = metrics
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "osslscope.dispatch.duration.nanoseconds")
        .expect("histogram instrument present");
    let points = hist_metric["histogram"]["dataPoints"].as_array().unwrap();
    assert!(
        !points.iter().any(|p| p["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["value"]["stringValue"] == "success")),
        "malformed success point must omit"
    );
    // Every emitted point agrees exactly (differences sum to count).
    for p in points {
        let counts: Vec<u64> = p["bucketCounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().parse().unwrap())
            .collect();
        let count: u64 = p["count"].as_str().unwrap().parse().unwrap();
        assert_eq!(counts.iter().sum::<u64>(), count, "agreement");
    }
}

#[test]
fn prometheus_omits_malformed_distributions_like_otlp() {
    // P2fix2 item 13 (codex NEW-P2f): Prometheus and OTLP admit
    // the SAME valid distributions — a malformed distribution
    // (non-cumulative buckets) omits its 21 Prometheus series
    // exactly like its OTLP point omits; valid distributions
    // render on both.
    use osslscope::presentation::{Presenter, snapshot};
    let (window, totals) = fold_canary();
    let summary = t::summarize(&window, &totals, "latency", None);
    let mut doc = snapshot::test_document(5, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let mut snap = Presenter::oneshot(&doc).unwrap();
    let hist = snap.histograms.as_mut().expect("histograms");
    hist.success.buckets[0] = 9;
    hist.success.buckets[1] = 2;
    hist.success.count = 9;
    let prom = osslscope::presentation::prometheus::render(&snap);
    // P-17 series only (P-16 legitimately carries outcome_class
    // labels for the same classes).
    let buckets: Vec<&str> = prom
        .lines()
        .filter(|l| l.starts_with("osslscope_dispatch_duration_nanoseconds_"))
        .collect();
    assert!(
        !buckets
            .iter()
            .any(|l| l.contains("outcome_class=\"success\"")),
        "malformed success distribution must omit its series: {prom:?}"
    );
    // Valid distributions still render (parity positive control).
    assert!(
        buckets
            .iter()
            .any(|l| l.contains("outcome_class=\"failure\"")),
        "valid distributions flow: {prom:?}"
    );
    assert!(
        prom.contains("osslscope_trace_calls_total"),
        "P-16 flows: {prom:?}"
    );
}

#[test]
fn adapters_omit_zero_count_positive_sum_in_lockstep() {
    // P2fix3 NEW-P2f: `count=0, sum>0` is an impossible
    // distribution (no pairs folded a positive total) — BOTH
    // adapters omit it; the honest empty distribution
    // (count=0, sum=0) still renders on both (positive control).
    use osslscope::presentation::{Presenter, snapshot};
    let (window, totals) = fold_canary();
    let summary = t::summarize(&window, &totals, "latency", None);
    let mut doc = snapshot::test_document(5, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let mut snap = Presenter::oneshot(&doc).unwrap();
    let hist = snap.histograms.as_mut().expect("histograms");
    hist.success.buckets = [0; 19];
    hist.success.count = 0;
    hist.success.sum = 50;
    hist.failure.buckets = [0; 19];
    hist.failure.count = 0;
    hist.failure.sum = 0;
    // OTel: success point omits, failure point renders.
    let otel = osslscope::presentation::otel::render(&snap);
    let v: serde_json::Value = serde_json::from_str(&otel).unwrap();
    let metrics = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
    let hist_metric = metrics
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "osslscope.dispatch.duration.nanoseconds")
        .expect("histogram instrument present");
    let points = hist_metric["histogram"]["dataPoints"].as_array().unwrap();
    let has_class = |class: &str| {
        points.iter().any(|p| {
            p["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "outcome_class" && a["value"]["stringValue"] == class)
        })
    };
    assert!(!has_class("success"), "count=0/sum>0 must omit");
    assert!(has_class("failure"), "honest empty renders");
    // Prometheus: same rule, same classes.
    let prom = osslscope::presentation::prometheus::render(&snap);
    let buckets: Vec<&str> = prom
        .lines()
        .filter(|l| l.starts_with("osslscope_dispatch_duration_nanoseconds_"))
        .collect();
    assert!(
        !buckets
            .iter()
            .any(|l| l.contains("outcome_class=\"success\"")),
        "prometheus must omit count=0/sum>0: {prom:?}"
    );
    assert!(
        buckets
            .iter()
            .any(|l| l.contains("outcome_class=\"failure\"")),
        "prometheus renders honest empty: {prom:?}"
    );
}

#[test]
fn frame_lines_strip_control_characters() {
    // P2fix1 item 6: persisted strings (counter names) must not
    // inject escapes or line breaks into terminal output.
    use osslscope::presentation::{Presenter, snapshot};
    let doc = snapshot::test_document(3, "complete");
    let mut snap = Presenter::oneshot(&doc).unwrap();
    let clean_lines = osslscope::presentation::watch::render_frame(&snap)
        .lines()
        .count();
    snap.loss.counters.push(serde_json::json!({
        "kind": "Loss",
        "name": " NationX\x1b[31mred\nINJECTED",
        "value": 7,
    }));
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(!frame.contains('\x1b'), "frame carries escapes");
    // The injected newline adds no physical lines (stripped, and
    // the counter renders one row).
    assert_eq!(frame.lines().count(), clean_lines + 1);
    assert!(
        frame.contains("INJECTED"),
        "content preserved minus controls"
    );
}

#[test]
fn outcome_classes_cross_without_rv_scalars() {
    // BPF-side `rv` never crosses (D0-3/D0-4 C1): the host sees
    // classes 0..4 only, and every output repeats classes only.
    // (Raw outcome 0 on operational folds class-0 `unknown`.)
    let (window, _totals) = fold_canary();
    assert_eq!(window.class_counts, [1, 1, 1, 1, 1]);
    let detail = t::detail_json(&window);
    for row in detail.as_array().unwrap() {
        let outcome = row["outcome"].as_u64().unwrap();
        assert!(outcome <= 4, "non-class outcome {outcome}");
    }
    // No `rv` key anywhere in any projection.
    for body in [
        serde_json::to_string(&detail).unwrap(),
        serde_json::to_string(&t::summarize(
            &window,
            &t::TraceTotals::default(),
            "latency",
            None,
        ))
        .unwrap(),
    ] {
        assert!(!body.contains("\"rv\""), "rv scalar crosses: {body:?}");
        assert!(!body.contains("\"arg0\""), "param crosses: {body:?}");
        assert!(!body.contains("\"arg2\""), "param crosses: {body:?}");
    }
}
