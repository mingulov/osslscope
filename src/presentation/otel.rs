// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C OTel mapping (§6C-7): OTLP/HTTP JSON metrics push payload.
//! Consumes the same `OperatorSnapshot` value and the shared
//! admission set as the Prometheus adapter (lockstep).
use super::budget::Budget;
use super::labels;
use super::prometheus::Admitted;
use super::snapshot::{Distribution, OperatorSnapshot};

/// (Prometheus name, OTel instrument, kind, unit) in P-number order.
pub const TABLE: [(&str, &str, &str, &str); 17] = [
    (
        "osslscope_epoch_calls_total",
        "osslscope.epoch.calls",
        "sum",
        "1",
    ),
    (
        "osslscope_window_site_rows",
        "osslscope.window.site.rows",
        "gauge",
        "1",
    ),
    (
        "osslscope_members_observed",
        "osslscope.members.observed",
        "gauge",
        "1",
    ),
    (
        "osslscope_members_retired_total",
        "osslscope.members.retired",
        "sum",
        "1",
    ),
    (
        "osslscope_policy_outcome_info",
        "osslscope.policy.outcome.info",
        "gauge",
        "1",
    ),
    (
        "osslscope_window_completeness_info",
        "osslscope.window.completeness.info",
        "gauge",
        "1",
    ),
    (
        "osslscope_window_cut_info",
        "osslscope.window.cut.info",
        "gauge",
        "1",
    ),
    (
        "osslscope_loss_events_total",
        "osslscope.loss.events",
        "sum",
        "1",
    ),
    (
        "osslscope_epoch_partial_total",
        "osslscope.epoch.partial",
        "sum",
        "1",
    ),
    (
        "osslscope_stream_drops_total",
        "osslscope.stream.drops",
        "sum",
        "1",
    ),
    (
        "osslscope_snapshot_age_nanoseconds",
        "osslscope.snapshot.age.nanoseconds",
        "gauge",
        "ns",
    ),
    (
        "osslscope_snapshot_stale",
        "osslscope.snapshot.stale",
        "gauge",
        "1",
    ),
    (
        "osslscope_epoch_changes_total",
        "osslscope.epoch.changes",
        "sum",
        "1",
    ),
    (
        "osslscope_exporter_series_overflow_total",
        "osslscope.exporter.series.overflow",
        "sum",
        "1",
    ),
    (
        "osslscope_window_exit_code",
        "osslscope.window.exit.code",
        "gauge",
        "1",
    ),
    (
        "osslscope_trace_calls_total",
        "osslscope.trace.calls",
        "sum",
        "1",
    ),
    (
        "osslscope_dispatch_duration_nanoseconds",
        "osslscope.dispatch.duration.nanoseconds",
        "histogram",
        "ns",
    ),
];

/// One attribute set + value per data point.
type LabeledValue<'a> = (Vec<(&'a str, String)>, String);
/// Points per instrument.
type InstrumentPoints<'a> = Vec<(&'a str, Vec<LabeledValue<'a>>)>;

/// Instrument table for contract pins: (instrument, kind, unit).
pub fn instrument_table() -> Vec<(&'static str, &'static str, &'static str)> {
    TABLE.iter().map(|(_, i, k, u)| (*i, *k, *u)).collect()
}

fn help_of(prom: &str) -> &'static str {
    super::prometheus::TABLE
        .iter()
        .find(|(n, _, _)| *n == prom)
        .map(|(_, h, _)| *h)
        .unwrap_or("")
}

/// Epoch-scoped instruments (start time resets per epoch, §6C-7).
fn is_epoch_scoped(prom: &str) -> bool {
    matches!(
        prom,
        "osslscope_epoch_calls_total"
            | "osslscope_members_retired_total"
            | "osslscope_loss_events_total"
            | "osslscope_epoch_partial_total"
            | "osslscope_stream_drops_total"
            | "osslscope_trace_calls_total"
            | "osslscope_dispatch_duration_nanoseconds"
    )
}

fn attrs(pairs: &[(&str, String)]) -> serde_json::Value {
    let mut out: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| serde_json::json!({"key": k, "value": {"stringValue": v}}))
        .collect();
    out.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    serde_json::Value::Array(out)
}

/// Render with explicit accumulation starts (export path): the
/// shared admission set is computed once and both adapters consume
/// it (lockstep, §6C-12). Sample timestamps are the production
/// time (deterministic one-shot rendering).
pub(crate) fn render_admitted(
    snap: &OperatorSnapshot,
    admitted: &Admitted,
    epoch_start_wall_ns: u64,
    run_start_wall_ns: u64,
) -> String {
    render_admitted_at(
        snap,
        admitted,
        epoch_start_wall_ns,
        run_start_wall_ns,
        snap.produced_wall_ns,
    )
}

/// Render over the shared admission set with an explicit sample
/// instant (P2fix2 item 21): the push worker samples NOW, so stale
/// last-good health points carry fresh sample timestamps (the
/// production time stays visible via the age gauge — staleness
/// honest, sampling current).
pub(crate) fn render_admitted_at(
    snap: &OperatorSnapshot,
    admitted: &Admitted,
    epoch_start_wall_ns: u64,
    run_start_wall_ns: u64,
    sample_wall_ns: u64,
) -> String {
    let point_time = sample_wall_ns.to_string();
    let mut metrics: Vec<serde_json::Value> = vec![];
    // Presence mirrors the Prometheus admission set: an instrument
    // renders iff at least one of its series was admitted. Default
    // instruments always admit fully (159-schema proof); opt-in
    // histograms render only admitted units.
    let has = |prefix: &str| {
        admitted
            .samples
            .iter()
            .any(|(m, _, _)| m == prefix || m.starts_with(&format!("{prefix}_")))
    };
    let mut sum_points: InstrumentPoints = vec![];
    let mut gauge_points: InstrumentPoints = vec![];
    // Collect points per instrument from the snapshot (same values
    // as Prometheus — one snapshot value, two spellings).
    collect_points(snap, &mut sum_points, &mut gauge_points);
    for (prom, inst, kind, unit) in TABLE {
        if kind == "histogram" {
            if let Some(m) = histogram_metric(
                snap,
                admitted,
                prom,
                inst,
                unit,
                &point_time,
                epoch_start_wall_ns,
            ) {
                metrics.push(m);
            }
            continue;
        }
        let pool = if kind == "sum" {
            &sum_points
        } else {
            &gauge_points
        };
        let Some((_, points)) = pool.iter().find(|(p, _)| *p == prom) else {
            continue;
        };
        if points.is_empty() || !has(prom) {
            continue;
        }
        let start = if kind == "sum" {
            if is_epoch_scoped(prom) {
                epoch_start_wall_ns.to_string()
            } else {
                run_start_wall_ns.to_string()
            }
        } else {
            String::new()
        };
        let data_points: Vec<serde_json::Value> = points
            .iter()
            .map(|(labels, value)| {
                let mut dp = serde_json::json!({
                    "attributes": attrs(labels),
                    "timeUnixNano": point_time,
                    "asInt": value,
                });
                if kind == "sum" {
                    dp["startTimeUnixNano"] = serde_json::Value::String(start.clone());
                }
                dp
            })
            .collect();
        let body = if kind == "sum" {
            serde_json::json!({
                "dataPoints": data_points,
                "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                "isMonotonic": true,
            })
        } else {
            serde_json::json!({"dataPoints": data_points})
        };
        metrics.push(serde_json::json!({
            "name": inst,
            "description": help_of(prom),
            "unit": unit,
            kind: body,
        }));
    }
    // No raw boot-ID text in resources (P2fix2 item 24): intake
    // bounds boot IDs, and this sink takes 8 chars max + strips
    // anything outside a conservative display set (defense in
    // depth — a hand-built snapshot can never smuggle raw text or
    // controls into resource attributes).
    let clean8 = |boot: &str| {
        boot.chars()
            .take(8)
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>()
    };
    let instance = match snap.source.mode.as_str() {
        "service" => snap
            .source
            .run_id
            .as_ref()
            .map(|r| format!("{}-{}-{}", r.pid, r.starttime, clean8(&r.boot_id)))
            .unwrap_or_else(|| "unknown".to_string()),
        _ => format!("oneshot-{}", std::process::id()),
    };
    let payload = serde_json::json!({
        "resourceMetrics": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "osslscope"}},
                {"key": "service.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}},
                {"key": "service.instance.id", "value": {"stringValue": instance}},
            ]},
            "scopeMetrics": [{
                "scope": {"name": "osslscope", "version": super::snapshot::SCHEMA},
                "metrics": metrics,
            }],
        }],
    });
    let mut text = serde_json::to_string(&payload).unwrap_or_default();
    text.push('\n');
    text
}

#[allow(clippy::too_many_lines)]
fn collect_points(
    snap: &OperatorSnapshot,
    sums: &mut InstrumentPoints,
    gauges: &mut InstrumentPoints,
) {
    // P-01.
    sums.push((
        "osslscope_epoch_calls_total",
        [
            ("legacy_exclusive", snap.counts.lanes.legacy_exclusive),
            (
                "non_legacy_exclusive",
                snap.counts.lanes.non_legacy_exclusive,
            ),
            ("shared_ambiguous", snap.counts.lanes.shared_ambiguous),
            ("unfenced_tails", snap.counts.lanes.unfenced_tails),
        ]
        .into_iter()
        .map(|(lane, v)| (vec![("lane", lane.to_string())], v.to_string()))
        .collect(),
    ));
    // P-02/P-03/P-04.
    gauges.push((
        "osslscope_window_site_rows",
        snap.counts
            .site_rows
            .map(|v| vec![(vec![], v.to_string())])
            .unwrap_or_default(),
    ));
    gauges.push((
        "osslscope_members_observed",
        snap.members
            .observed
            .map(|v| vec![(vec![], v.to_string())])
            .unwrap_or_default(),
    ));
    sums.push((
        "osslscope_members_retired_total",
        vec![(vec![], snap.members.retired_epoch.to_string())],
    ));
    // P-05/P-06/P-07 one-hots.
    gauges.push((
        "osslscope_policy_outcome_info",
        snap.policy
            .outcome
            .as_deref()
            .map(|o| {
                labels::OUTCOME
                    .iter()
                    .map(|v| {
                        (
                            vec![("outcome", v.to_string())],
                            if *v == o { "1" } else { "0" }.to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    ));
    gauges.push((
        "osslscope_window_completeness_info",
        snap.completeness
            .state
            .as_deref()
            .map(|s| {
                labels::COMPLETENESS
                    .iter()
                    .map(|v| {
                        (
                            vec![("completeness", v.to_string())],
                            if *v == s { "1" } else { "0" }.to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    ));
    gauges.push((
        "osslscope_window_cut_info",
        snap.window
            .as_ref()
            .map(|w| {
                let cut = match (w.signal_cut, w.accum_cut) {
                    (false, false) => "none",
                    (true, false) => "signal_cut",
                    (false, true) => "accum_cut",
                    (true, true) => "both_cuts",
                };
                labels::CUT
                    .iter()
                    .map(|v| {
                        (
                            vec![("cut", v.to_string())],
                            if *v == cut { "1" } else { "0" }.to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    ));
    // P-08.
    sums.push((
        "osslscope_loss_events_total",
        [
            ("corpse_wait", snap.loss.epoch_by_cause.corpse_wait),
            ("cgroup_move", snap.loss.epoch_by_cause.cgroup_move),
            (
                "membership_unknown",
                snap.loss.epoch_by_cause.membership_unknown,
            ),
            ("ring_loss", snap.loss.epoch_by_cause.ring_loss),
            ("connector_drops", snap.loss.epoch_by_cause.connector_drops),
            (
                "connector_enobufs",
                snap.loss.epoch_by_cause.connector_enobufs,
            ),
            ("scan_loss", snap.loss.epoch_by_cause.scan_loss),
            (
                "signal_prefix_unwitnessed",
                snap.loss.epoch_by_cause.signal_prefix_unwitnessed,
            ),
            ("drain_pending", snap.loss.epoch_by_cause.drain_pending),
            (
                "exec_spanning_aggregate",
                snap.loss.epoch_by_cause.exec_spanning_aggregate,
            ),
            ("coalesced_loss", snap.loss.epoch_by_cause.coalesced_loss),
            ("skipped_tick", snap.loss.epoch_by_cause.skipped_tick),
        ]
        .into_iter()
        .map(|(c, v)| (vec![("loss_cause", c.to_string())], v.to_string()))
        .collect(),
    ));
    // P-09.
    sums.push((
        "osslscope_epoch_partial_total",
        [
            (
                "unknown_denominator",
                snap.completeness.epoch_partial_by_class.unknown_denominator,
            ),
            (
                "undiscovered_sites",
                snap.completeness.epoch_partial_by_class.undiscovered_sites,
            ),
            (
                "unattached_sites",
                snap.completeness.epoch_partial_by_class.unattached_sites,
            ),
            ("loss", snap.completeness.epoch_partial_by_class.loss),
            (
                "unattributed_calls",
                snap.completeness.epoch_partial_by_class.unattributed_calls,
            ),
            (
                "startup_gap",
                snap.completeness.epoch_partial_by_class.startup_gap,
            ),
            (
                "tail_gap",
                snap.completeness.epoch_partial_by_class.tail_gap,
            ),
            (
                "signal_cut",
                snap.completeness.epoch_partial_by_class.signal_cut,
            ),
            (
                "visibility_lost",
                snap.completeness.epoch_partial_by_class.visibility_lost,
            ),
            (
                "no_reasons",
                snap.completeness.epoch_partial_by_class.no_reasons,
            ),
        ]
        .into_iter()
        .map(|(c, v)| (vec![("gap_class", c.to_string())], v.to_string()))
        .collect(),
    ));
    // P-10.
    sums.push((
        "osslscope_stream_drops_total",
        snap.stream
            .as_ref()
            .map(|s| {
                [
                    ("queue_full", s.drops.queue_full.records),
                    ("epipe", s.drops.epipe.records),
                    ("stream_abandoned", s.drops.stream_abandoned.records),
                ]
                .into_iter()
                .map(|(r, v)| (vec![("drop_reason", r.to_string())], v.to_string()))
                .collect()
            })
            .unwrap_or_default(),
    ));
    // P-11/P-12/P-13/P-14/P-15.
    gauges.push((
        "osslscope_snapshot_age_nanoseconds",
        snap.health
            .snapshot_age_ns
            .map(|v| vec![(vec![], v.to_string())])
            .unwrap_or_default(),
    ));
    gauges.push((
        "osslscope_snapshot_stale",
        vec![(
            vec![],
            if snap.health.stale { "1" } else { "0" }.to_string(),
        )],
    ));
    sums.push((
        "osslscope_epoch_changes_total",
        vec![(vec![], snap.presenter.epoch_changes.to_string())],
    ));
    sums.push((
        "osslscope_exporter_series_overflow_total",
        vec![(vec![], snap.presenter.series_overflow.to_string())],
    ));
    gauges.push((
        "osslscope_window_exit_code",
        snap.exit_hint
            .map(|v| vec![(vec![], v.to_string())])
            .unwrap_or_default(),
    ));
    // P-16 (absent when the epoch classes withhold).
    sums.push((
        "osslscope_trace_calls_total",
        snap.trace
            .as_ref()
            .and_then(|t| t.class_epoch.as_ref())
            .map(|e| {
                [
                    ("success", e.success),
                    ("failure", e.failure),
                    ("empty", e.empty),
                    ("retry", e.retry),
                    ("unknown", e.unknown),
                ]
                .into_iter()
                .map(|(c, v)| (vec![("outcome_class", c.to_string())], v.to_string()))
                .collect()
            })
            .unwrap_or_default(),
    ));
}

/// P-17 histogram metric (default distributions + admitted opt-in
/// units only — lockstep with Prometheus).
fn histogram_metric(
    snap: &OperatorSnapshot,
    admitted: &Admitted,
    prom: &str,
    inst: &str,
    unit: &str,
    point_time: &str,
    epoch_start_wall_ns: u64,
) -> Option<serde_json::Value> {
    let hist = snap.histograms.as_ref()?;
    let mut points: Vec<serde_json::Value> = vec![];
    // Default distributions render iff their series were admitted
    // (always — 159-schema proof — but check anyway).
    let default_admitted = |class: &str| {
        admitted.samples.iter().any(|(m, l, _)| {
            m == "osslscope_dispatch_duration_nanoseconds_count"
                && l.contains(&format!("outcome_class=\"{class}\""))
                && !l.contains("api=")
        })
    };
    for (class, dist) in [
        ("success", &hist.success),
        ("failure", &hist.failure),
        ("empty", &hist.empty),
        ("retry", &hist.retry),
        ("unknown", &hist.unknown),
    ] {
        if !default_admitted(class) {
            continue;
        }
        // Malformed distributions omit (adapters omit, never emit
        // incoherent metrics — intake rejects them upstream).
        if !distribution_valid(dist) {
            continue;
        }
        points.push(histogram_point(
            &[("outcome_class", class.to_string())],
            dist,
            point_time,
            epoch_start_wall_ns,
        ));
    }
    // Opt-in units: the SHARED admitted set (never re-derived here).
    if let Some(by_api) = hist.by_api.as_ref() {
        for (api, class) in admitted.opt_units.iter() {
            let entry = by_api.get(api.as_str())?;
            let dist = match class.as_str() {
                "success" => &entry.success,
                "failure" => &entry.failure,
                "empty" => &entry.empty,
                "retry" => &entry.retry,
                "unknown" => &entry.unknown,
                _ => continue,
            };
            if !distribution_valid(dist) {
                continue;
            }
            points.push(histogram_point(
                &[("api", api.clone()), ("outcome_class", class.clone())],
                dist,
                point_time,
                epoch_start_wall_ns,
            ));
        }
    }
    if points.is_empty() {
        return None;
    }
    let _ = prom;
    Some(serde_json::json!({
        "name": inst,
        "description": help_of(prom),
        "unit": unit,
        "histogram": {
            "dataPoints": points,
            "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
        },
    }))
}

/// A distribution the adapter may convert: cumulative buckets
/// with `buckets[18] == count` (intake guarantees this for
/// producer data; the adapter re-checks so a malformed
/// hand-built snapshot can never emit disagreeing counts), and
/// no positive sum without pairs (P2fix3 NEW-P2f: `count=0,
/// sum>0` is impossible — no pairs folded a positive total).
pub(crate) fn distribution_valid(dist: &Distribution) -> bool {
    if dist.buckets[18] != dist.count {
        return false;
    }
    if dist.count == 0 && dist.sum > 0 {
        return false;
    }
    let mut prev = 0u64;
    for b in dist.buckets.iter() {
        if *b < prev {
            return false;
        }
        prev = *b;
    }
    true
}

fn histogram_point(
    labels: &[(&str, String)],
    dist: &Distribution,
    point_time: &str,
    epoch_start_wall_ns: u64,
) -> serde_json::Value {
    // Consecutive differences of the cumulative buckets (§6D-3).
    // Callers admit only valid distributions (see above), so the
    // differences telescope EXACTLY to `count` — no
    // saturating-subtraction disagreement is reachable.
    let mut counts: Vec<String> = Vec::with_capacity(19);
    let mut prev = 0u64;
    for b in dist.buckets.iter() {
        counts.push(b.saturating_sub(prev).to_string());
        prev = *b;
    }
    debug_assert_eq!(
        counts
            .iter()
            .map(|c| c.parse::<u64>().unwrap_or(0))
            .sum::<u64>(),
        dist.count,
        "bucket/count agreement"
    );
    let bounds: Vec<u64> = vec![
        50, 100, 250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000,
        1000000, 2000000, 5000000, 10000000,
    ];
    serde_json::json!({
        "attributes": attrs(labels),
        "startTimeUnixNano": epoch_start_wall_ns.to_string(),
        "timeUnixNano": point_time,
        "count": dist.count.to_string(),
        "sum": dist.sum as f64,
        "bucketCounts": counts,
        "explicitBounds": bounds,
    })
}

/// Render with a fresh per-call budget (single admission —
/// starts default to the snapshot's own produced time, correct for
/// oneshot and first snapshots; the export loop passes real starts
/// via [`render_admitted`] with the shared admission set).
pub fn render(snap: &OperatorSnapshot) -> String {
    let mut budget = Budget::new();
    let admitted = super::prometheus::admit(snap, &mut budget);
    render_admitted(
        snap,
        &admitted,
        snap.produced_wall_ns,
        snap.produced_wall_ns,
    )
}
