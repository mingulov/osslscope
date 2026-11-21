// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C Prometheus exposition (§6C-6): exact names/help/types,
//! omission (never zero-fill), deterministic order, `# EOF`.
use super::budget::{Budget, SeriesKey, sort_series_keys};
use super::labels;
use super::snapshot::OperatorSnapshot;

/// (name, help verbatim, type) in P-number order.
pub const TABLE: [(&str, &str, &str); 17] = [
    (
        "osslscope_epoch_calls_total",
        "Provider dispatch callback entries in the current epoch, by legacy partition lane.",
        "counter",
    ),
    (
        "osslscope_window_site_rows",
        "Merged site rows in the current window document.",
        "gauge",
    ),
    (
        "osslscope_members_observed",
        "Members in the observed set at window close.",
        "gauge",
    ),
    (
        "osslscope_members_retired_total",
        "Members retired during the current epoch.",
        "counter",
    ),
    (
        "osslscope_policy_outcome_info",
        "Current window policy outcome; exactly one series has value 1.",
        "gauge",
    ),
    (
        "osslscope_window_completeness_info",
        "Current window completeness; exactly one series has value 1.",
        "gauge",
    ),
    (
        "osslscope_window_cut_info",
        "Current window cut state; exactly one series has value 1.",
        "gauge",
    ),
    (
        "osslscope_loss_events_total",
        "Session lost-interval events in the current epoch, by cause.",
        "counter",
    ),
    (
        "osslscope_epoch_partial_total",
        "Windows finalizing partial or fatal in the current epoch, by first gap class.",
        "counter",
    ),
    (
        "osslscope_stream_drops_total",
        "Stream tap records dropped in the current epoch, by reason. Absent when the stream is unconfigured.",
        "counter",
    ),
    (
        "osslscope_snapshot_age_nanoseconds",
        "Nanoseconds from window effective end to snapshot build.",
        "gauge",
    ),
    (
        "osslscope_snapshot_stale",
        "1 when the snapshot is stale per the delivery contract, else 0.",
        "gauge",
    ),
    (
        "osslscope_epoch_changes_total",
        "Observed generation changes in the presenter run.",
        "counter",
    ),
    (
        "osslscope_exporter_series_overflow_total",
        "Series omitted by the cardinality budget in the presenter run.",
        "counter",
    ),
    (
        "osslscope_window_exit_code",
        "exit_for value of the current window.",
        "gauge",
    ),
    (
        "osslscope_trace_calls_total",
        "Paired public API invocations in the current epoch, by return class. Absent when trace mode is off or metadata.",
        "counter",
    ),
    (
        "osslscope_dispatch_duration_nanoseconds",
        "Paired public API duration in nanoseconds, by return class. Absent when trace mode is off, metadata, or status. Buckets are the frozen 6D edges.",
        "histogram",
    ),
];

/// Series table for contract pins.
pub fn series_table() -> Vec<(&'static str, &'static str, &'static str)> {
    TABLE.to_vec()
}

fn help_of(name: &str) -> &'static str {
    TABLE
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, h, _)| *h)
        .unwrap_or("")
}

fn type_of(name: &str) -> &'static str {
    TABLE
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, t)| *t)
        .unwrap_or("gauge")
}

/// One rendered sample: (metric, labelset bytes, value).
pub(crate) type Sample = (String, String, String);

/// Escape a label value for exposition format.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

/// Build candidate samples from the snapshot (omission applied).
/// Every label name/value comes from the closed §6C-5 sets on
/// EVERY profile (item 6): offending series omit (persisted
/// inputs never escape the finite vocabulary). Accidental drops
/// of legitimate series are caught by the byte-exact golden
/// re-renders + explicit series-presence pins, not by panics.
fn push_labeled(out: &mut Vec<Sample>, metric: &str, labels: &[(&str, String)], value: String) {
    for (name, val) in labels {
        if !labels::is_name_allowed(name) || !labels::is_value_allowed(name, val) {
            return;
        }
    }
    let mut set: Vec<(&str, String)> = labels.to_vec();
    set.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
    let rendered = set
        .iter()
        .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
        .collect::<Vec<_>>()
        .join(",");
    out.push((metric.to_string(), rendered, value));
}

fn candidates(snap: &OperatorSnapshot) -> Vec<Sample> {
    let mut out: Vec<Sample> = vec![];
    // P-01: epoch lanes (always present — defined-zero start).
    for (lane, value) in [
        ("legacy_exclusive", snap.counts.lanes.legacy_exclusive),
        (
            "non_legacy_exclusive",
            snap.counts.lanes.non_legacy_exclusive,
        ),
        ("shared_ambiguous", snap.counts.lanes.shared_ambiguous),
        ("unfenced_tails", snap.counts.lanes.unfenced_tails),
    ] {
        push_labeled(
            &mut out,
            "osslscope_epoch_calls_total",
            &[("lane", lane.to_string())],
            value.to_string(),
        );
    }
    // P-02/P-03/P-04.
    if let Some(rows) = snap.counts.site_rows {
        out.push((
            "osslscope_window_site_rows".to_string(),
            String::new(),
            rows.to_string(),
        ));
    }
    if let Some(observed) = snap.members.observed {
        out.push((
            "osslscope_members_observed".to_string(),
            String::new(),
            observed.to_string(),
        ));
    }
    out.push((
        "osslscope_members_retired_total".to_string(),
        String::new(),
        snap.members.retired_epoch.to_string(),
    ));
    // P-05/P-06/P-07: one-hot _info gauges (absent pre-first-window).
    if let Some(outcome) = snap.policy.outcome.as_deref() {
        for value in labels::OUTCOME {
            push_labeled(
                &mut out,
                "osslscope_policy_outcome_info",
                &[("outcome", value.to_string())],
                if value == outcome { "1" } else { "0" }.to_string(),
            );
        }
    }
    if let Some(state) = snap.completeness.state.as_deref() {
        for value in labels::COMPLETENESS {
            push_labeled(
                &mut out,
                "osslscope_window_completeness_info",
                &[("completeness", value.to_string())],
                if value == state { "1" } else { "0" }.to_string(),
            );
        }
    }
    if let Some(window) = snap.window.as_ref() {
        let cut = match (window.signal_cut, window.accum_cut) {
            (false, false) => "none",
            (true, false) => "signal_cut",
            (false, true) => "accum_cut",
            (true, true) => "both_cuts",
        };
        for value in labels::CUT {
            push_labeled(
                &mut out,
                "osslscope_window_cut_info",
                &[("cut", value.to_string())],
                if value == cut { "1" } else { "0" }.to_string(),
            );
        }
    }
    // P-08: epoch lost-interval events by cause.
    let causes = [
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
    ];
    for (cause, value) in causes {
        push_labeled(
            &mut out,
            "osslscope_loss_events_total",
            &[("loss_cause", cause.to_string())],
            value.to_string(),
        );
    }
    // P-09: epoch partial/fatal by first gap class.
    let classes = [
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
    ];
    for (class, value) in classes {
        push_labeled(
            &mut out,
            "osslscope_epoch_partial_total",
            &[("gap_class", class.to_string())],
            value.to_string(),
        );
    }
    // P-10: stream drops (absent when unconfigured).
    if let Some(stream) = snap.stream.as_ref() {
        for (reason, totals) in [
            ("queue_full", stream.drops.queue_full.records),
            ("epipe", stream.drops.epipe.records),
            ("stream_abandoned", stream.drops.stream_abandoned.records),
        ] {
            push_labeled(
                &mut out,
                "osslscope_stream_drops_total",
                &[("drop_reason", reason.to_string())],
                totals.to_string(),
            );
        }
    }
    // P-11/P-12/P-13/P-14/P-15.
    if let Some(age) = snap.health.snapshot_age_ns {
        out.push((
            "osslscope_snapshot_age_nanoseconds".to_string(),
            String::new(),
            age.to_string(),
        ));
    }
    out.push((
        "osslscope_snapshot_stale".to_string(),
        String::new(),
        if snap.health.stale { "1" } else { "0" }.to_string(),
    ));
    out.push((
        "osslscope_epoch_changes_total".to_string(),
        String::new(),
        snap.presenter.epoch_changes.to_string(),
    ));
    out.push((
        "osslscope_exporter_series_overflow_total".to_string(),
        String::new(),
        snap.presenter.series_overflow.to_string(),
    ));
    if let Some(hint) = snap.exit_hint {
        out.push((
            "osslscope_window_exit_code".to_string(),
            String::new(),
            hint.to_string(),
        ));
    }
    // P-16: trace class epoch (absent when trace null or the
    // epoch classes withhold — pairing uncertainty or the DELTA-2
    // service rescope).
    if let Some(epoch) = snap.trace.as_ref().and_then(|t| t.class_epoch.as_ref()) {
        for (class, value) in [
            ("success", epoch.success),
            ("failure", epoch.failure),
            ("empty", epoch.empty),
            ("retry", epoch.retry),
            ("unknown", epoch.unknown),
        ] {
            push_labeled(
                &mut out,
                "osslscope_trace_calls_total",
                &[("outcome_class", class.to_string())],
                value.to_string(),
            );
        }
    }
    // P-17 default keying is budget-atomic per distribution; the
    // adapter admits default-schema series first (they always fit —
    // 159-schema proof), then opt-in units last. Default
    // distributions render inline here; opt-in units render via
    // `render_with_budget` below.
    if let Some(hist) = snap.histograms.as_ref() {
        for (class, dist) in [
            ("success", &hist.success),
            ("failure", &hist.failure),
            ("empty", &hist.empty),
            ("retry", &hist.retry),
            ("unknown", &hist.unknown),
        ] {
            // Adapter parity (P2fix2 item 13): Prometheus admits
            // the SAME valid distributions as OTLP (shared rule —
            // malformed hand-built snapshots omit, never emit
            // incoherent metrics; intake rejects them upstream).
            if !super::otel::distribution_valid(dist) {
                continue;
            }
            render_distribution(&mut out, None, class, &dist.buckets, dist.sum, dist.count);
        }
    }
    out
}

/// Render one 21-series distribution (19 buckets + sum + count).
fn render_distribution(
    out: &mut Vec<Sample>,
    api: Option<&str>,
    class: &str,
    buckets: &[u64; 19],
    sum: u64,
    count: u64,
) {
    for (i, bound) in labels::LE.iter().enumerate() {
        let mut set = vec![
            ("outcome_class", class.to_string()),
            ("le", bound.to_string()),
        ];
        if let Some(id) = api {
            set.push(("api", id.to_string()));
        }
        set.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
        // Closed-vocabulary omission on every profile (item 6 —
        // same rule as push_labeled; a poisoned api label omits the
        // whole unit since every member carries it).
        for (name, val) in &set {
            if !labels::is_name_allowed(name) || !labels::is_value_allowed(name, val) {
                return;
            }
        }
        let rendered = set
            .iter()
            .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
            .collect::<Vec<_>>()
            .join(",");
        out.push((
            "osslscope_dispatch_duration_nanoseconds_bucket".to_string(),
            rendered,
            buckets[i].to_string(),
        ));
    }
    let mut base = vec![("outcome_class", class.to_string())];
    if let Some(id) = api {
        base.push(("api", id.to_string()));
    }
    base.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
    let rendered = base
        .iter()
        .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
        .collect::<Vec<_>>()
        .join(",");
    out.push((
        "osslscope_dispatch_duration_nanoseconds_sum".to_string(),
        rendered.clone(),
        sum.to_string(),
    ));
    out.push((
        "osslscope_dispatch_duration_nanoseconds_count".to_string(),
        rendered,
        count.to_string(),
    ));
}

/// Opt-in by-api units in deterministic admission order: api
/// bytes ascending (all two-digit ⇒ numeric), then outcome_class
/// bytes ascending (`empty` < `failure` < `retry` < `success` <
/// `unknown`). No `by_api` block ⇒ no units (never zeros).
fn opt_in_units(snap: &OperatorSnapshot) -> Vec<Vec<Sample>> {
    let mut units = vec![];
    let Some(hist) = snap.histograms.as_ref() else {
        return units;
    };
    let Some(by_api) = hist.by_api.as_ref() else {
        return units;
    };
    for (api, entry) in by_api.iter() {
        // Persisted api keys outside the decimal vocabulary omit
        // the whole unit (item 6 — the per-sample check below is
        // defense in depth for the same rule).
        if !labels::is_value_allowed("api", api) {
            continue;
        }
        for (class, dist) in [
            ("empty", &entry.empty),
            ("failure", &entry.failure),
            ("retry", &entry.retry),
            ("success", &entry.success),
            ("unknown", &entry.unknown),
        ] {
            // Same adapter-parity rule as the default schema above
            // (a malformed unit omits whole — OTLP consumes the
            // shared admission set, so both adapters agree).
            if !super::otel::distribution_valid(dist) {
                continue;
            }
            let mut unit = vec![];
            render_distribution(
                &mut unit,
                Some(api.as_str()),
                class,
                &dist.buckets,
                dist.sum,
                dist.count,
            );
            debug_assert_eq!(unit.len(), super::budget::UNIT_SERIES);
            units.push(unit);
        }
    }
    units
}

/// Admitted snapshot: the §6C-12 lockstep SET, computed once per
/// snapshot and shared by construction by both adapters.
#[derive(Debug, Clone, Default)]
pub(crate) struct Admitted {
    /// Admitted Prometheus samples (default + opt-in units).
    pub(crate) samples: Vec<Sample>,
    /// Admitted opt-in units as (api, class) identities.
    pub(crate) opt_units: Vec<(String, String)>,
}

/// Compute the admitted set (default schema first, opt-in units
/// last, deterministic order). Overflow is counted inside `budget`
/// — but ONLY for genuinely new windows: same-window re-renders
/// re-derive the identical set through the non-counting filter
/// (item 20 — admission/omission accounting binds to window
/// identity, never per-render resets).
pub(crate) fn admit(snap: &OperatorSnapshot, budget: &mut Budget) -> Admitted {
    let fresh = budget.begin_window_for((
        snap.source.mode.clone(),
        snap.source.generation,
        snap.source.window_seq,
        snap.source.window_sha256.clone(),
    ));
    let samples = candidates(snap);
    // Default-schema admission (deterministic order).
    let mut keys: Vec<SeriesKey> = samples
        .iter()
        .map(|(m, l, _)| (m.clone(), l.clone()))
        .collect();
    sort_series_keys(&mut keys);
    // Admit in order; drop omitted (counted inside the budget on
    // fresh windows only).
    let mut admitted: Vec<Sample> = vec![];
    // Direct lookup is exact: samples are unique per (metric,
    // labelset) — histogram bucket/sum/count triples carry distinct
    // metric names.
    for key in &keys {
        let keep = if fresh {
            budget.admit_series(&key.0, &key.1)
        } else {
            budget.is_admitted(&key.0, &key.1)
        };
        if keep {
            if let Some(s) = samples.iter().find(|(m, l, _)| m == &key.0 && l == &key.1) {
                admitted.push(s.clone());
            }
        }
    }
    // Opt-in units last (atomic whole-unit admission;
    // `opt_in_units` is empty without a `by_api` block).
    let mut opt_units = vec![];
    for unit in opt_in_units(snap) {
        let keys: Vec<SeriesKey> = unit
            .iter()
            .map(|(m, l, _)| (m.clone(), l.clone()))
            .collect();
        let keep = if fresh {
            budget.admit_unit(&keys)
        } else {
            // Atomic re-derivation: a unit shows iff every member
            // admitted (units admit whole-or-nothing, so partial
            // membership cannot occur — all-or-nothing by
            // construction).
            keys.iter().all(|k| budget.is_admitted(&k.0, &k.1))
        };
        if keep {
            // Recover the (api, class) identity from the unit's
            // labelset (deterministic render — parse back).
            if let Some(id) = unit_identity(&unit) {
                opt_units.push(id);
            }
            admitted.extend(unit);
        }
    }
    Admitted {
        samples: admitted,
        opt_units,
    }
}

/// Parse an (api, class) identity back from a unit's first sample
/// labelset (`api="20",le="+Inf",outcome_class="empty"` order may
/// vary — scan all pairs).
fn unit_identity(unit: &[Sample]) -> Option<(String, String)> {
    let first = unit.first()?;
    let mut api: Option<String> = None;
    let mut class: Option<String> = None;
    for pair in first.1.split("\",") {
        let pair = pair.trim_end_matches('"');
        if let Some(v) = pair.strip_prefix("api=\"") {
            api = Some(v.to_string());
        } else if let Some(v) = pair.strip_prefix("outcome_class=\"") {
            class = Some(v.to_string());
        }
    }
    Some((api?, class?))
}

/// Render with a persistent budget (export path): default schema
/// first, opt-in units last, overflow adopted by the caller.
pub fn render_with_budget(snap: &OperatorSnapshot, budget: &mut Budget) -> String {
    let admitted = admit(snap, budget);
    render_samples(&admitted.samples)
}

/// Refresh the freshness samples (P-11/P-12) of an admitted set at
/// serve time (item 18 — stale last-good counters advance at the
/// source cadence while frozen counters stay frozen).
pub(crate) fn refresh_freshness_samples(samples: &mut [Sample], age: Option<u64>, stale: bool) {
    for (metric, labelset, value) in samples.iter_mut() {
        if metric == "osslscope_snapshot_age_nanoseconds" && labelset.is_empty() {
            if let Some(a) = age {
                *value = a.to_string();
            }
        } else if metric == "osslscope_snapshot_stale" && labelset.is_empty() {
            *value = if stale { "1" } else { "0" }.to_string();
        }
    }
}

/// Render with a fresh per-call budget (watch/json path — the
/// default schema always fits, so overflow reads 0).
pub fn render(snap: &OperatorSnapshot) -> String {
    let mut budget = Budget::new();
    render_with_budget(snap, &mut budget)
}

/// Exposition text: `# HELP` + `# TYPE` per metric, metrics sorted
/// by name ascending, labelsets sorted, no timestamps, `# EOF`.
pub(crate) fn render_samples(samples: &[Sample]) -> String {
    // Group by metric stem (histogram _bucket/_sum/_count share the
    // P-17 HELP/TYPE).
    let mut by_metric: std::collections::BTreeMap<String, Vec<&Sample>> =
        std::collections::BTreeMap::new();
    for s in samples {
        let stem = if s.0 == "osslscope_dispatch_duration_nanoseconds_bucket"
            || s.0 == "osslscope_dispatch_duration_nanoseconds_sum"
            || s.0 == "osslscope_dispatch_duration_nanoseconds_count"
        {
            "osslscope_dispatch_duration_nanoseconds".to_string()
        } else {
            s.0.clone()
        };
        by_metric.entry(stem).or_default().push(s);
    }
    let mut out = String::new();
    for (stem, mut group) in by_metric {
        group.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out.push_str(&format!("# HELP {stem} {}\n", help_of(&stem)));
        out.push_str(&format!("# TYPE {stem} {}\n", type_of(&stem)));
        for (metric, labelset, value) in group {
            if labelset.is_empty() {
                out.push_str(&format!("{metric} {value}\n"));
            } else {
                out.push_str(&format!("{metric}{{{labelset}}} {value}\n"));
            }
        }
    }
    out.push_str("# EOF\n");
    out
}
