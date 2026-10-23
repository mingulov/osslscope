//! SPDX-License-Identifier: GPL-3.0-or-later
//! Auditor-report conformance (P6): the checked-in golden pins the
//! auditor-visible `report` document byte-shape; the same checker
//! validates live story output (environment-private, via
//! `OSSLSCOPE_AUDITOR_STORY`) and rejects tampered documents.
//!
//! Shape source: `src/report.rs` `doc()` (+ `src/check.rs`
//! `doc_with_policy()` for the optional `policy` section). Key sets
//! are exact: serde_json without `preserve_order` emits keys sorted,
//! so the golden is byte-stable under parse + pretty-print. Reason
//! vocabulary mirrors the `REASON_TAXONOMY` table in
//! `src/report.rs` tests; rule names mirror `src/check.rs`. Any
//! emitter change fails this test by design -- update the golden and
//! the checker together, by review, never by regeneration alone.
//!
//! v2 conformance (T11) follows below the v1 suite: the v2 checker
//! is `osslscope::schema::{validate_v2, check_v2_semantics}` (actual
//! JSON Schema validation plus cross-field semantics, shared with
//! `tests/output_contract.rs`), pinning `tests/auditor_golden_v2.json`
//! and validating explicitly supplied artifacts via
//! `OSSLSCOPE_AUDITOR_STORY_V2`. The v1 suite is frozen history.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// PARTIAL reason vocabulary (mirror of `REASON_TAXONOMY` in
/// `src/report.rs` -- update together, by review).
const REASONS: &[&str] = &[
    "no-query",
    "empty-inventory",
    "harvest-no-query-trigger",
    "missed-attaches",
    "unresolved-offsets",
    "unattributed",
    "dropped-events",
    "pid-prewindow-blind",
    "drain-shortfall",
    "cold-gap",
    "fips-unlabeled",
    "discovery-loss",
    "lifecycle-polling-partial",
    "startup-gap",
    "tail-gap",
    "late-attach",
    "pid-recycled",
    "fork-exec-ignored",
    "over-budget",
    "interrupted",
    "engine-fallback-uninstrumented",
    "meth-fallback-uninstrumented",
    "lowlevel-fallback-uninstrumented",
    "harvest-pid-recycled",
    "harvest-anchor-unresolved",
    "harvest-zero-rows",
    "harvest-fenced-rows",
    "harvest-zero-row-ops",
    "harvest-truncated-walk",
    "harvest-partial",
];

/// Rule-name vocabulary (`src/check.rs` `RuleSet` flags).
const RULES: &[&str] = &[
    "require-provider",
    "deny-provider",
    "deny-engine",
    "deny-algorithm",
    "deny-weak",
    "require-executed",
];

/// Known `legacy`-block keys (emitted core + live-harvest extensions).
/// The block stays open-ended across harvest versions, but unknown keys
/// fail: a novel key is a shape change, not silent data.
const LEGACY_KEYS: &[&str] = &[
    "capability",
    "engine",
    "entries",
    "findings",
    "flags",
    "legacy_provider",
    "lowlevel",
    "meth_new",
    "unreadable",
    "weak",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn obj<'a>(v: &'a Value, ctx: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{ctx}: expected object"))
}

fn exact_keys(o: &serde_json::Map<String, Value>, want: &[&str], ctx: &str) -> Result<(), String> {
    let got: BTreeSet<&str> = o.keys().map(String::as_str).collect();
    let want: BTreeSet<&str> = want.iter().copied().collect();
    if got != want {
        let extra: Vec<&&str> = got.difference(&want).collect();
        let missing: Vec<&&str> = want.difference(&got).collect();
        return Err(format!(
            "{ctx}: key mismatch (extra={extra:?} missing={missing:?})"
        ));
    }
    Ok(())
}

fn get<'a>(o: &'a serde_json::Map<String, Value>, k: &str, ctx: &str) -> Result<&'a Value, String> {
    o.get(k).ok_or_else(|| format!("{ctx}: missing key {k:?}"))
}

fn as_str<'a>(v: &'a Value, ctx: &str) -> Result<&'a str, String> {
    v.as_str().ok_or_else(|| format!("{ctx}: expected string"))
}

fn as_u64(v: &Value, ctx: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("{ctx}: expected u64"))
}

fn as_f64(v: &Value, ctx: &str) -> Result<f64, String> {
    // Strict float: the emitter writes `as_secs_f64()` values, always
    // with a fraction (`30.0`), never bare integers.
    if v.is_f64() {
        v.as_f64().ok_or_else(|| format!("{ctx}: expected f64"))
    } else {
        Err(format!("{ctx}: expected f64"))
    }
}

fn as_bool(v: &Value, ctx: &str) -> Result<bool, String> {
    v.as_bool().ok_or_else(|| format!("{ctx}: expected bool"))
}

fn as_arr<'a>(v: &'a Value, ctx: &str) -> Result<&'a Vec<Value>, String> {
    v.as_array().ok_or_else(|| format!("{ctx}: expected array"))
}

fn opt_u64(v: &Value, ctx: &str) -> Result<(), String> {
    if v.is_null() {
        Ok(())
    } else {
        as_u64(v, ctx).map(|_| ())
    }
}

fn str_map(o: &serde_json::Map<String, Value>, ctx: &str) -> Result<(), String> {
    for (k, v) in o {
        as_u64(v, &format!("{ctx}.{k}"))?;
    }
    Ok(())
}

fn check_identity(o: &serde_json::Map<String, Value>, ctx: &str) -> Result<(), String> {
    exact_keys(o, &["alg_class", "funcid", "offset", "op", "provider"], ctx)?;
    as_str(get(o, "alg_class", ctx)?, &format!("{ctx}.alg_class"))?;
    as_u64(get(o, "funcid", ctx)?, &format!("{ctx}.funcid"))?;
    as_u64(get(o, "offset", ctx)?, &format!("{ctx}.offset"))?;
    as_u64(get(o, "op", ctx)?, &format!("{ctx}.op"))?;
    as_str(get(o, "provider", ctx)?, &format!("{ctx}.provider"))?;
    Ok(())
}

fn check_execution(v: &Value, ctx: &str) -> Result<(), String> {
    let o = obj(v, ctx)?;
    exact_keys(
        o,
        &[
            "alg_class",
            "aliases",
            "cookie",
            "count",
            "first_ns",
            "funcid",
            "last_ns",
            "offset",
            "op",
            "provider",
        ],
        ctx,
    )?;
    as_u64(get(o, "cookie", ctx)?, &format!("{ctx}.cookie"))?;
    as_u64(get(o, "count", ctx)?, &format!("{ctx}.count"))?;
    as_u64(get(o, "first_ns", ctx)?, &format!("{ctx}.first_ns"))?;
    as_u64(get(o, "last_ns", ctx)?, &format!("{ctx}.last_ns"))?;
    as_str(get(o, "provider", ctx)?, &format!("{ctx}.provider"))?;
    as_u64(get(o, "op", ctx)?, &format!("{ctx}.op"))?;
    as_u64(get(o, "funcid", ctx)?, &format!("{ctx}.funcid"))?;
    as_str(get(o, "alg_class", ctx)?, &format!("{ctx}.alg_class"))?;
    as_u64(get(o, "offset", ctx)?, &format!("{ctx}.offset"))?;
    for (i, a) in as_arr(get(o, "aliases", ctx)?, &format!("{ctx}.aliases"))?
        .iter()
        .enumerate()
    {
        check_identity(
            obj(a, &format!("{ctx}.aliases[{i}]"))?,
            &format!("{ctx}.aliases[{i}]"),
        )?;
    }
    Ok(())
}

fn check_legacy(v: &Value, ctx: &str) -> Result<(), String> {
    if v.is_null() {
        return Ok(());
    }
    let o = obj(v, ctx)?;
    for k in o.keys() {
        if !LEGACY_KEYS.contains(&k.as_str()) {
            return Err(format!("{ctx}: unknown legacy key {k:?}"));
        }
    }
    if let Some(e) = o.get("entries") {
        for (i, item) in as_arr(e, &format!("{ctx}.entries"))?.iter().enumerate() {
            let c = format!("{ctx}.entries[{i}]");
            let io = obj(item, &c)?;
            exact_keys(io, &["class", "name", "probed", "state"], &c)?;
            as_str(get(io, "class", &c)?, &format!("{c}.class"))?;
            as_str(get(io, "name", &c)?, &format!("{c}.name"))?;
            as_bool(get(io, "probed", &c)?, &format!("{c}.probed"))?;
            let st = as_str(get(io, "state", &c)?, &format!("{c}.state"))?;
            if !["observed", "absent", "uninstrumented"].contains(&st) {
                return Err(format!("{c}.state: unknown state {st:?}"));
            }
        }
    }
    if let Some(w) = o.get("weak") {
        let c = format!("{ctx}.weak");
        let wo = obj(w, &c)?;
        exact_keys(
            wo,
            &[
                "executed_algs",
                "executed_calls",
                "legacy_algs",
                "unknown_calls",
            ],
            &c,
        )?;
        for s in as_arr(get(wo, "legacy_algs", &c)?, &format!("{c}.legacy_algs"))? {
            as_str(s, &format!("{c}.legacy_algs[]"))?;
        }
        for s in as_arr(get(wo, "executed_algs", &c)?, &format!("{c}.executed_algs"))? {
            as_str(s, &format!("{c}.executed_algs[]"))?;
        }
        as_u64(
            get(wo, "executed_calls", &c)?,
            &format!("{c}.executed_calls"),
        )?;
        as_u64(get(wo, "unknown_calls", &c)?, &format!("{c}.unknown_calls"))?;
    }
    if let Some(cp) = o.get("capability") {
        let c = format!("{ctx}.capability");
        let co = obj(cp, &c)?;
        exact_keys(
            co,
            &["syms_present", "tripwires_attached", "tripwires_missed"],
            &c,
        )?;
        as_u64(get(co, "syms_present", &c)?, &format!("{c}.syms_present"))?;
        as_u64(
            get(co, "tripwires_attached", &c)?,
            &format!("{c}.tripwires_attached"),
        )?;
        as_u64(
            get(co, "tripwires_missed", &c)?,
            &format!("{c}.tripwires_missed"),
        )?;
    }
    if let Some(f) = o.get("flags") {
        for s in as_arr(f, &format!("{ctx}.flags"))? {
            as_str(s, &format!("{ctx}.flags[]"))?;
        }
    }
    if let Some(e) = o.get("engine") {
        let c = format!("{ctx}.engine");
        let eo = obj(e, &c)?;
        exact_keys(eo, &["calls_by_entrypoint", "engine_id_class"], &c)?;
        str_map(
            obj(
                get(eo, "calls_by_entrypoint", &c)?,
                &format!("{c}.calls_by_entrypoint"),
            )?,
            &format!("{c}.calls_by_entrypoint"),
        )?;
        str_map(
            obj(
                get(eo, "engine_id_class", &c)?,
                &format!("{c}.engine_id_class"),
            )?,
            &format!("{c}.engine_id_class"),
        )?;
    }
    if let Some(l) = o.get("legacy_provider") {
        let c = format!("{ctx}.legacy_provider");
        let lo = obj(l, &c)?;
        exact_keys(
            lo,
            &[
                "algs",
                "executed_queries",
                "executed_calls",
                "shared_ambiguous_calls",
                "non_legacy_exclusive_calls",
                "unfenced_tail_calls",
                "loads",
            ],
            &c,
        )?;
        str_map(
            obj(get(lo, "loads", &c)?, &format!("{c}.loads"))?,
            &format!("{c}.loads"),
        )?;
        as_u64(
            get(lo, "executed_queries", &c)?,
            &format!("{c}.executed_queries"),
        )?;
        for k in [
            "executed_calls",
            "shared_ambiguous_calls",
            "non_legacy_exclusive_calls",
            "unfenced_tail_calls",
        ] {
            as_u64(get(lo, k, &c)?, &format!("{c}.{k}"))?;
        }
        for s in as_arr(get(lo, "algs", &c)?, &format!("{c}.algs"))? {
            as_str(s, &format!("{c}.algs[]"))?;
        }
    }
    if let Some(f) = o.get("findings") {
        for s in as_arr(f, &format!("{ctx}.findings"))? {
            as_str(s, &format!("{ctx}.findings[]"))?;
        }
    }
    for k in ["lowlevel", "meth_new", "unreadable"] {
        if let Some(x) = o.get(k) {
            obj(x, &format!("{ctx}.{k}"))?;
        }
    }
    Ok(())
}

fn check_policy(v: &Value, ctx: &str) -> Result<(), String> {
    let o = obj(v, ctx)?;
    exact_keys(
        o,
        &[
            "kat_excluded",
            "kat_note",
            "param_blind",
            "rules",
            "unseen_deny_providers",
            "verdict",
            "violations",
        ],
        ctx,
    )?;
    let verdict = as_str(get(o, "verdict", ctx)?, &format!("{ctx}.verdict"))?;
    if !["pass", "violation", "no-verdict"].contains(&verdict) {
        return Err(format!("{ctx}.verdict: unknown verdict {verdict:?}"));
    }
    for (i, r) in as_arr(get(o, "rules", ctx)?, &format!("{ctx}.rules"))?
        .iter()
        .enumerate()
    {
        let c = format!("{ctx}.rules[{i}]");
        let ro = obj(r, &c)?;
        exact_keys(ro, &["matches", "result", "rule", "value"], &c)?;
        let rule = as_str(get(ro, "rule", &c)?, &format!("{c}.rule"))?;
        if !RULES.contains(&rule) {
            return Err(format!("{c}.rule: unknown rule {rule:?}"));
        }
        as_str(get(ro, "value", &c)?, &format!("{c}.value"))?;
        let res = as_str(get(ro, "result", &c)?, &format!("{c}.result"))?;
        if !["pass", "violation"].contains(&res) {
            return Err(format!("{c}.result: unknown result {res:?}"));
        }
        as_u64(get(ro, "matches", &c)?, &format!("{c}.matches"))?;
    }
    for (i, x) in as_arr(get(o, "violations", ctx)?, &format!("{ctx}.violations"))?
        .iter()
        .enumerate()
    {
        let c = format!("{ctx}.violations[{i}]");
        let xo = obj(x, &c)?;
        exact_keys(
            xo,
            &[
                "absent",
                "alg",
                "cmdline",
                "container_id",
                "count",
                "fenced_gen",
                "first_ns",
                "funcid",
                "image_digest",
                "last_ns",
                "matcher",
                "op",
                "op_name",
                "provider",
                "provider_label",
                "rule",
                "window",
            ],
            &c,
        )?;
        let rule = as_str(get(xo, "rule", &c)?, &format!("{c}.rule"))?;
        if !RULES.contains(&rule) {
            return Err(format!("{c}.rule: unknown rule {rule:?}"));
        }
        as_str(get(xo, "matcher", &c)?, &format!("{c}.matcher"))?;
        as_str(
            get(xo, "provider_label", &c)?,
            &format!("{c}.provider_label"),
        )?;
        as_u64(get(xo, "op", &c)?, &format!("{c}.op"))?;
        as_str(get(xo, "op_name", &c)?, &format!("{c}.op_name"))?;
        as_str(get(xo, "alg", &c)?, &format!("{c}.alg"))?;
        as_u64(get(xo, "funcid", &c)?, &format!("{c}.funcid"))?;
        as_u64(get(xo, "count", &c)?, &format!("{c}.count"))?;
        opt_u64(get(xo, "first_ns", &c)?, &format!("{c}.first_ns"))?;
        opt_u64(get(xo, "last_ns", &c)?, &format!("{c}.last_ns"))?;
        opt_u64(get(xo, "fenced_gen", &c)?, &format!("{c}.fenced_gen"))?;
        as_bool(get(xo, "absent", &c)?, &format!("{c}.absent"))?;
        let w = obj(get(xo, "window", &c)?, &format!("{c}.window"))?;
        exact_keys(w, &["end_epoch", "start_epoch"], &format!("{c}.window"))?;
        as_f64(
            get(w, "start_epoch", &c)?,
            &format!("{c}.window.start_epoch"),
        )?;
        as_f64(get(w, "end_epoch", &c)?, &format!("{c}.window.end_epoch"))?;
        as_str(get(xo, "cmdline", &c)?, &format!("{c}.cmdline"))?;
        as_str(get(xo, "container_id", &c)?, &format!("{c}.container_id"))?;
        as_str(get(xo, "image_digest", &c)?, &format!("{c}.image_digest"))?;
        let p = obj(get(xo, "provider", &c)?, &format!("{c}.provider"))?;
        exact_keys(p, &["build_id", "path"], &format!("{c}.provider"))?;
        as_str(get(p, "path", &c)?, &format!("{c}.provider.path"))?;
        as_str(get(p, "build_id", &c)?, &format!("{c}.provider.build_id"))?;
    }
    for s in as_arr(
        get(o, "unseen_deny_providers", ctx)?,
        &format!("{ctx}.unseen_deny_providers"),
    )? {
        as_str(s, &format!("{ctx}.unseen_deny_providers[]"))?;
    }
    as_bool(get(o, "param_blind", ctx)?, &format!("{ctx}.param_blind"))?;
    as_u64(get(o, "kat_excluded", ctx)?, &format!("{ctx}.kat_excluded"))?;
    as_str(get(o, "kat_note", ctx)?, &format!("{ctx}.kat_note"))?;
    Ok(())
}

/// Strict auditor-document conformance: exact key sets, exact types,
/// frozen vocabularies. Accepts the `report` document and, when
/// present, the `check` `policy` section -- the same checker validates
/// the frozen golden and live story output.
fn check_auditor_shape(v: &Value) -> Result<(), String> {
    let o = obj(v, "doc")?;
    let mut want: BTreeSet<&str> = [
        "schema_version",
        "target",
        "window",
        "kernel",
        "provider",
        "completeness",
        "executions",
        "legacy",
        "stale",
        "drain_wall_us",
    ]
    .into_iter()
    .collect();
    for k in ["child_exit", "policy"] {
        if o.contains_key(k) {
            want.insert(k);
        }
    }
    let got: BTreeSet<&str> = o.keys().map(String::as_str).collect();
    if got != want {
        let extra: Vec<&&str> = got.difference(&want).collect();
        let missing: Vec<&&str> = want.difference(&got).collect();
        return Err(format!(
            "doc: key mismatch (extra={extra:?} missing={missing:?})"
        ));
    }
    let sv = as_str(get(o, "schema_version", "doc")?, "doc.schema_version")?;
    if sv != "observed-crypto-v1.0" {
        return Err(format!("doc.schema_version: unknown {sv:?}"));
    }
    let t = obj(get(o, "target", "doc")?, "doc.target")?;
    exact_keys(
        t,
        &["cmdline", "comm", "container_id", "image_digest", "pid"],
        "doc.target",
    )?;
    as_u64(get(t, "pid", "doc")?, "doc.target.pid")?;
    as_str(get(t, "comm", "doc")?, "doc.target.comm")?;
    as_str(get(t, "cmdline", "doc")?, "doc.target.cmdline")?;
    as_str(get(t, "container_id", "doc")?, "doc.target.container_id")?;
    as_str(get(t, "image_digest", "doc")?, "doc.target.image_digest")?;
    let w = obj(get(o, "window", "doc")?, "doc.window")?;
    exact_keys(
        w,
        &["actual_s", "end_epoch", "planned_s", "start_epoch"],
        "doc.window",
    )?;
    as_f64(get(w, "planned_s", "doc")?, "doc.window.planned_s")?;
    as_f64(get(w, "actual_s", "doc")?, "doc.window.actual_s")?;
    as_f64(get(w, "start_epoch", "doc")?, "doc.window.start_epoch")?;
    as_f64(get(w, "end_epoch", "doc")?, "doc.window.end_epoch")?;
    as_str(get(o, "kernel", "doc")?, "doc.kernel")?;
    let p = obj(get(o, "provider", "doc")?, "doc.provider")?;
    exact_keys(p, &["build_id", "path"], "doc.provider")?;
    as_str(get(p, "path", "doc")?, "doc.provider.path")?;
    as_str(get(p, "build_id", "doc")?, "doc.provider.build_id")?;
    let c = obj(get(o, "completeness", "doc")?, "doc.completeness")?;
    exact_keys(c, &["counters", "reasons", "status"], "doc.completeness")?;
    let status = as_str(get(c, "status", "doc")?, "doc.completeness.status")?;
    if !["COMPLETE", "PARTIAL", "FATAL"].contains(&status) {
        return Err(format!("doc.completeness.status: unknown {status:?}"));
    }
    for r in as_arr(get(c, "reasons", "doc")?, "doc.completeness.reasons")? {
        let s = as_str(r, "doc.completeness.reasons[]")?;
        if !REASONS.contains(&s) {
            return Err(format!("doc.completeness.reasons: unknown {s:?}"));
        }
    }
    let k = obj(get(c, "counters", "doc")?, "doc.completeness.counters")?;
    exact_keys(
        k,
        &[
            "cold_gap_calls",
            "drain_shortfall",
            "dropped_events",
            "dropped_events_bpf",
            "dropped_events_userspace",
            "engine_fallback_uninstrumented",
            "fork_exec_ignored",
            "missed_attaches",
            "over_budget",
            "provider_changed",
            "scan_budget_exhaustions",
            "table_staleness_events",
            "uninstrumented_ops",
            "unresolved_offsets",
        ],
        "doc.completeness.counters",
    )?;
    for (name, v) in k {
        as_u64(v, &format!("doc.completeness.counters.{name}"))?;
    }
    for (i, e) in as_arr(get(o, "executions", "doc")?, "doc.executions")?
        .iter()
        .enumerate()
    {
        check_execution(e, &format!("doc.executions[{i}]"))?;
    }
    check_legacy(get(o, "legacy", "doc")?, "doc.legacy")?;
    for (i, s) in as_arr(get(o, "stale", "doc")?, "doc.stale")?
        .iter()
        .enumerate()
    {
        let c = format!("doc.stale[{i}]");
        let so = obj(s, &c)?;
        exact_keys(so, &["detail", "events", "generation", "keys"], &c)?;
        as_u64(get(so, "generation", &c)?, &format!("{c}.generation"))?;
        as_u64(get(so, "events", &c)?, &format!("{c}.events"))?;
        as_u64(get(so, "keys", &c)?, &format!("{c}.keys"))?;
        for (j, d) in as_arr(get(so, "detail", &c)?, &format!("{c}.detail"))?
            .iter()
            .enumerate()
        {
            let dc = format!("{c}.detail[{j}]");
            let dd = obj(d, &dc)?;
            exact_keys(
                dd,
                &[
                    "alg_class",
                    "cookie",
                    "count",
                    "first_ns",
                    "funcid",
                    "last_ns",
                    "offset",
                    "op",
                    "provider",
                ],
                &dc,
            )?;
            as_u64(get(dd, "cookie", &dc)?, &format!("{dc}.cookie"))?;
            as_str(get(dd, "provider", &dc)?, &format!("{dc}.provider"))?;
            as_u64(get(dd, "op", &dc)?, &format!("{dc}.op"))?;
            as_u64(get(dd, "funcid", &dc)?, &format!("{dc}.funcid"))?;
            as_str(get(dd, "alg_class", &dc)?, &format!("{dc}.alg_class"))?;
            as_u64(get(dd, "offset", &dc)?, &format!("{dc}.offset"))?;
            as_u64(get(dd, "count", &dc)?, &format!("{dc}.count"))?;
            as_u64(get(dd, "first_ns", &dc)?, &format!("{dc}.first_ns"))?;
            as_u64(get(dd, "last_ns", &dc)?, &format!("{dc}.last_ns"))?;
        }
    }
    as_u64(get(o, "drain_wall_us", "doc")?, "doc.drain_wall_us")?;
    if let Some(x) = o.get("child_exit") {
        x.as_i64()
            .ok_or_else(|| "doc.child_exit: expected integer".to_string())?;
    }
    if let Some(pv) = o.get("policy") {
        check_policy(pv, "doc.policy")?;
    }
    Ok(())
}

fn load_golden() -> (String, Value) {
    let path = manifest_dir().join("tests/auditor_golden.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    (text, v)
}

#[test]
fn golden_conforms() {
    let (_, v) = load_golden();
    check_auditor_shape(&v).expect("golden must conform");
}

#[test]
fn golden_bytes_stable() {
    // Byte-shape pin: the golden round-trips through the real
    // toolchain serializer unchanged (sorted keys, pretty, trailing
    // newline) -- the same bytes the emitter convention produces.
    let (text, v) = load_golden();
    let back = serde_json::to_string_pretty(&v).unwrap() + "\n";
    assert_eq!(text, back, "golden is not byte-stable under re-serialize");
}

#[test]
fn golden_exercises_branches() {
    // The fixture must actually cover the shapes it pins: a bare
    // `{}`-shaped golden would pass the checker while proving nothing.
    let (_, v) = load_golden();
    let o = v.as_object().unwrap();
    assert!(
        !o["executions"].as_array().unwrap().is_empty(),
        "golden needs executions"
    );
    assert!(
        o["executions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| !e["aliases"].as_array().unwrap().is_empty()),
        "golden needs an aliased execution"
    );
    assert!(o["legacy"].is_object(), "golden needs a legacy block");
    assert!(
        !o["stale"].as_array().unwrap().is_empty()
            && !o["stale"][0]["detail"].as_array().unwrap().is_empty(),
        "golden needs fenced detail"
    );
    assert!(o.contains_key("child_exit"), "golden needs child_exit");
}

#[test]
fn tampered_documents_rejected() {
    // Negative proof: every tamper below must fail the checker. A
    // conformance test that cannot say NO is a golden-match ritual.
    type Tamper = (&'static str, Box<dyn Fn(&mut Value)>);
    let (_, v) = load_golden();
    let mut cases: Vec<Tamper> = Vec::new();
    cases.push((
        "drop completeness",
        Box::new(|d: &mut Value| {
            d.as_object_mut().unwrap().remove("completeness");
        }),
    ));
    cases.push((
        "add top-level key",
        Box::new(|d: &mut Value| {
            d["extra"] = Value::from(1);
        }),
    ));
    cases.push((
        "status vocabulary",
        Box::new(|d: &mut Value| {
            d["completeness"]["status"] = Value::from("COMPLETE-ISH");
        }),
    ));
    cases.push((
        "status type flip",
        Box::new(|d: &mut Value| {
            d["completeness"]["status"] = Value::from(3);
        }),
    ));
    cases.push((
        "unknown reason",
        Box::new(|d: &mut Value| {
            d["completeness"]["reasons"] = Value::from(vec!["bogus-reason"]);
        }),
    ));
    cases.push((
        "drop counter",
        Box::new(|d: &mut Value| {
            d["completeness"]["counters"]
                .as_object_mut()
                .unwrap()
                .remove("over_budget");
        }),
    ));
    cases.push((
        "drop execution funcid",
        Box::new(|d: &mut Value| {
            d["executions"][0].as_object_mut().unwrap().remove("funcid");
        }),
    ));
    cases.push((
        "count type flip",
        Box::new(|d: &mut Value| {
            d["executions"][0]["count"] = Value::from("500");
        }),
    ));
    cases.push((
        "schema version",
        Box::new(|d: &mut Value| {
            d["schema_version"] = Value::from("observed-crypto-v2.0");
        }),
    ));
    cases.push((
        "legacy entry state",
        Box::new(|d: &mut Value| {
            d["legacy"]["entries"][0]["state"] = Value::from("maybe");
        }),
    ));
    cases.push((
        "stale detail extra key",
        Box::new(|d: &mut Value| {
            d["stale"][0]["detail"][0]["zzz"] = Value::from(0);
        }),
    ));
    cases.push((
        "window int for float",
        Box::new(|d: &mut Value| {
            d["window"]["planned_s"] = Value::from(1);
        }),
    ));
    cases.push((
        "child_exit type flip",
        Box::new(|d: &mut Value| {
            d["child_exit"] = Value::from("0");
        }),
    ));
    cases.push((
        "policy bad verdict",
        Box::new(|d: &mut Value| {
            d["policy"] = serde_json::json!({
                "verdict": "unknown",
                "rules": [],
                "violations": [],
                "unseen_deny_providers": [],
                "param_blind": false,
                "kat_excluded": 0,
                "kat_note": "x",
            });
        }),
    ));
    assert!(!cases.is_empty());
    for (name, tamper) in &cases {
        let mut d = v.clone();
        tamper(&mut d);
        assert!(
            check_auditor_shape(&d).is_err(),
            "tamper accepted (must reject): {name}"
        );
    }
}

#[test]
fn story_output_conforms() {
    // Live story output (environment-private: paths, build-ids, timestamps)
    // never ships in this repo; validate it with the same checker by
    // pointing this env var at the story JSON. Unset (CI default) ->
    // nothing to validate, pass.
    let Some(path) = std::env::var_os("OSSLSCOPE_AUDITOR_STORY") else {
        return;
    };
    let text = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    check_auditor_shape(&v).expect("story output must conform");
}

// ---------------------------------------------------------------- v2 conformance
//
// The v2 checker is the shared library validator (schema +
// semantics), not a second hand-rolled walker: auditor conformance
// and the output contract can never drift apart. The golden below
// is generated from the fixture by review
// (`OSSLSCOPE_REGENERATE_AUDITOR_GOLDEN=1`), then pinned.

use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, CounterKind,
    CounterSource, CounterUnits, DispositionRecord, ExpectedScope, FinalizeInput, GapCounter,
    LegacyCallPartition, ObjectId, ObjectRecord, OpensslVersion, PolicyRecord, PolicyRuleResult,
    PolicyVerdict, RuleVerdict, ScopeCoverage, SiteExecution, SiteKey, TargetRecord, finalize,
};
use osslscope::report::render_json;
use osslscope::schema::{check_v2_semantics, validate_v2};

/// Strict v2 auditor conformance: actual JSON Schema validation plus
/// cross-field semantics. Accepts report documents and, when
/// present, the check `policy` section.
fn check_auditor_v2_shape(v: &Value) -> Result<(), String> {
    validate_v2(v).map_err(|e| format!("schema: {e}"))?;
    check_v2_semantics(v).map_err(|e| format!("semantics: {e}"))?;
    Ok(())
}

fn auditor_v2_fixture() -> CaptureDocument {
    let obj = |id: &str| ObjectId(id.to_string());
    let cand = |provider: &str, class: &str, op: u32, func: u32, algs: &[&str], weak: bool| {
        CandidateIdentity::new(
            obj(provider),
            class.to_string(),
            op,
            func,
            algs.iter().map(|a| a.to_string()).collect(),
            weak,
        )
    };
    let site = |object: &str,
                inode: u64,
                offset: u64,
                generation: u32,
                calls: u64,
                cands: Vec<CandidateIdentity>,
                cov: CandidateCoverage| {
        SiteExecution {
            site: SiteKey {
                object: obj(object),
                device: 8,
                inode,
                offset,
            },
            generation,
            candidates: cands,
            candidates_coverage: cov,
            calls,
            first_ns: 10,
            last_ns: 90,
            installed_at: None,
        }
    };
    const FP_A: &str = "build:aaaa0123456789aaaa0123456789aaaa0123456789aaaa0123456789";
    const FP_B: &str = "build:bbbb0123456789bbbb0123456789bbbb0123456789bbbb0123456789";
    let input = FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 30_000_000_000,
            effective_start_ns: 0,
            effective_end_ns: 30_000_000_000,
            signal_cut: false,
            count_admission: None,
        },
        sites: vec![
            site(
                FP_A,
                100,
                0x1000,
                0,
                400,
                vec![cand(FP_A, "default", 2, 21, &["DES"], false)],
                CandidateCoverage::Complete,
            ),
            site(
                FP_B,
                200,
                0x1000,
                0,
                60,
                vec![
                    cand(FP_B, "default", 2, 21, &["AES-256-GCM"], false),
                    cand(FP_B, "default", 2, 21, &["ARIA-256-GCM"], true),
                ],
                CandidateCoverage::Complete,
            ),
            site(
                FP_A,
                100,
                0x2000,
                0,
                0,
                vec![cand(FP_A, "default", 1, 7, &["SHA-256"], false)],
                CandidateCoverage::Complete,
            ),
        ],
        fenced: vec![osslscope::evidence::FencedGeneration {
            generation: 2,
            sites: vec![site(
                FP_A,
                100,
                0x1000,
                2,
                40,
                vec![cand(FP_A, "default", 2, 21, &["DES"], false)],
                CandidateCoverage::Complete,
            )],
        }],
        objects: vec![
            ObjectRecord {
                id: obj(FP_A),
                device: 8,
                inode: 100,
                display_locator: "/usr/lib/ossl-modules/default.so".to_string(),
            },
            ObjectRecord {
                id: obj(FP_B),
                device: 8,
                inode: 200,
                display_locator: "/usr/lib/ossl-modules/legacy.so".to_string(),
            },
        ],
        coverage: vec![ScopeCoverage {
            scope: "provider/default".to_string(),
            expected: ExpectedScope::Applicable { sites: 3 },
            discovered: 3,
            attached: 3,
        }],
        // Round 2, residual M: the lossy traversal content (one
        // non-Complete entry, one finding) carries the Loss
        // counters assembly emits for exactly that content — the
        // fixture is honestly PARTIAL, like assembly's.
        counters: vec![
            GapCounter {
                name: "count.map_insert_dropped".to_string(),
                kind: CounterKind::Loss,
                units: CounterUnits::Events,
                source: CounterSource::KernelMap,
                value: 0,
            },
            GapCounter {
                name: "traversal.incomplete".to_string(),
                kind: CounterKind::Loss,
                units: CounterUnits::Events,
                source: CounterSource::Discovery,
                value: 1,
            },
            GapCounter {
                name: "traversal.unjoined".to_string(),
                kind: CounterKind::Loss,
                units: CounterUnits::Events,
                source: CounterSource::Discovery,
                value: 1,
            },
        ],
        fatal: None,
        target: TargetRecord::new(
            42,
            "audited".to_string(),
            "cid-auditor".to_string(),
            "sha256:auditor".to_string(),
        ),
        openssl: OpensslVersion::verified("3.0.14".to_string()),
        disposition: Some(DispositionRecord::exited(0)),
        policy: Some(PolicyRecord {
            verdict: PolicyVerdict::Violation,
            rules: vec![
                PolicyRuleResult {
                    rule: "deny-algorithm".to_string(),
                    predicate: "algorithm=DES".to_string(),
                    result: RuleVerdict::Violation,
                    definite: 440,
                    possible: Some(440),
                    evidence: vec![
                        osslscope::evidence::PolicyEvidenceRef {
                            object: obj(FP_A),
                            device: 8,
                            inode: 100,
                            offset: 0x1000,
                            generation: 0,
                            calls: 400,
                        },
                        osslscope::evidence::PolicyEvidenceRef {
                            object: obj(FP_A),
                            device: 8,
                            inode: 100,
                            offset: 0x1000,
                            generation: 2,
                            calls: 40,
                        },
                    ],
                    engine_evidence: Vec::new(),
                },
                PolicyRuleResult {
                    rule: "deny-weak".to_string(),
                    predicate: "weak-alias".to_string(),
                    result: RuleVerdict::Pass,
                    definite: 0,
                    possible: Some(0),
                    evidence: Vec::new(),
                    engine_evidence: Vec::new(),
                },
            ],
        }),
        // Honest by construction: every candidate above is
        // default-class, so all 500 counted calls (400 + 0 + 60
        // current, 40 fenced) land non-legacy-exclusive.
        legacy_partition: LegacyCallPartition {
            legacy_exclusive: 0,
            non_legacy_exclusive: 500,
            shared_ambiguous: 0,
            unfenced_tails: 0,
        },
        engine_observations: Vec::new(),
        traversal: Some(traversal_record_fixture()),
    };
    // Round 2, residual M: the lossy traversal content finalizes
    // PARTIAL (the traversal Loss counters above), like
    // assembly's — never COMPLETE.
    let doc = finalize(input);
    assert!(
        matches!(
            doc.status,
            osslscope::evidence::Completeness::Partial { .. }
        ),
        "lossy-traversal auditor fixture must be PARTIAL: {:?}",
        doc.status
    );
    doc
}

/// I4/T2-1: the auditor's traversal section (same fully-populated
/// shape as the output-contract fixture — all ten keys incl. the
/// census/entry fields — so the auditor checker exercises the
/// traversal defs on every run).
fn traversal_record_fixture() -> osslscope::evidence::TraversalRecord {
    use osslscope::evidence::{TraversalObject, TraversalRecord, TraversalRecordEntry};
    use osslscope::scan::oracle::{Outcome, PartialReason, TrueT};
    use std::collections::BTreeMap;
    TraversalRecord {
        harvest: TraversalObject {
            path: "/lib/osslscope/osslscope-harvest".to_string(),
            sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        },
        count: TraversalObject {
            path: "/lib/osslscope/osslscope-count".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        },
        members: TraversalObject {
            path: "/lib/osslscope/osslscope-members".to_string(),
            sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae".to_string(),
        },
        records: 2,
        findings: 1,
        polls: 3,
        admitted: BTreeMap::from([(7u32, 10u64), (12u32, 4u64)]),
        entries: vec![
            TraversalRecordEntry {
                tid: 7,
                seq: 0,
                op: 7,
                outcome: Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
                true_t: TrueT::Proven(6),
                alg_count: 7,
                row_count: 3,
                generation: Some(9),
            },
            TraversalRecordEntry {
                tid: 7,
                seq: 1,
                op: 12,
                outcome: Outcome::Partial {
                    reasons: vec![
                        PartialReason::Holes(vec![3]),
                        PartialReason::Trunc(6),
                        PartialReason::CacheShrink {
                            cached: 9,
                            observed: 4,
                        },
                        PartialReason::DrainLoss,
                    ],
                },
                true_t: TrueT::Candidate(4),
                alg_count: 5,
                row_count: 0,
                generation: None,
            },
        ],
        admitted_unknown: vec![9],
        census_loss: 2,
    }
}

fn load_golden_v2() -> (String, Value) {
    // Read-only by design: regeneration is the single-writer test
    // below (parallel writers would tear the file).
    let path = manifest_dir().join("tests/auditor_golden_v2.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    (text, v)
}

#[test]
fn regenerate_auditor_golden_v2() {
    // Single writer: run filtered
    // (`OSSLSCOPE_REGENERATE_AUDITOR_GOLDEN=1 cargo test
    // --test auditor_report regenerate_auditor_golden_v2`), review
    // the diff, then commit. Without the env var this is a no-op.
    if std::env::var("OSSLSCOPE_REGENERATE_AUDITOR_GOLDEN").is_err() {
        return;
    }
    let path = manifest_dir().join("tests/auditor_golden_v2.json");
    let bytes = render_json(&auditor_v2_fixture()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
}

#[test]
fn golden_v2_conforms() {
    let (_, v) = load_golden_v2();
    check_auditor_v2_shape(&v).expect("v2 golden must conform");
}

#[test]
fn golden_v2_bytes_stable() {
    // Same byte-shape pin as v1: the golden round-trips through the
    // real toolchain serializer unchanged.
    let (text, v) = load_golden_v2();
    let back = serde_json::to_string_pretty(&v).unwrap() + "\n";
    assert_eq!(
        text, back,
        "v2 golden is not byte-stable under re-serialize"
    );
    // And it equals a fresh render of the fixture (the emitter, not
    // a hand-written lookalike, is the shape source).
    let fresh = render_json(&auditor_v2_fixture()).unwrap();
    assert_eq!(
        text.as_bytes(),
        fresh.as_slice(),
        "v2 golden drifted from emitter"
    );
}

#[test]
fn golden_v2_exercises_branches() {
    let (_, v) = load_golden_v2();
    let o = v.as_object().unwrap();
    assert_eq!(o["schema_version"], "observed-crypto-v2.3");
    assert!(
        !o["sites"].as_array().unwrap().is_empty(),
        "v2 golden needs sites"
    );
    assert!(
        o["sites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["candidates"].as_array().unwrap().len() > 1),
        "v2 golden needs an ambiguous site"
    );
    assert!(
        !o["fenced"].as_array().unwrap().is_empty()
            && !o["fenced"][0]["sites"].as_array().unwrap().is_empty(),
        "v2 golden needs fenced detail"
    );
    assert!(o.contains_key("policy"), "v2 golden needs policy");
    assert_eq!(o["policy"]["verdict"], "violation");
    assert!(o.contains_key("disposition"), "v2 golden needs disposition");
    assert_eq!(o["openssl"]["state"], "verified");
    // H8: the golden pins the legacy partition and its
    // conservation (500 = 400 + 0 + 60 current + 40 fenced).
    let part = o["legacy_partition"].as_object().unwrap();
    assert_eq!(part["non_legacy_exclusive_calls"], 500);
    // I4/T2-1: the golden pins the traversal section (all ten
    // keys incl. the census/entry fields — the auditor checker
    // exercises the traversal defs on every conformance run).
    let t = o["traversal"].as_object().unwrap();
    for key in [
        "harvest",
        "count",
        "members",
        "records",
        "findings",
        "polls",
        "admitted",
        "entries",
        "admitted_unknown",
        "census_loss",
    ] {
        assert!(t.contains_key(key), "v2 golden needs traversal.{key}");
    }
    assert_eq!(t["entries"].as_array().unwrap().len(), 2);
    assert_eq!(t["census_loss"], 2);
    assert_eq!(
        part["legacy_exclusive_calls"]
            .as_u64()
            .unwrap()
            .saturating_add(part["non_legacy_exclusive_calls"].as_u64().unwrap())
            .saturating_add(part["shared_ambiguous_calls"].as_u64().unwrap())
            .saturating_add(part["unfenced_tail_calls"].as_u64().unwrap()),
        500
    );
}

#[test]
fn tampered_v2_documents_rejected() {
    // Negative proof for the v2 checker: every tamper below must
    // fail schema validation, semantics, or both. Cases marked
    // `semantics` pass the schema by design (JSON Schema cannot
    // express them) and must fail the semantic layer instead.
    type Tamper = (&'static str, Option<&'static str>, Box<dyn Fn(&mut Value)>);
    let (_, v) = load_golden_v2();
    let mut cases: Vec<Tamper> = Vec::new();
    cases.push((
        "drop sites",
        None,
        Box::new(|d: &mut Value| {
            d.as_object_mut().unwrap().remove("sites");
        }),
    ));
    cases.push((
        "add top-level key",
        None,
        Box::new(|d: &mut Value| {
            d["extra"] = Value::from(1);
        }),
    ));
    cases.push((
        "status vocabulary",
        None,
        Box::new(|d: &mut Value| {
            d["completeness"]["status"] = Value::from("COMPLETE-ISH");
        }),
    ));
    cases.push((
        "unknown reason kind",
        None,
        Box::new(|d: &mut Value| {
            d["completeness"]["reasons"] = Value::from(vec![serde_json::json!({"kind": "bogus"})]);
        }),
    ));
    cases.push((
        "drop counter value",
        None,
        Box::new(|d: &mut Value| {
            d["completeness"]["counters"][0]
                .as_object_mut()
                .unwrap()
                .remove("value");
        }),
    ));
    cases.push((
        "count type flip",
        None,
        Box::new(|d: &mut Value| {
            d["sites"][0]["calls"] = Value::from("400");
        }),
    ));
    cases.push((
        "drop legacy_partition",
        None,
        Box::new(|d: &mut Value| {
            d.as_object_mut().unwrap().remove("legacy_partition");
        }),
    ));
    cases.push((
        "skew partition bucket",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["legacy_partition"]["unfenced_tail_calls"] = Value::from(1);
        }),
    ));
    cases.push((
        "v1 schema_version",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["schema_version"] = Value::from("observed-crypto-v1.0");
        }),
    ));
    cases.push((
        "negative calls",
        None,
        Box::new(|d: &mut Value| {
            d["sites"][0]["calls"] = Value::from(-1);
        }),
    ));
    cases.push((
        "dangling object ref",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["sites"][0]["object"] = Value::from("build:nope");
        }),
    ));
    cases.push((
        "inconsistent window",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["window"]["effective_end_ns"] = Value::from(99_000_000_000u64);
        }),
    ));
    cases.push((
        "smuggled address",
        None,
        Box::new(|d: &mut Value| {
            d["sites"][0]["address"] = Value::from(140737348900864u64);
        }),
    ));
    cases.push((
        "argv_redacted false",
        None,
        Box::new(|d: &mut Value| {
            d["target"]["argv_redacted"] = Value::from(false);
        }),
    ));
    cases.push((
        "policy bad verdict",
        None,
        Box::new(|d: &mut Value| {
            d["policy"]["verdict"] = Value::from("unknown");
        }),
    ));
    cases.push((
        "evidence wrong generation",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["policy"]["rules"][0]["evidence"][0]["generation"] = Value::from(9);
        }),
    ));
    cases.push((
        "exited without code",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["disposition"]["code"] = Value::Null;
        }),
    ));
    cases.push((
        "definite exceeds possible",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["policy"]["rules"][0]["definite"] = Value::from(441);
        }),
    ));
    cases.push((
        "verdict contradicts rules",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["policy"]["verdict"] = Value::from("pass");
        }),
    ));
    cases.push((
        "site contradicts object triple",
        Some("semantics"),
        Box::new(|d: &mut Value| {
            d["sites"][0]["inode"] = Value::from(999);
        }),
    ));
    assert!(!cases.is_empty());
    for (name, layer, tamper) in &cases {
        let mut d = v.clone();
        tamper(&mut d);
        let schema_err = validate_v2(&d).is_err();
        let semantics_err = check_v2_semantics(&d).is_err();
        match *layer {
            Some("semantics") => {
                assert!(
                    !schema_err,
                    "tamper must pass schema by design (case {name}): use a semantic-only shape"
                );
                assert!(semantics_err, "tamper accepted (must reject): {name}");
            }
            _ => {
                assert!(
                    schema_err || semantics_err,
                    "tamper accepted (must reject): {name}"
                );
            }
        }
        assert!(
            check_auditor_v2_shape(&d).is_err(),
            "auditor v2 checker accepted tamper: {name}"
        );
    }
}

#[test]
fn story_v2_output_conforms() {
    // Explicitly supplied v2 artifacts (fresh generator output, live
    // story captures) validate with the same checker. Unset (CI
    // default) -> nothing to validate, pass.
    let Some(path) = std::env::var_os("OSSLSCOPE_AUDITOR_STORY_V2") else {
        return;
    };
    let text = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    check_auditor_v2_shape(&v).expect("supplied v2 artifact must conform");
}
