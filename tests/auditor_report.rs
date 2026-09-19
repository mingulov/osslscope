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
    "reharvest-skipped",
    "cold-gap",
    "reharvest-no-query",
    "fips-unlabeled",
    "reharvest-failed",
    "replan-skipped",
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
        exact_keys(lo, &["algs", "executed_calls", "loads"], &c)?;
        str_map(
            obj(get(lo, "loads", &c)?, &format!("{c}.loads"))?,
            &format!("{c}.loads"),
        )?;
        as_u64(
            get(lo, "executed_calls", &c)?,
            &format!("{c}.executed_calls"),
        )?;
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
