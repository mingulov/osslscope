//! Provisional P2 `report` (JSON doc + minimal human table; P3
//! freezes the schema, adds `check`, and narrows exits).
//!
//! `report [--duration S] [--format human|json] [--out FILE]
//! [--provider P] [--builtin] [--object O] [--count-object C]
//! [--settle S] [--timeout S] [--grace S] {--pid P | run -- <cmd>}`
//!
//! Exit precedence (PRD §6 proposal): child non-zero → 1 (with
//! `child_exit` in the doc — the subject failed, evidence rides
//! along); fatal (recycled / zero-attached / environment) → 4;
//! PARTIAL → 3; clean COMPLETE → 0; usage → 2. Violation (10) and
//! inconclusive (11) arrive with `check` at P3.
use crate::capture;
use std::process::ExitCode;
use std::time::Duration;

struct Args {
    cfg: capture::Config,
    target: capture::Target,
    format: String,
    out: Option<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut duration: Option<f64> = None;
    let mut format = "human".to_string();
    let mut out: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut builtin = false;
    let mut object: Option<String> = None;
    let mut count_object: Option<String> = None;
    let mut settle = 2.0f64;
    let mut timeout = 60.0f64;
    let mut grace = 5.0f64;
    let mut pid: Option<u32> = None;
    let mut run_at: Option<usize> = None;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "run" {
            run_at = Some(i);
            break;
        }
        let val = |k: &str| -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{k} needs a value"))
        };
        match a {
            "--duration" => {
                duration = Some(val(a)?.parse().map_err(|_| "--duration needs seconds")?)
            }
            "--format" => format = val(a)?,
            "--out" => out = Some(val(a)?),
            "--provider" => provider = Some(val(a)?),
            "--builtin" => builtin = true,
            "--object" => object = Some(val(a)?),
            "--count-object" => count_object = Some(val(a)?),
            "--settle" => settle = val(a)?.parse().map_err(|_| "--settle needs seconds")?,
            "--timeout" => timeout = val(a)?.parse().map_err(|_| "--timeout needs seconds")?,
            "--grace" => grace = val(a)?.parse().map_err(|_| "--grace needs seconds")?,
            "--pid" => pid = Some(val(a)?.parse().map_err(|_| "--pid needs an integer")?),
            x => return Err(format!("unknown flag {x}")),
        }
        i += 2;
    }
    if format != "human" && format != "json" {
        return Err("--format must be human|json".to_string());
    }
    let target = match (pid, run_at) {
        (Some(p), None) => capture::Target::Pid(p),
        (None, Some(j)) => {
            if argv.get(j + 1).map(String::as_str) != Some("--") {
                return Err("run needs -- before the command".to_string());
            }
            let cmd: Vec<String> = argv[j + 2..].to_vec();
            if cmd.is_empty() {
                return Err("run -- needs a command".to_string());
            }
            capture::Target::Spawn { argv: cmd }
        }
        _ => return Err("need exactly one of --pid P | run -- <cmd>".to_string()),
    };
    let duration =
        duration.ok_or_else(|| "--duration S is required (no --forever in v1)".to_string())?;
    if !duration.is_finite() || duration <= 0.0 {
        return Err("--duration must be > 0".to_string());
    }
    for (name, v) in [
        ("--settle", settle),
        ("--timeout", timeout),
        ("--grace", grace),
    ] {
        if !v.is_finite() || v < 0.0 {
            return Err(format!("{name} must be >= 0 seconds"));
        }
    }
    Ok(Args {
        cfg: capture::Config {
            harvest_object: object.ok_or("--object O is required")?.into(),
            count_object: count_object.ok_or("--count-object C is required")?.into(),
            provider: provider.ok_or("--provider P is required")?.into(),
            builtin,
            duration: Duration::from_secs_f64(duration),
            settle: Duration::from_secs_f64(settle),
            harvest_timeout: Duration::from_secs_f64(timeout),
            grace: Duration::from_secs_f64(grace),
        },
        target,
        format,
        out,
    })
}

/// Exit for a finished capture (pure — unit-tested).
fn exit_for(c: &capture::Capture) -> u8 {
    if matches!(c.child_exit, Some(code) if code != 0) {
        return 1;
    }
    match &c.outcome {
        capture::Outcome::Fatal(_) => 4,
        capture::Outcome::Partial => 3,
        capture::Outcome::Complete => 0,
    }
}

fn doc(c: &capture::Capture) -> serde_json::Value {
    let status = match &c.outcome {
        capture::Outcome::Complete => "COMPLETE",
        capture::Outcome::Partial => "PARTIAL",
        capture::Outcome::Fatal(_) => "FATAL",
    };
    let k = &c.counters;
    let executions: Vec<serde_json::Value> = c
        .executions
        .iter()
        .map(|e| {
            serde_json::json!({
                "cookie": e.cookie,
                "provider": e.id.provider,
                "op": e.id.op,
                "funcid": e.id.funcid,
                "alg_class": e.id.alg_class,
                "offset": e.id.offset,
                "count": e.count,
                "first_ns": e.first_ns,
                "last_ns": e.last_ns,
                "aliases": e.aliases.iter().map(|a| serde_json::json!({
                    "provider": a.provider, "op": a.op, "funcid": a.funcid,
                    "alg_class": a.alg_class, "offset": a.offset,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut d = serde_json::json!({
        "schema_version": "0.2-provisional",
        "target": {"pid": c.target_pid, "comm": c.target_comm},
        "window": {"planned_s": c.window_planned.as_secs_f64(), "actual_s": c.window_actual.as_secs_f64()},
        "completeness": {
            "status": status,
            "reasons": c.reasons,
            "counters": {
                "dropped_events": k.dropped_bpf + k.dropped_userspace,
                "dropped_events_bpf": k.dropped_bpf,
                "dropped_events_userspace": k.dropped_userspace,
                "missed_attaches": k.missed_attaches,
                "unresolved_offsets": k.unresolved_offsets,
                "table_staleness_events": k.table_staleness_events,
                "cold_gap_calls": k.cold_gap_calls,
                "provider_changed": k.provider_changed,
                "scan_budget_exhaustions": k.scan_budget_exhaustions,
                "engine_fallback_uninstrumented": k.engine_fallback_uninstrumented,
                "drain_shortfall": k.drain_shortfall,
                "uninstrumented_ops": k.uninstrumented_ops,
                "fork_exec_ignored": k.fork_exec_ignored,
                "over_budget": k.over_budget,
            },
        },
        "executions": executions,
        "legacy": legacy_with_executed_weak(c),
        "stale": c.stale.iter().map(|s| serde_json::json!({
            "generation": s.generation, "events": s.events, "keys": s.keys,
            "detail": s.detail.iter().map(|d| serde_json::json!({
                "cookie": d.cookie,
                "provider": d.id.provider, "op": d.id.op, "funcid": d.id.funcid,
                "alg_class": d.id.alg_class, "offset": d.id.offset,
                "count": d.count, "first_ns": d.first_ns, "last_ns": d.last_ns,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "drain_wall_us": c.drain_wall_us,
    });
    if let Some(code) = c.child_exit {
        d["child_exit"] = code.into();
    }
    d
}

/// Adopted harvest `legacy` block plus window-executed weak rollup:
/// `weak.executed_calls`/`weak.executed_algs` count executions (and
/// fenced detail) whose class is registry-weak; `weak.unknown_calls`
/// counts `other`-class executions (custom spellings — triage, never
/// auto-deny). Null legacy stays null (no harvest produced one).
fn legacy_with_executed_weak(c: &capture::Capture) -> serde_json::Value {
    let mut legacy = c.legacy.clone();
    if legacy.is_null() {
        return legacy;
    }
    let mut calls = 0u64;
    let mut unknown = 0u64;
    let mut algs = std::collections::BTreeSet::new();
    let mut fold = |class: &str, n: u64| {
        if crate::kinds::is_weak_alg(class) {
            calls += n;
            algs.insert(class.to_string());
        } else if class == "other" {
            unknown += n;
        }
    };
    for e in &c.executions {
        fold(&e.id.alg_class, e.count);
    }
    for s in &c.stale {
        for d in &s.detail {
            fold(&d.id.alg_class, d.count);
        }
    }
    legacy["weak"]["executed_calls"] = calls.into();
    legacy["weak"]["executed_algs"] = algs.into_iter().collect::<Vec<_>>().into();
    legacy["weak"]["unknown_calls"] = unknown.into();
    legacy
}

fn human(c: &capture::Capture) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "osslscope report: pid={} ({}) window={:.1}s/{:.1}s planned\n",
        c.target_pid,
        c.target_comm,
        c.window_actual.as_secs_f64(),
        c.window_planned.as_secs_f64()
    ));
    s.push_str("cookie provider op funcid alg_class count\n");
    for e in &c.executions {
        s.push_str(&format!(
            "{} {} {} {} {} {}\n",
            e.cookie, e.id.provider, e.id.op, e.id.funcid, e.id.alg_class, e.count
        ));
    }
    let status = match &c.outcome {
        capture::Outcome::Complete => "COMPLETE",
        capture::Outcome::Partial => "PARTIAL",
        capture::Outcome::Fatal(_) => "FATAL",
    };
    s.push_str(&format!("status={status}"));
    if !c.reasons.is_empty() {
        s.push_str(&format!(" reasons={}", c.reasons.join(",")));
    }
    let k = &c.counters;
    let mut nz = Vec::new();
    for (name, v) in [
        ("dropped", k.dropped_bpf + k.dropped_userspace),
        ("missed", k.missed_attaches),
        ("unresolved", k.unresolved_offsets),
        ("staleness", k.table_staleness_events),
        ("cold_gap", k.cold_gap_calls),
        ("prov_changed", k.provider_changed),
        ("scan_overruns", k.scan_budget_exhaustions),
        ("shortfall", k.drain_shortfall),
        ("uninstrumented_ops", k.uninstrumented_ops),
        ("fork_ignored", k.fork_exec_ignored),
        ("over_budget", k.over_budget),
    ] {
        if v > 0 {
            nz.push(format!("{name}={v}"));
        }
    }
    if !nz.is_empty() {
        s.push_str(&format!(" counters[{}]", nz.join(" ")));
    }
    if let Some(code) = c.child_exit {
        s.push_str(&format!(" child_exit={code}"));
    }
    s.push('\n');
    s
}

pub fn run(argv: &[String]) -> ExitCode {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("osslscope report: {e}");
            eprintln!(
                "usage: report --duration S --provider P --object O --count-object C [--format human|json] [--out F] [--builtin] [--settle S] [--timeout S] [--grace S] {{--pid P | run -- <cmd>}}"
            );
            return ExitCode::from(2);
        }
    };
    let c = match capture::run(&args.cfg, args.target) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("osslscope report: {e:#}");
            return ExitCode::from(4);
        }
    };
    let text = if args.format == "json" {
        serde_json::to_string_pretty(&doc(&c)).unwrap() + "\n"
    } else {
        human(&c)
    };
    if let Some(path) = &args.out {
        if let Err(e) = std::fs::write(path, &text) {
            eprintln!("osslscope report: write {path}: {e}");
            return ExitCode::from(4);
        }
    } else {
        print!("{text}");
    }
    ExitCode::from(exit_for(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(outcome: capture::Outcome, child_exit: Option<i32>) -> capture::Capture {
        capture::Capture {
            target_pid: 7,
            target_comm: "t".to_string(),
            window_planned: Duration::from_secs(1),
            window_actual: Duration::from_secs(1),
            outcome,
            reasons: Vec::new(),
            executions: Vec::new(),
            stale: Vec::new(),
            counters: capture::Counters::default(),
            child_exit,
            drain_wall_us: 0,
            harvest_doc: serde_json::json!({}),
            legacy: serde_json::Value::Null,
        }
    }

    #[test]
    fn exit_precedence() {
        use capture::{FatalKind, Outcome};
        assert_eq!(exit_for(&cap(Outcome::Complete, None)), 0);
        assert_eq!(exit_for(&cap(Outcome::Complete, Some(0))), 0);
        assert_eq!(exit_for(&cap(Outcome::Partial, None)), 3);
        assert_eq!(
            exit_for(&cap(Outcome::Fatal(FatalKind::AttachZero), None)),
            4
        );
        // Child failure dominates evidence status (never 10 without a verdict).
        assert_eq!(exit_for(&cap(Outcome::Complete, Some(2))), 1);
        assert_eq!(exit_for(&cap(Outcome::Partial, Some(139))), 1);
        assert_eq!(
            exit_for(&cap(Outcome::Fatal(FatalKind::Recycled), Some(1))),
            1
        );
    }

    #[test]
    fn doc_shape() {
        let d = doc(&cap(capture::Outcome::Complete, Some(0)));
        assert_eq!(d["schema_version"], "0.2-provisional");
        assert_eq!(d["completeness"]["status"], "COMPLETE");
        assert!(d["completeness"]["counters"]["dropped_events"].is_number());
        assert!(d["executions"].as_array().unwrap().is_empty());
        assert_eq!(d["child_exit"], 0);
        let d = doc(&cap(capture::Outcome::Partial, None));
        assert!(d.get("child_exit").is_none());
    }

    #[test]
    fn parse_matrix() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--duration",
            "5",
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
        ];
        let mut pid = base.clone();
        pid.extend(["--pid", "9"]);
        assert!(parse(&v(pid)).is_ok());
        let mut run = base.clone();
        run.extend(["run", "--", "echo", "hi"]);
        assert!(parse(&v(run)).is_ok());
        assert!(parse(&v(base.clone())).is_err()); // no target
        let mut both = base.clone();
        both.extend(["--pid", "9", "run", "--", "x"]);
        assert!(parse(&v(both)).is_err()); // both targets
        assert!(parse(&v(vec!["--provider", "p", "--pid", "9"])).is_err()); // no duration
        let mut yaml = base.clone();
        yaml.extend(["--pid", "9", "--format", "yaml"]);
        assert!(parse(&v(yaml)).is_err());
    }
}
