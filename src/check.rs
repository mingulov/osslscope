//! P3 `check`: bounded-window policy gate (CI use).
//!
//! `check [capture flags] [rules] {--pid P | run -- <cmd>}`
//! Rules (AND semantics, repeatable): `--require-provider P`,
//! `--deny-provider P`, `--deny-engine`, `--deny-algorithm X`,
//! `--deny-weak`, `--require-executed X`.
//!
//! Match domain is EXECUTED evidence (current + fenced detail):
//! queried-but-unexecuted classes (legacy block) are reported, not
//! policy-evaluated. Provider labels are file stems (`default` for
//! `--builtin`, else the provider .so stem) — exact match; the PRD
//! §7 `third-party:<hash>` class mapping is P5. Algorithm names are
//! exact frozen-registry matches (unknown → exit 2, typo-safe).
//! Require-rules on PARTIAL evidence fail closed (exit 10 with the
//! PARTIAL caveat); on FATAL there is no verdict at all (exit 4).
//! Exit 11 is reserved and never emitted in v1 (gate record).
use crate::capture;
use std::process::ExitCode;
use std::time::Duration;

/// Parsed rule set (repeatable flags accumulate).
#[derive(Debug, Default)]
pub(crate) struct RuleSet {
    pub require_provider: Vec<String>,
    pub deny_provider: Vec<String>,
    pub deny_engine: bool,
    pub deny_algorithm: Vec<String>,
    pub deny_weak: bool,
    pub require_executed: Vec<String>,
}

impl RuleSet {
    fn is_empty(&self) -> bool {
        self.require_provider.is_empty()
            && self.deny_provider.is_empty()
            && !self.deny_engine
            && self.deny_algorithm.is_empty()
            && !self.deny_weak
            && self.require_executed.is_empty()
    }
}

/// One executed identity (current or fenced) for rule matching.
struct Exec<'a> {
    provider: &'a str,
    op: u32,
    funcid: u32,
    alg: &'a str,
    count: u64,
    first_ns: u64,
    last_ns: u64,
    fenced_gen: Option<u32>,
}

/// Executed evidence: current executions plus fenced detail.
fn execs(c: &capture::Capture) -> Vec<Exec<'_>> {
    let mut v: Vec<Exec<'_>> = c
        .executions
        .iter()
        .map(|e| Exec {
            provider: &e.id.provider,
            op: e.id.op,
            funcid: e.id.funcid,
            alg: &e.id.alg_class,
            count: e.count,
            first_ns: e.first_ns,
            last_ns: e.last_ns,
            fenced_gen: None,
        })
        .collect();
    for s in &c.stale {
        for d in &s.detail {
            v.push(Exec {
                provider: &d.id.provider,
                op: d.id.op,
                funcid: d.id.funcid,
                alg: &d.id.alg_class,
                count: d.count,
                first_ns: d.first_ns,
                last_ns: d.last_ns,
                fenced_gen: Some(s.generation),
            });
        }
    }
    v
}

/// One violation with the actionability tuple (PRD §6): the
/// capture-level tuple (window, cmdline, container, image,
/// provider object) rides in the JSON envelope; the per-violation
/// identity rides here. `absent` require-violations carry no
/// identity (nothing matched); engine violations are untimed
/// (tripwire counts only).
#[derive(Debug)]
pub(crate) struct Violation {
    pub rule: String,
    pub matcher: String,
    pub provider_label: String,
    pub op: u32,
    pub op_name: String,
    pub alg: String,
    pub funcid: u32,
    pub count: u64,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub fenced_gen: Option<u32>,
    pub absent: bool,
}

#[derive(Debug)]
pub(crate) struct RuleResult {
    pub rule: String,
    pub value: String,
    pub passed: bool,
    pub matches: u64,
}

#[derive(Debug)]
pub(crate) struct Verdict {
    pub no_verdict: bool,
    pub violations: Vec<Violation>,
    pub results: Vec<RuleResult>,
    pub unseen_deny_providers: Vec<String>,
    pub param_blind: bool,
}

/// Evaluate rules against executed evidence (pure — unit-tested).
/// Unknown registry names are rejected by parse (exit 2), so this
/// never sees them. FATAL evidence yields no verdict (nothing to
/// evaluate — never a violation without evidence).
pub(crate) fn evaluate(c: &capture::Capture, rules: &RuleSet) -> Verdict {
    if matches!(c.outcome, capture::Outcome::Fatal(_)) {
        return Verdict {
            no_verdict: true,
            violations: Vec::new(),
            results: Vec::new(),
            unseen_deny_providers: Vec::new(),
            param_blind: false,
        };
    }
    let ex = execs(c);
    let mut v = Verdict {
        no_verdict: false,
        violations: Vec::new(),
        results: Vec::new(),
        unseen_deny_providers: Vec::new(),
        param_blind: !rules.deny_algorithm.is_empty(),
    };
    let hit = |e: &Exec<'_>, rule: &str, matcher: String| Violation {
        rule: rule.to_string(),
        matcher,
        provider_label: e.provider.to_string(),
        op: e.op,
        op_name: crate::report::op_display(e.op),
        alg: e.alg.to_string(),
        funcid: e.funcid,
        count: e.count,
        first_ns: Some(e.first_ns),
        last_ns: Some(e.last_ns),
        fenced_gen: e.fenced_gen,
        absent: false,
    };
    let miss = |rule: &str, matcher: &str| Violation {
        rule: rule.to_string(),
        matcher: matcher.to_string(),
        provider_label: String::new(),
        op: 0,
        op_name: String::new(),
        alg: String::new(),
        funcid: 0,
        count: 0,
        first_ns: None,
        last_ns: None,
        fenced_gen: None,
        absent: true,
    };
    for p in &rules.require_provider {
        let n: u64 = ex.iter().filter(|e| e.provider == p).map(|e| e.count).sum();
        let passed = n > 0;
        if !passed {
            v.violations.push(miss("require-provider", p));
        }
        v.results.push(RuleResult {
            rule: "require-provider".to_string(),
            value: p.clone(),
            passed,
            matches: n,
        });
    }
    for p in &rules.deny_provider {
        let hits: Vec<&Exec<'_>> = ex.iter().filter(|e| e.provider == p).collect();
        if hits.is_empty() && !v.unseen_deny_providers.iter().any(|u| u == p) {
            v.unseen_deny_providers.push(p.clone());
        }
        for e in &hits {
            v.violations.push(hit(e, "deny-provider", (*p).clone()));
        }
        v.results.push(RuleResult {
            rule: "deny-provider".to_string(),
            value: p.clone(),
            passed: hits.is_empty(),
            matches: hits.iter().map(|e| e.count).sum(),
        });
    }
    if rules.deny_engine {
        let calls = c
            .legacy
            .pointer("/engine/calls_by_entrypoint")
            .and_then(|m| m.as_object())
            .map(|m| {
                let mut v: Vec<(&String, u64)> = m
                    .iter()
                    .map(|(k, n)| (k, n.as_u64().unwrap_or(0)))
                    .filter(|(_, n)| *n > 0)
                    .collect();
                v.sort_by(|a, b| a.0.cmp(b.0));
                v
            })
            .unwrap_or_default();
        for (entry, n) in &calls {
            v.violations.push(Violation {
                rule: "deny-engine".to_string(),
                matcher: (*entry).clone(),
                provider_label: "engine".to_string(),
                op: 0,
                op_name: "ENGINE".to_string(),
                alg: (*entry).clone(),
                funcid: 0,
                count: *n,
                first_ns: None,
                last_ns: None,
                fenced_gen: None,
                absent: false,
            });
        }
        v.results.push(RuleResult {
            rule: "deny-engine".to_string(),
            value: String::new(),
            passed: calls.is_empty(),
            matches: calls.iter().map(|(_, n)| n).sum(),
        });
    }
    for a in &rules.deny_algorithm {
        let hits: Vec<&Exec<'_>> = ex.iter().filter(|e| e.alg == a).collect();
        for e in &hits {
            v.violations.push(hit(e, "deny-algorithm", (*a).clone()));
        }
        v.results.push(RuleResult {
            rule: "deny-algorithm".to_string(),
            value: a.clone(),
            passed: hits.is_empty(),
            matches: hits.iter().map(|e| e.count).sum(),
        });
    }
    if rules.deny_weak {
        let hits: Vec<&Exec<'_>> = ex
            .iter()
            .filter(|e| crate::kinds::is_weak_alg(e.alg))
            .collect();
        for e in &hits {
            v.violations.push(hit(e, "deny-weak", e.alg.to_string()));
        }
        v.results.push(RuleResult {
            rule: "deny-weak".to_string(),
            value: String::new(),
            passed: hits.is_empty(),
            matches: hits.iter().map(|e| e.count).sum(),
        });
    }
    for x in &rules.require_executed {
        let n: u64 = ex.iter().filter(|e| e.alg == x).map(|e| e.count).sum();
        let passed = n > 0;
        if !passed {
            v.violations.push(miss("require-executed", x));
        }
        v.results.push(RuleResult {
            rule: "require-executed".to_string(),
            value: x.clone(),
            passed,
            matches: n,
        });
    }
    v
}

struct Args {
    cfg: capture::Config,
    target: capture::Target,
    format: String,
    out: Option<String>,
    rules: RuleSet,
}

/// Exit for a checked capture (pure — unit-tested). Violation
/// dominates (even child failure); otherwise child failure, then
/// evidence status. Exit 11 is reserved and never emitted in v1.
fn exit_for(c: &capture::Capture, v: &Verdict) -> u8 {
    if !v.violations.is_empty() {
        return 10;
    }
    if matches!(c.child_exit, Some(code) if code != 0) {
        return 1;
    }
    match &c.outcome {
        capture::Outcome::Fatal(_) => 4,
        capture::Outcome::Partial => 3,
        capture::Outcome::Complete => 0,
    }
}

// Capture-flag parsing intentionally mirrors report::parse: the
// two flag sets diverge (report owns --cbom, check owns rules),
// and a shared strict parser costs more than it saves. The rule
// flags are check-only (repeatable; validated below).
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
    let mut image_digest = String::new();
    let mut pid: Option<u32> = None;
    let mut run_at: Option<usize> = None;
    let mut rules = RuleSet::default();
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
            "--builtin" => {
                builtin = true;
                i += 1;
                continue;
            }
            "--object" => object = Some(val(a)?),
            "--count-object" => count_object = Some(val(a)?),
            "--settle" => settle = val(a)?.parse().map_err(|_| "--settle needs seconds")?,
            "--timeout" => timeout = val(a)?.parse().map_err(|_| "--timeout needs seconds")?,
            "--grace" => grace = val(a)?.parse().map_err(|_| "--grace needs seconds")?,
            "--image-digest" => image_digest = val(a)?,
            "--pid" => pid = Some(val(a)?.parse().map_err(|_| "--pid needs an integer")?),
            "--require-provider" => rules.require_provider.push(val(a)?),
            "--deny-provider" => rules.deny_provider.push(val(a)?),
            "--deny-engine" => {
                rules.deny_engine = true;
                i += 1;
                continue;
            }
            "--deny-algorithm" => rules.deny_algorithm.push(val(a)?),
            "--deny-weak" => {
                rules.deny_weak = true;
                i += 1;
                continue;
            }
            "--require-executed" => rules.require_executed.push(val(a)?),
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
    let duration = duration.unwrap_or(crate::report::DEFAULT_DURATION_SECS);
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
    // Algorithm names are exact frozen-registry matches: unknown
    // names are config errors, never silent non-matches.
    for a in rules.deny_algorithm.iter().chain(&rules.require_executed) {
        if !crate::kinds::is_known_alg(a) {
            return Err(format!("unknown algorithm '{a}' (not in frozen registry)"));
        }
    }
    if rules.is_empty() {
        return Err("check needs at least one rule (a ruleness pass would mask a misconfigured gate)".to_string());
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
            image_digest,
        },
        target,
        format,
        out,
        rules,
    })
}

/// One violation as JSON: per-violation identity plus the
/// capture-level actionability tuple (PRD §6).
fn violation_json(c: &capture::Capture, x: &Violation) -> serde_json::Value {
    serde_json::json!({
        "rule": x.rule,
        "matcher": x.matcher,
        "provider_label": x.provider_label,
        "op": x.op,
        "op_name": x.op_name,
        "alg": x.alg,
        "funcid": x.funcid,
        "count": x.count,
        "first_ns": x.first_ns,
        "last_ns": x.last_ns,
        "fenced_gen": x.fenced_gen,
        "absent": x.absent,
        "window": {
            "start_epoch": crate::report::epoch_of(c.window_start_wall),
            "end_epoch": crate::report::epoch_of(c.window_end_wall),
        },
        "cmdline": c.target_cmdline,
        "container_id": c.target_container_id,
        "image_digest": c.image_digest,
        "provider": {"path": c.provider_path, "build_id": c.provider_build_id},
    })
}

/// The `policy` document section (CI-parseable verdict).
pub(crate) fn policy_json(c: &capture::Capture, v: &Verdict) -> serde_json::Value {
    let verdict = if v.no_verdict {
        "no-verdict"
    } else if v.violations.is_empty() {
        "pass"
    } else {
        "violation"
    };
    serde_json::json!({
        "verdict": verdict,
        "rules": v.results.iter().map(|r| serde_json::json!({
            "rule": r.rule,
            "value": r.value,
            "result": if r.passed { "pass" } else { "violation" },
            "matches": r.matches,
        })).collect::<Vec<_>>(),
        "violations": v.violations.iter().map(|x| violation_json(c, x)).collect::<Vec<_>>(),
        "unseen_deny_providers": v.unseen_deny_providers,
        "param_blind": v.param_blind,
        "kat_excluded": 0,
        "kat_note": "v1 executions are unlabeled (no KAT discriminator); exclusion vacuous — see fips-unlabeled",
    })
}

/// Report document plus the `policy` section.
pub(crate) fn doc_with_policy(c: &capture::Capture, v: &Verdict) -> serde_json::Value {
    let mut d = crate::report::doc(c);
    d["policy"] = policy_json(c, v);
    d
}

/// Human tuple: window edges, cmdline, container/image, provider.
fn tuple_human(c: &capture::Capture) -> String {
    let cmdline = if c.target_cmdline.is_empty() {
        "(unknown)".to_string()
    } else {
        format!("\"{}\"", c.target_cmdline)
    };
    let opt = |s: &str| {
        if s.is_empty() {
            "(none)".to_string()
        } else {
            s.to_string()
        }
    };
    format!(
        "window={} - {} cmdline={} container={} image={} provider={} build={}",
        crate::report::iso8601_utc(crate::report::epoch_secs(c.window_start_wall)),
        crate::report::iso8601_utc(crate::report::epoch_secs(c.window_end_wall)),
        cmdline,
        opt(&c.target_container_id),
        opt(&c.image_digest),
        c.provider_path,
        c.provider_build_id,
    )
}

/// Verdict-first human output: violations, then passes, then the
/// evidence line plus doctrine notes.
fn human(c: &capture::Capture, v: &Verdict) -> String {
    use crate::report::grouped;
    let mut s = String::new();
    let nv = v.results.iter().filter(|r| !r.passed).count();
    let np = v.results.iter().filter(|r| r.passed).count();
    if v.no_verdict {
        s.push_str(&format!(
            "osslscope check: NO VERDICT (FATAL evidence; run doctor) pid={} ({})\n",
            c.target_pid, c.target_comm
        ));
    } else if v.violations.is_empty() {
        s.push_str(&format!(
            "osslscope check: PASS ({np} passed) pid={} ({})\n",
            c.target_pid, c.target_comm
        ));
    } else {
        s.push_str(&format!(
            "osslscope check: VIOLATION ({nv} rules violated, {np} passed) pid={} ({})\n",
            c.target_pid, c.target_comm
        ));
    }
    if !v.no_verdict {
        let tup = tuple_human(c);
        for x in &v.violations {
            if x.absent {
                s.push_str(&format!(
                    "  [{} {}] not observed in window {tup}\n",
                    x.rule, x.matcher
                ));
            } else if x.rule == "deny-engine" {
                s.push_str(&format!(
                    "  [{} {}] ENGINE call: {} calls (tripwire, untimed) {tup}\n",
                    x.rule,
                    x.matcher,
                    grouped(x.count)
                ));
            } else {
                let fenced = x
                    .fenced_gen
                    .map(|g| format!(", fenced gen {g}"))
                    .unwrap_or_default();
                s.push_str(&format!(
                    "  [{} {}] {} via {}: {} calls ({} funcid={}{fenced}) {tup}\n",
                    x.rule,
                    x.matcher,
                    x.alg,
                    x.provider_label,
                    grouped(x.count),
                    x.op_name,
                    x.funcid
                ));
            }
        }
        for r in v.results.iter().filter(|r| r.passed) {
            if r.value.is_empty() {
                s.push_str(&format!("  [{}] pass ({} calls)\n", r.rule, grouped(r.matches)));
            } else {
                s.push_str(&format!(
                    "  [{} {}] pass ({} calls)\n",
                    r.rule,
                    r.value,
                    grouped(r.matches)
                ));
            }
        }
    }
    s.push_str(&format!("evidence: {}\n", crate::report::status_line(c)));
    s.push_str("absence = not-observed in window (never \"not present / never used\")\n");
    if v.param_blind {
        s.push_str("note: --deny-algorithm is blind to SIGN/MAC/KDF digest selection (param values never captured)\n");
    }
    if !v.unseen_deny_providers.is_empty() {
        s.push_str(&format!(
            "note: --deny-provider matched nothing (verify spelling): {}\n",
            v.unseen_deny_providers.join(", ")
        ));
    }
    if c.reasons.iter().any(|r| r == "fips-unlabeled") {
        s.push_str("note: FIPS executions unlabeled in v1 (self-test calls not distinguished)\n");
    }
    s.push_str("note: alg-name-only strength (key sizes unobservable); window-only claims\n");
    s
}

pub fn run(argv: &[String]) -> ExitCode {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("osslscope check: {e}");
            eprintln!("usage: check [--duration S] --provider P --object O --count-object C [rules] [--format human|json] [--out F] [--builtin] [--settle S] [--timeout S] [--grace S] [--image-digest D] {{--pid P | run -- <cmd>}}");
            eprintln!("rules: [--require-provider P] [--deny-provider P] [--deny-engine] [--deny-algorithm X] [--deny-weak] [--require-executed X] (repeatable; at least one required)");
            return ExitCode::from(2);
        }
    };
    let c = match capture::run(&args.cfg, args.target) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("osslscope check: {e:#}");
            return ExitCode::from(4);
        }
    };
    let v = evaluate(&c, &args.rules);
    let text = if args.format == "json" {
        serde_json::to_string_pretty(&doc_with_policy(&c, &v)).unwrap() + "\n"
    } else {
        human(&c, &v)
    };
    if let Some(path) = &args.out {
        if let Err(e) = std::fs::write(path, &text) {
            eprintln!("osslscope check: write {path}: {e}");
            return ExitCode::from(4);
        }
    } else {
        print!("{text}");
    }
    ExitCode::from(exit_for(&c, &v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(outcome: capture::Outcome) -> capture::Capture {
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
            child_exit: None,
            drain_wall_us: 0,
            harvest_doc: serde_json::json!({}),
            legacy: serde_json::Value::Null,
            window_start_wall: std::time::UNIX_EPOCH,
            window_end_wall: std::time::UNIX_EPOCH,
            kernel_release: "k".to_string(),
            target_cmdline: "t".to_string(),
            target_container_id: String::new(),
            provider_build_id: "unknown".to_string(),
            provider_path: "/p".to_string(),
            image_digest: String::new(),
        }
    }

    fn exec(op: u32, provider: &str, alg: &str, funcid: u32, count: u64) -> capture::Execution {
        capture::Execution {
            cookie: 0,
            id: crate::plan::Identity {
                provider: provider.to_string(),
                op,
                funcid,
                alg_class: alg.to_string(),
                offset: 0,
            },
            aliases: Vec::new(),
            count,
            first_ns: 100,
            last_ns: 200,
        }
    }

    fn rules() -> RuleSet {
        RuleSet::default()
    }

    #[test]
    fn deny_algorithm_hit_and_miss() {
        let mut c = cap(capture::Outcome::Complete);
        c.executions = vec![exec(1, "default", "DES", 11, 500)];
        let mut r = rules();
        r.deny_algorithm = vec!["DES".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        let x = &v.violations[0];
        assert_eq!(x.rule, "deny-algorithm");
        assert_eq!(x.matcher, "DES");
        assert_eq!(x.provider_label, "default");
        assert_eq!((x.op, x.funcid, x.count), (1, 11, 500));
        assert_eq!(x.op_name, "DIGEST");
        assert_eq!((x.first_ns, x.last_ns), (Some(100), Some(200)));
        assert_eq!(x.fenced_gen, None);
        assert!(!x.absent);
        assert!(v.results.iter().all(|t| !t.passed));
        // Miss: satisfied, no violation.
        r.deny_algorithm = vec!["RC2".to_string()];
        let v = evaluate(&c, &r);
        assert!(v.violations.is_empty());
        assert!(v.results.iter().all(|t| t.passed));
        assert!(v.param_blind, "deny-algorithm always carries the caveat");
    }

    #[test]
    fn deny_matches_fenced_detail() {
        let mut c = cap(capture::Outcome::Complete);
        c.stale = vec![capture::StaleBucket {
            generation: 3,
            events: 9,
            keys: 1,
            detail: vec![capture::StaleDetail {
                cookie: 0,
                id: crate::plan::Identity {
                    provider: "spike".to_string(),
                    op: 2,
                    funcid: 21,
                    alg_class: "RC2".to_string(),
                    offset: 0,
                },
                count: 9,
                first_ns: 1,
                last_ns: 2,
            }],
        }];
        let mut r = rules();
        r.deny_algorithm = vec!["RC2".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert_eq!(v.violations[0].fenced_gen, Some(3));
    }

    #[test]
    fn require_executed_fail_closed() {
        let mut c = cap(capture::Outcome::Complete);
        c.executions = vec![exec(1, "default", "SHA-256", 11, 5)];
        let mut r = rules();
        r.require_executed = vec!["SHA-256".to_string()];
        assert!(evaluate(&c, &r).violations.is_empty());
        // Absent on COMPLETE: violation with no identity.
        r.require_executed = vec!["MD5".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert!(v.violations[0].absent);
        assert_eq!(v.violations[0].matcher, "MD5");
        // Absent on PARTIAL: still a violation (fail closed —
        // degraded evidence must not silently pass a require).
        c.outcome = capture::Outcome::Partial;
        c.reasons = vec!["cold-gap".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert!(v.violations[0].absent);
    }

    #[test]
    fn provider_rules() {
        let mut c = cap(capture::Outcome::Complete);
        c.executions = vec![exec(1, "spike", "SHA-256", 11, 5)];
        let mut r = rules();
        r.require_provider = vec!["spike".to_string()];
        assert!(evaluate(&c, &r).violations.is_empty());
        r.require_provider = vec!["fips".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert!(v.violations[0].absent);
        // Deny hit: one record per matched identity.
        r = rules();
        r.deny_provider = vec!["spike".to_string()];
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert_eq!(v.violations[0].provider_label, "spike");
        // Deny unseen: satisfied, but noted (typo visibility).
        r.deny_provider = vec!["fips".to_string()];
        let v = evaluate(&c, &r);
        assert!(v.violations.is_empty());
        assert_eq!(v.unseen_deny_providers, vec!["fips".to_string()]);
    }

    #[test]
    fn deny_weak_and_engine() {
        let mut c = cap(capture::Outcome::Complete);
        c.executions = vec![
            exec(1, "default", "SHA-256", 11, 5),
            exec(2, "default", "DES", 21, 7),
        ];
        let mut r = rules();
        r.deny_weak = true;
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        assert_eq!(v.violations[0].matcher, "DES");
        // Engine: tripwire counts only (untimed violation).
        c.legacy = serde_json::json!({
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 2}},
        });
        r = rules();
        r.deny_engine = true;
        let v = evaluate(&c, &r);
        assert_eq!(v.violations.len(), 1);
        let x = &v.violations[0];
        assert_eq!((x.rule.as_str(), x.matcher.as_str()), ("deny-engine", "ENGINE_init"));
        assert_eq!(x.op_name, "ENGINE");
        assert_eq!(x.count, 2);
        assert_eq!((x.first_ns, x.last_ns), (None, None));
        // Quiet engine: pass (zero calls and null legacy alike).
        c.legacy = serde_json::json!({"engine": {"calls_by_entrypoint": {}}});
        assert!(evaluate(&c, &r).violations.is_empty());
        c.legacy = serde_json::Value::Null;
        assert!(evaluate(&c, &r).violations.is_empty());
    }

    #[test]
    fn parse_rules_matrix() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--provider", "p", "--object", "o", "--count-object", "c", "--pid", "9",
        ];
        // Full ruleset, repeatable flags accumulate.
        let mut full = base.clone();
        full.extend([
            "--require-provider", "default", "--deny-provider", "fips",
            "--deny-provider", "acme", "--deny-engine", "--deny-algorithm", "DES",
            "--deny-algorithm", "RC2", "--deny-weak", "--require-executed", "SHA-256",
        ]);
        let a = parse(&v(full)).unwrap();
        assert_eq!(a.rules.require_provider, vec!["default".to_string()]);
        assert_eq!(a.rules.deny_provider, vec!["fips".to_string(), "acme".to_string()]);
        assert!(a.rules.deny_engine);
        assert_eq!(a.rules.deny_algorithm, vec!["DES".to_string(), "RC2".to_string()]);
        assert!(a.rules.deny_weak);
        assert_eq!(a.rules.require_executed, vec!["SHA-256".to_string()]);
        assert_eq!(a.cfg.duration, Duration::from_secs(30));
        // Unknown registry names are config errors (typo-safe).
        let mut typo = base.clone();
        typo.extend(["--deny-algorithm", "AES-256-GCMX"]);
        assert!(parse(&v(typo)).is_err());
        let mut typo2 = base.clone();
        typo2.extend(["--require-executed", "SHA257"]);
        assert!(parse(&v(typo2)).is_err());
        // Ruleness checks are rejected (a pass with no rules would
        // mask a misconfigured gate).
        assert!(parse(&v(base.clone())).is_err());
        // Same target discipline as report.
        let mut norun = base.clone();
        norun.extend(["--deny-weak"]);
        assert!(parse(&v(norun)).is_ok());
        let mut neither: Vec<&str> = vec!["--deny-weak"];
        assert!(parse(&v(neither.clone())).is_err());
        neither.extend(["run", "--", "x"]);
        assert!(parse(&v(neither)).is_err(), "objects still required");
    }

    fn viol_cap() -> capture::Capture {
        let mut c = cap(capture::Outcome::Partial);
        c.reasons = vec!["cold-gap".to_string()];
        c.counters.cold_gap_calls = 5;
        c.executions = vec![exec(2, "default", "DES", 21, 500)];
        c
    }

    #[test]
    fn human_violation_shape() {
        let c = viol_cap();
        let mut r = rules();
        r.deny_algorithm = vec!["DES".to_string()];
        r.require_executed = vec!["SHA-256".to_string()];
        let v = evaluate(&c, &r);
        let w = "1970-01-01T00:00:00Z - 1970-01-01T00:00:00Z";
        let tup = "window=".to_string() + w + " cmdline=\"t\" container=(none) image=(none) provider=/p build=unknown";
        let want = format!("osslscope check: VIOLATION (2 rules violated, 0 passed) pid=7 (t)\n  [deny-algorithm DES] DES via default: 500 calls (CIPHER funcid=21) {tup}\n  [require-executed SHA-256] not observed in window {tup}\nevidence: status=PARTIAL reasons=cold-gap counters[cold_gap=5]\nabsence = not-observed in window (never \"not present / never used\")\nnote: --deny-algorithm is blind to SIGN/MAC/KDF digest selection (param values never captured)\nnote: alg-name-only strength (key sizes unobservable); window-only claims\n");
        assert_eq!(human(&c, &v), want);
    }

    #[test]
    fn human_pass_and_mixed_order() {
        // All pass.
        let mut c = cap(capture::Outcome::Complete);
        c.executions = vec![exec(1, "default", "SHA-256", 11, 5)];
        let mut r = rules();
        r.require_executed = vec!["SHA-256".to_string()];
        r.deny_weak = true;
        let v = evaluate(&c, &r);
        let out = human(&c, &v);
        assert!(out.starts_with("osslscope check: PASS (2 passed) pid=7 (t)\n"), "{out}");
        assert!(out.contains("  [deny-weak] pass (0 calls)\n"), "{out}");
        assert!(out.contains("  [require-executed SHA-256] pass (5 calls)\n"), "{out}");
        assert!(out.contains("evidence: status=COMPLETE\n"), "{out}");
        // Mixed: violations first, then passes (rule order within).
        let mut r = rules();
        r.deny_algorithm = vec!["RC2".to_string()];
        r.deny_weak = true;
        c.executions.push(exec(2, "default", "DES", 21, 7));
        let v = evaluate(&c, &r);
        let out = human(&c, &v);
        let vv = out.find("[deny-weak DES]").expect("violation line");
        let pp = out.find("[deny-algorithm RC2] pass").expect("pass line");
        assert!(vv < pp, "violations before passes:\n{out}");
    }

    #[test]
    fn human_no_verdict_and_unseen() {
        let mut c = cap(capture::Outcome::Fatal(capture::FatalKind::AttachZero));
        c.reasons = vec!["pid-recycled".to_string()];
        let mut r = rules();
        r.deny_weak = true;
        let v = evaluate(&c, &r);
        let out = human(&c, &v);
        assert!(out.starts_with("osslscope check: NO VERDICT (FATAL evidence; run doctor) pid=7 (t)\n"), "{out}");
        // Unseen deny-provider note.
        let c = cap(capture::Outcome::Complete);
        let mut r = rules();
        r.deny_provider = vec!["fips".to_string()];
        let v = evaluate(&c, &r);
        let out = human(&c, &v);
        assert!(out.contains("note: --deny-provider matched nothing (verify spelling): fips\n"), "{out}");
    }

    #[test]
    fn policy_json_shape() {
        let c = viol_cap();
        let mut r = rules();
        r.deny_algorithm = vec!["DES".to_string()];
        r.deny_provider = vec!["fips".to_string()];
        let v = evaluate(&c, &r);
        let p = policy_json(&c, &v);
        assert_eq!(p["verdict"], "violation");
        assert_eq!(p["rules"].as_array().unwrap().len(), 2);
        assert_eq!(p["param_blind"], true);
        assert_eq!(p["kat_excluded"], 0);
        assert!(p["kat_note"].as_str().unwrap().contains("v1"));
        assert_eq!(p["unseen_deny_providers"], serde_json::json!(["fips"]));
        let x = &p["violations"].as_array().unwrap()[0];
        assert_eq!(x["rule"], "deny-algorithm");
        assert_eq!(x["matcher"], "DES");
        assert_eq!(x["provider_label"], "default");
        assert_eq!(x["op_name"], "CIPHER");
        assert_eq!(x["count"], 500);
        assert_eq!(x["first_ns"], 100);
        assert_eq!(x["absent"], false);
        assert!(x["fenced_gen"].is_null());
        // Actionability tuple (PRD §6).
        assert_eq!(x["window"]["start_epoch"], 0.0);
        assert_eq!(x["cmdline"], "t");
        assert_eq!(x["container_id"], "");
        assert_eq!(x["image_digest"], "");
        assert_eq!(x["provider"]["path"], "/p");
        assert_eq!(x["provider"]["build_id"], "unknown");
        // Pass + no-verdict verdicts.
        let c2 = cap(capture::Outcome::Complete);
        let mut r2 = rules();
        r2.deny_weak = true;
        assert_eq!(policy_json(&c2, &evaluate(&c2, &r2))["verdict"], "pass");
        let c3 = cap(capture::Outcome::Fatal(capture::FatalKind::AttachZero));
        assert_eq!(policy_json(&c3, &evaluate(&c3, &r2))["verdict"], "no-verdict");
    }

    #[test]
    fn doc_carries_policy() {
        let c = cap(capture::Outcome::Complete);
        let mut r = rules();
        r.deny_weak = true;
        let d = doc_with_policy(&c, &evaluate(&c, &r));
        assert_eq!(d["schema_version"], "observed-crypto-v1.0");
        assert_eq!(d["policy"]["verdict"], "pass");
        assert_eq!(d["policy"]["rules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn exit_matrix() {
        let viol = || Verdict {
            no_verdict: false,
            violations: vec![Violation {
                rule: "deny-weak".to_string(),
                matcher: "DES".to_string(),
                provider_label: "default".to_string(),
                op: 2,
                op_name: "CIPHER".to_string(),
                alg: "DES".to_string(),
                funcid: 21,
                count: 1,
                first_ns: Some(0),
                last_ns: Some(0),
                fenced_gen: None,
                absent: false,
            }],
            results: Vec::new(),
            unseen_deny_providers: Vec::new(),
            param_blind: false,
        };
        let clean = || Verdict {
            no_verdict: false,
            violations: Vec::new(),
            results: Vec::new(),
            unseen_deny_providers: Vec::new(),
            param_blind: false,
        };
        // Violation dominates everything (even child failure).
        let mut c = cap(capture::Outcome::Partial);
        c.child_exit = Some(1);
        assert_eq!(exit_for(&c, &viol()), 10);
        let c = cap(capture::Outcome::Complete);
        assert_eq!(exit_for(&c, &viol()), 10);
        // No violation: child failure, then evidence status.
        let mut c = cap(capture::Outcome::Complete);
        c.child_exit = Some(2);
        assert_eq!(exit_for(&c, &clean()), 1);
        let c = cap(capture::Outcome::Fatal(capture::FatalKind::AttachZero));
        assert_eq!(exit_for(&c, &clean()), 4);
        let c = cap(capture::Outcome::Partial);
        assert_eq!(exit_for(&c, &clean()), 3);
        let c = cap(capture::Outcome::Complete);
        assert_eq!(exit_for(&c, &clean()), 0);
    }

    #[test]
    fn fatal_has_no_verdict() {
        let c = cap(capture::Outcome::Fatal(capture::FatalKind::AttachZero));
        let mut r = rules();
        r.require_executed = vec!["SHA-256".to_string()];
        r.deny_weak = true;
        let v = evaluate(&c, &r);
        assert!(v.no_verdict);
        assert!(v.violations.is_empty(), "never a violation without evidence");
        assert!(v.results.is_empty());
    }
}
