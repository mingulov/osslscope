//! SPDX-License-Identifier: GPL-3.0-or-later
//! T10 `check`: R06 policy gate over the finalized v2 evidence document.
//!
//! `check [capture flags] [rules] [--cbom FILE] {--pid P | run -- <cmd>}`
//! Rules (AND semantics, repeatable): `--require-provider P`,
//! `--deny-provider P`, `--deny-engine`, `--deny-algorithm X`,
//! `--deny-weak`, `--require-executed X`.
//!
//! Match domain is EXECUTED evidence (current + fenced sites) from
//! `capture.document`: queried-but-unexecuted shape and query/load
//! counters are reported, never policy-evaluated. Predicates match by
//! pinned provider class and classified algorithm (spec R06):
//! `--require-provider` stays existential, registry typos stay usage
//! errors, and possible use is inconclusive — never a definite
//! violation. Exit 11 carries `policy.verdict = inconclusive` (CI fails
//! closed); a proved violation stays exit 10 even when an artifact path
//! is unwritable or the child failed.
use crate::capture;
use crate::evidence::{CaptureDocument, Completeness, GapReason, RuleVerdict};
use crate::policy::{
    DefiniteHit, PolicyOutcome, PolicyRule, PolicyVerdict, apply_legacy_engine_fallback,
    evaluate_document, executed_param_blind_ops, fips_unlabeled_calls,
};
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

/// Map CLI rules to typed policy rules through the single
/// [`PolicyRule`] constructors (evaluation order below).
fn policy_rules(rules: &RuleSet) -> Vec<PolicyRule> {
    let mut out = Vec::new();
    for p in &rules.require_provider {
        out.push(PolicyRule::require_provider(p));
    }
    for p in &rules.deny_provider {
        out.push(PolicyRule::deny_provider(p));
    }
    if rules.deny_engine {
        out.push(PolicyRule::deny_engine());
    }
    for a in &rules.deny_algorithm {
        out.push(PolicyRule::deny_algorithm(a));
    }
    if rules.deny_weak {
        out.push(PolicyRule::deny_weak());
    }
    for x in &rules.require_executed {
        out.push(PolicyRule::require_executed(x));
    }
    out
}

struct Args {
    cfg: capture::Config,
    target: capture::Target,
    format: String,
    out: Option<String>,
    cbom: Option<String>,
    rules: RuleSet,
}

/// Exit for a checked capture (pure — unit-tested). R06 precedence,
/// after attempting requested artifacts: fatal is 4, a proved
/// violation is 10 (even with child/artifact failure), otherwise a
/// failed child or failed required artifact is 1, an unproven rule is
/// 11, a signal-cut or PARTIAL window with a passing verdict is 3,
/// else 0. Usage errors (2) never reach this function.
pub fn exit_for(
    outcome: PolicyOutcome,
    child_exit: Option<i32>,
    doc: &CaptureDocument,
    delivery: &DeliveryResult,
) -> u8 {
    if outcome == PolicyOutcome::NoVerdict {
        return 4;
    }
    if outcome == PolicyOutcome::Violation {
        return 10;
    }
    if matches!(child_exit, Some(code) if code != 0) {
        return 1;
    }
    if delivery.failed() {
        return 1;
    }
    if outcome == PolicyOutcome::Inconclusive {
        return 11;
    }
    match &doc.status {
        Completeness::Complete => 0,
        Completeness::Partial { .. } | Completeness::Fatal { .. } => 3,
    }
}

// Capture-flag parsing intentionally mirrors report::parse: the two
// flag sets share capture/cbom flags but diverge on rules vs report
// options, and a shared strict parser costs more than it saves.
fn parse(argv: &[String]) -> Result<Args, String> {
    // T04 (coordinator review): time flags are captured raw and validated
    // once via args::parse_seconds below (R08 bounds, no panics).
    let mut duration_raw: Option<String> = None;
    let mut format = "human".to_string();
    let mut out: Option<String> = None;
    let mut cbom: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut builtin = false;
    let mut object: Option<String> = None;
    let mut count_object: Option<String> = None;
    let mut settle_raw: Option<String> = None;
    let mut timeout_raw: Option<String> = None;
    let mut grace_raw: Option<String> = None;
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
            "--duration" => duration_raw = Some(val(a)?),
            "--format" => format = val(a)?,
            "--out" => out = Some(val(a)?),
            "--cbom" => cbom = Some(val(a)?),
            "--provider" => provider = Some(val(a)?),
            "--builtin" => {
                builtin = true;
                i += 1;
                continue;
            }
            "--object" => object = Some(val(a)?),
            "--count-object" => count_object = Some(val(a)?),
            "--settle" => settle_raw = Some(val(a)?),
            "--timeout" => timeout_raw = Some(val(a)?),
            "--grace" => grace_raw = Some(val(a)?),
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
    // T04 (coordinator review): single conversion point shared with
    // report (R08 bounds; rejects 1e30/NaN/inf/negatives/zero-rounding
    // before any target/BPF side effect). Defaults are exact.
    let duration = match &duration_raw {
        Some(s) => crate::args::parse_seconds("--duration", s)?,
        None => Duration::from_secs_f64(crate::report::DEFAULT_DURATION_SECS),
    };
    let settle = match &settle_raw {
        Some(s) => crate::args::parse_seconds("--settle", s)?,
        None => Duration::from_secs(2),
    };
    let timeout = match &timeout_raw {
        Some(s) => crate::args::parse_seconds("--timeout", s)?,
        None => Duration::from_secs(60),
    };
    let grace = match &grace_raw {
        Some(s) => crate::args::parse_seconds("--grace", s)?,
        None => Duration::from_secs(5),
    };
    // Algorithm names are exact frozen-registry matches: unknown
    // names are config errors, never silent non-matches. Provider
    // classes stay unvalidated: third-party opaque ids are open-ended,
    // so no finite registry can enumerate them.
    for a in rules.deny_algorithm.iter().chain(&rules.require_executed) {
        if !crate::kinds::is_known_alg(a) {
            return Err(format!("unknown algorithm '{a}' (not in frozen registry)"));
        }
    }
    if rules.is_empty() {
        return Err(
            "check needs at least one rule (a ruleness pass would mask a misconfigured gate)"
                .to_string(),
        );
    }
    Ok(Args {
        cfg: capture::Config {
            harvest_object: object.ok_or("--object O is required")?.into(),
            count_object: count_object.ok_or("--count-object C is required")?.into(),
            provider: provider.ok_or("--provider P is required")?.into(),
            builtin,
            duration,
            settle,
            harvest_timeout: timeout,
            grace,
            image_digest,
        },
        target,
        format,
        out,
        cbom,
        rules,
    })
}

/// Deny-provider matchers proved absent (definite 0, possible exactly
/// 0): typo visibility. Ambiguous matchers might be present and are not
/// listed here.
fn unseen_deny_providers(v: &PolicyVerdict) -> Vec<&str> {
    v.rules
        .iter()
        .filter(|r| {
            r.name == "deny-provider" && r.bounds.definite == 0 && r.bounds.possible == Some(0)
        })
        .map(|r| r.matcher.as_str())
        .collect()
}

/// The parameter caveat fires only when algorithm rules meet executed
/// parameter-blind operations — the ambiguity that actually shaped a
/// bound, not a blanket flag.
fn param_blind(doc: &CaptureDocument, v: &PolicyVerdict) -> bool {
    v.rules
        .iter()
        .any(|r| matches!(r.name, "deny-algorithm" | "require-executed"))
        && executed_param_blind_ops(doc)
}

/// Legacy ENGINE tripwire calls from the pre-T08 `legacy` block
/// (v1 shape; T08 retires it once ENGINE executions surface as
/// document sites). Sums positive per-entrypoint counts; a missing or
/// misshapen block contributes nothing.
pub(crate) fn legacy_engine_calls(legacy: &serde_json::Value) -> u64 {
    legacy
        .pointer("/engine/calls_by_entrypoint")
        .and_then(|m| m.as_object())
        .map(|m| m.values().map(|n| n.as_u64().unwrap_or(0)).sum())
        .unwrap_or(0)
}

/// The `policy` document section (CI-parseable verdict). T10-owned:
/// T11's real artifact renderer reuses this section verbatim.
pub fn policy_json(doc: &CaptureDocument, v: &PolicyVerdict) -> serde_json::Value {
    let verdict = match v.overall() {
        PolicyOutcome::NoVerdict => "no-verdict",
        PolicyOutcome::Pass => "pass",
        PolicyOutcome::Violation => "violation",
        PolicyOutcome::Inconclusive => "inconclusive",
    };
    let mut violations: Vec<serde_json::Value> = Vec::new();
    for r in v
        .rules
        .iter()
        .filter(|r| r.verdict == RuleVerdict::Violation)
    {
        if matches!(r.name, "require-provider" | "require-executed") {
            violations.push(serde_json::json!({
                "rule": r.name,
                "matcher": r.matcher,
                "absent": true,
                "definite": r.bounds.definite,
                "possible": r.bounds.possible,
            }));
            continue;
        }
        debug_assert!(
            !r.hits.is_empty() || r.legacy_engine_calls > 0,
            "deny violations always carry definite hits or legacy tripwire evidence"
        );
        for h in &r.hits {
            violations.push(serde_json::json!({
                "rule": r.name,
                "matcher": r.matcher,
                "absent": false,
                "site": h.site,
                "generation": h.generation,
                "fenced": h.fenced,
                "calls": h.calls,
                "first_ns": h.first_ns,
                "last_ns": h.last_ns,
                "candidates": h.candidates,
            }));
        }
        if r.hits.is_empty() && r.legacy_engine_calls > 0 {
            violations.push(serde_json::json!({
                "rule": r.name,
                "matcher": r.matcher,
                "absent": false,
                "legacy": true,
                "timed": false,
                "calls": r.legacy_engine_calls,
            }));
        }
    }
    serde_json::json!({
        "verdict": verdict,
        "rules": v.rules.iter().map(|r| serde_json::json!({
            "rule": r.name,
            "value": r.matcher,
            "result": match r.verdict {
                RuleVerdict::Pass => "pass",
                RuleVerdict::Violation => "violation",
                RuleVerdict::Inconclusive => "inconclusive",
            },
            "definite": r.bounds.definite,
            "possible": r.bounds.possible,
            "relevant_complete": r.relevant_complete,
        })).collect::<Vec<_>>(),
        "violations": violations,
        "unseen_deny_providers": unseen_deny_providers(v),
        "param_blind": param_blind(doc, v),
        "kat_excluded": 0,
        "kat_note": "executions are unlabeled (no KAT discriminator); exclusion vacuous — see fips_unlabeled_executions",
        "fips_unlabeled_executions": fips_unlabeled_calls(doc),
    })
}

fn reason_short(r: &GapReason) -> String {
    match r {
        GapReason::UnknownDenominator { scope } => format!("unknown-denominator({scope})"),
        GapReason::UndiscoveredSites { scope, missing } => {
            format!("undiscovered({scope}):{missing}")
        }
        GapReason::UnattachedSites { scope, missing } => {
            format!("unattached({scope}):{missing}")
        }
        GapReason::Loss { counter, value, .. } => format!("{counter}={value}"),
        GapReason::UnattributedCalls { sites, calls } => {
            format!("unattributed={sites}s/{calls}c")
        }
        GapReason::StartupGap { missing_ns } => format!("startup-gap={missing_ns}ns"),
        GapReason::TailGap { missing_ns } => format!("tail-gap={missing_ns}ns"),
        GapReason::SignalCut => "signal-cut".to_string(),
    }
}

fn status_line(doc: &CaptureDocument) -> String {
    let status = match &doc.status {
        Completeness::Complete => "COMPLETE".to_string(),
        Completeness::Partial { reasons } => format!(
            "PARTIAL reasons={}",
            reasons
                .iter()
                .map(reason_short)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Completeness::Fatal { kind, .. } => format!("FATAL kind={kind:?}"),
    };
    format!(
        "status={status} window={}-{} effective={}-{}",
        doc.window.requested_start_ns,
        doc.window.requested_end_ns,
        doc.window.effective_start_ns,
        doc.window.effective_end_ns,
    )
}

fn short_obj(id: &str) -> String {
    if id.len() > 16 {
        format!("{}...", &id[..16])
    } else {
        id.to_string()
    }
}

fn hit_line(h: &DefiniteHit) -> String {
    let mut provs: Vec<&str> = h
        .candidates
        .iter()
        .map(|c| c.provider_class.as_str())
        .collect();
    provs.sort();
    provs.dedup();
    let mut algs: Vec<&str> = h
        .candidates
        .iter()
        .flat_map(|c| c.algorithm_classes.iter().map(String::as_str))
        .collect();
    algs.sort();
    algs.dedup();
    let alg_display = if algs.is_empty() {
        "(no classes)".to_string()
    } else {
        algs.join(":")
    };
    let first = &h.candidates[0];
    format!(
        "{} via {}: {} calls (obj={} gen={}{}, {} funcid={})",
        alg_display,
        provs.join(","),
        crate::report::grouped(h.calls),
        short_obj(&h.site.object.0),
        h.generation,
        if h.fenced { ", fenced" } else { "" },
        crate::report::op_display(first.op),
        first.funcid,
    )
}

fn tag(name: &str, matcher: &str) -> String {
    if matcher.is_empty() {
        format!("[{name}]")
    } else {
        format!("[{name} {matcher}]")
    }
}

/// Verdict-first human output: violations, then inconclusive rules,
/// then passes, then the evidence line plus doctrine notes.
fn human(doc: &CaptureDocument, v: &PolicyVerdict) -> String {
    let mut s = String::new();
    let nv = v
        .rules
        .iter()
        .filter(|r| r.verdict == RuleVerdict::Violation)
        .count();
    let ni = v
        .rules
        .iter()
        .filter(|r| r.verdict == RuleVerdict::Inconclusive)
        .count();
    let np = v
        .rules
        .iter()
        .filter(|r| r.verdict == RuleVerdict::Pass)
        .count();
    if v.no_verdict {
        s.push_str("osslscope check: NO VERDICT (FATAL evidence; run doctor)\n");
    } else if v.overall() == PolicyOutcome::Violation {
        s.push_str(&format!(
            "osslscope check: VIOLATION ({nv} rules violated, {ni} inconclusive, {np} passed)\n"
        ));
    } else if v.overall() == PolicyOutcome::Inconclusive {
        s.push_str(&format!(
            "osslscope check: INCONCLUSIVE ({ni} rules unproven, {np} passed)\n"
        ));
    } else {
        s.push_str(&format!("osslscope check: PASS ({np} passed)\n"));
    }
    if !v.no_verdict {
        for r in v
            .rules
            .iter()
            .filter(|r| r.verdict == RuleVerdict::Violation)
        {
            if matches!(r.name, "require-provider" | "require-executed") {
                s.push_str(&format!(
                    "  {} not observed in window\n",
                    tag(r.name, &r.matcher)
                ));
            } else {
                for h in &r.hits {
                    s.push_str(&format!("  {} {}\n", tag(r.name, &r.matcher), hit_line(h)));
                }
                if r.hits.is_empty() && r.legacy_engine_calls > 0 {
                    s.push_str(&format!(
                        "  {} ENGINE call: {} calls (tripwire, untimed)\n",
                        tag(r.name, &r.matcher),
                        crate::report::grouped(r.legacy_engine_calls)
                    ));
                }
            }
        }
        for r in v
            .rules
            .iter()
            .filter(|r| r.verdict == RuleVerdict::Inconclusive)
        {
            let poss = match r.bounds.possible {
                Some(n) => n.to_string(),
                None => "unknown".to_string(),
            };
            s.push_str(&format!(
                "  {} inconclusive (definite={} possible={})\n",
                tag(r.name, &r.matcher),
                r.bounds.definite,
                poss,
            ));
        }
        for r in v.rules.iter().filter(|r| r.verdict == RuleVerdict::Pass) {
            s.push_str(&format!(
                "  {} pass ({} calls)\n",
                tag(r.name, &r.matcher),
                crate::report::grouped(r.bounds.definite)
            ));
        }
    }
    s.push_str(&format!("evidence: {}\n", status_line(doc)));
    s.push_str("absence = not-observed in window (never \"not present / never used\")\n");
    if param_blind(doc, v) {
        s.push_str("note: algorithm rules are blind to SIGN/MAC/KDF/ASYM-CIPHER parameter-selected components (param values never captured)\n");
    }
    let unseen = unseen_deny_providers(v);
    if !unseen.is_empty() {
        s.push_str(&format!(
            "note: --deny-provider matched nothing (verify spelling): {}\n",
            unseen.join(", ")
        ));
    }
    let fips = fips_unlabeled_calls(doc);
    if fips > 0 {
        s.push_str(&format!(
            "note: {fips} FIPS-class calls unlabeled (self-test not distinguished; never excluded)\n"
        ));
    }
    s.push_str("note: alg-name-only strength (key sizes unobservable); window-only claims\n");
    s
}

// ------------------------------------------------- T11 checkpoint
// Specified T11 interface, NOT YET LANDED in this branch: `report.rs`
// will declare `OutputRequest`/`DeliveryResult` and
// `write_artifacts(&CaptureDocument, &OutputRequest) -> DeliveryResult`.
// This local mirror keeps T10 compiling and is DELETED at merge — the
// coordinator swaps these paths for `crate::report::` (drift notes in
// the T10 handoff). The mirror renders placeholder envelopes only; all
// real v2 human/JSON/CBOM transformations belong to T11.

/// Requested artifacts for one checked document: the primary
/// human/JSON rendering plus an optional CBOM, with the T10-evaluated
/// policy the renderers embed.
pub struct OutputRequest {
    pub format: String,
    pub out: Option<String>,
    pub cbom: Option<String>,
    pub policy: PolicyVerdict,
}

/// Per-artifact delivery outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactOutcome {
    NotRequested,
    Delivered,
    Failed(String),
}

/// Delivery result across all requested artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    pub primary: ArtifactOutcome,
    pub cbom: ArtifactOutcome,
}

impl DeliveryResult {
    /// True when any REQUESTED artifact failed.
    pub fn failed(&self) -> bool {
        matches!(self.primary, ArtifactOutcome::Failed(_))
            || matches!(self.cbom, ArtifactOutcome::Failed(_))
    }

    /// Bounded failure diagnostics for stderr.
    pub fn failures(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let ArtifactOutcome::Failed(e) = &self.primary {
            out.push(format!("primary artifact: {e}"));
        }
        if let ArtifactOutcome::Failed(e) = &self.cbom {
            out.push(format!("cbom artifact: {e}"));
        }
        out
    }
}

/// Placeholder primary JSON: the finalized document plus the T10
/// policy section. T11 replaces the envelope with the real v2 schema
/// rendering (and reuses [`policy_json`]).
fn render_primary_json(doc: &CaptureDocument, policy: &PolicyVerdict) -> String {
    let mut v = serde_json::to_value(doc).expect("capture document serializes");
    v["policy"] = policy_json(doc, policy);
    serde_json::to_string_pretty(&v).expect("json renders") + "\n"
}

/// Placeholder CBOM: an honest stub carrying the exact capture window
/// so same-window delivery is testable before T11 lands the CycloneDX
/// renderer. Never shipped as a real CBOM.
fn render_cbom_placeholder(doc: &CaptureDocument, policy: &PolicyVerdict) -> Vec<u8> {
    let verdict = match policy.overall() {
        PolicyOutcome::NoVerdict => "no-verdict",
        PolicyOutcome::Pass => "pass",
        PolicyOutcome::Violation => "violation",
        PolicyOutcome::Inconclusive => "inconclusive",
    };
    let v = serde_json::json!({
        "renderer": "t11-pending",
        "note": "placeholder CBOM envelope: same-window stub only, replaced by T11 CycloneDX",
        "schema": doc.schema,
        "window": doc.window,
        "policy_verdict": verdict,
    });
    (serde_json::to_string_pretty(&v).expect("json renders") + "\n").into_bytes()
}

fn write_file(path: &str, bytes: &[u8]) -> ArtifactOutcome {
    match std::fs::write(path, bytes) {
        Ok(()) => ArtifactOutcome::Delivered,
        Err(e) => ArtifactOutcome::Failed(format!("write {path}: {e}")),
    }
}

fn write_stdout(text: &str) -> ArtifactOutcome {
    use std::io::Write;
    let mut lock = std::io::stdout().lock();
    match lock.write_all(text.as_bytes()).and_then(|()| lock.flush()) {
        Ok(()) => ArtifactOutcome::Delivered,
        Err(e) => ArtifactOutcome::Failed(format!("stdout: {e}")),
    }
}

/// Attempt every requested artifact write — even when another fails —
/// and report per-artifact outcomes. Diagnostics never pretend a
/// failed delivery succeeded.
pub fn write_artifacts(doc: &CaptureDocument, req: &OutputRequest) -> DeliveryResult {
    let primary_text = if req.format == "json" {
        render_primary_json(doc, &req.policy)
    } else {
        human(doc, &req.policy)
    };
    let primary = match &req.out {
        None => write_stdout(&primary_text),
        Some(path) => write_file(path, primary_text.as_bytes()),
    };
    let cbom = match &req.cbom {
        None => ArtifactOutcome::NotRequested,
        Some(path) => write_file(path, &render_cbom_placeholder(doc, &req.policy)),
    };
    DeliveryResult { primary, cbom }
}

const USAGE: [&str; 2] = [
    "usage: check [--duration S] --provider P --object O --count-object C [rules] [--format human|json] [--out F] [--cbom FILE] [--builtin] [--settle S] [--timeout S] [--grace S] [--image-digest D] {--pid P | run -- <cmd>}",
    "rules: [--require-provider P] [--deny-provider P] [--deny-engine] [--deny-algorithm X] [--deny-weak] [--require-executed X] (repeatable; at least one required)",
];

pub fn run(argv: &[String]) -> ExitCode {
    // --help anywhere on the osslscope side (a target command after
    // run -- may legitimately contain --help).
    if argv
        .iter()
        .take_while(|a| a.as_str() != "run")
        .any(|a| a == "--help" || a == "-h")
    {
        for l in USAGE {
            println!("{l}");
        }
        return ExitCode::from(0);
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("osslscope check: {e}");
            for l in USAGE {
                eprintln!("{l}");
            }
            return ExitCode::from(2);
        }
    };
    let c = match capture::run(&args.cfg, args.target) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("osslscope check: {e:#}");
            eprintln!("osslscope check: run 'osslscope doctor' to diagnose environment failures");
            return ExitCode::from(4);
        }
    };
    let mut verdict = evaluate_document(&policy_rules(&args.rules), &c.document);
    // Pre-T08 transition: the legacy ENGINE tripwire counted real
    // in-window executions the document does not model yet; fold them
    // in so --deny-engine cannot miss them. No-op once T08 retires the
    // legacy block (or when the document already has the hits).
    apply_legacy_engine_fallback(&mut verdict, legacy_engine_calls(&c.legacy));
    let req = OutputRequest {
        format: args.format,
        out: args.out,
        cbom: args.cbom,
        policy: verdict.clone(),
    };
    let delivery = write_artifacts(&c.document, &req);
    for f in delivery.failures() {
        eprintln!("osslscope check: {f}");
    }
    ExitCode::from(exit_for(
        verdict.overall(),
        c.child_exit,
        &c.document,
        &delivery,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        CandidateCoverage, CandidateIdentity, CaptureWindow, CounterKind, CounterSource,
        CounterUnits, FinalizeInput, GapCounter, ObjectId, SiteExecution, SiteKey,
    };
    use crate::policy::{Predicate, Rule};

    fn cand(
        provider: &str,
        class: &str,
        op: u32,
        func: u32,
        algs: &[&str],
        weak: bool,
    ) -> CandidateIdentity {
        CandidateIdentity::new(
            ObjectId(provider.to_string()),
            class.to_string(),
            op,
            func,
            algs.iter().map(|s| s.to_string()).collect(),
            weak,
        )
    }

    fn site(offset: u64, calls: u64, cands: Vec<CandidateIdentity>) -> SiteExecution {
        SiteExecution {
            site: SiteKey {
                object: ObjectId("exe-fingerprint".to_string()),
                device: 7,
                inode: 9,
                offset,
            },
            generation: 0,
            candidates: cands,
            candidates_coverage: CandidateCoverage::Complete,
            calls,
            first_ns: 100,
            last_ns: 200,
        }
    }

    fn doc(sites: Vec<SiteExecution>) -> CaptureDocument {
        crate::evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: 1_000,
                requested_end_ns: 2_000,
                effective_start_ns: 1_000,
                effective_end_ns: 2_000,
                signal_cut: false,
            },
            sites,
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
        })
    }

    fn ruleset() -> RuleSet {
        RuleSet::default()
    }

    fn ok_delivery() -> DeliveryResult {
        DeliveryResult {
            primary: ArtifactOutcome::Delivered,
            cbom: ArtifactOutcome::NotRequested,
        }
    }

    #[test]
    fn rule_mapping_uses_typed_constructors() {
        let mut r = ruleset();
        r.require_provider = vec!["default".to_string()];
        r.deny_provider = vec!["fips".to_string()];
        r.deny_engine = true;
        r.deny_algorithm = vec!["DES".to_string()];
        r.deny_weak = true;
        r.require_executed = vec!["SHA2-256".to_string()];
        let mapped = policy_rules(&r);
        let names: Vec<(&str, &str)> = mapped
            .iter()
            .map(|m| (m.name, m.matcher.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("require-provider", "default"),
                ("deny-provider", "fips"),
                ("deny-engine", ""),
                ("deny-algorithm", "DES"),
                ("deny-weak", ""),
                ("require-executed", "SHA2-256"),
            ]
        );
        assert!(matches!(
            mapped[2].rule,
            Rule::Deny(Predicate::ProviderClass(_))
        ));
        assert!(matches!(
            mapped[3].rule,
            Rule::Deny(Predicate::AlgorithmParamAware(_))
        ));
        assert!(matches!(
            mapped[4].rule,
            Rule::Deny(Predicate::WeakOrUnresolved)
        ));
        assert!(matches!(
            mapped[5].rule,
            Rule::Require(Predicate::AlgorithmParamAware(_))
        ));
    }

    #[test]
    fn parse_rules_matrix() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        // Full ruleset, repeatable flags accumulate; --cbom rides along.
        let mut full = base.clone();
        full.extend([
            "--require-provider",
            "default",
            "--deny-provider",
            "fips",
            "--deny-provider",
            "acme",
            "--deny-engine",
            "--deny-algorithm",
            "DES",
            "--deny-algorithm",
            "RC2",
            "--deny-weak",
            "--require-executed",
            "SHA2-256",
            "--format",
            "json",
            "--out",
            "r.json",
            "--cbom",
            "b.json",
        ]);
        let a = parse(&v(full)).unwrap();
        assert_eq!(a.rules.require_provider, vec!["default".to_string()]);
        assert_eq!(
            a.rules.deny_provider,
            vec!["fips".to_string(), "acme".to_string()]
        );
        assert!(a.rules.deny_engine);
        assert_eq!(
            a.rules.deny_algorithm,
            vec!["DES".to_string(), "RC2".to_string()]
        );
        assert!(a.rules.deny_weak);
        assert_eq!(a.rules.require_executed, vec!["SHA2-256".to_string()]);
        assert_eq!(a.format, "json");
        assert_eq!(a.out.as_deref(), Some("r.json"));
        assert_eq!(a.cbom.as_deref(), Some("b.json"));
        assert_eq!(a.cfg.duration, Duration::from_secs(30));
        // Unknown registry names are config errors (typo-safe).
        let mut typo = base.clone();
        typo.extend(["--deny-algorithm", "AES-256-GCMX"]);
        assert!(parse(&v(typo)).is_err());
        let mut typo2 = base.clone();
        typo2.extend(["--require-executed", "SHA257"]);
        assert!(parse(&v(typo2)).is_err());
        // Provider classes are NOT registry-validated: third-party
        // opaque ids are open-ended.
        let mut opaque = base.clone();
        opaque.extend(["--require-provider", "third-party:deadbeef"]);
        assert!(parse(&v(opaque)).is_ok());
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

    #[test]
    fn help_exits_zero_before_run_only() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(run(&v(vec!["--help"])), ExitCode::from(0));
        assert_eq!(run(&v(vec!["--deny-weak", "-h"])), ExitCode::from(0));
        assert_eq!(run(&v(vec!["run", "--", "--help"])), ExitCode::from(2));
    }

    #[test]
    fn exit_matrix() {
        let viol_doc = doc(vec![site(
            1,
            7,
            vec![cand("p", "default", 1, 7, &["MD5"], true)],
        )]);
        let violation =
            evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &viol_doc);
        let clean_doc = doc(Vec::new());
        let pass = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
            &clean_doc,
        );
        let gappy = crate::evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: 1_000,
                requested_end_ns: 2_000,
                effective_start_ns: 1_000,
                effective_end_ns: 2_000,
                signal_cut: false,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: vec![GapCounter {
                name: "discovery.table_aborted".to_string(),
                kind: CounterKind::Loss,
                units: CounterUnits::Events,
                source: CounterSource::Discovery,
                value: 1,
            }],
            fatal: None,
        });
        let inconclusive = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
            &gappy,
        );
        assert_eq!(pass.overall(), PolicyOutcome::Pass);
        assert_eq!(violation.overall(), PolicyOutcome::Violation);
        assert_eq!(inconclusive.overall(), PolicyOutcome::Inconclusive);
        let failed = DeliveryResult {
            primary: ArtifactOutcome::Failed("x".to_string()),
            cbom: ArtifactOutcome::NotRequested,
        };
        // Violation dominates child and artifact failure.
        assert_eq!(
            exit_for(violation.overall(), Some(1), &viol_doc, &ok_delivery()),
            10
        );
        assert_eq!(
            exit_for(violation.overall(), Some(0), &viol_doc, &failed),
            10
        );
        // Fatal (no verdict) is 4.
        assert_eq!(
            exit_for(PolicyOutcome::NoVerdict, None, &clean_doc, &ok_delivery()),
            4
        );
        // Child failure, then artifact failure, beat inconclusive.
        assert_eq!(
            exit_for(inconclusive.overall(), Some(7), &gappy, &ok_delivery()),
            1
        );
        assert_eq!(
            exit_for(inconclusive.overall(), Some(0), &gappy, &failed),
            1
        );
        assert_eq!(
            exit_for(pass.overall(), Some(2), &clean_doc, &ok_delivery()),
            1
        );
        // Inconclusive is 11; PARTIAL-with-pass is 3; clean is 0.
        assert_eq!(
            exit_for(inconclusive.overall(), Some(0), &gappy, &ok_delivery()),
            11
        );
        assert_eq!(
            exit_for(pass.overall(), Some(0), &clean_doc, &ok_delivery()),
            0
        );
    }

    #[test]
    fn fatal_has_no_verdict() {
        let fatal = crate::evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: 1_000,
                requested_end_ns: 2_000,
                effective_start_ns: 1_000,
                effective_end_ns: 2_000,
                signal_cut: false,
            },
            sites: vec![site(1, 7, vec![cand("p", "default", 1, 7, &["MD5"], true)])],
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: Some(crate::evidence::FatalKind::AttachZero),
        });
        let v = evaluate_document(
            &[
                PolicyRule::require_executed("SHA2-256"),
                PolicyRule::deny_weak(),
            ],
            &fatal,
        );
        assert!(v.no_verdict);
        assert!(v.rules.is_empty(), "never a verdict without evidence");
        assert_eq!(policy_json(&fatal, &v)["verdict"], "no-verdict");
        assert_eq!(exit_for(v.overall(), None, &fatal, &ok_delivery()), 4);
    }

    #[test]
    fn policy_json_shape() {
        let d = doc(vec![site(
            1,
            500,
            vec![cand("p", "default", 2, 21, &["DES"], true)],
        )]);
        let v = evaluate_document(
            &[
                PolicyRule::deny_algorithm("DES"),
                PolicyRule::deny_provider("fips"),
            ],
            &d,
        );
        let p = policy_json(&d, &v);
        assert_eq!(p["verdict"], "violation");
        assert_eq!(p["rules"].as_array().unwrap().len(), 2);
        assert_eq!(p["rules"][0]["result"], "violation");
        assert_eq!(p["rules"][0]["definite"], 500);
        assert_eq!(p["rules"][0]["possible"], 500);
        assert_eq!(p["rules"][1]["result"], "pass");
        assert_eq!(p["param_blind"], false);
        assert_eq!(p["kat_excluded"], 0);
        assert_eq!(p["fips_unlabeled_executions"], 0);
        assert_eq!(p["unseen_deny_providers"], serde_json::json!(["fips"]));
        let x = &p["violations"].as_array().unwrap()[0];
        assert_eq!(x["rule"], "deny-algorithm");
        assert_eq!(x["matcher"], "DES");
        assert_eq!(x["absent"], false);
        assert_eq!(x["site"]["object"], "exe-fingerprint");
        assert_eq!(x["site"]["device"], 7);
        assert_eq!(x["site"]["inode"], 9);
        assert_eq!(x["site"]["offset"], 1);
        assert_eq!(x["generation"], 0);
        assert_eq!(x["fenced"], false);
        assert_eq!(x["calls"], 500);
        assert_eq!(x["first_ns"], 100);
        assert_eq!(x["last_ns"], 200);
        assert_eq!(x["candidates"][0]["provider_class"], "default");
        // Require-absent violations carry no identity.
        let v = evaluate_document(
            std::slice::from_ref(&PolicyRule::require_executed("SHA2-256")),
            &doc(Vec::new()),
        );
        let p = policy_json(&doc(Vec::new()), &v);
        assert_eq!(p["verdict"], "violation");
        let x = &p["violations"].as_array().unwrap()[0];
        assert_eq!(x["absent"], true);
        assert_eq!(x["rule"], "require-executed");
        assert!(x.get("site").is_none());
    }

    #[test]
    fn human_verdict_shapes() {
        // Violation with a definite hit and an absent require.
        let d = doc(vec![site(
            1,
            500,
            vec![cand("p", "default", 2, 21, &["DES"], true)],
        )]);
        let v = evaluate_document(
            &[
                PolicyRule::deny_algorithm("DES"),
                PolicyRule::require_executed("SHA2-256"),
            ],
            &d,
        );
        let out = human(&d, &v);
        assert!(
            out.starts_with(
                "osslscope check: VIOLATION (2 rules violated, 0 inconclusive, 0 passed)\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("[deny-algorithm DES] DES via default: 500 calls"),
            "{out}"
        );
        assert!(
            out.contains("[require-executed SHA2-256] not observed in window\n"),
            "{out}"
        );
        assert!(out.contains("evidence: status=COMPLETE"), "{out}");
        // Inconclusive sorts between violations and passes.
        let gappy = crate::evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: 1_000,
                requested_end_ns: 2_000,
                effective_start_ns: 1_000,
                effective_end_ns: 2_000,
                signal_cut: false,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: vec![GapCounter {
                name: "discovery.table_aborted".to_string(),
                kind: CounterKind::Loss,
                units: CounterUnits::Events,
                source: CounterSource::Discovery,
                value: 1,
            }],
            fatal: None,
        });
        let v = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("RC2")),
            &gappy,
        );
        let out = human(&gappy, &v);
        assert!(
            out.starts_with("osslscope check: INCONCLUSIVE (1 rules unproven, 0 passed)\n"),
            "{out}"
        );
        assert!(
            out.contains("[deny-algorithm RC2] inconclusive (definite=0 possible=0)\n"),
            "{out}"
        );
        // Pass and no-verdict headers.
        let v = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_weak()),
            &doc(Vec::new()),
        );
        let out = human(&doc(Vec::new()), &v);
        assert!(
            out.starts_with("osslscope check: PASS (1 passed)\n"),
            "{out}"
        );
        assert!(out.contains("  [deny-weak] pass (0 calls)\n"), "{out}");
    }

    #[test]
    fn legacy_engine_extraction_sums_entrypoints() {
        let legacy = serde_json::json!({
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 2, "ENGINE_finish": 3}},
        });
        assert_eq!(legacy_engine_calls(&legacy), 5);
        // Missing or misshapen blocks contribute nothing (never a
        // violation from unparseable shape).
        assert_eq!(legacy_engine_calls(&serde_json::Value::Null), 0);
        assert_eq!(legacy_engine_calls(&serde_json::json!({"engine": {}})), 0);
        assert_eq!(
            legacy_engine_calls(&serde_json::json!({
                "engine": {"calls_by_entrypoint": {"ENGINE_init": "x"}},
            })),
            0
        );
    }

    #[test]
    fn delivery_result_reports_requested_failures() {
        let ok = DeliveryResult {
            primary: ArtifactOutcome::Delivered,
            cbom: ArtifactOutcome::NotRequested,
        };
        assert!(!ok.failed());
        assert!(ok.failures().is_empty());
        let bad = DeliveryResult {
            primary: ArtifactOutcome::Delivered,
            cbom: ArtifactOutcome::Failed("write b: denied".to_string()),
        };
        assert!(bad.failed());
        assert_eq!(bad.failures(), vec!["cbom artifact: write b: denied"]);
    }
}
