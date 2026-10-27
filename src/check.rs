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
use crate::evidence::{CaptureDocument, PolicyRecord, RuleVerdict};
use crate::policy::{
    PolicyOutcome, PolicyRule, PolicyVerdict, apply_legacy_engine_fallback, evaluate_document,
    executed_param_blind_ops, fips_unlabeled_calls,
};
use crate::policy_config::RuleSet;
use crate::report::{OutputDest, OutputFormat, OutputRequest};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

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
    libcrypto: Option<PathBuf>,
    observation_object: Option<PathBuf>,
    settle_explicit: bool,
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
// F-E/B3: the exit decision lives in report (shared by both commands);
// this re-export keeps the established `check::exit_for` path working.
pub use crate::report::exit_for;

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
    let mut libcrypto: Option<String> = None;
    let mut observation_object: Option<PathBuf> = None;
    let mut members_object: Option<String> = None;
    let mut dev_bundle: Option<String> = None;
    let mut force_offset_raw: Option<String> = None;
    let mut settle_raw: Option<String> = None;
    let mut timeout_raw: Option<String> = None;
    let mut grace_raw: Option<String> = None;
    let mut image_digest = String::new();
    let mut image_digest_explicit = false;
    let mut pid: Option<u32> = None;
    let mut run_at: Option<usize> = None;
    let mut workload_out: Option<String> = None;
    let mut workload_out_fd: Option<String> = None;
    let mut rules = RuleSet::default();
    let mut policy_path: Option<String> = None;
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
            "--policy" => {
                if policy_path.is_some() {
                    return Err("--policy may occur only once".into());
                }
                let path = val(a)?;
                if path.is_empty()
                    || path.starts_with("--")
                    || matches!(path.as_str(), "run" | "-h")
                {
                    return Err("--policy needs a value".into());
                }
                policy_path = Some(path);
            }
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
            "--observation-object" => {
                if observation_object.is_some() {
                    return Err("--observation-object may occur only once".into());
                }
                observation_object = Some(val(a)?.into());
            }
            "--libcrypto" => {
                if libcrypto.is_some() {
                    return Err("--libcrypto may occur only once".into());
                }
                libcrypto = Some(val(a)?);
            }
            "--members-object" => members_object = Some(val(a)?),
            "--dev-bundle" => {
                if dev_bundle.is_some() {
                    return Err("--dev-bundle may occur only once".into());
                }
                dev_bundle = Some(val(a)?);
            }
            "--table" | "--provider-table" => {
                return Err("table enrollment is deferred beyond v0.2".into());
            }
            "--force-offset" => force_offset_raw = Some(val(a)?),
            "--settle" => settle_raw = Some(val(a)?),
            "--timeout" => timeout_raw = Some(val(a)?),
            "--grace" => grace_raw = Some(val(a)?),
            "--image-digest" => {
                image_digest_explicit = true;
                image_digest = val(a)?;
            }
            "--workload-out" => workload_out = Some(val(a)?),
            "--workload-out-fd" => workload_out_fd = Some(val(a)?),
            "--pid" => {
                if pid.is_some() {
                    return Err("--pid may occur only once".into());
                }
                let value: u32 = val(a)?.parse().map_err(|_| "--pid needs an integer")?;
                if value == 0 || value > i32::MAX as u32 {
                    return Err("--pid is out of range".into());
                }
                pid = Some(value);
            }
            "--require-provider" => rules
                .require_provider
                .push(crate::args::parse_provider_matcher(a, val(a)?)?),
            "--deny-provider" => rules
                .deny_provider
                .push(crate::args::parse_provider_matcher(a, val(a)?)?),
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
    // H9/R07: destinations are meaningless without `run --`
    // (never silently ignored); mutual exclusion + fd shape live in
    // the shared args parser (report and check reject identically).
    let target = match (pid, run_at) {
        (Some(p), None) => {
            if workload_out.is_some() || workload_out_fd.is_some() {
                return Err("--workload-out/--workload-out-fd need run -- <cmd>".to_string());
            }
            capture::Target::Pid(p)
        }
        (None, Some(j)) => {
            if argv.get(j + 1).map(String::as_str) != Some("--") {
                return Err("run needs -- before the command".to_string());
            }
            let cmd: Vec<String> = argv[j + 2..].to_vec();
            if cmd.is_empty() {
                return Err("run -- needs a command".to_string());
            }
            capture::Target::Spawn {
                argv: cmd,
                workload: crate::args::parse_workload_dest(workload_out, workload_out_fd)?,
            }
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
    let force_offset = match &force_offset_raw {
        Some(s) => Some(crate::args::parse_force_offset(s)?),
        None => None,
    };
    if let Some(path) = policy_path {
        rules = crate::policy_config::merge(crate::policy_config::load(Path::new(&path))?, rules)?;
    }
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
    if libcrypto.is_some() && (pid.is_some() || observation_object.is_some()) {
        return Err("--libcrypto conflicts with --pid and --observation-object".into());
    }
    if libcrypto.is_none() {
        if provider.is_some()
            || builtin
            || object.is_some()
            || members_object.is_some()
            || dev_bundle.is_some()
            || force_offset_raw.is_some()
            || settle_raw.is_some()
            || image_digest_explicit
        {
            return Err(
                "legacy discovery/enrollment flags require explicit --libcrypto diagnostics".into(),
            );
        }
        if timeout.is_zero() || grace.is_zero() {
            return Err("--timeout and --grace must be positive".into());
        }
    }
    Ok(Args {
        observation_object,
        libcrypto: libcrypto.map(PathBuf::from),
        settle_explicit: settle_raw.is_some(),
        cfg: capture::Config {
            harvest_object: object.map(PathBuf::from),
            count_object: count_object.map(PathBuf::from),
            members_object: members_object.map(PathBuf::from),
            dev_bundle: dev_bundle.map(PathBuf::from),
            provider: provider.map(PathBuf::from),
            builtin,
            table: None,
            force_offset,
            provider_enrollment: None,
            resolved_provider: None,
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
            !r.hits.is_empty() || !r.engine_hits.is_empty() || r.legacy_engine_calls > 0,
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
        // R05: typed ENGINE observations are untimed (trip counters
        // carry no timestamps) but window-bound, unlike the legacy
        // side input below, which has neither timing nor document
        // provenance.
        for h in &r.engine_hits {
            violations.push(serde_json::json!({
                "rule": r.name,
                "matcher": r.matcher,
                "absent": false,
                "plane": "engine",
                "object": h.key.object.0,
                "device": h.key.device,
                "inode": h.key.inode,
                "offset": h.key.offset,
                "generation": h.generation,
                "entrypoint": h.entrypoint,
                "entrypoint_name": crate::evidence::engine_name(h.entrypoint),
                "timed": false,
                "calls": h.calls,
            }));
        }
        if r.hits.is_empty() && r.engine_hits.is_empty() && r.legacy_engine_calls > 0 {
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

/// Map a T10 [`PolicyVerdict`] onto the document [`PolicyRecord`]
/// the T11 renderers embed (merge reconciliation: T11's as-built
/// [`OutputRequest`](crate::report::OutputRequest) carries no policy
/// input — policy rides the document). Rules sort into document
/// order; definite hits become evidence refs resolving to sites in the
/// same document, and definite ENGINE observations become
/// engine-plane refs resolving to observations in the same document
/// (R05). Legacy ENGINE tripwire calls have no document site, so a
/// legacy-only violation maps to bounds WITHOUT evidence refs
/// (T08 retires the tripwire once ENGINE executions surface as
/// sites); exits and [`policy_json`] keep full fidelity either way.
pub fn policy_record(v: &PolicyVerdict) -> PolicyRecord {
    use crate::evidence::{
        EngineEvidenceRef, PolicyEvidenceRef, PolicyRuleResult, PolicyVerdict as DocVerdict,
    };
    let mut rules: Vec<PolicyRuleResult> = v
        .rules
        .iter()
        .map(|r| {
            // Canonical order mirrors finalize: evidence refs sort
            // (current hits precede fenced hits in evaluation order,
            // which is not document order) as do rules.
            let mut evidence: Vec<PolicyEvidenceRef> = r
                .hits
                .iter()
                .map(|h| PolicyEvidenceRef {
                    object: h.site.object.clone(),
                    device: h.site.device,
                    inode: h.site.inode,
                    offset: h.site.offset,
                    generation: h.generation,
                    calls: h.calls,
                })
                .collect();
            evidence.sort();
            let mut engine_evidence: Vec<EngineEvidenceRef> = r
                .engine_hits
                .iter()
                .map(|h| EngineEvidenceRef {
                    object: h.key.object.clone(),
                    device: h.key.device,
                    inode: h.key.inode,
                    offset: h.key.offset,
                    generation: h.generation,
                    entrypoint: h.entrypoint,
                    calls: h.calls,
                })
                .collect();
            engine_evidence.sort();
            PolicyRuleResult {
                rule: r.name.to_string(),
                predicate: r.matcher.clone(),
                result: r.verdict,
                definite: r.bounds.definite,
                possible: r.bounds.possible,
                evidence,
                engine_evidence,
            }
        })
        .collect();
    rules.sort();
    PolicyRecord {
        verdict: match v.overall() {
            PolicyOutcome::NoVerdict => DocVerdict::NoVerdict,
            PolicyOutcome::Pass => DocVerdict::Pass,
            PolicyOutcome::Violation => DocVerdict::Violation,
            PolicyOutcome::Inconclusive => DocVerdict::Inconclusive,
        },
        rules,
    }
}

/// Production check assembly (R02 fix round 1): evaluate the rules
/// against the finalized document, fold the legacy ENGINE tripwire,
/// and attach the policy section the renderers embed. [`run`] and the
/// controller close-failure fixture both flow through this one
/// orchestration point, so a regression here fails both together —
/// the fixture can no longer pass while production drifts.
pub(crate) fn assemble_checked_document(
    rules: &[PolicyRule],
    document: CaptureDocument,
    legacy: &serde_json::Value,
) -> (PolicyVerdict, CaptureDocument) {
    let mut verdict = evaluate_document(rules, &document);
    // Pre-T08 transition: the legacy ENGINE tripwire counted real
    // in-window executions the document does not model yet; fold them
    // in so --deny-engine cannot miss them. No-op once T08 retires the
    // legacy block (or when the document already has the hits).
    apply_legacy_engine_fallback(&mut verdict, legacy_engine_calls(legacy));
    // Policy rides the document for the T11 renderers (JSON `policy`
    // section, human policy block, CBOM `osslscope:policy-verdict`).
    let mut document = document;
    document.policy = Some(policy_record(&verdict));
    (verdict, document)
}

const USAGE: [&str; 2] = [
    "usage: check [--observation-object PATH] [--count-object PATH] [--policy FILE] [--duration S] [--format human|json] [--out FILE] [--cbom FILE] [--timeout S] [--grace S] [--workload-out FILE | --workload-out-fd N] [rules] {--pid PID | run -- COMMAND}; --libcrypto PATH selects legacy diagnostics",
    "rules: --require-executed ALGORITHM | --deny-algorithm ALGORITHM | --require-provider P | --deny-provider P | --deny-engine | --deny-weak (at least one required)",
];

pub fn run(argv: &[String]) -> ExitCode {
    match prepare(argv) {
        Ok(p) => ExitCode::from(p.execute().exit_code),
        Err(code) => code,
    }
}
pub(crate) fn prepare(argv: &[String]) -> Result<Prepared, ExitCode> {
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
        return Err(ExitCode::from(0));
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            crate::report::err_line(&format!("osslscope check: {e}"));
            for l in USAGE {
                crate::report::err_line(l);
            }
            return Err(ExitCode::from(2));
        }
    };
    if let Err(error) = if args.libcrypto.is_some() {
        args.rules.require_preview()
    } else {
        Ok(())
    } {
        crate::report::err_line(&format!("osslscope check: {error}"));
        return Err(ExitCode::from(2));
    }
    let setup_deadline = std::time::Instant::now()
        .checked_add(args.cfg.harvest_timeout)
        .ok_or_else(|| {
            crate::report::err_line("setup deadline overflow");
            ExitCode::from(2)
        })?;
    if args.libcrypto.is_none() {
        let objects = crate::package::commands::resolve_focused_objects(
            args.observation_object.as_deref(),
            args.cfg.count_object.as_deref(),
        )
        .map_err(|e| {
            crate::report::err_line(&format!("osslscope: {e}"));
            ExitCode::from(2)
        })?;
        let config = crate::focused_capture::FocusedConfig {
            duration: args.cfg.duration,
            timeout: args.cfg.harvest_timeout,
            grace: args.cfg.grace,
        };
        return Ok(Prepared {
            args,
            route: PreparedRoute::Focused { config, objects },
            setup_deadline,
        });
    }
    let preview = match capture::profiled::ProfiledConfig::for_command(
        args.libcrypto.clone(),
        &args.cfg,
        &args.target,
        args.settle_explicit,
    ) {
        Ok(config) => config,
        Err(error) => {
            crate::report::err_line(&format!("osslscope check: {error}"));
            return Err(ExitCode::from(2));
        }
    };
    let objects =
        match crate::package::commands::resolve_profiled_count(preview.count_object.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                let req = OutputRequest {
                    format: if args.format == "json" {
                        OutputFormat::Json
                    } else {
                        OutputFormat::Human
                    },
                    primary: args
                        .out
                        .as_ref()
                        .map_or(OutputDest::Stdout, |p| OutputDest::File(p.into())),
                    cbom: args.cbom.as_ref().map(|p| OutputDest::File(p.into())),
                };
                let discarded = matches!(
                    &args.target,
                    capture::Target::Spawn {
                        workload: crate::target::WorkloadDest::Null,
                        ..
                    }
                );
                let result = crate::report::consume_capture_result(
                    Err(e.into()),
                    crate::report::CaptureCommand::Check {
                        rules: &policy_rules(&args.rules),
                    },
                    &req,
                    discarded,
                );
                return Err(ExitCode::from(result.exit_code));
            }
        };
    Ok(Prepared {
        args,
        route: PreparedRoute::Legacy { preview, objects },
        setup_deadline,
    })
}
pub struct Prepared {
    setup_deadline: std::time::Instant,
    args: Args,
    route: PreparedRoute,
}
enum PreparedRoute {
    Focused {
        config: crate::focused_capture::FocusedConfig,
        objects: crate::focused_capture::FocusedObjects,
    },
    Legacy {
        objects: crate::package::commands::ProfiledCount,
        preview: capture::profiled::ProfiledConfig,
    },
}
impl Prepared {
    pub(crate) fn is_focused(&self) -> bool {
        matches!(self.route, PreparedRoute::Focused { .. })
    }
    pub(crate) fn setup_deadline(&self) -> Option<std::time::Instant> {
        Some(self.setup_deadline)
    }
    pub(crate) fn workload_fd(&self) -> std::io::Result<Option<std::os::fd::BorrowedFd<'_>>> {
        match &self.args.target {
            capture::Target::Spawn { workload, .. } => {
                crate::target::validate_workload_fd(workload)
            }
            _ => Ok(None),
        }
    }
    pub(crate) fn execute(self) -> crate::report::CaptureCommandResult {
        // Validate before invoking the controller: invalid workload delivery
        // must acquire neither target custody nor observer/count resources.
        let workload_fd_error = if self.is_focused() {
            self.workload_fd().err()
        } else {
            None
        };
        let args = self.args;
        let req = OutputRequest {
            format: if args.format == "json" {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            },
            primary: match args.out {
                None => OutputDest::Stdout,
                Some(path) => OutputDest::File(path.into()),
            },
            cbom: args.cbom.map(|path| OutputDest::File(path.into())),
        };
        // H9: captured before the target moves into capture (the T4
        // hint needs to know the workload was discarded post-run).
        let workload_discarded = matches!(
            &args.target,
            capture::Target::Spawn {
                workload: crate::target::WorkloadDest::Null,
                ..
            }
        );
        match self.route {
            PreparedRoute::Focused { config, objects } => crate::report::consume_focused_result(
                match workload_fd_error {
                    Some(error) => Err(error.into()),
                    None => crate::focused_capture::run(
                        config,
                        args.target,
                        objects,
                        self.setup_deadline,
                    ),
                },
                crate::report::CaptureCommand::Check {
                    rules: &policy_rules(&args.rules),
                },
                &req,
            ),
            PreparedRoute::Legacy { preview, objects } => crate::report::consume_capture_result(
                capture::profiled::run_profiled_before(
                    &preview,
                    args.target,
                    objects,
                    Some(self.setup_deadline),
                ),
                crate::report::CaptureCommand::Check {
                    rules: &policy_rules(&args.rules),
                },
                &req,
                workload_discarded,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod preview_admission_tests {
        use super::*;
        fn words(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| (*s).into()).collect()
        }

        fn preview_exit(rule: PolicyRule) -> u8 {
            let document = crate::capture::profiled::preview_document_for_test(true);
            let (verdict, document) =
                assemble_checked_document(&[rule], document, &serde_json::Value::Null);
            let delivery = crate::report::DeliveryResult {
                primary: crate::report::ArtifactOutcome {
                    dest: "stdout".into(),
                    ok: true,
                    bytes: 1,
                    error: None,
                },
                cbom: None,
                diagnostics: Vec::new(),
            };
            crate::report::exit_for(verdict.overall(), Some(0), &document, &delivery)
        }
        #[test]
        fn partial_positive_require_is_3() {
            assert_eq!(preview_exit(PolicyRule::require_executed("SHA256")), 3);
        }
        #[test]
        fn definite_deny_is_10() {
            assert_eq!(preview_exit(PolicyRule::deny_algorithm("SHA256")), 10);
        }
        #[test]
        fn unobserved_known_algorithm_is_11() {
            assert_eq!(
                preview_exit(PolicyRule::require_executed("AES-256-GCM")),
                11
            );
            assert_eq!(preview_exit(PolicyRule::deny_algorithm("AES-256-GCM")), 11);
        }

        #[test]
        fn preview_requires_libcrypto() {
            let args = words(&[
                "--require-executed",
                "SHA256",
                "--count-object",
                "/missing-count",
                "run",
                "--",
                "/bin/true",
            ]);
            assert!(matches!(prepare(&args), Err(code) if code == ExitCode::from(2)));
        }

        #[test]
        fn valid_preview_flags_reach_count_abi_admission() {
            let args = words(&[
                "--libcrypto",
                "/missing-library",
                "--require-executed",
                "SHA256",
                "--count-object",
                "/missing-count",
                "run",
                "--",
                "/bin/true",
            ]);
            assert!(matches!(prepare(&args), Err(code) if code == ExitCode::from(4)));
        }
    }
    use super::*;
    use crate::evidence::{
        CandidateCoverage, CandidateIdentity, CaptureWindow, CounterKind, CounterSource,
        CounterUnits, FinalizeInput, GapCounter, LegacyCallPartition, ObjectId, OpensslVersion,
        SiteExecution, SiteKey, TargetRecord,
    };
    use crate::policy::{Predicate, Rule};
    use crate::report::{ArtifactOutcome, DeliveryResult};

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
            installed_at: None,
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
                count_admission: None,
            },
            sites,
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        })
    }

    fn ruleset() -> RuleSet {
        RuleSet::default()
    }

    fn ok_delivery() -> DeliveryResult {
        DeliveryResult {
            primary: ArtifactOutcome {
                dest: "stdout".to_string(),
                ok: true,
                bytes: 8,
                error: None,
            },
            cbom: None,
            diagnostics: Vec::new(),
        }
    }

    fn failed_delivery() -> DeliveryResult {
        DeliveryResult {
            primary: ArtifactOutcome {
                dest: "stdout".to_string(),
                ok: false,
                bytes: 0,
                error: Some("x".to_string()),
            },
            cbom: None,
            diagnostics: vec!["primary stdout: x".to_string()],
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
                // F-E/B1: argument-less rules carry canonical
                // nonempty matchers (the old "" violated the v2
                // predicate minLength 1).
                ("deny-engine", "engine"),
                ("deny-algorithm", "DES"),
                ("deny-weak", "weak"),
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
    fn policy_file_and_cli_build_exact_rules_and_preserve_truth() {
        let path = std::env::temp_dir().join(format!(
            "osslscope-check-policy-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"version=1
require-provider=["default"]
deny-provider=["legacy"]
deny-engine=true
deny-algorithm=["MD5"]
deny-weak=true
require-executed=["SHA2-256"]
"#,
        )
        .unwrap();
        let file_args: Vec<String> = vec![
            "--policy".into(),
            path.to_string_lossy().into_owned(),
            "--require-provider".into(),
            "default".into(),
            "--deny-algorithm".into(),
            "DES".into(),
            "run".into(),
            "--".into(),
            "workload".into(),
            "--policy".into(),
            "target-argument".into(),
        ];
        let parsed = parse(&file_args).unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(matches!(parsed.target, capture::Target::Spawn { argv, .. }
            if argv == ["workload", "--policy", "target-argument"]));
        let actual = policy_rules(&parsed.rules);
        let expected = vec![
            PolicyRule::require_provider("default"),
            PolicyRule::require_provider("default"),
            PolicyRule::deny_provider("legacy"),
            PolicyRule::deny_engine(),
            PolicyRule::deny_algorithm("MD5"),
            PolicyRule::deny_algorithm("DES"),
            PolicyRule::deny_weak(),
            PolicyRule::require_executed("SHA2-256"),
        ];
        assert_eq!(actual, expected);
        let cli: Vec<String> = [
            "--pid",
            "9",
            "--require-provider",
            "default",
            "--require-provider",
            "default",
            "--deny-provider",
            "legacy",
            "--deny-engine",
            "--deny-algorithm",
            "MD5",
            "--deny-algorithm",
            "DES",
            "--deny-weak",
            "--require-executed",
            "SHA2-256",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(actual, policy_rules(&parse(&cli).unwrap().rules));
        for (document, outcome, exit) in [
            (
                doc(vec![site(
                    1,
                    2,
                    vec![cand("p", "default", 1, 1, &["SHA2-256"], false)],
                )]),
                PolicyOutcome::Pass,
                0,
            ),
            (
                doc(vec![site(
                    1,
                    2,
                    vec![cand("p", "default", 1, 1, &["MD5"], true)],
                )]),
                PolicyOutcome::Violation,
                10,
            ),
            (
                doc(vec![site(
                    1,
                    2,
                    vec![cand("p", "unknown", 1, 1, &["other"], false)],
                )]),
                PolicyOutcome::Inconclusive,
                11,
            ),
        ] {
            let verdict = evaluate_document(&actual, &document);
            assert_eq!(verdict.overall(), outcome);
            assert_eq!(
                exit_for(verdict.overall(), Some(0), &document, &ok_delivery()),
                exit
            );
        }
    }

    #[test]
    fn policy_path_is_loaded_only_after_argument_shape_validation() {
        let args: Vec<String> = [
            "--policy",
            "/nonexistent-policy",
            "--pid",
            "9",
            "--duration",
            "NaN",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(parse(&args).err().unwrap().contains("--duration"));
        let args: Vec<String> = [
            "--policy",
            "/nonexistent-policy",
            "--pid",
            "9",
            "--force-offset",
            "bad",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(parse(&args).err().unwrap().contains("--force-offset"));
        for args in [
            vec!["--policy"],
            vec!["--policy", "--pid", "9"],
            vec!["--policy", "", "--pid", "9"],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            assert!(
                parse(&args)
                    .err()
                    .unwrap()
                    .contains("--policy needs a value")
            );
        }
        // File-mode contradictions must not change established CLI-only admission.
        let cli: Vec<String> = [
            "--pid",
            "9",
            "--require-provider",
            "default",
            "--deny-provider",
            "default",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(parse(&cli).is_ok());
    }

    #[test]
    fn parse_rules_matrix() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--observation-object",
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
        // T12: provider/objects are optional (automatic discovery).
        let auto = parse(&v(neither)).unwrap();
        assert!(auto.cfg.provider.is_none());
        assert!(auto.cfg.harvest_object.is_none());
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
                count_admission: None,
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
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        let inconclusive = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("AES-256-GCM")),
            &gappy,
        );
        assert_eq!(pass.overall(), PolicyOutcome::Pass);
        assert_eq!(violation.overall(), PolicyOutcome::Violation);
        assert_eq!(inconclusive.overall(), PolicyOutcome::Inconclusive);
        let failed = failed_delivery();
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
                count_admission: None,
            },
            sites: vec![site(1, 7, vec![cand("p", "default", 1, 7, &["MD5"], true)])],
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: Some(crate::evidence::FatalKind::AttachZero),
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
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
    fn policy_record_mapping() {
        use crate::evidence::PolicyVerdict as DocVerdict;
        // Violation with a definite hit plus an absent require: both
        // rules map, hits become evidence refs, verdict is violation.
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
        let rec = policy_record(&v);
        assert_eq!(rec.verdict, DocVerdict::Violation);
        assert_eq!(rec.rules.len(), 2);
        // Document order, not CLI order: deny-algorithm sorts first.
        assert_eq!(rec.rules[0].rule, "deny-algorithm");
        assert_eq!(rec.rules[0].predicate, "DES");
        assert_eq!(rec.rules[0].result, RuleVerdict::Violation);
        assert_eq!(rec.rules[0].definite, 500);
        assert_eq!(rec.rules[0].possible, Some(500));
        assert_eq!(rec.rules[0].evidence.len(), 1);
        let e = &rec.rules[0].evidence[0];
        assert_eq!(e.object.0, "exe-fingerprint");
        assert_eq!((e.device, e.inode, e.offset), (7, 9, 1));
        assert_eq!(e.generation, 0);
        assert_eq!(e.calls, 500);
        assert_eq!(rec.rules[1].rule, "require-executed");
        assert_eq!(rec.rules[1].predicate, "SHA2-256");
        assert_eq!(rec.rules[1].result, RuleVerdict::Violation);
        assert!(rec.rules[1].evidence.is_empty(), "absence has no sites");
        // Legacy-only tripwire: bounds WITHOUT evidence refs (no
        // document site exists); the violation still maps.
        let quiet = doc(Vec::new());
        let mut v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_engine()), &quiet);
        crate::policy::apply_legacy_engine_fallback(&mut v, 5);
        let rec = policy_record(&v);
        assert_eq!(rec.verdict, DocVerdict::Violation);
        assert_eq!(rec.rules[0].definite, 5);
        assert_eq!(rec.rules[0].possible, None);
        assert!(rec.rules[0].evidence.is_empty());
        // Evidence refs sort into canonical order even though
        // evaluation emits current hits before fenced hits.
        let mut cur = site(9, 100, vec![cand("p", "default", 2, 21, &["DES"], true)]);
        cur.generation = 1;
        let mut fen = site(9, 50, vec![cand("p", "default", 2, 21, &["DES"], true)]);
        fen.generation = 0;
        let mixed = crate::evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: 1_000,
                requested_end_ns: 2_000,
                effective_start_ns: 1_000,
                effective_end_ns: 2_000,
                signal_cut: false,
                count_admission: None,
            },
            sites: vec![cur],
            fenced: vec![crate::evidence::FencedGeneration {
                generation: 0,
                sites: vec![fen],
            }],
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        let v = evaluate_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("DES")),
            &mixed,
        );
        let rec = policy_record(&v);
        let gens: Vec<u32> = rec.rules[0].evidence.iter().map(|e| e.generation).collect();
        assert_eq!(gens, vec![0, 1]);
    }

    #[test]
    fn assemble_checked_document_folds_legacy_and_attaches_policy() {
        use crate::evidence::PolicyVerdict as DocVerdict;
        // R02 fix round 1: the shared production seam evaluates the
        // rules, folds the legacy ENGINE tripwire, and attaches the
        // policy section the renderers embed — one orchestration
        // point for check::run and the close-failure fixture.
        let d = doc(vec![site(
            1,
            500,
            vec![cand("p", "default", 2, 21, &["DES"], true)],
        )]);
        let (verdict, document) = assemble_checked_document(
            std::slice::from_ref(&PolicyRule::deny_algorithm("DES")),
            d,
            &serde_json::Value::Null,
        );
        assert_eq!(verdict.overall(), PolicyOutcome::Violation);
        let policy = document.policy.as_ref().expect("assembly attaches policy");
        assert_eq!(policy.verdict, DocVerdict::Violation);
        assert_eq!(policy.rules[0].definite, 500);
        assert_eq!(policy.rules[0].evidence.len(), 1);
        // Legacy-only tripwire: no sites, five ENGINE calls — the
        // fallback convicts and the bounds ride the attached policy.
        let quiet = doc(Vec::new());
        let legacy = serde_json::json!({
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 5}},
        });
        let (verdict, document) = assemble_checked_document(
            std::slice::from_ref(&PolicyRule::deny_engine()),
            quiet,
            &legacy,
        );
        assert_eq!(verdict.overall(), PolicyOutcome::Violation);
        let policy = document.policy.as_ref().expect("assembly attaches policy");
        assert_eq!(policy.verdict, DocVerdict::Violation);
        assert_eq!(policy.rules[0].definite, 5);
        assert!(policy.rules[0].evidence.is_empty());
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
    fn empty_provider_matchers_rejected_on_every_occurrence() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--observation-object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        // Empty on either flag, first or repeat occurrence: usage error.
        for extra in [
            vec!["--deny-provider", ""],
            vec!["--require-provider", ""],
            vec!["--deny-provider", "default", "--deny-provider", ""],
            vec!["--deny-provider", "", "--deny-provider", "default"],
            vec!["--require-provider", "default", "--require-provider", ""],
            vec!["--require-provider", "", "--require-provider", "default"],
            vec!["--deny-provider", "default", "--require-provider", ""],
            vec!["--require-provider", "default", "--deny-provider", ""],
        ] {
            let mut args = base.clone();
            args.extend(extra.clone());
            assert!(parse(&v(args)).is_err(), "reject {extra:?}");
        }
        // Nonempty opaque ids parse — third-party values are never
        // enumerated, and matchers are NOT trimmed (" " is nonempty).
        for extra in [
            vec!["--deny-provider", "third-party:deadbeef"],
            vec!["--require-provider", "third-party:deadbeef"],
            vec!["--deny-provider", " "],
        ] {
            let mut args = base.clone();
            args.extend(extra.clone());
            assert!(parse(&v(args)).is_ok(), "accept {extra:?}");
        }
        // The shared helper rejects empty directly (per-occurrence).
        assert!(crate::args::parse_provider_matcher("--deny-provider", String::new()).is_err());
        assert_eq!(
            crate::args::parse_provider_matcher("--deny-provider", "x".to_string()).unwrap(),
            "x"
        );
    }

    #[test]
    fn accepted_provider_predicates_validate_against_producer_schema() {
        use crate::evidence::{DispositionRecord, ObjectRecord};
        use crate::policy::PolicyRule;
        // Schema-valid fixture: declared object triple, activity
        // inside the window, honest legacy partition.
        let sites = vec![
            SiteExecution {
                site: SiteKey {
                    object: ObjectId("exe-fingerprint".to_string()),
                    device: 7,
                    inode: 9,
                    offset: 1,
                },
                generation: 0,
                candidates: vec![cand(
                    "exe-fingerprint",
                    "default",
                    2,
                    21,
                    &["AES-256-GCM"],
                    false,
                )],
                candidates_coverage: CandidateCoverage::Complete,
                calls: 500,
                first_ns: 10,
                last_ns: 90,
                installed_at: None,
            },
            SiteExecution {
                site: SiteKey {
                    object: ObjectId("exe-fingerprint".to_string()),
                    device: 7,
                    inode: 9,
                    offset: 2,
                },
                generation: 0,
                candidates: vec![cand(
                    "exe-fingerprint",
                    "third-party:deadbeef",
                    1,
                    7,
                    &["SHA2-256"],
                    false,
                )],
                candidates_coverage: CandidateCoverage::Complete,
                calls: 100,
                first_ns: 10,
                last_ns: 90,
                installed_at: None,
            },
        ];
        let doc_of = |rules: &[PolicyRule]| {
            let input = FinalizeInput {
                window: CaptureWindow {
                    requested_start_ns: 0,
                    requested_end_ns: 100,
                    effective_start_ns: 0,
                    effective_end_ns: 100,
                    signal_cut: false,
                    count_admission: None,
                },
                sites: sites.clone(),
                fenced: Vec::new(),
                objects: vec![ObjectRecord {
                    id: ObjectId("exe-fingerprint".to_string()),
                    device: 7,
                    inode: 9,
                    display_locator: "/usr/lib/test/libcrypto.so".to_string(),
                }],
                coverage: Vec::new(),
                counters: Vec::new(),
                fatal: None,
                target: TargetRecord::new(7, "demo".to_string(), String::new(), String::new()),
                openssl: OpensslVersion::verified("3.5.1".to_string()),
                disposition: Some(DispositionRecord::exited(0)),
                policy: None,
                legacy_partition: LegacyCallPartition {
                    legacy_exclusive: 0,
                    non_legacy_exclusive: 600,
                    shared_ambiguous: 0,
                    unfenced_tails: 0,
                },
                traversal: None,
                engine_observations: Vec::new(),
            };
            let bare = crate::evidence::finalize(input);
            let verdict = evaluate_document(rules, &bare);
            let mut with_policy = bare;
            with_policy.policy = Some(policy_record(&verdict));
            with_policy
        };
        // Every accepted provider-matcher shape: rule → policy record
        // → render validates against the producer schema (F15: an
        // empty predicate would violate minLength 1).
        for (name, rule) in [
            ("require-provider", PolicyRule::require_provider("default")),
            (
                "require-provider-third-party",
                PolicyRule::require_provider("third-party:deadbeef"),
            ),
            ("deny-provider", PolicyRule::deny_provider("fips")),
            (
                "deny-provider-third-party",
                PolicyRule::deny_provider("third-party:deadbeef"),
            ),
        ] {
            let document = doc_of(std::slice::from_ref(&rule));
            let bytes = crate::report::render_json(&document).expect("render_json succeeds");
            let rendered: serde_json::Value =
                serde_json::from_slice(&bytes).expect("rendered JSON parses");
            crate::schema::validate_v2(&rendered)
                .unwrap_or_else(|e| panic!("{name} fails schema: {e}"));
            crate::schema::check_v2_semantics(&rendered)
                .unwrap_or_else(|e| panic!("{name} fails semantics: {e}"));
        }
    }

    // Delivery semantics (all-attempted, same-sink refusal,
    // diagnostics bounds) are T11's: pinned by output_contract, not
    // re-pinned here.
}

// The real entrypoint and the four-command source fixture use this same
// fixed-kind admission port; effects begin only after successful resolution.
#[cfg(test)]
pub(crate) fn with_check_objects<R>(
    overrides: &crate::package::commands::ObjectOverrides,
    resolve: impl FnOnce(
        crate::package::commands::CommandKind,
        &crate::package::commands::ObjectOverrides,
    )
        -> Result<crate::package::commands::AdmittedSet, crate::package::PackageError>,
    effect: impl FnOnce(crate::package::commands::AdmittedSet) -> R,
) -> Result<R, crate::package::PackageError> {
    capture::with_capture_objects(
        crate::package::commands::CommandKind::Check,
        overrides,
        resolve,
        effect,
    )
}

#[cfg(test)]
#[test]
fn normal_command_refuses_identity_v2_selection() {
    let args = [
        "--dev-bundle",
        "/missing/identity-v2",
        "--pid",
        "1",
        "--deny-weak",
    ]
    .map(String::from);
    assert!(
        parse(&args).is_err(),
        "normal commands refuse legacy bundle selection"
    );
}
