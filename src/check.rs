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
use crate::evidence::{CaptureDocument, FatalKind, PolicyRecord, RuleVerdict};
use crate::policy::{
    PolicyOutcome, PolicyRule, PolicyVerdict, apply_legacy_engine_fallback, evaluate_document,
    executed_param_blind_ops, fips_unlabeled_calls,
};
use crate::report::{
    OutputDest, OutputFormat, OutputRequest, bound_line, setup_failure_document, write_artifacts,
};
use std::path::{Path, PathBuf};
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
    let mut members_object: Option<String> = None;
    let mut table_raw: Option<String> = None;
    let mut force_offset_raw: Option<String> = None;
    let mut provider_table_raw: Option<String> = None;
    let mut settle_raw: Option<String> = None;
    let mut timeout_raw: Option<String> = None;
    let mut grace_raw: Option<String> = None;
    let mut image_digest = String::new();
    let mut pid: Option<u32> = None;
    let mut run_at: Option<usize> = None;
    let mut workload_out: Option<String> = None;
    let mut workload_out_fd: Option<String> = None;
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
            "--members-object" => members_object = Some(val(a)?),
            "--table" => table_raw = Some(val(a)?),
            "--force-offset" => force_offset_raw = Some(val(a)?),
            "--provider-table" => provider_table_raw = Some(val(a)?),
            "--settle" => settle_raw = Some(val(a)?),
            "--timeout" => timeout_raw = Some(val(a)?),
            "--grace" => grace_raw = Some(val(a)?),
            "--image-digest" => image_digest = val(a)?,
            "--workload-out" => workload_out = Some(val(a)?),
            "--workload-out-fd" => workload_out_fd = Some(val(a)?),
            "--pid" => pid = Some(val(a)?.parse().map_err(|_| "--pid needs an integer")?),
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
    // T12 onboarding: explicit tables are validated here (usage
    // errors, exit 2, before any target/BPF side effect); objects
    // and the target provider resolve inside capture (environment
    // errors there exit 4, never 2).
    let table: Option<PathBuf> = match &table_raw {
        Some(p) => {
            let path = PathBuf::from(p);
            crate::discovery::onboard::load_offset_table_file(&path).map_err(|e| e.full())?;
            Some(path)
        }
        None => None,
    };
    let provider_enrollment = match &provider_table_raw {
        Some(p) => Some(
            crate::discovery::onboard::load_enrollment_file(Path::new(p)).map_err(|e| e.full())?,
        ),
        None => None,
    };
    let force_offset = match &force_offset_raw {
        Some(s) => Some(crate::args::parse_force_offset(s)?),
        None => None,
    };
    Ok(Args {
        cfg: capture::Config {
            harvest_object: object.map(PathBuf::from),
            count_object: count_object.map(PathBuf::from),
            members_object: members_object.map(PathBuf::from),
            provider: provider.map(PathBuf::from),
            builtin,
            table,
            force_offset,
            provider_enrollment,
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
    "usage: check [--duration S] [--provider P] [--object O] [--count-object C] [--members-object M] [--table F] [--force-offset N] [--provider-table F] [rules] [--format human|json] [--out F] [--cbom FILE] [--builtin] [--settle S] [--timeout S] [--grace S] [--image-digest D] [--workload-out F] [--workload-out-fd N] {--pid P | run -- <cmd>}",
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
            crate::report::err_line(&format!("osslscope check: {e}"));
            for l in USAGE {
                crate::report::err_line(l);
            }
            return ExitCode::from(2);
        }
    };
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
    let c = match capture::run(&args.cfg, args.target) {
        Ok(c) => c,
        Err(e) => {
            // F-E/B4: setup/environment failures still attempt
            // every requested artifact — a fatal primary, a
            // no-verdict policy section, and a fatal CBOM — from a
            // typed no-evidence document. No legacy fallback: with
            // no capture there is no tripwire evidence to fold in.
            crate::report::err_line(&format!("osslscope check: {e:#}"));
            crate::report::err_line(
                "osslscope check: run 'osslscope doctor' to diagnose environment failures",
            );
            let mut document =
                setup_failure_document(FatalKind::Environment(bound_line(&format!("{e:#}"))));
            let verdict = evaluate_document(&[], &document);
            document.policy = Some(policy_record(&verdict));
            let delivery = write_artifacts(&document, &req);
            crate::report::emit_diagnostics(&delivery);
            return ExitCode::from(exit_for(verdict.overall(), None, &document, &delivery));
        }
    };
    // Check assembly flows through the shared production seam
    // (evaluate → legacy tripwire → policy attach); the controller
    // close-failure fixture uses the same function.
    let child_exit = c.child_exit;
    let (verdict, document) =
        assemble_checked_document(&policy_rules(&args.rules), c.document, &c.legacy);
    let delivery = write_artifacts(&document, &req);
    crate::report::emit_diagnostics(&delivery);
    // H9/R07 T4: nonzero child exit with discarded output → one
    // diagnostic line (exit + re-run hint, never workload bytes).
    if let Some(hint) = crate::report::workload_hint(child_exit, workload_discarded) {
        crate::report::err_line(&hint);
    }
    ExitCode::from(exit_for(
        verdict.overall(),
        child_exit,
        &document,
        &delivery,
    ))
}

#[cfg(test)]
mod tests {
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
            "--provider",
            "p",
            "--object",
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
