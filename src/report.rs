//! SPDX-License-Identifier: GPL-3.0-or-later
//! Provisional P2 `report` (JSON doc + minimal human table; P3
//! freezes the schema, adds `check`, and narrows exits).
//!
//! `report [--duration S] [--format human|json] [--out FILE]
//! [--provider P] [--builtin] [--object O] [--count-object C]
//! [--table F] [--force-offset N] [--provider-table F]
//! [--settle S] [--timeout S] [--grace S] {--pid P | run -- <cmd>}`
//!
//! Normal discovery is automatic: BPF objects resolve from trusted
//! installed locations and the target's libcrypto from its live
//! mappings (builtin mode). `--provider`/`--object`/`--count-object`
//! are explicit overrides; `--table`/`--force-offset`/
//! `--provider-table` are explicit local enrollment (R09).
//!
//! Exit precedence (PRD §6 proposal): child non-zero → 1 (with
//! `child_exit` in the doc — the subject failed, evidence rides
//! along); fatal (recycled / zero-attached / environment) → 4;
//! PARTIAL → 3; clean COMPLETE → 0; usage → 2. Violation (10) and
//! inconclusive (11) arrive with `check` at P3.
use crate::capture;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

/// Default window (P3 exit-5): 3× the 10 s P2 exactness cells that
/// went COMPLETE on all lanes (spawn + first crypto + loop ops all
/// observed) — comfortably exceeds seconds-scale target warmup
/// (attach runs pre-window) while keeping CI windows cheap.
pub(crate) const DEFAULT_DURATION_SECS: f64 = 30.0;

struct Args {
    cfg: capture::Config,
    target: capture::Target,
    format: String,
    out: Option<String>,
    cbom: Option<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    // T04 (coordinator review): time flags are captured raw and validated
    // once via args::parse_seconds below (R08 bounds, no panics).
    let mut duration_raw: Option<String> = None;
    let mut format = "human".to_string();
    let mut out: Option<String> = None;
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
    let mut pid: Option<u32> = None;
    let mut image_digest = String::new();
    let mut cbom: Option<String> = None;
    let mut workload_out: Option<String> = None;
    let mut workload_out_fd: Option<String> = None;
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
            "--duration" => duration_raw = Some(val(a)?),
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
            "--members-object" => members_object = Some(val(a)?),
            "--table" => table_raw = Some(val(a)?),
            "--force-offset" => force_offset_raw = Some(val(a)?),
            "--provider-table" => provider_table_raw = Some(val(a)?),
            "--settle" => settle_raw = Some(val(a)?),
            "--timeout" => timeout_raw = Some(val(a)?),
            "--grace" => grace_raw = Some(val(a)?),
            "--pid" => pid = Some(val(a)?.parse().map_err(|_| "--pid needs an integer")?),
            "--image-digest" => image_digest = val(a)?,
            "--cbom" => cbom = Some(val(a)?),
            "--workload-out" => workload_out = Some(val(a)?),
            "--workload-out-fd" => workload_out_fd = Some(val(a)?),
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
    // check (R08 bounds; rejects 1e30/NaN/inf/negatives/zero-rounding
    // before any target/BPF side effect). Defaults are exact.
    let duration = match &duration_raw {
        Some(s) => crate::args::parse_seconds("--duration", s)?,
        None => Duration::from_secs_f64(DEFAULT_DURATION_SECS),
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
    })
}

/// Shared exit decision for report and check (pure — unit-tested).
/// PRD §14 precedence: 2 (usage, decided by the caller) →
/// 4/no-verdict → 10 → 1 (child or delivery) → 11 → 3 → 0.
/// F-E/B3: this used to live in check only while report kept its
/// own ordering (child before fatal) and its own delivery code (4);
/// both commands now resolve through this one function. Report
/// maps its capture outcome to a policy outcome (fatal →
/// no-verdict, anything else → pass) and lets the shared table do
/// the rest.
/// Exit table (PRD §14 precedence, H7-extended): 2 usage (decided
/// at CLI parse, before this fn) > 10 violation > 1 salvaged
/// runtime-fatal > 4 setup-no-verdict > 1 failed child / failed
/// delivery > 11 inconclusive > 3 partial > 0 clean. (The 1-group is
/// split by normative PRD order: a salvaged doc dominates
/// no-verdict — observations exist to look at — while child/delivery
/// failures stay below it. Violation-vs-no-verdict order is moot:
/// one outcome never carries both.)
pub fn exit_for(
    outcome: crate::policy::PolicyOutcome,
    child_exit: Option<i32>,
    doc: &CaptureDocument,
    delivery: &DeliveryResult,
) -> u8 {
    if outcome == crate::policy::PolicyOutcome::Violation {
        return 10;
    }
    if matches!(
        &doc.status,
        Completeness::Fatal {
            kind: FatalKind::Runtime(_),
            ..
        }
    ) {
        return 1;
    }
    if outcome == crate::policy::PolicyOutcome::NoVerdict {
        return 4;
    }
    if matches!(child_exit, Some(code) if code != 0) {
        return 1;
    }
    if delivery.failed() {
        return 1;
    }
    if outcome == crate::policy::PolicyOutcome::Inconclusive {
        return 11;
    }
    match &doc.status {
        Completeness::Complete => 0,
        Completeness::Partial { .. } | Completeness::Fatal { .. } => 3,
    }
}

/// H9/R07 debug-UX hint: when a spawned child exits nonzero and no
/// workload destination was given, its output went to /dev/null —
/// one diagnostic line naming the exit + the re-run hint (never
/// workload bytes). Clean exits, foreign pids, and explicit
/// destinations stay silent. Shared by report and check.
pub(crate) fn workload_hint(child_exit: Option<i32>, discarded: bool) -> Option<String> {
    match (child_exit, discarded) {
        (Some(code), true) if code != 0 => Some(format!(
            "workload exited with status {code} and its output was discarded (default /dev/null); re-run with --workload-out FILE to capture it"
        )),
        _ => None,
    }
}

/// Op id → display name (`OSSL_OP_DIGEST` → `DIGEST`; kept:
/// the v2 CBOM renderer shares it).
pub(crate) fn op_display(id: u32) -> String {
    crate::kinds::OPS
        .iter()
        .find(|o| o.id == id)
        .map(|o| {
            o.name
                .strip_prefix("OSSL_OP_")
                .unwrap_or(o.name)
                .to_string()
        })
        .unwrap_or_else(|| format!("OP{id}"))
}

/// Thousands separator for call counts (kept: the v2 human
/// renderer shares it).
pub(crate) fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.bytes().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch as char);
    }
    out
}

const USAGE: &str = "usage: report [--duration S] [--provider P] [--object O] [--count-object C] [--members-object M] [--table F] [--force-offset N] [--provider-table F] [--format human|json] [--out F] [--cbom FILE] [--builtin] [--settle S] [--timeout S] [--grace S] [--image-digest D] [--workload-out F] [--workload-out-fd N] {--pid P | run -- <cmd>}";

pub fn run(argv: &[String]) -> ExitCode {
    // --help anywhere on the osslscope side (a target command after
    // run -- may legitimately contain --help).
    if argv
        .iter()
        .take_while(|a| a.as_str() != "run")
        .any(|a| a == "--help" || a == "-h")
    {
        println!("{USAGE}");
        return ExitCode::from(0);
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            err_line(&format!("osslscope report: {e}"));
            err_line(USAGE);
            return ExitCode::from(2);
        }
    };
    // T14r4: report renders the finalized v2 capture document
    // (policy None => report shape), never the historical v1
    // projection. PRD §14.1: the live producer schema is
    // observed-crypto-v2.1; v1 fixtures are history.
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
            // every requested artifact from a typed no-evidence
            // document instead of returning with nothing written.
            err_line(&format!("osslscope report: {e:#}"));
            err_line("osslscope report: run 'osslscope doctor' to diagnose environment failures");
            let document =
                setup_failure_document(FatalKind::Environment(bound_line(&format!("{e:#}"))));
            let delivery = write_artifacts(&document, &req);
            emit_diagnostics(&delivery);
            return ExitCode::from(exit_for(
                crate::policy::PolicyOutcome::NoVerdict,
                None,
                &document,
                &delivery,
            ));
        }
    };
    let delivery = write_artifacts(&c.document, &req);
    emit_diagnostics(&delivery);
    // H9/R07 T4: nonzero child exit with discarded output → one
    // diagnostic line (exit + re-run hint, never workload bytes).
    if let Some(hint) = workload_hint(c.child_exit, workload_discarded) {
        err_line(&hint);
    }
    // F-E/B3: report resolves through the shared exit table (fatal
    // capture maps to no-verdict so it dominates at 4).
    let outcome = match &c.outcome {
        capture::Outcome::Fatal(_) => crate::policy::PolicyOutcome::NoVerdict,
        capture::Outcome::Partial | capture::Outcome::Complete => {
            crate::policy::PolicyOutcome::Pass
        }
    };
    ExitCode::from(exit_for(outcome, c.child_exit, &c.document, &delivery))
}

// ---------------------------------------------------------------- v2 output
//
// T11 v2 human/JSON/CBOM API. T10 codes against these signatures;
// they are declared here before any T10 wiring exists. All renders
// take the finalized [`crate::evidence::CaptureDocument`] for one
// window: report shape when `policy` is None, check shape (with the
// `policy` section) when T10 sets it. No second capture is ever
// needed to produce additional artifacts from the same document.

use crate::evidence::CaptureDocument;
use crate::evidence::{
    CandidateCoverage, Completeness, CounterKind, CounterSource, CounterUnits, DispositionOutcome,
    ExpectedScope, FatalKind, GapReason, OpensslVersionState, PolicyVerdict, RuleVerdict,
    SiteExecution,
};

/// Primary artifact format for [`OutputRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

/// Artifact destination: process stdout or a file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputDest {
    Stdout,
    File(std::path::PathBuf),
}

/// Requested v2 artifacts from one finalized document (single
/// window): the primary report plus an optional CBOM sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRequest {
    pub format: OutputFormat,
    pub primary: OutputDest,
    pub cbom: Option<OutputDest>,
}

/// Per-artifact delivery outcome. `error` is a bounded one-line
/// summary, never a dump; `bytes` counts delivered bytes (0 unless
/// the full artifact was written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactOutcome {
    pub dest: String,
    pub ok: bool,
    pub bytes: u64,
    pub error: Option<String>,
}

/// Delivery result for one [`write_artifacts`] call: every requested
/// artifact was attempted independently (a failed primary never
/// suppresses the CBOM attempt and vice versa). T10 maps this onto
/// the R06 exit table: a proved violation stays exit 10 even when
/// delivery failed; otherwise any failure is exit 1. `diagnostics`
/// go to stderr (bounded: at most 8 lines, 200 chars each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    pub primary: ArtifactOutcome,
    pub cbom: Option<ArtifactOutcome>,
    pub diagnostics: Vec<String>,
}

impl DeliveryResult {
    /// True when any requested artifact failed delivery.
    pub fn failed(&self) -> bool {
        !self.primary.ok || self.cbom.as_ref().is_some_and(|c| !c.ok)
    }

    /// True when every requested artifact was delivered.
    pub fn delivered_all(&self) -> bool {
        !self.failed()
    }
}

/// Render the v2 JSON artifact (`observed-crypto-v2.1`) for one
/// finalized document: sorted keys, pretty-printed, trailing
/// newline. Sites carry conserved per-site counts with candidate
/// uncertainty; target/openssl/window/coverage/losses/disposition
/// and the optional policy section ride along. Validates against
/// `schemas/observed-crypto-v2.json`.
pub fn render_json(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>> {
    let mut out = serde_json::to_vec_pretty(&doc_json(doc))?;
    out.push(b'\n');
    Ok(out)
}

fn status_str(doc: &CaptureDocument) -> &'static str {
    match &doc.status {
        Completeness::Complete => "COMPLETE",
        Completeness::Partial { .. } => "PARTIAL",
        Completeness::Fatal { .. } => "FATAL",
    }
}

fn counter_kind_str(kind: CounterKind) -> &'static str {
    match kind {
        CounterKind::Loss => "loss",
        CounterKind::Activity => "activity",
    }
}

fn counter_units_str(units: CounterUnits) -> &'static str {
    match units {
        CounterUnits::Calls => "calls",
        CounterUnits::Sites => "sites",
        CounterUnits::TableRows => "table-rows",
        CounterUnits::Events => "events",
        CounterUnits::Probes => "probes",
    }
}

fn counter_source_str(source: CounterSource) -> &'static str {
    match source {
        CounterSource::KernelRing => "kernel-ring",
        CounterSource::KernelMap => "kernel-map",
        CounterSource::Discovery => "discovery",
        CounterSource::Attach => "attach",
        CounterSource::Drain => "drain",
        CounterSource::Lifecycle => "lifecycle",
        CounterSource::Setup => "setup",
    }
}

fn gap_reason_json(reason: &GapReason) -> serde_json::Value {
    match reason {
        GapReason::UnknownDenominator { scope } => {
            serde_json::json!({"kind": "unknown-denominator", "scope": scope})
        }
        GapReason::UndiscoveredSites { scope, missing } => {
            serde_json::json!({"kind": "undiscovered-sites", "scope": scope, "missing": missing})
        }
        GapReason::UnattachedSites { scope, missing } => {
            serde_json::json!({"kind": "unattached-sites", "scope": scope, "missing": missing})
        }
        GapReason::Loss {
            counter,
            source,
            value,
        } => serde_json::json!({
            "kind": "loss",
            "counter": counter,
            "source": counter_source_str(*source),
            "value": value,
        }),
        GapReason::UnattributedCalls { sites, calls } => {
            serde_json::json!({"kind": "unattributed-calls", "sites": sites, "calls": calls})
        }
        GapReason::StartupGap { missing_ns } => {
            serde_json::json!({"kind": "startup-gap", "missing_ns": missing_ns})
        }
        GapReason::TailGap { missing_ns } => {
            serde_json::json!({"kind": "tail-gap", "missing_ns": missing_ns})
        }
        GapReason::SignalCut => serde_json::json!({"kind": "signal-cut"}),
    }
}

fn site_json(site: &SiteExecution) -> serde_json::Value {
    let mut out = serde_json::json!({
        "object": site.site.object.0,
        "device": site.site.device,
        "inode": site.site.inode,
        "offset": site.site.offset,
        "generation": site.generation,
        "candidates": site.candidates.iter().map(|c| serde_json::json!({
            "provider": c.provider.0,
            "provider_class": c.provider_class,
            "op": c.op,
            "funcid": c.funcid,
            "algorithm_classes": c.algorithm_classes,
            "weak_alias": c.weak_alias,
        })).collect::<Vec<_>>(),
        "candidates_coverage": match site.candidates_coverage {
            CandidateCoverage::Complete => "complete",
            CandidateCoverage::Unknown => "unknown",
        },
        "calls": site.calls,
        "first_ns": site.first_ns,
        "last_ns": site.last_ns,
    });
    // v2.1: minors add optional keys only — absent when the
    // producer never recorded the cookie's install wall (v2.0
    // documents keep validating).
    if let Some(at) = site.installed_at {
        out["installed_at"] = serde_json::json!(at);
    }
    out
}

fn rule_verdict_str(verdict: RuleVerdict) -> &'static str {
    match verdict {
        RuleVerdict::Pass => "pass",
        RuleVerdict::Violation => "violation",
        RuleVerdict::Inconclusive => "inconclusive",
    }
}

fn doc_json(doc: &CaptureDocument) -> serde_json::Value {
    let fatal_kind = match &doc.status {
        Completeness::Fatal {
            kind: FatalKind::Recycled,
            ..
        } => serde_json::json!({"kind": "recycled", "detail": null}),
        Completeness::Fatal {
            kind: FatalKind::AttachZero,
            ..
        } => serde_json::json!({"kind": "attach-zero", "detail": null}),
        Completeness::Fatal {
            kind: FatalKind::Environment(detail),
            ..
        } => serde_json::json!({"kind": "environment", "detail": detail}),
        Completeness::Fatal {
            kind: FatalKind::Runtime(detail),
            ..
        } => serde_json::json!({"kind": "runtime", "detail": detail}),
        _ => serde_json::Value::Null,
    };
    let mut out = serde_json::json!({
        "schema_version": "observed-crypto-v2.1",
        "target": {
            "pid": doc.target.pid,
            "comm": doc.target.comm,
            "container_id": doc.target.container_id,
            "image_digest": doc.target.image_digest,
            "argv_redacted": true,
        },
        "openssl": {
            "state": match doc.openssl.state {
                OpensslVersionState::Verified => "verified",
                OpensslVersionState::Unknown => "unknown",
            },
            "version": doc.openssl.version.clone(),
        },
        "window": {
            "requested_start_ns": doc.window.requested_start_ns,
            "requested_end_ns": doc.window.requested_end_ns,
            "effective_start_ns": doc.window.effective_start_ns,
            "effective_end_ns": doc.window.effective_end_ns,
            "signal_cut": doc.window.signal_cut,
        },
        "completeness": {
            "status": status_str(doc),
            "fatal_kind": fatal_kind,
            "reasons": doc.reasons().iter().map(gap_reason_json).collect::<Vec<_>>(),
            "counters": doc.counters.iter().map(|c| serde_json::json!({
                "name": c.name,
                "kind": counter_kind_str(c.kind),
                "units": counter_units_str(c.units),
                "source": counter_source_str(c.source),
                "value": c.value,
            })).collect::<Vec<_>>(),
        },
        "sites": doc.sites.iter().map(site_json).collect::<Vec<_>>(),
        "fenced": doc.fenced.iter().map(|bucket| serde_json::json!({
            "generation": bucket.generation,
            "sites": bucket.sites.iter().map(site_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "objects": doc.objects.iter().map(|o| serde_json::json!({
            "id": o.id.0,
            "device": o.device,
            "inode": o.inode,
            "display_locator": o.display_locator,
        })).collect::<Vec<_>>(),
        "coverage": doc.coverage.iter().map(|c| {
            let (state, sites) = match &c.expected {
                ExpectedScope::Applicable { sites } => ("applicable", Some(*sites)),
                ExpectedScope::NotApplicable => ("not-applicable", None),
                ExpectedScope::Unknown => ("unknown", None),
            };
            serde_json::json!({
                "scope": c.scope,
                "expected": {"state": state, "sites": sites},
                "discovered": c.discovered,
                "attached": c.attached,
            })
        }).collect::<Vec<_>>(),
        "legacy_partition": serde_json::json!({
            "legacy_exclusive_calls": doc.legacy_partition.legacy_exclusive,
            "non_legacy_exclusive_calls": doc.legacy_partition.non_legacy_exclusive,
            "shared_ambiguous_calls": doc.legacy_partition.shared_ambiguous,
            "unfenced_tail_calls": doc.legacy_partition.unfenced_tails,
        }),
    });
    // Report/check convention (v1-compatible): unevaluated policy
    // and unrecorded disposition omit their sections.
    // v2.1 traversal: runs without the members backend omit the
    // section; traversal runs name the exact selected triple
    // (paths + sha256 — the same provenance doctor verifies).
    if let Some(t) = &doc.traversal {
        let obj = |o: &crate::evidence::TraversalObject| serde_json::json!({"path": o.path, "sha256": o.sha256});
        out["traversal"] = serde_json::json!({
            "harvest": obj(&t.harvest),
            "count": obj(&t.count),
            "members": obj(&t.members),
            "records": t.records,
            "findings": t.findings,
            "polls": t.polls,
        });
    }
    if let Some(disposition) = &doc.disposition {
        let (outcome, code, pid) = match disposition.outcome {
            DispositionOutcome::Exited => ("exited", disposition.code, None),
            DispositionOutcome::DetachedRunning => ("detached-running", None, disposition.pid),
            DispositionOutcome::ForeignObserved => ("foreign-observed", None, disposition.pid),
        };
        out["disposition"] = serde_json::json!({
            "outcome": outcome,
            "code": code,
            "pid": pid,
        });
    }
    if let Some(policy) = &doc.policy {
        out["policy"] = serde_json::json!({
            "verdict": match policy.verdict {
                PolicyVerdict::Pass => "pass",
                PolicyVerdict::Violation => "violation",
                PolicyVerdict::Inconclusive => "inconclusive",
                PolicyVerdict::NoVerdict => "no-verdict",
            },
            "rules": policy.rules.iter().map(|r| serde_json::json!({
                "rule": r.rule,
                "predicate": r.predicate,
                "result": rule_verdict_str(r.result),
                "definite": r.definite,
                "possible": r.possible,
                "evidence": r.evidence.iter().map(|e| serde_json::json!({
                    "object": e.object.0,
                    "device": e.device,
                    "inode": e.inode,
                    "offset": e.offset,
                    "generation": e.generation,
                    "calls": e.calls,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
    }
    out
}

/// Render the v2 human artifact for one finalized document:
/// callback counts with explicit definite/ambiguous/unattributed
/// attribution, verified-or-unknown OpenSSL version, coverage,
/// source-tagged losses, disposition and safe actionability
/// (`argv_redacted`, no raw argv or addresses).
pub fn render_human(doc: &CaptureDocument) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "osslscope report (observed-crypto-v2.1): pid={} ({}) window={}..{}ns effective={}..{}ns\n",
        doc.target.pid,
        doc.target.comm,
        doc.window.requested_start_ns,
        doc.window.requested_end_ns,
        doc.window.effective_start_ns,
        doc.window.effective_end_ns,
    ));
    match (&doc.openssl.state, &doc.openssl.version) {
        (OpensslVersionState::Verified, Some(version)) => {
            s.push_str(&format!("openssl: {version} (verified object metadata)\n"));
        }
        _ => s.push_str("openssl: unknown (no verified version)\n"),
    }
    let or_none = |text: &str| {
        if text.is_empty() {
            "(none)".to_string()
        } else {
            text.to_string()
        }
    };
    s.push_str(&format!(
        "target: argv_redacted=true container_id={} image_digest={}\n",
        or_none(&doc.target.container_id),
        or_none(&doc.target.image_digest),
    ));
    match &doc.disposition {
        Some(d) if d.outcome == DispositionOutcome::Exited => {
            s.push_str(&format!(
                "disposition: exited code={}\n",
                d.code.unwrap_or(0)
            ));
        }
        Some(d) if d.outcome == DispositionOutcome::DetachedRunning => {
            s.push_str(&format!(
                "disposition: detached-running pid={}\n",
                d.pid.unwrap_or(0)
            ));
        }
        Some(d) => {
            s.push_str(&format!(
                "disposition: foreign-observed pid={}\n",
                d.pid.unwrap_or(0)
            ));
        }
        None => s.push_str("disposition: unknown (not recorded)\n"),
    }
    s.push('\n');
    // Sites: conserved per-site counts; attribution is definite
    // only for a complete set with one agreed algorithm.
    let fenced_sites: usize = doc.fenced.iter().map(|g| g.sites.len()).sum();
    if fenced_sites == 0 {
        s.push_str(&format!(
            "sites ({}, {} calls):\n",
            doc.sites.len(),
            grouped(doc.total_calls()),
        ));
    } else {
        s.push_str(&format!(
            "sites ({} current + {} fenced, {} calls):\n",
            doc.sites.len(),
            fenced_sites,
            grouped(doc.total_calls()),
        ));
    }
    if doc.sites.is_empty() && fenced_sites == 0 {
        s.push_str("  none (no usable evidence)\n");
    }
    for site in &doc.sites {
        human_site(site, &mut s);
    }
    s.push('\n');
    if !doc.fenced.is_empty() {
        s.push_str("fenced generations:\n");
        for bucket in &doc.fenced {
            s.push_str(&format!(
                "  gen {}: {} sites, {} calls (detail in JSON)\n",
                bucket.generation,
                bucket.sites.len(),
                grouped(SiteExecution::sum_calls(&bucket.sites)),
            ));
        }
        s.push('\n');
    }
    s.push_str("coverage:\n");
    if doc.coverage.is_empty() {
        s.push_str("  none recorded\n");
    }
    for scope in &doc.coverage {
        match &scope.expected {
            ExpectedScope::Applicable { sites } => {
                let state = if scope.is_complete() {
                    "complete"
                } else {
                    "gap"
                };
                s.push_str(&format!(
                    "  {}: expected={} discovered={} attached={} ({state})\n",
                    scope.scope, sites, scope.discovered, scope.attached,
                ));
            }
            ExpectedScope::NotApplicable => {
                s.push_str(&format!("  {}: not applicable\n", scope.scope));
            }
            ExpectedScope::Unknown => {
                s.push_str(&format!(
                    "  {}: expected=UNKNOWN discovered={} attached={} (gap)\n",
                    scope.scope, scope.discovered, scope.attached,
                ));
            }
        }
    }
    s.push('\n');
    // Loss counters always show (even zero: the observer checked);
    // activity counters show when nonzero.
    s.push_str("counters:\n");
    let mut shown = 0;
    for counter in &doc.counters {
        if counter.kind == CounterKind::Activity && counter.value == 0 {
            continue;
        }
        shown += 1;
        s.push_str(&format!(
            "  {} {} ({} from {}) = {}\n",
            counter_kind_str(counter.kind),
            counter.name,
            counter_units_str(counter.units),
            counter_source_str(counter.source),
            grouped(counter.value),
        ));
    }
    if shown == 0 {
        s.push_str("  none recorded\n");
    }
    s.push('\n');
    s.push_str(&format!("completeness: {}\n", status_str(doc)));
    s.push('\n');
    if let Completeness::Fatal { kind, .. } = &doc.status {
        match kind {
            FatalKind::Recycled => {
                s.push_str("fatal: recycled (pid reused mid-window; all observations discarded)\n");
            }
            FatalKind::AttachZero => {
                s.push_str("fatal: attach-zero (no probes attached; no usable evidence)\n");
            }
            FatalKind::Environment(detail) => {
                s.push_str(&format!("fatal: environment: {detail}\n"));
            }
            FatalKind::Runtime(detail) => {
                s.push_str(&format!("fatal: runtime: {detail}\n"));
            }
        }
        s.push('\n');
    }
    if !doc.reasons().is_empty() {
        s.push_str("reasons:\n");
        for reason in doc.reasons() {
            s.push_str(&format!("  - {}\n", gap_reason_human(reason)));
        }
        s.push('\n');
    }
    match &doc.policy {
        None => s.push_str("policy: (not evaluated)\n"),
        Some(policy) => {
            let verdict = match policy.verdict {
                PolicyVerdict::Pass => "pass",
                PolicyVerdict::Violation => "violation",
                PolicyVerdict::Inconclusive => "inconclusive",
                PolicyVerdict::NoVerdict => "no-verdict",
            };
            s.push_str(&format!("policy: {verdict}\n"));
            for rule in &policy.rules {
                let possible = rule
                    .possible
                    .map(grouped)
                    .unwrap_or_else(|| "unknown".to_string());
                s.push_str(&format!(
                    "  rule {} ({}): {} (definite={}, possible={possible})\n",
                    rule.rule,
                    rule.predicate,
                    rule_verdict_str(rule.result),
                    grouped(rule.definite),
                ));
                for evidence in &rule.evidence {
                    s.push_str(&format!(
                        "    evidence: {} file-offset={} gen={} ({} calls)\n",
                        fp_short(&evidence.object.0),
                        evidence.offset,
                        evidence.generation,
                        grouped(evidence.calls),
                    ));
                }
            }
        }
    }
    s.push('\n');
    s.push_str(&format!("status={}\n", status_str(doc)));
    s.push_str("absence = not-observed in window (never \"not present / never used\")\n");
    s.push_str("note: argv redacted; file offsets are not runtime addresses; window-only claims\n");
    s
}

/// First 12 characters of an object fingerprint for display
/// (char-boundary cut: fingerprints are opaque strings, never
/// assumed ASCII).
fn fp_short(fp: &str) -> String {
    fp.chars().take(12).collect()
}

/// Attribution summary shared by the human render and the CBOM
/// definite-asset rule: `Some` only when the site executed, its
/// candidate set is complete, and every candidate agrees on
/// provider, class, op, funcid and one single *resolved* algorithm
/// class (the `other` bucket never qualifies). `weak_alias` may
/// vary (surfaced, not silently dropped).
struct DefiniteAsset {
    algorithm: String,
    provider: String,
    provider_class: String,
    op: u32,
    funcid: u32,
    weak: bool,
}

fn definite_asset(site: &SiteExecution) -> Option<DefiniteAsset> {
    if site.calls == 0 || site.candidates_coverage != CandidateCoverage::Complete {
        return None;
    }
    let first = site.candidates.first()?;
    if first.algorithm_classes.len() != 1 {
        return None;
    }
    // The unresolved bucket is never a definite asset: a candidate
    // carrying `other` proves neither a match nor an absence
    // (`crate::policy::UNRESOLVED_ALGORITHM_CLASS`).
    if first.algorithm_classes[0] == crate::policy::UNRESOLVED_ALGORITHM_CLASS {
        return None;
    }
    for candidate in &site.candidates[1..] {
        if candidate.provider != first.provider
            || candidate.provider_class != first.provider_class
            || candidate.op != first.op
            || candidate.funcid != first.funcid
            || candidate.algorithm_classes != first.algorithm_classes
        {
            return None;
        }
    }
    Some(DefiniteAsset {
        algorithm: first.algorithm_classes[0].clone(),
        provider: first.provider.0.clone(),
        provider_class: first.provider_class.clone(),
        op: first.op,
        funcid: first.funcid,
        weak: site.candidates.iter().any(|c| c.weak_alias),
    })
}

fn human_site(site: &SiteExecution, s: &mut String) {
    s.push_str(&format!(
        "  site {} file-offset={} gen={}: {} calls, ",
        fp_short(&site.site.object.0),
        site.site.offset,
        site.generation,
        grouped(site.calls),
    ));
    if site.calls == 0 {
        s.push_str("quiet (no calls in window)\n");
        return;
    }
    if site.candidates_coverage == CandidateCoverage::Unknown {
        s.push_str("UNATTRIBUTED (candidate set incomplete)\n");
        return;
    }
    if let Some(asset) = definite_asset(site) {
        s.push_str(&format!(
            "definite: {} ({}) via {}{}\n",
            asset.algorithm,
            op_display(asset.op),
            asset.provider_class,
            if asset.weak { " [weak alias]" } else { "" },
        ));
        return;
    }
    if site.candidates.is_empty() {
        s.push_str("UNATTRIBUTED (no candidates)\n");
        return;
    }
    // Complete set, unresolvable algorithm class: the provider, op
    // and funcid below are certain, the algorithm is not.
    if site.candidates.iter().all(|c| {
        c.algorithm_classes.len() == 1
            && c.algorithm_classes[0] == crate::policy::UNRESOLVED_ALGORITHM_CLASS
    }) {
        s.push_str(&format!(
            "UNRESOLVED ({} {}, algorithm class unresolvable):\n",
            site.candidates.len(),
            plural(site.candidates.len(), "candidate"),
        ));
        human_candidates(site, s);
        return;
    }
    s.push_str(&format!(
        "AMBIGUOUS ({} {}, attribution uncertain):\n",
        site.candidates.len(),
        plural(site.candidates.len(), "candidate"),
    ));
    human_candidates(site, s);
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

fn human_candidates(site: &SiteExecution, s: &mut String) {
    for candidate in &site.candidates {
        s.push_str(&format!(
            "    candidate: provider={} class={} op={} funcid={} algs=[{}]{}\n",
            fp_short(&candidate.provider.0),
            candidate.provider_class,
            op_display(candidate.op),
            candidate.funcid,
            candidate.algorithm_classes.join(", "),
            if candidate.weak_alias { " weak" } else { "" },
        ));
    }
}

fn gap_reason_human(reason: &GapReason) -> String {
    match reason {
        GapReason::UnknownDenominator { scope } => {
            format!("unknown-denominator: {scope} (expected sites unknowable, never complete)")
        }
        GapReason::UndiscoveredSites { scope, missing } => {
            format!("undiscovered-sites: {scope} missing={missing}")
        }
        GapReason::UnattachedSites { scope, missing } => {
            format!("unattached-sites: {scope} missing={missing}")
        }
        GapReason::Loss {
            counter,
            source,
            value,
        } => format!(
            "loss: {counter} ({}) = {}",
            counter_source_str(*source),
            grouped(*value),
        ),
        GapReason::UnattributedCalls { sites, calls } => {
            format!(
                "unattributed-calls: {sites} sites, {} calls (candidate sets incomplete)",
                grouped(*calls),
            )
        }
        GapReason::StartupGap { missing_ns } => {
            format!("startup-gap: {missing_ns}ns unobserved at window start")
        }
        GapReason::TailGap { missing_ns } => {
            format!("tail-gap: {missing_ns}ns unobserved at window end")
        }
        GapReason::SignalCut => "signal-cut: window ended by signal".to_string(),
    }
}

/// Render the v2 CycloneDX CBOM for one finalized document:
/// definite algorithm assets only (one component per definite site,
/// never one per candidate); omitted ambiguous counts plus evidence
/// references stay explicit metadata. Same window on
/// pass/violation/PARTIAL/inconclusive; explicit empty/fatal
/// artifact when no evidence exists.
pub fn render_cbom(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>> {
    let mut out = serde_json::to_vec_pretty(&cbom_json(doc))?;
    out.push(b'\n');
    Ok(out)
}

/// Omitted-site evidence ref for CBOM metadata: short fingerprint,
/// decimal file offset, generation and calls (bounded count at the
/// call site; never a runtime address).
fn omitted_ref(site: &SiteExecution) -> String {
    format!(
        "{}@{}#{}:{}",
        fp_short(&site.site.object.0),
        site.site.offset,
        site.generation,
        site.calls,
    )
}

/// Short gap vocabulary for the CBOM disclaimer line.
fn gap_reason_short(reason: &GapReason) -> String {
    match reason {
        GapReason::UnknownDenominator { scope } => format!("unknown-denominator:{scope}"),
        GapReason::UndiscoveredSites { scope, .. } => format!("undiscovered-sites:{scope}"),
        GapReason::UnattachedSites { scope, .. } => format!("unattached-sites:{scope}"),
        GapReason::Loss { counter, .. } => format!("loss:{counter}"),
        GapReason::UnattributedCalls { .. } => "unattributed-calls".to_string(),
        GapReason::StartupGap { .. } => "startup-gap".to_string(),
        GapReason::TailGap { .. } => "tail-gap".to_string(),
        GapReason::SignalCut => "signal-cut".to_string(),
    }
}

/// Sanitize an algorithm class for `bom-ref` embedding (classes are
/// operator-visible strings; only URI-safe characters survive).
fn bom_slug(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn cbom_json(doc: &CaptureDocument) -> serde_json::Value {
    let fatal = matches!(doc.status, Completeness::Fatal { .. });
    let prop = |name: &str, value: String| serde_json::json!({"name": name, "value": value});
    let window_props = || {
        vec![
            prop(
                "osslscope:window-requested-start-ns",
                doc.window.requested_start_ns.to_string(),
            ),
            prop(
                "osslscope:window-requested-end-ns",
                doc.window.requested_end_ns.to_string(),
            ),
            prop(
                "osslscope:window-effective-start-ns",
                doc.window.effective_start_ns.to_string(),
            ),
            prop(
                "osslscope:window-effective-end-ns",
                doc.window.effective_end_ns.to_string(),
            ),
        ]
    };
    // One component per definite site (current + fenced); ambiguous,
    // unknown-coverage and quiet sites contribute none. FATAL
    // carries no components at all: the evidence is unusable.
    let mut components: Vec<serde_json::Value> = Vec::new();
    let mut omitted_ambiguous_sites = 0u64;
    let mut omitted_ambiguous_calls = 0u64;
    let mut omitted_unknown_sites = 0u64;
    let mut omitted_unknown_calls = 0u64;
    let mut omitted_refs: Vec<String> = Vec::new();
    if !fatal {
        let mut visit = |site: &SiteExecution| {
            if site.calls == 0 {
                return;
            }
            if site.candidates_coverage == CandidateCoverage::Unknown {
                omitted_unknown_sites += 1;
                omitted_unknown_calls = omitted_unknown_calls.saturating_add(site.calls);
                omitted_refs.push(omitted_ref(site));
                return;
            }
            let Some(asset) = definite_asset(site) else {
                omitted_ambiguous_sites += 1;
                omitted_ambiguous_calls = omitted_ambiguous_calls.saturating_add(site.calls);
                omitted_refs.push(omitted_ref(site));
                return;
            };
            let mut props = vec![
                prop("osslscope:algorithm", asset.algorithm.clone()),
                prop("osslscope:provider-class", asset.provider_class.clone()),
                prop("osslscope:provider-object", asset.provider.clone()),
                prop("osslscope:backing-object", site.site.object.0.clone()),
                prop("osslscope:op", op_display(asset.op)),
                prop("osslscope:funcid", asset.funcid.to_string()),
                prop("osslscope:calls", site.calls.to_string()),
                prop("osslscope:generation", site.generation.to_string()),
                prop(
                    "osslscope:weak-alias",
                    if asset.weak { "true" } else { "false" }.to_string(),
                ),
                prop(
                    "osslscope:execution-evidence-completeness",
                    status_str(doc).to_string(),
                ),
            ];
            props.extend(window_props());
            components.push(serde_json::json!({
                "bom-ref": format!(
                    "urn:osslscope:exec:v2:{}:{}:{}:{}:{}:{}",
                    site.generation,
                    site.site.device,
                    site.site.inode,
                    site.site.offset,
                    site.site.object.0,
                    bom_slug(&asset.algorithm),
                ),
                "type": "cryptographic-asset",
                "name": format!(
                    "{} ({}) via {}",
                    asset.algorithm,
                    op_display(asset.op),
                    asset.provider_class,
                ),
                "cryptoProperties": {"assetType": "algorithm"},
                "properties": props,
            }));
        };
        for site in &doc.sites {
            visit(site);
        }
        for bucket in &doc.fenced {
            for site in &bucket.sites {
                visit(site);
            }
        }
    }
    // Omitted refs stay explicit but bounded (16 refs, then a count).
    let refs_value = if omitted_refs.len() <= 16 {
        omitted_refs.join(",")
    } else {
        format!(
            "{},+{} more",
            omitted_refs[..16].join(","),
            omitted_refs.len() - 16,
        )
    };
    let mut metadata = vec![
        prop(
            "osslscope:schema-version",
            "observed-crypto-v2.1".to_string(),
        ),
        prop(
            "osslscope:execution-evidence-completeness",
            status_str(doc).to_string(),
        ),
        prop(
            "osslscope:omitted-ambiguous-sites",
            omitted_ambiguous_sites.to_string(),
        ),
        prop(
            "osslscope:omitted-ambiguous-calls",
            omitted_ambiguous_calls.to_string(),
        ),
        prop(
            "osslscope:omitted-unknown-coverage-sites",
            omitted_unknown_sites.to_string(),
        ),
        prop(
            "osslscope:omitted-unknown-coverage-calls",
            omitted_unknown_calls.to_string(),
        ),
        prop("osslscope:omitted-evidence-refs", refs_value),
    ];
    metadata.extend(window_props());
    if let Some(policy) = &doc.policy {
        metadata.push(prop(
            "osslscope:policy-verdict",
            match policy.verdict {
                PolicyVerdict::Pass => "pass",
                PolicyVerdict::Violation => "violation",
                PolicyVerdict::Inconclusive => "inconclusive",
                PolicyVerdict::NoVerdict => "no-verdict",
            }
            .to_string(),
        ));
    }
    match &doc.status {
        Completeness::Complete => {}
        Completeness::Partial { .. } => {
            let why = doc
                .reasons()
                .iter()
                .map(gap_reason_short)
                .collect::<Vec<_>>()
                .join(",");
            let mut disclaimer = format!(
                "PARTIAL evidence ({}); absence = not-observed in window",
                if why.is_empty() { "unknown" } else { &why },
            );
            if disclaimer.chars().count() > 2000 {
                disclaimer = format!("{}...", disclaimer.chars().take(1997).collect::<String>());
            }
            metadata.push(prop("osslscope:completeness-disclaimer", disclaimer));
        }
        Completeness::Fatal { kind, .. } => {
            let why = doc
                .reasons()
                .iter()
                .map(gap_reason_short)
                .collect::<Vec<_>>()
                .join(",");
            let why = if why.is_empty() {
                match kind {
                    FatalKind::Recycled => "recycled",
                    FatalKind::AttachZero => "attach-zero",
                    FatalKind::Environment(_) => "environment",
                    FatalKind::Runtime(_) => "runtime",
                }
                .to_string()
            } else {
                why
            };
            metadata.push(prop(
                "osslscope:completeness-disclaimer",
                format!("FATAL: no usable evidence ({why})"),
            ));
        }
    }
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"properties": metadata},
        "components": components,
    })
}

/// Bound a diagnostic to one line of at most 200 chars (destinations
/// and OS errors are operator data, never trusted for length).
pub(crate) fn bound_line(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if flat.chars().count() <= 200 {
        return flat;
    }
    format!("{}...", flat.chars().take(197).collect::<String>())
}

fn dest_display(dest: &OutputDest) -> String {
    match dest {
        OutputDest::Stdout => "stdout".to_string(),
        OutputDest::File(path) => path.display().to_string(),
    }
}

fn write_dest(dest: &OutputDest, bytes: &[u8]) -> ArtifactOutcome {
    let display = dest_display(dest);
    let result = match dest {
        OutputDest::Stdout => {
            use std::io::Write;
            std::io::stdout()
                .write_all(bytes)
                .and_then(|()| std::io::stdout().flush())
        }
        OutputDest::File(path) => std::fs::write(path, bytes),
    };
    match result {
        Ok(()) => ArtifactOutcome {
            dest: display,
            ok: true,
            bytes: bytes.len() as u64,
            error: None,
        },
        Err(e) => ArtifactOutcome {
            dest: display,
            ok: false,
            bytes: 0,
            error: Some(bound_line(&e.to_string())),
        },
    }
}

fn render_failed_outcome(dest: &OutputDest, detail: &str) -> ArtifactOutcome {
    ArtifactOutcome {
        dest: dest_display(dest),
        ok: false,
        bytes: 0,
        error: Some(bound_line(detail)),
    }
}

/// Typed no-evidence document for capture setup failures (F-E/B4).
/// `report`/`check` convert a `capture::run` error into this fatal
/// document and attempt every requested artifact from it, instead of
/// returning with nothing written. Zero window (nothing was
/// observed), unknown target/toolchain, caller attaches the policy
/// section for the check shape.
pub fn setup_failure_document(fatal: FatalKind) -> CaptureDocument {
    use crate::evidence::{
        CaptureWindow, FinalizeInput, LegacyCallPartition, OpensslVersion, TargetRecord, finalize,
    };
    finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: Some(fatal),
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        traversal: None,
    })
}

/// Deliver requested artifacts from one finalized document: render
/// once per format, attempt every destination independently, and
/// return per-artifact outcomes plus bounded stderr diagnostics.
pub fn write_artifacts(doc: &CaptureDocument, req: &OutputRequest) -> DeliveryResult {
    // Primary + CBOM to the same sink would concatenate (stdout)
    // or overwrite (same file): refuse the CBOM side while the
    // primary still delivers. Path comparison is lexical; distinct
    // spellings of one file are the caller's responsibility.
    let same_sink = match &req.cbom {
        None => false,
        Some(dest) => req.primary == *dest,
    };
    let primary_render: Result<Vec<u8>, String> = match req.format {
        OutputFormat::Human => Ok(render_human(doc).into_bytes()),
        OutputFormat::Json => render_json(doc).map_err(|e| format!("render failed: {e:#}")),
    };
    let cbom_render: Option<Result<Vec<u8>, String>> = match (&req.cbom, same_sink) {
        (Some(_), false) => Some(render_cbom(doc).map_err(|e| format!("render failed: {e:#}"))),
        _ => None,
    };
    let primary = match primary_render {
        Ok(bytes) => write_dest(&req.primary, &bytes),
        Err(detail) => render_failed_outcome(&req.primary, &detail),
    };
    let cbom = match (&req.cbom, cbom_render) {
        (None, _) => None,
        (Some(dest), None) => Some(ArtifactOutcome {
            dest: dest_display(dest),
            ok: false,
            bytes: 0,
            error: Some(
                "cbom and primary target the same sink (refused: artifacts would concatenate or overwrite)"
                    .to_string(),
            ),
        }),
        (Some(dest), Some(Ok(bytes))) => Some(write_dest(dest, &bytes)),
        (Some(dest), Some(Err(detail))) => Some(render_failed_outcome(dest, &detail)),
    };
    let mut diagnostics = Vec::new();
    if !primary.ok {
        diagnostics.push(format!(
            "primary {}: {}",
            primary.dest,
            primary.error.as_deref().unwrap_or("failed"),
        ));
    }
    if let Some(outcome) = &cbom {
        if !outcome.ok {
            diagnostics.push(format!(
                "cbom {}: {}",
                outcome.dest,
                outcome.error.as_deref().unwrap_or("failed"),
            ));
        }
    }
    let diagnostics: Vec<String> = diagnostics
        .into_iter()
        .map(|line| bound_line(&line))
        .take(8)
        .collect();
    DeliveryResult {
        primary,
        cbom,
        diagnostics,
    }
}

/// Render bounded delivery diagnostics into any sink (H7/B-7):
/// the sink error surfaces to the caller (tests observe it); the
/// CLI wrapper below discards it — diagnostics are advisory and
/// must never perturb the exit nor panic (no 101).
pub fn emit_diagnostics_to(
    writer: &mut dyn std::io::Write,
    result: &DeliveryResult,
) -> std::io::Result<()> {
    for line in &result.diagnostics {
        writeln!(writer, "osslscope: {line}")?;
    }
    Ok(())
}

/// Emit bounded delivery diagnostics to stderr (T10 calls this after
/// [`write_artifacts`]; the same strings are in
/// [`DeliveryResult::diagnostics`] for tests). A broken stderr
/// degrades to silence, never to a panic.
pub fn emit_diagnostics(result: &DeliveryResult) {
    let stderr = std::io::stderr();
    let mut locked = stderr.lock();
    let _ = emit_diagnostics_to(&mut locked, result);
}

/// One CLI error line to locked stderr, panic-free (H7/B-7): every
/// CLI error-path print goes through here so a broken stderr
/// degrades to silence, never to exit 101. Deliberately infallible
/// (the `let _` is the design, not a swallow — see the T6 audit).
pub fn err_line(text: &str) {
    use std::io::Write as _;
    let stderr = std::io::stderr();
    let mut locked = stderr.lock();
    let _ = writeln!(locked, "{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h9_t4_hint_names_exit_and_rerun_only_when_discarded() {
        // T4 (RED): nonzero child exit without a workload
        // destination → one line naming the exit + the re-run
        // hint. Clean exits, foreign pids, and explicit
        // destinations stay silent.
        let hint = workload_hint(Some(7), true).expect("hint on nonzero+discarded");
        assert!(hint.contains('7'), "names the exit: {hint}");
        assert!(hint.contains("--workload-out"), "re-run hint: {hint}");
        assert!(!hint.contains('\n'), "one line: {hint}");
        assert!(workload_hint(Some(0), true).is_none(), "clean exit silent");
        assert!(workload_hint(None, true).is_none(), "foreign pid silent");
        assert!(
            workload_hint(Some(7), false).is_none(),
            "explicit dest silent"
        );
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
                dest: "/nope/out.json".to_string(),
                ok: false,
                bytes: 0,
                error: Some("denied".to_string()),
            },
            cbom: None,
            diagnostics: Vec::new(),
        }
    }

    fn doc_with(status: Completeness) -> CaptureDocument {
        let mut d = capture::empty_document();
        d.status = status;
        d
    }

    #[test]
    fn exit_precedence() {
        use crate::policy::PolicyOutcome;
        let pass = PolicyOutcome::Pass;
        let no_verdict = PolicyOutcome::NoVerdict;
        let complete = doc_with(Completeness::Complete);
        let partial = doc_with(Completeness::Partial {
            reasons: Vec::new(),
        });
        let fatal = doc_with(Completeness::Fatal {
            kind: FatalKind::AttachZero,
            reasons: Vec::new(),
        });
        assert_eq!(exit_for(pass, None, &complete, &ok_delivery()), 0);
        assert_eq!(exit_for(pass, Some(0), &complete, &ok_delivery()), 0);
        assert_eq!(exit_for(pass, None, &partial, &ok_delivery()), 3);
        assert_eq!(exit_for(no_verdict, None, &fatal, &ok_delivery()), 4);
        // F-E/B3: fatal/no-verdict (4) dominates child failure (1)
        // per PRD §14 precedence; report maps fatal captures to
        // no-verdict so this row covers the old report path too.
        assert_eq!(exit_for(no_verdict, Some(1), &fatal, &ok_delivery()), 4);
        // Child failure dominates evidence status (never 10 without a verdict).
        assert_eq!(exit_for(pass, Some(2), &complete, &ok_delivery()), 1);
        assert_eq!(exit_for(pass, Some(139), &partial, &ok_delivery()), 1);
        // F-E/B3: delivery failure is an internal error (1), not an
        // environment failure (4); report used to return 4 here.
        assert_eq!(exit_for(pass, None, &complete, &failed_delivery()), 1);
        assert_eq!(exit_for(pass, Some(0), &partial, &failed_delivery()), 1);
    }

    #[test]
    fn report_shape_is_v2_without_policy() {
        // report renders the finalized v2 capture document with
        // policy None (PRD §14.1 v2-only live producer): v2 schema
        // key, no policy section. The v1 projection is deleted, so
        // no regression path back to it compiles.
        let doc = capture::empty_document();
        assert!(doc.policy.is_none());
        let bytes = render_json(&doc).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schema_version"], "observed-crypto-v2.1");
        assert!(v.get("policy").is_none());
    }

    #[test]
    fn cbom_flag_parses() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse(&v(vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
            "--cbom",
            "/tmp/x.cdx.json",
        ]))
        .unwrap();
        assert_eq!(a.cbom, Some("/tmp/x.cdx.json".to_string()));
        let a = parse(&v(vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ]))
        .unwrap();
        assert_eq!(a.cbom, None);
    }

    #[test]
    fn help_exits_zero_before_run_only() {
        use std::process::ExitCode;
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(run(&v(vec!["--help"])), ExitCode::from(0));
        assert_eq!(run(&v(vec!["-h"])), ExitCode::from(0));
        // A target command after run -- may contain --help: it must
        // not print our help (nonzero either way — capture of a
        // nonexistent command cannot succeed; exact code depends on
        // whether BPF objects are installed on this host).
        assert_ne!(run(&v(vec!["run", "--", "--help"])), ExitCode::from(0));
    }

    #[test]
    fn duration_defaults_to_30s() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let no_dur = vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        assert_eq!(
            parse(&v(no_dur)).unwrap().cfg.duration,
            Duration::from_secs(30)
        );
        let explicit = vec![
            "--duration",
            "5",
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        assert_eq!(
            parse(&v(explicit)).unwrap().cfg.duration,
            Duration::from_secs(5)
        );
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
        // T12: provider/objects are optional (automatic discovery).
        let auto = parse(&v(vec!["--pid", "9"])).unwrap();
        assert!(auto.cfg.provider.is_none());
        assert!(auto.cfg.harvest_object.is_none());
        assert!(auto.cfg.count_object.is_none());
        // Explicit enrollment validates at parse time (exit 2).
        let mut bad_table = vec!["--pid", "9"];
        bad_table.extend(["--table", "/nonexistent-table.json"]);
        assert!(parse(&v(bad_table)).is_err());
        let mut bad_enroll = vec!["--pid", "9"];
        bad_enroll.extend(["--provider-table", "/nonexistent-enroll.json"]);
        assert!(parse(&v(bad_enroll)).is_err());
        let mut bad_force = vec!["--pid", "9"];
        bad_force.extend(["--force-offset", "xyz"]);
        assert!(parse(&v(bad_force)).is_err());
        let mut force = vec!["--pid", "9"];
        force.extend(["--force-offset", "0x10"]);
        assert_eq!(parse(&v(force)).unwrap().cfg.force_offset, Some(0x10));
        let mut yaml = base.clone();
        yaml.extend(["--pid", "9", "--format", "yaml"]);
        assert!(parse(&v(yaml)).is_err());
        let mut digest = base.clone();
        digest.extend(["--pid", "9", "--image-digest", "sha256:abc"]);
        assert_eq!(parse(&v(digest)).unwrap().cfg.image_digest, "sha256:abc");
        let mut no_digest = base.clone();
        no_digest.extend(["--pid", "9"]);
        assert_eq!(parse(&v(no_digest)).unwrap().cfg.image_digest, "");
        // Valueless flags consume one slot (mid-argv position).
        let mut bi = base.clone();
        bi.extend(["--builtin", "--pid", "9"]);
        let a = parse(&v(bi)).unwrap();
        assert!(a.cfg.builtin);
        assert!(matches!(a.target, capture::Target::Pid(9)));
    }
}
