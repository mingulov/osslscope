// SPDX-License-Identifier: GPL-3.0-or-later

//! H7: failure fidelity — exit codes, diagnostics sinks, the
//! close-flow audits, and the `runtime` fatal-kind contract.
//!
//! - T1-exit: salvaged (runtime-fatal) docs exit 1.
//! - T3: a proved violation in salvaged sites still exits 10
//!   (real verdict on salvaged docs; R06 priority preserved).
//! - T2: setup failure (bad BPF object path) → unchanged
//!   no-evidence path, exit 4 — see `h7_cli.rs` (spawn pin).
//! - T5-unit: diagnostics render into any sink; a failing sink
//!   surfaces Err (the CLI wrapper discards it — diagnostics are
//!   advisory). T5-spawn lives in `h7_cli.rs`.
//! - T6: CLI-surface files carry no `eprintln!`/`panic!`/
//!   `expect(`/`unwrap(` in production code (stdout `println!`
//!   EPIPE is a documented residual, not a diagnostic path).
//! - Acceptance (?-classification): the post-observation close
//!   flow never `?`s and never `let _`s a close call — every
//!   close error is caught and recorded.
//! - Contract: the `runtime` fatal kind renders in JSON (with
//!   detail), human text, and validates under the v2 schema.

use osslscope::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, Completeness, FatalKind,
    FinalizeInput, LegacyCallPartition, ObjectId, OpensslVersion, SiteExecution, SiteKey,
    TargetRecord, finalize,
};
use osslscope::policy::{PolicyOutcome, PolicyRule, evaluate_document};
use osslscope::report::{
    ArtifactOutcome, DeliveryResult, exit_for, render_human, render_json, setup_failure_document,
};

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

fn runtime_doc() -> CaptureDocument {
    setup_failure_document(FatalKind::Runtime("close_and_drain: boom".to_string()))
}

fn env_doc() -> CaptureDocument {
    setup_failure_document(FatalKind::Environment("no bpf".to_string()))
}

fn obj(id: &str) -> ObjectId {
    ObjectId(id.to_string())
}

fn cand(
    provider: &str,
    class: &str,
    op: u32,
    func: u32,
    algs: &[&str],
    weak: bool,
) -> CandidateIdentity {
    CandidateIdentity::new(
        obj(provider),
        class.to_string(),
        op,
        func,
        algs.iter().map(|s| s.to_string()).collect(),
        weak,
    )
}

fn site_with(
    offset: u64,
    calls: u64,
    cands: Vec<CandidateIdentity>,
    cov: CandidateCoverage,
) -> SiteExecution {
    SiteExecution {
        site: SiteKey {
            object: obj("exe-fingerprint"),
            device: 7,
            inode: 9,
            offset,
        },
        generation: 0,
        candidates: cands,
        candidates_coverage: cov,
        calls,
        first_ns: 100,
        last_ns: 200,
        installed_at: None,
    }
}

fn doc_with(sites: Vec<SiteExecution>, fatal: Option<FatalKind>) -> CaptureDocument {
    finalize(FinalizeInput {
        corpse_wait: None,
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
        fatal,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    })
}

#[test]
fn h7_violation_beats_tool_failure() {
    // T3-mapping: a salvaged doc that still violates policy exits
    // 10, not 1 — the security verdict dominates the tool-failure
    // signal. (T3-verdict below proves the violation is real, not
    // injected.)
    let doc = runtime_doc();
    assert!(matches!(doc.status, Completeness::Fatal { .. }));
    assert_eq!(
        exit_for(PolicyOutcome::Violation, None, &doc, &ok_delivery()),
        10
    );
}

#[test]
fn h7_runtime_violation_is_proved_not_injected() {
    // T3 (RED): policy EVALUATES salvaged docs — a definite
    // violating site under a runtime fatal still convicts (exit
    // 10). Pre-H7 the policy short-circuits every Fatal doc to
    // no-verdict.
    let viol = doc_with(
        vec![site_with(
            1,
            7,
            vec![cand("prov-default", "default", 1, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )],
        Some(FatalKind::Runtime("discovery finish: boom".to_string())),
    );
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &viol);
    assert_eq!(v.overall(), PolicyOutcome::Violation);
    assert!(!v.rules.is_empty(), "salvaged docs must evaluate rules");
    assert_eq!(exit_for(v.overall(), None, &viol, &ok_delivery()), 10);
    // And other fatal kinds still yield no verdict (pin).
    let attach_zero = doc_with(
        vec![site_with(
            1,
            7,
            vec![cand("prov-default", "default", 1, 7, &["MD5"], true)],
            CandidateCoverage::Complete,
        )],
        Some(FatalKind::AttachZero),
    );
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &attach_zero);
    assert_eq!(v.overall(), PolicyOutcome::NoVerdict);
    assert!(v.rules.is_empty());
}

#[test]
fn h7_runtime_fatal_exits_1() {
    // T1-exit: a salvaged (runtime-fatal) doc with no violation is
    // a tool failure — exit 1 — however it combines with child or
    // delivery failures (all exit 1; no masking either way). The
    // doc evaluates instead of short-circuiting to no-verdict
    // (Inconclusive here — absence is unprovable over a broken
    // close — and the tool-failure 1 dominates the 11).
    let doc = runtime_doc();
    let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &doc);
    assert_eq!(v.overall(), PolicyOutcome::Inconclusive);
    assert!(!v.rules.is_empty(), "salvaged docs must evaluate rules");
    assert_eq!(exit_for(v.overall(), None, &doc, &ok_delivery()), 1);
    assert_eq!(
        exit_for(PolicyOutcome::Pass, Some(3), &doc, &ok_delivery()),
        1
    );
    let mut failed = ok_delivery();
    failed.primary.ok = false;
    failed.primary.error = Some("denied".to_string());
    assert_eq!(exit_for(PolicyOutcome::Pass, None, &doc, &failed), 1);
}

#[test]
fn h7_exit_table_pins() {
    // PRD §14 order with the H7 insertion: salvaged-runtime (1)
    // sits between violation (10) and setup-no-verdict (4), while
    // child/delivery failures (1) stay below no-verdict.
    let env = env_doc();
    assert_eq!(
        exit_for(PolicyOutcome::NoVerdict, None, &env, &ok_delivery()),
        4
    );
    // The `report` shape for a salvaged capture (fatal outcome maps
    // to no-verdict; the doc carries the Runtime kind) still exits 1.
    let runtime = runtime_doc();
    assert_eq!(
        exit_for(PolicyOutcome::NoVerdict, None, &runtime, &ok_delivery()),
        1
    );
    // PRD §14 corners: no-verdict dominates child and delivery
    // failures on evidence-free docs.
    let mut failed = ok_delivery();
    failed.primary.ok = false;
    failed.primary.error = Some("denied".to_string());
    assert_eq!(
        exit_for(PolicyOutcome::NoVerdict, Some(1), &env, &ok_delivery()),
        4
    );
    assert_eq!(exit_for(PolicyOutcome::NoVerdict, None, &env, &failed), 4);
    let mut partial = osslscope::capture::empty_document();
    partial.status = Completeness::Partial {
        reasons: Vec::new(),
    };
    assert_eq!(
        exit_for(PolicyOutcome::Pass, None, &partial, &ok_delivery()),
        3
    );
    let mut complete = osslscope::capture::empty_document();
    complete.status = Completeness::Complete;
    assert_eq!(
        exit_for(PolicyOutcome::Pass, None, &complete, &ok_delivery()),
        0
    );
    assert_eq!(
        exit_for(PolicyOutcome::Inconclusive, None, &complete, &ok_delivery()),
        11
    );
}

struct FailingWriter;

impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "out of space",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "out of space",
        ))
    }
}

#[test]
fn h7_diagnostics_render_to_sink_and_surface_errors() {
    // T5-unit: diagnostics render into the given sink, and a
    // failing sink surfaces Err (no panic; the CLI wrapper
    // discards the Err — diagnostics are advisory).
    let mut delivery = ok_delivery();
    delivery.diagnostics = vec!["first".to_string(), "second".to_string()];
    let mut buf = Vec::new();
    osslscope::report::emit_diagnostics_to(&mut buf, &delivery).unwrap();
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "osslscope: first\nosslscope: second\n"
    );
    let mut empty = Vec::new();
    osslscope::report::emit_diagnostics_to(&mut empty, &ok_delivery()).unwrap();
    assert!(empty.is_empty());
    let err = osslscope::report::emit_diagnostics_to(&mut FailingWriter, &delivery)
        .expect_err("failing sink must surface Err, not panic");
    assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
}

#[test]
fn h7_runtime_json_shape_and_schema() {
    // Contract: `runtime` renders with its detail and validates —
    // and the schema REQUIRES the detail (like `environment`).
    let doc = runtime_doc();
    let bytes = render_json(&doc).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["completeness"]["status"], "FATAL");
    assert_eq!(v["completeness"]["fatal_kind"]["kind"], "runtime");
    assert_eq!(
        v["completeness"]["fatal_kind"]["detail"],
        "close_and_drain: boom"
    );
    osslscope::schema::validate_v2(&v).unwrap();
    osslscope::schema::check_v2_semantics(&v).unwrap();
    let mut bare = v.clone();
    bare["completeness"]["fatal_kind"]["detail"] = serde_json::Value::Null;
    let err =
        osslscope::schema::check_v2_semantics(&bare).expect_err("detail-less runtime must fail");
    assert!(err.contains("runtime"), "unexpected: {err}");
}

#[test]
fn c3_fatal_detail_normalizes_target_proc_paths() {
    // Round 3, residual C.3 (publication): fatal detail carries
    // bounded observer-setup provenance — operation names and
    // observer paths pass through bounded; target-namespaced
    // /proc/<pid> paths normalize to the fixed /proc/<pid>
    // token (the pid already publishes structurally — the path
    // form never does). Both detail-carrying kinds, both text
    // renders, schema-validated.
    for (kind, want) in [
        (
            FatalKind::Environment(
                "open /opt/osslscope/members.o: read /proc/12345/maps failed".to_string(),
            ),
            "open /opt/osslscope/members.o: read /proc/<pid>/maps failed",
        ),
        (
            FatalKind::Runtime(
                "discovery finish: read /proc/987/maps: No such file or directory (os error 2)"
                    .to_string(),
            ),
            "discovery finish: read /proc/<pid>/maps: No such file or directory (os error 2)",
        ),
    ] {
        let doc = setup_failure_document(kind);
        let bytes = render_json(&doc).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["completeness"]["fatal_kind"]["detail"].as_str(),
            Some(want),
            "JSON detail must normalize"
        );
        osslscope::schema::validate_v2(&v).unwrap();
        osslscope::schema::check_v2_semantics(&v).unwrap();
        let text = render_human(&doc);
        assert!(text.contains(want), "human detail must normalize:\n{text}");
        assert!(
            !text.contains("/proc/12345") && !text.contains("/proc/987"),
            "no raw target pid path survives:\n{text}"
        );
    }
}

#[test]
fn c3_config_value_never_publishes_raw() {
    // Round 4, residual C.3-config (review's chain): an
    // initially valid --table file replaced with a fallback
    // carrying "openssl":"unexpected-config-value" travels
    // builtin interpolation → onboard chain preservation →
    // capture environment-failure route → publication. The
    // producer now emits FIXED wording, so no raw
    // configuration value reaches any render (JSON + human
    // carry the fixed diagnostic; CBOM carries the kind word
    // only).
    for suffix in ["short".to_owned(), "long".repeat(48)] {
        let dir =
            std::env::temp_dir().join(format!("osslscope-c3-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("table.json");
        std::fs::write(
            &path,
            r#"{"table_version":1,"entries":[],
                "fallback":[{"openssl":"unexpected-config-value",
                             "anchor":"OSSL_PROVIDER_available","delta":8}]}"#,
        )
        .unwrap();
        let err = osslscope::discovery::onboard::load_offset_table_file(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
        // Capture's environment-failure route wraps the preserved
        // chain (capture.rs `offset table: {full}`).
        let detail = format!("offset table: {}", err.full());
        assert!(
            !detail.contains("unexpected-config-value"),
            "raw configuration value must not survive the chain: {detail}"
        );
        let doc = setup_failure_document(FatalKind::Environment(detail));
        let bytes = render_json(&doc).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let published = v["completeness"]["fatal_kind"]["detail"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(published.chars().count() <= 200 && !published.contains(['\n', '\r']));
        assert!(
            published.contains("bad fallback version (want numeric major.minor)"),
            "JSON detail must carry the fixed diagnostic: {published}"
        );
        assert!(
            !published.contains("unexpected-config-value"),
            "JSON detail must not carry the raw value: {published}"
        );
        osslscope::schema::validate_v2(&v).unwrap();
        osslscope::schema::check_v2_semantics(&v).unwrap();
        let text = render_human(&doc);
        assert!(
            text.contains("bad fallback version (want numeric major.minor)"),
            "human detail must carry the fixed diagnostic:\n{text}"
        );
        assert!(
            !text.contains("unexpected-config-value"),
            "human detail must not carry the raw value:\n{text}"
        );
        // CBOM carries the kind word only — neither the detail nor
        // the raw value appears.
        let cbom: serde_json::Value =
            serde_json::from_slice(&osslscope::report::render_cbom(&doc).unwrap()).unwrap();
        let flat = serde_json::to_string(&cbom).unwrap();
        assert!(
            flat.contains("environment"),
            "CBOM must carry the kind word: {flat}"
        );
        assert!(
            !flat.contains("unexpected-config-value") && !flat.contains("bad fallback version"),
            "CBOM must not carry detail at all: {flat}"
        );
    }
}

#[test]
fn h7_runtime_human_shape() {
    // Contract: the human renderer names the runtime failure.
    let text = render_human(&runtime_doc());
    assert!(
        text.contains("fatal: runtime: close_and_drain: boom"),
        "unexpected human block:\n{text}"
    );
}

#[test]
fn h7_usable_evidence_is_kind_eligibility() {
    // R02: has_usable_evidence centralizes fatal-kind eligibility —
    // non-fatal and salvaged-Runtime docs are usable; every other
    // fatal kind is evidence-free. Ambiguous and site-free Runtime
    // docs stay usable: per-site tests still decide definite vs
    // possible (see the stub-runner controls).
    let mut complete = osslscope::capture::empty_document();
    complete.status = Completeness::Complete;
    assert!(complete.has_usable_evidence());
    let mut partial = osslscope::capture::empty_document();
    partial.status = Completeness::Partial {
        reasons: Vec::new(),
    };
    assert!(partial.has_usable_evidence());
    assert!(runtime_doc().has_usable_evidence());
    let ambiguous = doc_with(
        vec![site_with(
            1,
            7,
            vec![
                cand("prov-default", "default", 1, 7, &["MD5"], true),
                cand("prov-default", "default", 1, 7, &["SHA2-256"], false),
            ],
            CandidateCoverage::Complete,
        )],
        Some(FatalKind::Runtime("discovery finish: boom".to_string())),
    );
    assert!(ambiguous.has_usable_evidence());
    assert!(!env_doc().has_usable_evidence());
    assert!(!setup_failure_document(FatalKind::Recycled).has_usable_evidence());
    assert!(!setup_failure_document(FatalKind::AttachZero).has_usable_evidence());
}

#[test]
fn h7_evidence_free_fatal_stays_no_verdict() {
    // R02 controls: environment/recycled/attach-zero docs carry no
    // usable evidence — check assembly yields no-verdict, semantics
    // accepts no-verdict (and still rejects evaluated verdicts),
    // the CBOM is explicitly empty with the no-usable-evidence
    // disclaimer, and the exit stays 4.
    for (name, kind) in [
        ("environment", FatalKind::Environment("no bpf".to_string())),
        ("recycled", FatalKind::Recycled),
        ("attach-zero", FatalKind::AttachZero),
    ] {
        let doc = setup_failure_document(kind);
        assert!(!doc.has_usable_evidence(), "{name}");
        let v = evaluate_document(std::slice::from_ref(&PolicyRule::deny_weak()), &doc);
        assert_eq!(v.overall(), PolicyOutcome::NoVerdict, "{name}");
        assert!(v.rules.is_empty(), "{name}");
        let mut cdoc = doc.clone();
        cdoc.policy = Some(osslscope::check::policy_record(&v));
        let bytes = render_json(&cdoc).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        osslscope::schema::validate_v2(&val).unwrap();
        osslscope::schema::check_v2_semantics(&val)
            .unwrap_or_else(|e| panic!("{name}: no-verdict must validate: {e}"));
        assert_eq!(val["policy"]["verdict"], "no-verdict", "{name}");
        let mut bad = val.clone();
        bad["policy"] = serde_json::json!({"verdict": "pass", "rules": []});
        assert!(
            osslscope::schema::check_v2_semantics(&bad).is_err(),
            "{name}: evaluated verdict on evidence-free fatal accepted"
        );
        let cbom: serde_json::Value =
            serde_json::from_slice(&osslscope::report::render_cbom(&cdoc).unwrap()).unwrap();
        assert_eq!(cbom["components"].as_array().unwrap().len(), 0, "{name}");
        let disclaimer = cbom["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "osslscope:completeness-disclaimer")
            .unwrap()["value"]
            .as_str()
            .unwrap();
        assert!(
            disclaimer.contains("no usable evidence"),
            "{name}: {disclaimer}"
        );
        assert_eq!(
            exit_for(v.overall(), None, &cdoc, &ok_delivery()),
            4,
            "{name}"
        );
    }
}

// --- Acceptance: post-observation close-flow audit -----------------------
// The close flow (close_and_finalize, fail/salvage, recycled) never
// `?`s — every error is caught and folded into the salvaged doc —
// and never `let _`s a close call — every close error is recorded
// as a typed loss counter. Any `?` or `let _` in these bodies fails
// LOUDLY with the offending line.

const AUDITED_FNS: &[&str] = &["close_and_finalize", "fail", "salvage", "recycled"];

/// Strip `//` comments and double-quoted spans (with `\` escapes);
/// what remains is code the audit can judge.
fn strip_comments_and_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }
        out.push(c);
    }
    out
}

fn normalize(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Byte-offset line range of `fn NAME(` .. its balanced closing
/// brace (brace counting skips strings/comments; `None` when the fn
/// is absent — itself an audit failure).
/// TODO(post-stop): unify with the stateful T6 scanner — the
/// legacy per-line stripper misreads quotes in chars, raws,
/// blocks, and continuations (claude R1-F1; split scope, no
/// live instance: zero fooling shapes in capture.rs).
fn fn_body(src: &str, name: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let pat = format!("fn {name}(");
    let start = lines.iter().position(|l| {
        let n = normalize(l);
        n.contains(&pat) && n.starts_with("fn ")
    })?;
    let mut depth = 0i32;
    let mut opened = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for c in strip_comments_and_strings(line).chars() {
            if c == '{' {
                depth += 1;
                opened = true;
            } else if c == '}' {
                depth -= 1;
            }
        }
        if opened && depth == 0 {
            return Some((start, i));
        }
    }
    None
}

#[test]
fn h7_close_flow_never_questions_nor_discards() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("capture.rs");
    let src = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let mut violations = Vec::new();
    for name in AUDITED_FNS {
        let Some((start, end)) = fn_body(&src, name) else {
            violations.push(format!("fn {name} not found (audit scope broken)"));
            continue;
        };
        for (i, line) in lines.iter().enumerate().take(end + 1).skip(start) {
            let code = strip_comments_and_strings(line);
            if code.contains('?') {
                violations.push(format!(
                    "{}:{}: `?` in close flow: {}",
                    path.display(),
                    i + 1,
                    normalize(line)
                ));
            }
            if normalize(&code).contains("let _ =") {
                violations.push(format!(
                    "{}:{}: `let _` in close flow: {}",
                    path.display(),
                    i + 1,
                    normalize(line)
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "H7 close-flow audit failed:\n{}",
        violations.join("\n")
    );
}

// --- T6: CLI-surface panic audit (token-based, D120) ------------------------
// Every CLI error-path print goes through the panic-free sink
// helper; production code in the CLI-surface files carries no
// `eprintln!`, `eprint!`, `panic!`, `expect(`, or `unwrap(`,
// in method, macro, or path (`Option::unwrap`) form.
// (`println!` to stdout is out of scope: stdout-EPIPE while
// piping artifacts is a documented residual with
// Unix-philosophy questions, not a diagnostic path.
// Engine-internal `eprintln!` warnings outside these files are
// likewise out of scope — reviewed, not converted.)
// Scope is WRITTEN call sites (claude R5): macro-built calls
// (`call!(v, unwrap)` expanding to `$v.$m()`) and renamed
// imports (`use std::panic as boom`) need macro expansion or
// name resolution — neither tokens nor syn provide them. If
// those ever need coverage, clippy restriction lints run
// after expansion (`unwrap_used`, `expect_used`, `panic`,
// `print_stderr` denied on these modules — post-stop).
// `assert!` is deliberately out (claude R6): its 282 hits are
// invariant checks, a different contract from error-path
// panics — not an oversight. (`unreachable!`/`todo!`/
// `unimplemented!` censused 2-test-skipped/0/0, kept out per
// codex R14; revisit with the census if the contract grows.)
//
// After three rounds of hand-lexer desync classes (N1→C1→F1→
// M1/M2/LRM, codex R12 + claude R4), the matcher works
// directly on the proc-macro2 token stream — the same lexer
// rustc's front-end agrees with — so there is no second
// lexer to desync and no differential to keep. Patterns are
// sibling token triples (`.` + `unwrap`/`expect` + paren
// group; `panic`/`eprintln`/`eprint` + `!` + group; joint
// terminal `::` + `unwrap`/`expect`, call or fn-pointer;
// trailing-dot float + `unwrap`/`expect` + paren group),
// matched at every nesting level; skips are top-level
// `#[cfg(test)] mod` brace spans (half-open). Threat model:
// files that lex (an unlexable file cannot compile, so it
// cannot ship); a lex failure is a loud test error, never
// a silent pass.

const T6_FILES: &[&str] = &[
    "src/report.rs",
    "src/check.rs",
    "src/cli.rs",
    "src/main.rs",
    "src/doctor.rs",
    "src/inspect.rs",
    "src/aliases.rs",
];

/// True when `bracket` is exactly `[cfg(test)]` — the only
/// attribute that opens a T6 skip. Whitespace inside is
/// invisible to the tokenizer (`#[cfg (test)]` skips too, a
/// deliberate fix over the old exact-string gate); anything
/// else in the brackets (cfg-expressions, other attrs) does
/// not govern, and the module stays scanned (fail-closed).
fn t6_is_cfg_test_attr(bracket: &proc_macro2::Group) -> bool {
    use proc_macro2::{Delimiter, TokenTree};
    if bracket.delimiter() != Delimiter::Bracket {
        return false;
    }
    let mut inner = bracket.stream().into_iter();
    let (Some(TokenTree::Ident(cfg)), Some(TokenTree::Group(parens)), None) =
        (inner.next(), inner.next(), inner.next())
    else {
        return false;
    };
    if cfg != "cfg" || parens.delimiter() != Delimiter::Parenthesis {
        return false;
    }
    let mut args = parens.stream().into_iter();
    matches!(
        (args.next(), args.next()),
        (Some(TokenTree::Ident(t)), None) if t == "test"
    )
}

/// True when `ident` names `name`, counting the raw
/// form `r#name` (same identifier — Tier-1 R12-F1: raw
/// panic calls compile, execute, and must flag).
fn t6_ident_is(ident: &proc_macro2::Ident, name: &str) -> bool {
    let s = ident.to_string();
    s.strip_prefix("r#").unwrap_or(&s) == name
}

/// True when a method call follows at `level[j]`: the paren
/// argument group, or a joint `::` opening COMPLETE turbofish
/// plus the call (claude R7-TF1 — `v.unwrap::<>(…)`; rustfmt
/// strips it in normal code but macro bodies are opaque to
/// rustfmt). Bare `::`, `::u8`, or call-less `::<u8>` are
/// macro data, not calls (codex R16-F1) — only a balanced
/// `<>` plus parens counts.
fn t6_call_follows(level: &[proc_macro2::TokenTree], j: usize) -> bool {
    use proc_macro2::{Delimiter, TokenTree};
    match (level.get(j), level.get(j + 1)) {
        (Some(TokenTree::Group(g)), _) => g.delimiter() == Delimiter::Parenthesis,
        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
            if a.as_char() == ':'
                && b.as_char() == ':'
                && a.spacing() == proc_macro2::Spacing::Joint =>
        {
            t6_turbofish_call(level, j + 2)
        }
        _ => false,
    }
}

/// True when `level[j..]` is balanced turbofish args plus the
/// paren call: `<…>` (nesting counted over sibling puncts;
/// `->` arrows don't count as closers; denylisted puncts,
/// `=>`, compounds, and `::` runs (see the match arms)
/// preclude generic args) followed by `(`. Anything
/// unbalanced or uncalled returns false.
fn t6_turbofish_call(level: &[proc_macro2::TokenTree], j: usize) -> bool {
    use proc_macro2::{Delimiter, TokenTree};
    if !matches!(level.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '<') {
        return false;
    }
    // Balance-scan from just inside the `<` (so `i - 1` below
    // never underflows: every `>` sits past the opener).
    let mut depth = 1u32;
    let mut i = j + 1;
    while let Some(tok) = level.get(i) {
        match tok {
            TokenTree::Punct(p) if p.as_char() == '<' => depth += 1,
            TokenTree::Punct(p) if p.as_char() == '>' => {
                // Fat arrow (codex R20-F1): `=>` never closes —
                // match arms need blocks. Contrast `->`, which
                // must be skipped (valid `fn() -> T` args).
                if matches!(
                    level.get(i - 1),
                    Some(TokenTree::Punct(q)) if q.as_char() == '='
                ) {
                    return false;
                }
                let arrow = matches!(
                    level.get(i - 1),
                    Some(TokenTree::Punct(q)) if q.as_char() == '-'
                );
                if !arrow {
                    depth -= 1;
                    if depth == 0 {
                        return matches!(
                            level.get(i + 1),
                            Some(TokenTree::Group(g))
                                if g.delimiter() == Delimiter::Parenthesis
                        );
                    }
                }
            }
            // Tokens impossible in generic args (codex R17-F2/R18-F2,
            // Tier-1 R20-F1..F4/R21-F1): `;` (bare const exprs
            // need braces), `@` (patterns need const blocks), `|`
            // (bounds use `+`; closures/patterns grouped), `#`
            // (attrs never in args; raw idents lex whole), `.`
            // (floats/chars lex whole; `a.b` is not a type),
            // `?` (E0658 kills `?Trait` in objects; `?Sized`
            // declaration-only), `%`/`^`/`/` (binops need
            // const blocks), `~` (no unary `~`; `~const`
            // declaration-only). Each is macro data, never
            // turbofish.
            TokenTree::Punct(p) if p.as_char() == ';' => return false,
            TokenTree::Punct(p) if p.as_char() == '@' => return false,
            TokenTree::Punct(p) if p.as_char() == '|' => return false,
            TokenTree::Punct(p) if p.as_char() == '#' => return false,
            TokenTree::Punct(p) if p.as_char() == '.' => return false,
            TokenTree::Punct(p) if p.as_char() == '?' => return false,
            TokenTree::Punct(p) if p.as_char() == '%' => return false,
            TokenTree::Punct(p) if p.as_char() == '^' => return false,
            TokenTree::Punct(p) if p.as_char() == '/' => return false,
            TokenTree::Punct(p) if p.as_char() == '~' => return false,
            // Compound comparisons/assignments preclude generic args
            // (codex R20-F2): `==`/`!=`/`+=`/`-=`/`*=`/`&=` never
            // appear ungrouped in turbofish (plain `=`/`!`/`+`/
            // `-`/`*`/`&` preserved — bindings, never-type,
            // bounds, unary minus, pointers).
            TokenTree::Punct(p)
                if matches!(p.as_char(), '=' | '!' | '+' | '-' | '*' | '&')
                    && matches!(level.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == '=') =>
            {
                return false;
            }
            TokenTree::Punct(p) if p.as_char() == ':' => {
                // Lone `:` precludes generic args (Tier-1 R20-F4):
                // joint `::` pairs (paths) are skipped, anything
                // else returns false. A pair followed by another
                // `:` is a run (`::::`), never a separator
                // (codex R20-F2).
                let pair = p.spacing() == proc_macro2::Spacing::Joint
                    && matches!(level.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == ':');
                if !pair {
                    return false;
                }
                if matches!(level.get(i + 2), Some(TokenTree::Punct(q)) if q.as_char() == ':') {
                    return false;
                }
                i += 1; // consume the partner colon
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// True when `level[j..]` continues a path past the name: a
/// joint `::` leading to another segment, a braced import, or
/// a glob (codex R14-F1/R15-F1). Turbofish (`::<>`) is NOT a
/// continuation by itself — see `t6_turbofish_continues`.
fn t6_path_continues(level: &[proc_macro2::TokenTree], j: usize) -> bool {
    use proc_macro2::{Delimiter, TokenTree};
    let pair = matches!(
        (level.get(j), level.get(j + 1)),
        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
            if a.as_char() == ':'
                && a.spacing() == proc_macro2::Spacing::Joint
                && b.as_char() == ':'
    );
    pair && match level.get(j + 2) {
        Some(TokenTree::Ident(_)) => true,
        Some(TokenTree::Group(g)) => g.delimiter() == Delimiter::Brace,
        Some(TokenTree::Punct(p)) => p.as_char() == '*',
        _ => false,
    }
}

/// True when `level[j..]` opens turbofish whose close is
/// followed by another path segment: `expect::<u8>::Some`
/// still continues the path (codex R16-F3). Balance-scans
/// `<>` (`->` arrows don't count as closers; denylisted
/// puncts, `=>`, compounds, and `::` runs preclude generic
/// args, same rules as the call scan); unbalanced
/// turbofish, or turbofish followed by anything but a joint
/// `::` segment (e.g. the paren call), returns false.
fn t6_turbofish_continues(level: &[proc_macro2::TokenTree], j: usize) -> bool {
    use proc_macro2::TokenTree;
    if !matches!(level.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '<') {
        return false;
    }
    let mut depth = 1u32;
    let mut i = j + 1;
    while let Some(tok) = level.get(i) {
        match tok {
            TokenTree::Punct(p) if p.as_char() == '<' => depth += 1,
            TokenTree::Punct(p) if p.as_char() == '>' => {
                // Fat arrow (codex R20-F1): `=>` never closes —
                // match arms need blocks. Contrast `->`, which
                // must be skipped (valid `fn() -> T` args).
                if matches!(
                    level.get(i - 1),
                    Some(TokenTree::Punct(q)) if q.as_char() == '='
                ) {
                    return false;
                }
                let arrow = matches!(
                    level.get(i - 1),
                    Some(TokenTree::Punct(q)) if q.as_char() == '-'
                );
                if !arrow {
                    depth -= 1;
                    if depth == 0 {
                        return t6_path_continues(level, i + 1);
                    }
                }
            }
            // Same impossible-token rules as the call scan
            // (codex R17-F2/R18-F2, Tier-1 R20-F1..F4/R21-F1):
            // consistency between the two scanners; the loud
            // direction (flag) on rejected code.
            TokenTree::Punct(p) if p.as_char() == ';' => return false,
            TokenTree::Punct(p) if p.as_char() == '@' => return false,
            TokenTree::Punct(p) if p.as_char() == '|' => return false,
            TokenTree::Punct(p) if p.as_char() == '#' => return false,
            TokenTree::Punct(p) if p.as_char() == '.' => return false,
            TokenTree::Punct(p) if p.as_char() == '?' => return false,
            TokenTree::Punct(p) if p.as_char() == '%' => return false,
            TokenTree::Punct(p) if p.as_char() == '^' => return false,
            TokenTree::Punct(p) if p.as_char() == '/' => return false,
            TokenTree::Punct(p) if p.as_char() == '~' => return false,
            // Same compound rule as the call scan (codex R20-F2).
            TokenTree::Punct(p)
                if matches!(p.as_char(), '=' | '!' | '+' | '-' | '*' | '&')
                    && matches!(level.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == '=') =>
            {
                return false;
            }
            TokenTree::Punct(p) if p.as_char() == ':' => {
                let pair = p.spacing() == proc_macro2::Spacing::Joint
                    && matches!(level.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == ':');
                if !pair {
                    return false;
                }
                // Same run rule as the call scan (codex R20-F2).
                if matches!(level.get(i + 2), Some(TokenTree::Punct(q)) if q.as_char() == ':') {
                    return false;
                }
                i += 1; // consume the partner colon
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// True when the float at `level[k]` (k >= 1) hangs off
/// tuple-field access: walking back through consecutive
/// trailing-dot floats reaches a standalone `.` (codex
/// R18-F1 — `0..1. 2.` chains bottom out at a range dot,
/// never field access). A root dot at level start counts,
/// mirroring the method gate (fail-closed; no compiling
/// expression starts with `.`).
fn t6_float_chain_rooted(level: &[proc_macro2::TokenTree], k: usize) -> bool {
    use proc_macro2::TokenTree;
    if k == 0 {
        return false;
    }
    let mut j = k - 1;
    while j > 0
        && matches!(level.get(j), Some(TokenTree::Literal(l)) if l.to_string().ends_with('.'))
    {
        j -= 1;
    }
    matches!(level.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '.')
        && (j == 0 || !matches!(level.get(j - 1), Some(TokenTree::Punct(p)) if p.as_char() == '.'))
}

/// T6 matcher over one file's text: reports `rel:line: pat:
/// code` violations for panic patterns in production code,
/// skipping top-level `#[cfg(test)] mod` bodies by span.
/// Rules:
/// - Patterns are sibling token triples at any nesting
///   level: `.` + `unwrap`/`expect` + call (paren group or
///   complete turbofish; the dot must be standalone — a
///   range's second dot never starts a triple),
///   `panic`/`eprintln`/`eprint` + `!` + group, `::` +
///   `unwrap`/`expect` with or without a call (path and
///   fn-pointer forms; the separator must be a joint pair
///   with no preceding colon, and the name must be
///   terminal — a following `::` leading to a segment, a
///   braced import, or a glob continues the path instead,
///   including through turbofish args), or
///   float-literal-ending-in-dot + `unwrap`/`expect` +
///   call, hanging off tuple-field access (a standalone dot
///   or a chain of trailing-dot floats rooted at one; a
///   range's second dot never qualifies, wherever the chain
///   bottoms out). Turbofish args must be denylist-free
///   (no `;@|#.?%^/~`, lone `:`, `=>`, compounds, or
///   `::` runs; joint `::` pairs skipped), balanced,
///   plus parens for calls.
///   Raw `r#…` spellings included — same names. Siblings
///   only — a triple split across a group boundary never
///   matches.
///   Whitespace, comments, and line breaks between the
///   tokens are invisible (claude R4-M2). Reported with
///   the historical substring labels (`.unwrap(` etc.).
/// - Skip: a top-level `#` + `[cfg(test)]` + `mod` + name +
///   brace group (stacked attrs ride, exactly like rustc
///   attachment; any other top-level token spends
///   governance). Inner `#![…]` attrs never govern. The
///   brace group's span is the skip — no opener/closer
///   heuristics, no column or depth gates, no trivia
///   sensitivity. Spans are half-open: the closer's own end
///   position is outside, so an invocation glued to `}`
///   flags. A pattern occurrence inside a skip span (by
///   token position, not by line) is silent; code on the
///   closer's own line still flags (span-precise).
/// - Structure inside groups (macro input, fn bodies) is
///   scanned for patterns but never opens a skip
///   (fail-closed, codex R10-F3/R12). `mod name;` opens
///   nothing. Nested (non-top-level) `#[cfg(test)] mod`
///   is NOT skipped (hand-matcher parity, pinned).
fn t6_violations(text: &str, rel: &str) -> Vec<String> {
    use proc_macro2::{Delimiter, TokenTree};
    use std::str::FromStr;
    let lines: Vec<&str> = text.lines().collect();
    let stream = proc_macro2::TokenStream::from_str(text)
        .unwrap_or_else(|e| panic!("{rel}: T6 input must lex: {e}"));
    // Pass 1: top-level `#[cfg(test)] mod name { … }` spans.
    let top: Vec<TokenTree> = stream.into_iter().collect();
    let mut skips: Vec<((usize, usize), (usize, usize))> = Vec::new();
    let mut pending_cfg = false;
    let mut i = 0;
    while i < top.len() {
        match &top[i] {
            TokenTree::Punct(p) if p.as_char() == '#' => {
                match (top.get(i + 1), top.get(i + 2)) {
                    // `#![…]` inner attribute: governance
                    // resets (hand-matcher parity).
                    (Some(TokenTree::Punct(q)), Some(TokenTree::Group(_)))
                        if q.as_char() == '!' =>
                    {
                        pending_cfg = false;
                        i += 3;
                    }
                    (Some(TokenTree::Group(g)), _) if t6_is_cfg_test_attr(g) => {
                        pending_cfg = true;
                        i += 2;
                    }
                    // Any other `#[…]`: rides through stacked,
                    // pending unchanged (codex R10-F2 parity).
                    (Some(TokenTree::Group(g)), _) if g.delimiter() == Delimiter::Bracket => {
                        i += 2;
                    }
                    _ => {
                        pending_cfg = false;
                        i += 1;
                    }
                }
            }
            TokenTree::Ident(id) if id == "mod" && pending_cfg => {
                match (top.get(i + 1), top.get(i + 2)) {
                    (Some(TokenTree::Ident(_)), Some(TokenTree::Group(g)))
                        if g.delimiter() == Delimiter::Brace =>
                    {
                        let s = g.span_open().start();
                        let e = g.span_close().end();
                        skips.push(((s.line, s.column), (e.line, e.column)));
                        pending_cfg = false;
                        i += 3;
                    }
                    // `mod name;` or anything else: no body, no
                    // skip; governance spent (hand parity).
                    _ => {
                        pending_cfg = false;
                        i += 1;
                    }
                }
            }
            _ => {
                pending_cfg = false;
                i += 1;
            }
        }
    }
    // Pass 2: pattern triples among siblings at every level.
    let mut hits: Vec<((usize, usize), &'static str)> = Vec::new();
    let mut levels: Vec<Vec<TokenTree>> = vec![top];
    while let Some(level) = levels.pop() {
        let mut k = 0;
        while k < level.len() {
            let triple = (level.get(k), level.get(k + 1), level.get(k + 2));
            if let (Some(TokenTree::Punct(dot)), Some(TokenTree::Ident(name))) =
                (level.get(k), level.get(k + 1))
            {
                // Standalone dot (codex R13-F2): the second dot
                // of a range (`..unwrap()`) must not start a
                // triple — the previous sibling decides, not
                // spacing (spaced ranges lex Alone too).
                let standalone = k == 0
                    || !matches!(level.get(k - 1), Some(TokenTree::Punct(p)) if p.as_char() == '.');
                if dot.as_char() == '.'
                    && standalone
                    && (t6_ident_is(name, "unwrap") || t6_ident_is(name, "expect"))
                    && t6_call_follows(&level, k + 2)
                {
                    let s = dot.span().start();
                    let pat = if t6_ident_is(name, "unwrap") {
                        ".unwrap("
                    } else {
                        ".expect("
                    };
                    hits.push(((s.line, s.column), pat));
                }
            }
            if let (
                Some(TokenTree::Ident(name)),
                Some(TokenTree::Punct(bang)),
                Some(TokenTree::Group(_)),
            ) = triple
            {
                if (t6_ident_is(name, "panic")
                    || t6_ident_is(name, "eprintln")
                    || t6_ident_is(name, "eprint"))
                    && bang.as_char() == '!'
                {
                    let s = name.span().start();
                    let pat = if t6_ident_is(name, "panic") {
                        "panic!"
                    } else if t6_ident_is(name, "eprintln") {
                        "eprintln!"
                    } else {
                        "eprint!"
                    };
                    hits.push(((s.line, s.column), pat));
                }
            }
            // Path calls (claude R5-U1): `Option::unwrap(v)`
            // and the fn-pointer form `Option::unwrap` (no
            // call follows) panic the same way — flag with or
            // without a group. Residual: a path call to a
            // same-named free function over-flags (no corpus
            // instance; excluding it needs name resolution).
            // Refinements (codex R14/R15/R16): the separator
            // must be a joint pair (rustc rejects `: :`), with
            // no preceding colon (so `:::` can't supply a
            // suffix pair), and the name must be terminal — a
            // joint `::` leading to another segment, a braced
            // import, or a glob continues the path instead,
            // including through turbofish args
            // (`expect::<u8>::Some`); turbofish plus a paren
            // call still flags.
            if let (
                Some(TokenTree::Punct(c1)),
                Some(TokenTree::Punct(c2)),
                Some(TokenTree::Ident(name)),
            ) = triple
            {
                let joint_pair = c1.as_char() == ':'
                    && c1.spacing() == proc_macro2::Spacing::Joint
                    && c2.as_char() == ':'
                    && (k == 0
                        || !matches!(level.get(k - 1), Some(TokenTree::Punct(p)) if p.as_char() == ':'));
                // Path continuations (codex R14/R15/R16): a joint
                // `::` after the name continues the path when it
                // leads to another segment, a braced import, or
                // a glob — including through turbofish args
                // (`expect::<u8>::Some`), which the balance
                // scan looks past. The turbofish arm is ANCHORED
                // on the joint pair (Tier-1 R17-F1): without the
                // anchor, a `<` five tokens later (e.g. a
                // qualified path in the NEXT statement) would
                // silence a real preceding call.
                let joint_here = matches!(
                    (level.get(k + 3), level.get(k + 4)),
                    (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                        if a.as_char() == ':'
                            && a.spacing() == proc_macro2::Spacing::Joint
                            && b.as_char() == ':'
                );
                let continued = t6_path_continues(&level, k + 3)
                    || (joint_here && t6_turbofish_continues(&level, k + 5));
                if joint_pair
                    && !continued
                    && (t6_ident_is(name, "unwrap") || t6_ident_is(name, "expect"))
                {
                    let s = name.span().start();
                    let pat = if t6_ident_is(name, "unwrap") {
                        ".unwrap("
                    } else {
                        ".expect("
                    };
                    hits.push(((s.line, s.column), pat));
                }
            }
            // Tuple-field float (claude R6-FL1): `x.1. unwrap`
            // (space/comment/newline after the dot) lexes `1.`
            // as one float literal in pm AND rustc (the parser
            // splits it back into field access), swallowing the
            // dot — match the literal directly, reported at the
            // name, but only hanging off a field-access dot
            // (codex R15-F2): a level-start float is macro
            // data, and rustc only accepts the dotted form as
            // field access otherwise.
            if let (Some(TokenTree::Literal(lit)), Some(TokenTree::Ident(name))) =
                (level.get(k), level.get(k + 1))
            {
                // Tuple-field context (codex R15-F2/R16-F2/R17-F1/
                // R18-F1): the float must hang off tuple-field
                // access — a standalone dot, or a chain of
                // trailing-dot floats rooted at one
                // (`x.0. 0.`); range-seeded chains (`0..1. 2.`)
                // and receiver-less floats never qualify.
                let field_dot = t6_float_chain_rooted(&level, k);
                if lit.to_string().ends_with('.')
                    && field_dot
                    && (t6_ident_is(name, "unwrap") || t6_ident_is(name, "expect"))
                    && t6_call_follows(&level, k + 2)
                {
                    let s = name.span().start();
                    let pat = if t6_ident_is(name, "unwrap") {
                        ".unwrap("
                    } else {
                        ".expect("
                    };
                    hits.push(((s.line, s.column), pat));
                }
            }
            if let Some(TokenTree::Group(g)) = level.get(k) {
                levels.push(g.stream().into_iter().collect());
            }
            k += 1;
        }
    }
    hits.sort();
    let mut violations = Vec::new();
    for ((line, col), pat) in hits {
        // Half-open spans (codex R13-F1): `span_close().end()`
        // is exclusive (one past `}`), so an invocation glued
        // to the closer (`}panic!()`) sits outside the skip.
        let inside = skips
            .iter()
            .any(|(s, e)| *s <= (line, col) && (line, col) < *e);
        if !inside {
            let code = lines
                .get(line - 1)
                .map(|l| normalize(l))
                .unwrap_or_default();
            violations.push(format!("{rel}:{line}: {pat}: {code}"));
        }
    }
    violations
}

// (Hand lexer retired, D120: `raw_closer_end`, `skip_raw`,
// `skip_suffix`, `skip_char`, and `strip_block_scan` stood
// here. proc-macro2 is the single lexer now; every shape
// they learned across R7–R11 lives on as a matcher pin.)

// (Scanner unit pins retired with the hand lexer, D120:
// P1/P3/P4/R2/R3/handoff/c0/stringy/token-start cases are
// re-expressed as end-to-end matcher pins below — a token
// matcher has no cross-line states to unit-test.)

/// T6 matcher-level pins (codex R9-F2 + claude R1, kept
/// through the D120 token rewrite): evasion shapes end to
/// end through `t6_violations` over synthetic sources. Same
/// inputs and verdicts as the hand-lexer era; only the
/// mechanism comments changed.
#[test]
fn t6_matcher_flags_and_skips_hold() {
    // F1-forward (codex R9): a literal between the attribute
    // and `mod` spends governance — no skip opens and the
    // production unwrap flags. (The input stays balanced so
    // it lexes; the old hand matcher never required that.)
    let v = t6_violations(
        "#[cfg(test)]\n\"a\\\nsecond\"/*c*/mod tests {\npub fn p() -> u8 {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:") && v[0].contains(".unwrap("), "{v:?}");
    // F1-reverse (codex R9): macro token soup inside the
    // skipped brace span stays skipped — group spans, not
    // brace counting, delimit the skip.
    let v = t6_violations(
        "#[cfg(test)]\nmod tests {\n    macro_rules! m {\n        ({ \"a\\\nx\"}\"y\") => {};\n    }\n    fn t() {\n        Some(1).unwrap()\n    }\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // F2-char (codex R9 / claude R1-F1): a quote inside a
    // char literal is one token — the call flags.
    let v = t6_violations(
        "pub fn p(s: &str) -> usize {\ns.find('\"').unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    // F1-raw (claude R1-F1): backslash inside a raw string
    // is content — the call flags.
    let v = t6_violations(
        "pub fn p(s: &str) -> &str {\ns.strip_prefix(r\"C:\\\").unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    // F1-block (claude R1-F1): a quote inside a block comment
    // is trivia — the call flags.
    let v = t6_violations(
        "pub fn p() -> u8 {\nlet v = /* \" */ Some(1).unwrap();\nv\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // claude R1-F2: a shipped `mod tests` (no attribute)
    // must NOT skip.
    let v = t6_violations(
        "#[allow(dead_code)]\nmod tests {\npub fn h() -> u8 {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":4:"), "{v:?}");
    // Control: a real cfg(test) module still skips, and
    // production around it still flags.
    let v = t6_violations(
        "pub fn a() -> u8 {\nSome(1).unwrap()\n}\n#[cfg(test)]\nmod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
}

/// T6 matcher pins, round 2 (codex R10 + claude R2,
/// kept through the D120 token rewrite): attribute lists,
/// group-opaque skips, literal-suffix shapes, and C
/// strings, end to end.
#[test]
fn t6_matcher_r10_rules_hold() {
    // Transparent closer (codex R10-F1): the brace span ends
    // at `}` regardless of the comment prefix — production
    // after it flags.
    let v = t6_violations(
        "#[cfg(test)]\nmod tests {\nfn t() {}\n/*c*/}\npub fn p() -> u8 {\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":6:"), "{v:?}");
    // Stacked attributes (codex R10-F2): governance rides
    // the whole list — the test body stays skipped.
    let v = t6_violations(
        "#[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Trailing trivia (codex R10-F2): same, with a comment.
    let v = t6_violations(
        "#[cfg(test)] // Local harness.\nmod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // No transfer across code (codex R10-F2 lock): the attr
    // governed the fn, not the module — flags.
    let v = t6_violations(
        "#[cfg(test)]\nfn helper() {}\nmod prod {\nfn f() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Macro-dropped attribute (codex R10-F3): attr+mod
    // inside a group never govern — both unwraps flag.
    let v = t6_violations(
        "macro_rules! expose {\n(#[$meta:meta] $item:item) => {\n$item\n};\n}\nexpose! {\n#[cfg(test)]\nmod fixture {\npub fn prod(v: Option<u8>) -> u8 {\nv.unwrap()\n}\n}\n}\npub fn real() -> u8 {\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 2, "{v:?}");
    assert!(v[0].contains(":10:") && v[1].contains(":15:"), "{v:?}");
    // Suffix letters (claude R2-N1): `1r`, `"a"r`, `'c'r`
    // are ordinary tokens to proc-macro2 (all three lex —
    // probed) — the production unwrap flags.
    for prefix in ["1r", "\"a\"r", "'c'r"] {
        let text = format!(
            "macro_rules! sink {{\n($($t:tt)*) => {{}};\n}}\nsink! {{ {prefix}\"\\\"x\" }}\npub fn p() -> u8 {{\nSome(1).unwrap()\n}}\n"
        );
        let v = t6_violations(&text, "synth.rs");
        assert_eq!(v.len(), 1, "{prefix}: {v:?}");
        assert!(v[0].contains(":6:"), "{prefix}: {v:?}");
    }
    // Prefixed opener (D120 deliberate inversion): `/*c*/mod`
    // with the attribute now SKIPS — comments are trivia to
    // the tokenizer, and the module IS cfg(test). The old
    // over-flag was a column heuristic, not a rule.
    let v = t6_violations(
        "#[cfg(test)]\n/*c*/mod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Raw C strings (claude R3-C1): `cr"\"` is one literal
    // token — the production unwrap flags.
    let v = t6_violations(
        "pub fn p(x: Option<u8>) -> u8 {\nlet _s = cr\"\\\";\nlet v = x.unwrap();\nlet _q = '\"';\nv\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":3:"), "{v:?}");
    // Hashed raw C string: same, with `#` armor.
    let v = t6_violations(
        "pub fn p(x: Option<u8>) -> u8 {\nlet _s = cr#\"\\\"#;\nlet v = x.unwrap();\nlet _q = '\"';\nv\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":3:"), "{v:?}");
    // Cooked C string control: one literal token — flags too
    // (locks the non-raw path).
    let v = t6_violations(
        "pub fn p(x: Option<u8>) -> u8 {\nlet _s = c\"\\\\\";\nlet v = x.unwrap();\nlet _q = '\"';\nv\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":3:"), "{v:?}");
    // Tier-1 R10-F1 (Q): the delimiter-neutral shape that
    // broke the parity claim — under tokens it is just
    // another must-flag: the literal interior never yields
    // a `.`+`unwrap`+group triple, the real call does.
    let v = t6_violations(
        "pub fn p() {\nlet _s = cr\"\\\";\nv.unwrap(\"x(y)z\");\n// \" resolve\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":3:"), "{v:?}");
}

// (Lexer differential retired with the hand lexer, D120:
// with proc-macro2 as the single lexer there is nothing to
// cross-check — a desync class cannot exist.)

/// T6 matcher pins, round 3 (codex R12 + claude R4,
/// D120): every shape that broke the hand lexer, locked
/// against the token matcher — plus rule-shape locks and
/// the deliberate divergences from hand behavior.
#[test]
fn t6_matcher_r12_token_rules_hold() {
    // M1 (claude R4 = codex R12 ASCII variant): multiline
    // raw close with a suffix `r` — the old continuation
    // path skipped suffix handling and hid the call with a
    // green differential. Tokens have no suffix path.
    let v = t6_violations(
        "macro_rules! sink {\n    ($($t:tt)*) => {};\n}\n\n#[allow(dead_code)]\npub(crate) fn probe_mrs(v: Option<&str>) -> usize {\n    sink! {\n    r#\"a\n\"#r\"\\\"x\"\n    \"}\" }\n    let n = v.unwrap().len() + \"()()()\".len();\n    // \" resolve\n    n + 1\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":11:") && v[0].contains(".unwrap("), "{v:?}");
    // M2 (claude R4): whitespace between the method and its
    // parens inside a macro body — text matching missed
    // with no lexer bug at all. Triples ignore trivia.
    let v = t6_violations(
        "macro_rules! emit {\n    ($($t:tt)*) => { $($t)* };\n}\n\nemit! {\n    #[allow(dead_code)]\n    pub(crate) fn probe_ws(v: Option<u8>) -> u8 { v.unwrap () }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":7:"), "{v:?}");
    // LRM (codex R12 finding 1): U+200E between a string and
    // `r#` — the old suffix walk consumed it as ident content
    // and hid the call (a regression: old flagged, tip
    // missed). The shape compiles, so it is in-threat-model.
    let lrm = char::from_u32(0x200e).unwrap().to_string();
    let text = format!(
        "macro_rules! t6_review_sink {{\n    ($($t:tt)*) => {{}};\n}}\n\npub fn t6_review_r12(v: Result<u8, &'static str>) -> u8 {{\n    t6_review_sink! {{ \"label\"{lrm}r#\"\"}}\"\\\"# }}\n    let result = v.expect(\"reason (key) here\");\n    // \" restore\n    result\n}}\n"
    );
    let v = t6_violations(&text, "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":7:") && v[0].contains(".expect("), "{v:?}");
    // Attribute leak (codex R12 syn trio): the cfg attr sits
    // inside the macro group; the group-closing line must not
    // launder governance to the top-level `mod`.
    let v = t6_violations(
        "macro_rules! t6_review_sink {\n    ($($t:tt)*) => {};\n}\n\nt6_review_sink! {\n#[cfg(test)]\n#[allow(dead_code)]}\nmod t6_review_prod {\n    pub fn t6_review_r12(value: Option<u8>) -> u8 {\n        value.unwrap()\n    }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":10:"), "{v:?}");
    // Comment-prefixed closer (codex R12 syn trio): the brace
    // span ends at `}` — production after it flags.
    let v = t6_violations(
        "#[cfg(test)]\n#[rustfmt::skip]\nmod t6_review_tests {\n    #[test]\n    fn verifies() {}\n/* note */ }\n\npub fn t6_review_r12(value: Option<u8>) -> u8 {\n    value.unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":9:"), "{v:?}");
    // Comment between method and parens (codex R12 syn trio):
    // trivia inside the triple cannot hide the call.
    let v = t6_violations(
        "pub fn t6_review_r12(value: Option<u8>) -> u8 {\n    value.unwrap /* reason */ ()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Line comment splitting the triple: reported at the
    // `.`'s line (lexable; compilability is irrelevant for
    // synth pins — the corpus is compiled separately).
    let v = t6_violations(
        "pub fn t6_review_r12(value: Option<u8>) -> u8 {\n    value.unwrap // reason\n        ()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Combining-mark suffix (claude R4 nit): the old ident
    // predicates disagreed on non-ASCII; the single lexer
    // has no predicates to disagree.
    let comb = char::from_u32(0x301).unwrap().to_string();
    let text = format!(
        "macro_rules! sink {{\n    ($($t:tt)*) => {{}};\n}}\nsink! {{ 1x{comb}r\"\\\"x\" }}\n\n#[allow(dead_code)]\npub(crate) fn probe_n1(x: Option<u8>) -> u8 {{\n    x.unwrap()\n}}\n\nsink! {{ 1x{comb}r\"\\\"x\" }}\n"
    );
    let v = t6_violations(&text, "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":8:"), "{v:?}");
    // cfg-expression: not exactly `cfg(test)` — the module
    // stays scanned (fail-closed and loud, preserved).
    let v = t6_violations(
        "#[cfg(all(test, unix))]\nmod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":4:"), "{v:?}");
    // Spaced cfg (D120 deliberate fix): `#[cfg (test)]` IS a
    // test module — skips (the old exact-string gate
    // false-positived).
    let v = t6_violations(
        "#[cfg (test)]\nmod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Same-line attr+mod (D120 deliberate fix): tokens have
    // no lines — skips (the old line gate false-positived).
    let v = t6_violations(
        "#[cfg(test)] mod tests {\nfn t() {\nSome(1).unwrap()\n}\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Spaced bang (D120 deliberate fix): `panic !(…)` calls
    // panic — flags (the old substring missed it).
    let v = t6_violations("pub fn p() {\npanic !(\"boom\");\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains("panic!"), "{v:?}");
    // Trailing code on the closer's line: span-precise
    // skipping flags it (the old closer line was never
    // scanned — a hole, now closed).
    let v = t6_violations(
        "#[cfg(test)]\nmod tests {\nfn t() {}\n} pub fn p() -> u8 { Some(1).unwrap() }\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":4:"), "{v:?}");
    // `mod name;` opens nothing: no brace group, no skip.
    let v = t6_violations(
        "#[cfg(test)]\nmod foo;\npub fn p() -> u8 {\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":4:"), "{v:?}");
    // Pattern text inside a string is content, not a call.
    let v = t6_violations(
        "pub fn p() {\nlet _s = \"call .unwrap( here\";\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Pattern text inside comments (line, block, doc) is
    // trivia, not a call.
    let v = t6_violations(
        "pub fn p() {\n// .unwrap( in comment\n/* .expect( */\n/// panic! docs\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Field without parens: no group, no call.
    let v = t6_violations("pub fn p(v: V) -> F {\nv.unwrap\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    // Free function without a dot: no receiver, no method.
    let v = t6_violations("pub fn p() {\nlet _x = unwrap(1);\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    // `println!` stays out of scope (documented residual).
    let v = t6_violations("pub fn p() {\nprintln!(\"hi\");\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    // Braced panic: any group flavor after `!` is a call.
    let v = t6_violations("pub fn p() {\npanic!{\"boom\"}\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Macro-pattern controls: `eprintln!`, `panic!`, and
    // `.expect(` each flag (the suite historically pinned
    // only `.unwrap(`).
    let v = t6_violations(
        "pub fn p(v: Result<u8, &str>) -> u8 {\neprintln!(\"oops\");\nif v.is_err() {\npanic!(\"boom\");\n}\nv.expect(\"reason\")\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 3, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains("eprintln!"), "{v:?}");
    assert!(v[1].contains(":4:") && v[1].contains("panic!"), "{v:?}");
    assert!(v[2].contains(":6:") && v[2].contains(".expect("), "{v:?}");
    // Nested test module: top-level-only skip (hand-matcher
    // parity, deliberately not expanded) — flags.
    let v = t6_violations(
        "mod outer {\n#[cfg(test)]\nmod inner {\nfn t() {\nSome(1).unwrap()\n}\n}\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Inner `#![…]` attribute: never governs — flags.
    let v = t6_violations(
        "#![doc = \"x\"]\npub fn p() -> u8 {\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":3:"), "{v:?}");
    // Continuation-adjacent call (P1/P3 re-expressed): a
    // multiline cooked string with comment-looking tail —
    // the call after it flags.
    let v = t6_violations(
        "pub fn p() -> u8 {\nlet h = \"a\\\nmid\\\n/* tail\";\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Multiline-raw-adjacent call (R2 re-expressed): block
    // tokens inside the raw are content — the call flags.
    let v = t6_violations(
        "pub fn p() -> u8 {\nlet f = r#\"l1\n/* poison\ntail\"#;\nSome(1).unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Sibling lock: a triple split across a group boundary
    // never matches — the `.` here lives inside the macro
    // group while `unwrap()` sits outside.
    let v = t6_violations(
        "macro_rules! m {\n($t:tt) => {};\n}\nm!(.);\nfn p(v: V) {\nunwrap()\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Raw identifiers (Tier-1 R12-F1): `r#unwrap` etc. are
    // the same names — they compile, execute, and must flag
    // (the `r#panic!`/`r#eprintln!` half was a token-rewrite
    // regression: the old substring matched them).
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\nlet _ = v.r#unwrap();\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".unwrap("), "{v:?}");
    let v = t6_violations(
        "pub fn p(v: Result<u8, &str>) -> u8 {\nlet _ = v.r#expect(\"x\");\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".expect("), "{v:?}");
    let v = t6_violations("pub fn p() {\nr#panic!(\"boom\");\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains("panic!"), "{v:?}");
    let v = t6_violations("pub fn p() {\nr#eprintln!(\"oops\");\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains("eprintln!"), "{v:?}");
    // Adjacent-after-close (codex R13-F1): `span_close().end()`
    // is exclusive — an invocation glued to `}` sits outside
    // the skip and flags. (The `abort!` inside the macro
    // definition is not a pattern name — stays silent.)
    let v = t6_violations(
        "use core::panic as abort;\n\nmacro_rules! panic {\n    () => {\n        pub fn production() {\n            abort!(\"boom\");\n        }\n    };\n}\n\n#[cfg(test)]\nmod tests {}panic!();\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":12:") && v[0].contains("panic!"), "{v:?}");
    // Range dot (codex R13-F2): the second dot of `..` never
    // starts a triple — the freestanding call stays silent.
    let v = t6_violations(
        "fn unwrap() -> u8 {\n    1\n}\n\npub fn production() -> std::ops::RangeTo<u8> {\n    .. /* end bound */ unwrap()\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Range no-overcorrection: a REAL method call after a
    // range (`0..x.unwrap()` parses as `0..(x.unwrap())`)
    // still flags — only the range's own dot is excluded.
    let v = t6_violations(
        "pub fn p(x: Option<u8>) -> u8 {\nlet _r = 0..x.unwrap();\n0\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Path calls (claude R5-U1): `Option::unwrap(v)` panics
    // like the method — flags (reported at the name).
    let v = t6_violations(
        "pub(crate) fn probe_ufcs(v: Option<u8>) -> u8 {\n    Option::unwrap(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".unwrap("), "{v:?}");
    let v = t6_violations(
        "pub(crate) fn probe_ufcsr(r: Result<u8, String>) -> u8 {\n    Result::expect(r, \"boom\")\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".expect("), "{v:?}");
    // Fn-pointer form: no call follows, still the panic fn.
    let v = t6_violations(
        "pub(crate) fn probe_fnptr(v: Vec<Option<u8>>) -> Vec<u8> {\n    v.into_iter().map(Option::unwrap).collect()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Qualified path: turbofish receiver doesn't hide it.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    <Option<u8>>::unwrap(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Path no-overreach: `unwrap_or_clone` is one ident, not
    // `unwrap` (locks the live corpus instance silent).
    let v = t6_violations(
        "pub fn p(x: std::sync::Arc<u8>) -> u8 {\n    std::sync::Arc::unwrap_or_clone(x)\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `eprint!` (claude R5): the same stderr diagnostic path
    // as `eprintln!` — flags (corpus census: zero hits).
    let v = t6_violations("pub fn p() {\neprint!(\"boom\\n\");\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains("eprint!"), "{v:?}");
    let v = t6_violations("pub fn p() {\nr#eprint!(\"boom\");\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // UFCS namespace segment (codex R14-F1): `expect` followed
    // by `::Spec` is a qualifier, not a call — silent.
    let v = t6_violations(
        "pub mod expect {\n    pub struct Spec;\n}\n\npub fn spec() -> crate::expect::Spec {\n    expect::Spec\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // UFCS triple colon (codex R14-F2): `:::` supplies no
    // suffix pair — silent.
    let v = t6_violations(
        "macro_rules! flags {\n    ($key:ident :: : $value:ident) => {};\n}\n\nflags!(status:::expect);\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // UFCS spaced colons (codex R14-F2): `: :` is not a path
    // separator — silent.
    let v = t6_violations(
        "macro_rules! flags {\n    ($key:ident : : $value:ident) => {};\n}\n\nflags!(status: : expect);\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // UFCS terminal turbofish: `::<>` after the name preserves
    // the call (E0107 for std unwrap — synth-only shape that
    // locks the terminal check from over-skipping).
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    Option::unwrap::<u8>(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // UFCS spaced separator: `Option :: unwrap ( v )` compiles
    // (Tier-1 R14 probed) — the joint pair is what matters.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    Option :: unwrap ( v )\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Tuple-field float, spaced (claude R6-FL1): `1.` lexes as
    // one float, swallowing the dot — matched literally.
    let v = t6_violations(
        "pub fn p(x: (u8, Option<u8>)) -> u8 {\n    x.1. unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".unwrap("), "{v:?}");
    // Tuple-field float, comment-split: same, with `/**/` where
    // the dot was.
    let v = t6_violations(
        "pub fn p(x: (u8, Result<u8, String>)) -> u8 {\n    x.1./**/expect(\"m\")\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".expect("), "{v:?}");
    // Tuple-field control: unspaced, the dot stays separate and
    // the ordinary method rule fires.
    let v = t6_violations(
        "pub fn p(x: (u8, Option<u8>)) -> u8 {\n    x.1.unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // `assert!` stays out (claude R6): deliberate invariant
    // checks, a different contract — locked silent.
    let v = t6_violations("pub fn p(x: bool) {\n    assert!(x);\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    // Braced import (codex R15-F1): `expect::{…}` continues
    // the path — silent.
    let v = t6_violations(
        "pub mod expect {\n    pub struct Spec;\n    pub struct Error;\n}\n\npub use crate::expect::{Error, Spec};\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Glob import (codex R15-F1): `expect::*` continues the
    // path — silent.
    let v = t6_violations(
        "pub mod expect {\n    pub struct Spec;\n}\n\npub use crate::expect::*;\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Float in macro data (codex R15-F2): level-start float
    // has no field-access dot — silent.
    let v = t6_violations(
        "macro_rules! rule {\n    ($value:literal $name:ident $payload:tt) => {\n        pub const EXPECTED: f64 = $value;\n    };\n}\n\nrule! { 1. expect(\"allowed\") }\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Empty turbofish in macros (claude R7-TF1): rustfmt
    // strips `::<>` in normal code but macro bodies are
    // opaque to it — the call hides there without the rule.
    let v = t6_violations(
        "macro_rules! emit {\n    ($($t:tt)*) => { $($t)* };\n}\nemit! {\n    pub(crate) fn probe_tfm(v: Option<u8>) -> u8 { v.unwrap::<>() }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    let v = t6_violations(
        "macro_rules! emit {\n    ($($t:tt)*) => { $($t)* };\n}\nemit! {\n    pub(crate) fn probe_tfe(r: Result<u8, String>) -> u8 { r.expect::<>(\"m\") }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    let v = t6_violations(
        "macro_rules! emit {\n    ($($t:tt)*) => { $($t)* };\n}\nemit! {\n    pub(crate) fn probe_tfflt(x: (u8, Option<u8>)) -> u8 { x.1. unwrap::<>() }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Spaced turbofish colons: `: :` is not a path separator
    // (mirrors the UFCS joint gate) — silent on rejected code.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    v.unwrap: :<>(v)\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Turbofish without a call (codex R16-F1): macro data
    // matching `($ns . $key :: < $ty >)` — no parens, no
    // call, silent.
    let v = t6_violations(
        "macro_rules! describe {\n    ($ns:ident . $key:ident :: < $ty:ty >) => {\n        pub type Param = $ty;\n    };\n}\n\ndescribe! { record.expect::<u8> }\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Bare `::` after a name (codex R16-F1): `::u8` and
    // trailing `::` open no turbofish — silent.
    let v = t6_violations("pub fn p() {\n    m!(record.expect::u8);\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    let v = t6_violations("pub fn p() {\n    m!(v.unwrap::);\n}\n", "synth.rs");
    assert!(v.is_empty(), "{v:?}");
    // Range-dot float (codex R16-F2): the float's dot is a
    // range's second dot, not field access — silent.
    let v = t6_violations(
        "macro_rules! threshold {\n    ($lo:literal .. $hi:literal $name:ident $label:tt) => {\n        pub const BOUNDS: (u8, f64) = ($lo, $hi);\n    };\n}\n\nthreshold! { 0..1. expect(\"allowed\") }\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Range-float no-overcorrection: a REAL tuple-field call
    // after a range still flags — only the range's own dot
    // is excluded.
    let v = t6_violations(
        "pub fn p(v: (u8, Option<u8>)) -> u8 {\n    0..v.1. /* access */ unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Post-turbofish continuation (codex R16-F3): a path
    // segment after the generic args still continues —
    // silent.
    let v = t6_violations(
        "#[allow(non_camel_case_types)]\npub type expect<T> = Option<T>;\n\npub fn sample() -> Option<u8> {\n    crate::expect::<u8>::Some(1)\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Terminal turbofish call: `<>` plus parens still flags.
    let v = t6_violations(
        "pub fn p() -> u8 {\n    Probe::expect::<u8>()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Arrow inside turbofish: `->` is not a closer — the scan
    // continues to the real close, then sees `::Assoc`.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<fn() -> u8>::Assoc;\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Anchored turbofish scan (Tier-1 R17-F1): without the
    // joint-pair anchor, the `<` of a qualified path in the
    // NEXT statement sits exactly at k+5 and silences a real
    // preceding call. Both must flag.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    Option::unwrap(v); <Vec<u8>>::new();\n    0\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".unwrap("), "{v:?}");
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    Option::unwrap(v); <u8>::MAX;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Chained tuple selectors (codex R17-F1): the second
    // float hangs off the first — the real call flags.
    let v = t6_violations(
        "pub fn required(x: ((Option<u8>,),)) -> u8 {\n    x.0. /* outer */ 0. /* inner */ unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:") && v[0].contains(".unwrap("), "{v:?}");
    // Chained float plus turbofish in a forwarding macro:
    // both refinements compose.
    let v = t6_violations(
        "macro_rules! fwd {\n    ($($t:tt)*) => { $($t)* };\n}\nfwd! {\n    pub fn p(x: ((Option<u8>,),)) -> u8 { x.0. 0. unwrap::<>() }\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":5:"), "{v:?}");
    // Three-link chain: each link checks one predecessor.
    let v = t6_violations(
        "pub fn p(x: (((Option<u8>,),),)) -> u8 {\n    x.0. 0. 0. unwrap()\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Semicolon turbofish data (codex R17-F2): `;` precludes
    // generic args — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $lo:literal ; $hi:literal > $data:tt) => {\n        pub const BOUNDS: (u8, u8) = ($lo, $hi);\n    };\n}\n\nset!(record.expect::<0; 1>(\"healthy\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Semicolon in a path continuation: same `;` rule in both
    // scans (consistency) — flags loud on rejected code.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<0; 1>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Range-seeded chain (codex R18-F1): the float chain
    // bottoms out at a range dot, not field access — silent.
    let v = t6_violations(
        "macro_rules! limit {\n    ($lo:literal .. $hi:literal $scale:literal $tag:ident $label:tt) => {\n        pub const BOUNDS: (u8, f64, f64) = ($lo, $hi, $scale);\n    };\n}\n\nlimit! { 0..1. 2. expect(\"allowed\") }\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Inclusive-range seed: the walk ends at `=`, not a dot.
    let v = t6_violations(
        "pub fn p() {\n    m!(0..=1. 2. expect(\"x\"));\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Dot-less seed: the walk ends at an ident, not a dot.
    let v = t6_violations(
        "pub fn p() {\n    m!(x 1. 2. expect(\"x\"));\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Level-start root dot: allowed, mirroring the method
    // gate (fail-closed soup noise; no compiling expression
    // starts with `.`).
    let v = t6_violations("pub fn p() {\n    m!(. 1. 2. unwrap());\n}\n", "synth.rs");
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // At-sign turbofish data (codex R18-F2): ungrouped `@`
    // precludes generic args (patterns need const blocks) —
    // macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $lo:literal @ $hi:literal > $data:tt) => {\n        pub const BOUNDS: (u8, u8) = ($lo, $hi);\n    };\n}\n\nset!(record.expect::<0 @ 1>(\"healthy\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // At-sign in a path continuation: same `@` rule in both
    // scans (consistency) — flags loud on rejected code.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<0 @ 1>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare pipe in turbofish (Tier-1 R20-F1): bounds use `+`,
    // closures/patterns need groups — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a | b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Pipe in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a | b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare hash in turbofish (Tier-1 R20-F2): attrs never in
    // args — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a # b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Hash in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a # b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Dotted key in turbofish (Tier-1 R20-F3): `a.b` is not a
    // type — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident . $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a.b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Range in turbofish (Tier-1 R20-F3): `..` hits the same
    // dot arm — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $lo:literal .. $hi:literal > $data:tt) => {\n        pub const BOUNDS: (u8, u8) = ($lo, $hi);\n    };\n}\nset!(record.expect::<0 .. 1>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Dot in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a.b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Lone colon in turbofish (Tier-1 R20-F4): `a : b` is not
    // a path — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident : $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a : b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Lone colon in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a : b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Regression anchors: paths, fragments, and dyn bindings
    // inside turbofish keep flagging.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    v.expect::<std::vec::Vec<u8>>(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    v.expect::<$t>(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    v.expect::<Box<dyn Iterator<Item = u8>>>(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Paths inside a continued turbofish: still skipped.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<std::vec::Vec<u8>>::Assoc;\n}\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Bare `?` in turbofish (Tier-1 R21-F1): `?Trait` dead
    // (E0658), `?Sized` declaration-only — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < ? > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<?>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `?` in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a ? b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare `%` in turbofish (Tier-1 R21-F1): binops need
    // const blocks — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a % b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `%` in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a % b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare `^` in turbofish (Tier-1 R21-F1): binops need
    // const blocks — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a ^ b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `^` in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a ^ b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare `/` in turbofish (Tier-1 R21-F1): binops need
    // const blocks — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a / b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `/` in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a / b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Bare `~` in turbofish (Tier-1 R21-F1): no unary `~`,
    // `~const` declaration-only — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident $sep:tt $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a ~ b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // `~` in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a ~ b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Fat arrow in turbofish (codex R20-F1): `=>` is never a
    // real closer (match arms need blocks) — macro data,
    // silent. Contrast `->`, which must be skipped.
    let v = t6_violations(
        "macro_rules! route {\n    ($record:ident . $name:ident :: < $key:ident => $target:tt > $label:tt) => {\n        pub const QUEUE: &str = stringify!($key);\n    };\n}\n\nroute!(record.expect::<work => (worker)>(\"ready\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Fat arrow in a path continuation: same rule — loud.
    // (Shaped so the `::Assoc` follower would falsely skip
    // without the rejection: an early close + `::` follower
    // skips, so only the `=>` rejection keeps it loud.)
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a => ::Assoc>;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Compound `==` in turbofish (codex R20-F2): comparisons
    // need const blocks — macro data, silent.
    let v = t6_violations(
        "macro_rules! set {\n    ($record:ident . $name:ident :: < $a:ident == $b:ident > $data:tt) => {\n        pub const PAIR: u8 = 1;\n    };\n}\nset!(record.expect::<a == b>(\"x\"));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // The other five compounds: same rule, same silence.
    for op in ["!=", "+=", "-=", "*=", "&="] {
        let text = format!(
            "macro_rules! set {{\n    ($record:ident . $name:ident :: < $a:ident {op} $b:ident > $data:tt) => {{\n        pub const PAIR: u8 = 1;\n    }};\n}}\nset!(record.expect::<a {op} b>(\"x\"));\n"
        );
        let v = t6_violations(&text, "synth.rs");
        assert!(v.is_empty(), "{op}: {v:?}");
    }
    // Compound in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a == b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Colon run in turbofish (codex R20-F2): `::::` never
    // separates — macro data, silent.
    let v = t6_violations(
        "macro_rules! m {\n    ($($t:tt)*) => {};\n}\nm!(v.expect::<a::::b>(x));\n",
        "synth.rs",
    );
    assert!(v.is_empty(), "{v:?}");
    // Colon run in a path continuation: same rule — loud.
    let v = t6_violations(
        "pub fn p() {\n    let _ = crate::expect::<a::::b>::Assoc;\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    // Regression anchors: unary minus, bare-`>` comparison.
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> u8 {\n    v.expect::<-1>(v)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
    let v = t6_violations(
        "pub fn p(v: Option<u8>) -> bool {\n    v.expect::<u8>() > Some(1)\n}\n",
        "synth.rs",
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(":2:"), "{v:?}");
}

#[test]
fn h7_cli_surface_carries_no_panics() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for rel in T6_FILES {
        let text = std::fs::read_to_string(root.join(rel)).unwrap();
        violations.extend(t6_violations(&text, rel));
    }
    assert!(
        violations.is_empty(),
        "H7-T6 CLI-surface audit failed:\n{}",
        violations.join("\n")
    );
}

// Real host controller, count routing, finalization, policy and artifact I/O.
// The doubles replace only target/discovery/kernel operations, never the CLI
// result consumer. The raw positive prefix is deliberately impossible evidence
// for a never-released child and must remain rejected, not policy input.
mod g1_host {
    use osslscope::{
        capture::*,
        count_session::*,
        discovery::{maps::Mapping, session::*},
        evidence::*,
        plan, target,
    };
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
        path::PathBuf,
        rc::Rc,
        sync::Arc,
        time::{Duration, Instant, SystemTime},
    };
    pub const PID: u32 = 4242;
    #[derive(Clone, Copy, Debug)]
    pub enum Scenario {
        Cancelled,
        Exit(i32),
        SetupIo,
        ReleaseIo,
        CustodyIo,
        CountIo,
        Pending,
        ExternalOpen,
        Binding,
        Contradictory,
        Timeout,
        DiscoveryFinishIo,
        CustodyFinishIo,
    }
    pub struct Clock {
        ns: Cell<u64>,
        base: Instant,
    }
    impl ClockPort for Clock {
        fn checked_monotonic_ns(&self) -> Option<u64> {
            Some(self.ns.get())
        }
        fn monotonic_ns(&self) -> u64 {
            self.ns.get()
        }
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.ns.get())
        }
        fn wall_now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000)
        }
        fn sleep(&self, d: Duration) {
            self.ns.set(self.ns.get() + d.as_nanos() as u64);
        }
    }
    struct Backend {
        inner: Rc<RefCell<FakeCountBackend>>,
        ready: Ready,
        clock: Rc<Clock>,
        requests: Rc<Cell<usize>>,
    }
    impl CountBackend for Backend {
        type Link = FakeLink;
        fn ready(&self) -> &Ready {
            &self.ready
        }
        fn attach(&mut self, r: AttachRequest) -> CommandResult<AttachAck<FakeLink>> {
            self.inner.borrow_mut().attach(r)
        }
        fn open_window(&mut self, r: OpenRequest) -> CommandResult<OpenReceipt> {
            self.inner.borrow_mut().open_window(r)
        }
        fn set_generation(&mut self, r: GenerationRequest) -> CommandResult<()> {
            self.inner.borrow_mut().set_generation(r)
        }
        fn drain(&mut self, r: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
            self.inner.borrow_mut().drain(r)
        }
        fn terminal_request(&mut self, d: Instant, f: ControllerFrontier) -> TerminalRequest {
            self.requests.set(self.requests.get() + 1);
            self.inner.borrow_mut().terminal_request(d, f)
        }
        fn terminal(&mut self, r: TerminalRequest) -> RawTerminal {
            let mut b = self.inner.borrow_mut();
            b.set_modeled_seal(Some(self.clock.ns.get()), Some(self.clock.ns.get()));
            b.terminal(r)
        }
        fn progress(&self) -> Option<RawCheckpoint> {
            self.inner.borrow().progress()
        }
        fn fork_permit(&self, _d: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
            Err(ForkBlocked::Unresolved)
        }
    }
    struct Discovery {
        scenario: Scenario,
        clock: Rc<Clock>,
        backend: Rc<RefCell<FakeCountBackend>>,
        cookie: u32,
        object: DiscoveredObject,
    }
    impl DiscoveryPort for Discovery {
        fn poll(&mut self, _b: PollBudget) -> anyhow::Result<DiscoveryDelta> {
            match self.scenario {
                Scenario::ExternalOpen => {}
                Scenario::SetupIo => {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                Scenario::Timeout => self.clock.sleep(Duration::from_secs(6)),
                _ => self.clock.ns.set(1100),
            }
            Ok(DiscoveryDelta {
                objects: vec![self.object.clone()],
                ..Default::default()
            })
        }
        fn traversal_active(&self) -> bool {
            matches!(self.scenario, Scenario::ExternalOpen)
        }
        fn poll_traversal(&mut self, _baseline: bool) -> anyhow::Result<TraversalDelta> {
            self.clock.ns.set(1400);
            self.backend.borrow_mut().fire(PID, self.cookie, 1400, 5);
            self.clock.ns.set(1450);
            Err(std::io::Error::from_raw_os_error(libc::EIO).into())
        }
        fn snapshot(&self) -> DiscoverySnapshot {
            DiscoverySnapshot::default()
        }
        fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
            if matches!(self.scenario, Scenario::DiscoveryFinishIo) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            Ok(self.snapshot())
        }
    }
    struct Target {
        scenario: Scenario,
        clock: Rc<Clock>,
        resolved: Rc<Cell<usize>>,
        finishes: Rc<Cell<usize>>,
        released: bool,
    }
    impl TargetPort for Target {
        fn pid(&self) -> u32 {
            PID
        }
        fn is_owned(&self) -> bool {
            !matches!(self.scenario, Scenario::ExternalOpen)
        }
        fn release(&mut self) -> anyhow::Result<()> {
            if matches!(self.scenario, Scenario::ReleaseIo) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            if matches!(self.scenario, Scenario::Exit(_)) {
                anyhow::bail!("child exited before release");
            }
            self.released = true;
            self.clock.ns.set(1400);
            Ok(())
        }
        fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
            Ok(match self.scenario {
                Scenario::Exit(n) => Some(n),
                _ if self.resolved.get() > 0 => Some(137),
                Scenario::Binding | Scenario::Contradictory if self.released => Some(0),
                _ => None,
            })
        }
        fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
            self.resolved.set(self.resolved.get() + 1);
            if matches!(self.scenario, Scenario::CustodyIo) {
                Err(std::io::Error::from_raw_os_error(libc::ECHILD).into())
            } else {
                Ok(())
            }
        }
        fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
            self.finishes.set(self.finishes.get() + 1);
            if matches!(self.scenario, Scenario::CustodyFinishIo) {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD).into());
            }
            Ok(match self.poll_exit()? {
                Some(code) => target::TargetDisposition::Exited { code },
                None => target::TargetDisposition::Detached { pid: PID },
            })
        }
        fn verify(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }
    struct Lifecycle;
    impl LifecyclePort for Lifecycle {
        fn poll(&mut self) -> LifecycleDelta {
            LifecycleDelta::default()
        }
        fn fallback_partial(&self) -> bool {
            false
        }
    }
    struct Proc {
        live: Vec<Mapping>,
    }
    impl ProcPort for Proc {
        fn read_maps(&mut self, _p: u32) -> anyhow::Result<Vec<Mapping>> {
            Ok(self.live.clone())
        }
        fn read_file(&mut self, p: &str) -> anyhow::Result<Vec<u8>> {
            Ok(std::fs::read(p)?)
        }
        fn read_file_bound(
            &mut self,
            p: &str,
            _allowance: usize,
        ) -> std::io::Result<(Arc<[u8]>, (u64, u64))> {
            // Failure-fidelity scenarios are not bound tests: the
            // fixture object is this suite's own debug binary, which
            // outgrows any fixed per-object cap. Size the cap to the
            // file itself (pinned-identity + tear semantics of the
            // bounded helper are unchanged); bound enforcement stays
            // covered by the dedicated R14 suites.
            let bound = std::fs::metadata(p)
                .ok()
                .and_then(|m| usize::try_from(m.len()).ok())
                .unwrap_or(usize::MAX - 1);
            plan::read_file_bounded(p, bound).map(|f| (f.bytes, (f.dev, f.ino)))
        }
        fn stat_file(&mut self, _p: &str) -> Option<FileStat> {
            None
        }
        fn read_exe(&mut self, _p: u32) -> Option<PathBuf> {
            None
        }
        fn file_len(&mut self, p: &str) -> Option<u64> {
            std::fs::metadata(p).ok().map(|m| m.len())
        }
        fn read_comm(&mut self, _p: u32) -> Option<String> {
            None
        }
    }
    pub struct Run {
        pub result: anyhow::Result<Capture>,
        pub resolved: Rc<Cell<usize>>,
        pub requests: Rc<Cell<usize>>,
        pub finishes: Rc<Cell<usize>>,
    }
    pub fn run(scenario: Scenario) -> Run {
        use std::os::unix::fs::MetadataExt as _;
        let path = std::env::current_exe().unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        // Bound the self-read by the binary's own stat'd size: debug
        // test binaries outgrow any fixed guess (CI builds top the old
        // 128 MiB cap); the ELF program-header parse below needs the
        // whole file but nothing more.
        let file = plan::read_file_bounded(path.to_str().unwrap(), meta.len() as usize).unwrap();
        let elf = goblin::elf::Elf::parse(&file.bytes).unwrap();
        let off = elf
            .program_headers
            .iter()
            .find(|p| p.p_type == 1 && p.p_flags & 1 != 0)
            .unwrap()
            .p_offset
            + 16;
        let device = plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev()));
        let live = vec![Mapping {
            start: 0x70000000,
            end: 0x80000000,
            x: true,
            offset: 0,
            dev: plan::render_device(device),
            ino: meta.ino(),
            path: path.to_str().unwrap().into(),
        }];
        let clock = Rc::new(Clock {
            ns: Cell::new(if matches!(scenario, Scenario::ExternalOpen) {
                1300
            } else {
                1000
            }),
            base: Instant::now(),
        });
        let inner = Rc::new(RefCell::new(FakeCountBackend::new()));
        let requests = Rc::new(Cell::new(0));
        let ready = *inner.borrow().ready();
        let mut count = CountSession::new(
            PID,
            Backend {
                inner: inner.clone(),
                ready,
                clock: clock.clone(),
                requests: requests.clone(),
            },
        );
        let object_id = ObjectId(format!(
            "build:{}",
            osslscope::discovery::elf::read_build_id(&file.bytes).unwrap()
        ));
        let object = DiscoveredObject {
            dev: plan::render_device(device),
            ino: meta.ino(),
            display_locator: path.to_str().unwrap().into(),
        };
        let delta = CountDelta {
            discovered: vec![DiscoveredSite {
                site: SiteKey {
                    object: object_id.clone(),
                    device,
                    inode: meta.ino(),
                    offset: off,
                },
                candidates: vec![CandidateIdentity::new(
                    object_id,
                    "default".into(),
                    1,
                    7,
                    vec!["digest".into()],
                    false,
                )],
                candidates_coverage: CandidateCoverage::Complete,
            }],
            losses: vec![],
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        count
            .attach_delta(
                &delta,
                &live,
                &HashMap::from([(path.to_str().unwrap().into(), file)]),
                900,
                deadline,
            )
            .unwrap();
        let cookie = count.cookie_for(device, meta.ino(), off).unwrap();
        if !matches!(scenario, Scenario::ExternalOpen) {
            let first = if matches!(scenario, Scenario::Contradictory) {
                1050
            } else {
                1400
            };
            inner.borrow_mut().inject_row(
                cookie,
                0,
                osslscope_ebpf_common::CountValue {
                    count: 11,
                    first_ns: first,
                    last_ns: first,
                },
            );
            count.fence(FenceReason::MappingsChanged, deadline).unwrap();
            inner.borrow_mut().inject_row(
                cookie,
                1,
                osslscope_ebpf_common::CountValue {
                    count: 7,
                    first_ns: 1500,
                    last_ns: 1500,
                },
            );
        }
        if matches!(scenario, Scenario::Pending) {
            inner.borrow_mut().terminal_faults(FakeTerminalFaults {
                cleanup_pending: true,
                quiescence_unknown: true,
                enumeration: Some(EnumerationStatus::Unfinished),
                ..Default::default()
            });
        }
        if matches!(scenario, Scenario::CountIo) {
            inner.borrow_mut().terminal_faults(FakeTerminalFaults {
                close_errno: Some(libc::EIO),
                ..Default::default()
            });
        }
        let resolved = Rc::new(Cell::new(0));
        let finishes = Rc::new(Cell::new(0));
        let cfg = Config {
            duration: Duration::from_nanos(1000),
            settle: Duration::ZERO,
            harvest_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(1),
            harvest_object: None,
            count_object: None,
            members_object: None,
            dev_bundle: None,
            provider: None,
            builtin: false,
            table: None,
            force_offset: None,
            provider_enrollment: None,
            resolved_provider: None,
            image_digest: String::new(),
            trace_mode: osslscope::provider_observation::trace::TRACE_MODE_OFF,
            trace_by_api: false,
        };
        let info = TargetInfo {
            pid: PID,
            owned: !matches!(scenario, Scenario::ExternalOpen),
            comm: "fixture".into(),
            cmdline: String::new(),
            container_id: String::new(),
            kernel_release: "host-model".into(),
            sysctls: None,
            provider_build_id: String::new(),
            version_observations: Vec::new(),
            provider_path: String::new(),
            image_digest: String::new(),
            acquired_ns: 1000,
            acquired_instant: clock.base + Duration::from_nanos(1000),
            acquired_wall: clock.wall_now(),
        };
        let result = observe(
            &cfg,
            &info,
            SessionSet {
                discovery: Discovery {
                    scenario,
                    clock: clock.clone(),
                    backend: inner,
                    cookie,
                    object,
                },
                count,
                target: Target {
                    scenario,
                    clock: clock.clone(),
                    resolved: resolved.clone(),
                    finishes: finishes.clone(),
                    released: false,
                },
                lifecycle: Lifecycle,
            },
            clock.as_ref(),
            &mut Proc { live },
            &|| {
                matches!(
                    scenario,
                    Scenario::Cancelled
                        | Scenario::CustodyIo
                        | Scenario::CountIo
                        | Scenario::Pending
                )
            },
        );
        Run {
            result,
            resolved,
            requests,
            finishes,
        }
    }
}

fn g1_request(tag: &str) -> (std::path::PathBuf, osslscope::report::OutputRequest) {
    use osslscope::report::{OutputDest, OutputFormat, OutputRequest};
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "osslscope-g1-consumer-{}-{}-{tag}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (
        dir.clone(),
        OutputRequest {
            format: OutputFormat::Json,
            primary: OutputDest::File(dir.join("primary.json")),
            cbom: Some(OutputDest::File(dir.join("cbom.json"))),
        },
    )
}
fn g1_keep_artifacts(dir: &std::path::Path, result: &osslscope::report::CaptureCommandResult) {
    let retained = std::env::temp_dir()
        .join("osslscope-g1-production-consumer")
        .join(dir.file_name().unwrap());
    std::fs::create_dir_all(&retained).unwrap();
    for name in ["primary.json", "cbom.json"] {
        if dir.join(name).is_file() {
            std::fs::copy(dir.join(name), retained.join(name)).unwrap();
        }
    }
    std::fs::write(retained.join("human.txt"), render_human(&result.document)).unwrap();
    let artifact =
        |a: &ArtifactOutcome| serde_json::json!({"ok":a.ok,"bytes":a.bytes,"error":a.error});
    let context = result.failure_context.as_ref();
    std::fs::write(retained.join("result.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "exit_code":result.exit_code,"child_exit":result.child_exit,"calls":result.document.total_calls(),
        "primary":artifact(&result.delivery.primary),"cbom":result.delivery.cbom.as_ref().map(artifact),
        "diagnostics":result.diagnostics,"rejected_known_calls":context.and_then(|c|c.rejected.known_calls),
        "rejected_known_rows":context.and_then(|c|c.rejected.known_rows),
    })).unwrap()).unwrap();
}
fn g1_validate_artifacts(dir: &std::path::Path, result: &osslscope::report::CaptureCommandResult) {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("primary.json")).unwrap()).unwrap();
    osslscope::schema::validate_v2(&value).unwrap();
    osslscope::schema::check_v2_semantics(&value).unwrap();
    assert_eq!(
        value,
        serde_json::from_slice::<serde_json::Value>(&render_json(&result.document).unwrap())
            .unwrap()
    );
    let cbom: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("cbom.json")).unwrap()).unwrap();
    assert_eq!(cbom["bomFormat"], "CycloneDX");
    assert!(result.delivery.delivered_all());
    g1_keep_artifacts(dir, result);
    assert!(result.diagnostics.len() <= 8);
    assert!(result.diagnostics.iter().all(|s| s.chars().count() <= 200));
}
#[test]
fn g1_no_observation_cli_consumer_preserves_cause_and_custody() {
    use g1_host::Scenario::*;
    use osslscope::capture::{PreObservationCount, PreObservationFailure};
    use osslscope::report::*;
    for (scenario, want_report, want_check, status) in [
        (Cancelled, 3, 11, 137),
        (Exit(7), 1, 1, 7),
        (Exit(0), 3, 11, 0),
        (SetupIo, 4, 4, 137),
        (ReleaseIo, 4, 4, 137),
        (CustodyIo, 4, 4, 137),
        (CountIo, 4, 4, 137),
        (Pending, 3, 11, 137),
    ] {
        for check in [false, true] {
            let run = g1_host::run(scenario);
            let error = run.result.unwrap_err();
            let terminal = match &error.downcast_ref::<PreObservationFailure>().unwrap().count {
                PreObservationCount::Terminal(t) => t.clone(),
                _ => panic!("missing terminal"),
            };
            let (dir, request) = g1_request("no-observation");
            let rules = [PolicyRule::deny_provider("default")];
            let command = if check {
                CaptureCommand::Check { rules: &rules }
            } else {
                CaptureCommand::Report
            };
            let mut diagnostics = Vec::new();
            let result = consume_capture_result_with_diagnostics(
                Err(error.context("inner boundary").context("outer boundary")),
                command,
                &request,
                true,
                &mut diagnostics,
            );
            assert_eq!(
                result.exit_code,
                if check { want_check } else { want_report },
                "{scenario:?}, check={check}"
            );
            assert_eq!(result.child_exit, Some(status));
            assert_eq!(
                result.disposition,
                Some(osslscope::target::TargetDisposition::Exited { code: status })
            );
            assert!(result.document.sites.is_empty() && result.document.fenced.is_empty());
            assert_eq!(result.document.window.requested_start_ns, 0);
            assert_eq!(result.document.window.requested_end_ns, 0);
            let context = result.failure_context.as_ref().unwrap();
            assert_eq!(context.rejected.known_calls, Some(18));
            let PreObservationCount::Terminal(t) = &context.count else {
                panic!("lost terminal")
            };
            assert!(std::sync::Arc::ptr_eq(t, &terminal));
            assert_eq!(
                run.resolved.get(),
                if matches!(scenario, Exit(_)) { 0 } else { 1 }
            );
            assert_eq!(run.requests.get(), 1);
            if matches!(scenario, Cancelled | Exit(_) | Pending) {
                assert!(matches!(
                    result.document.status,
                    Completeness::Partial { .. }
                ));
                assert_eq!(
                    result
                        .document
                        .counters
                        .iter()
                        .filter(|c| c.name == "capture.no_observation" && c.value == 1)
                        .count(),
                    1
                );
                if check {
                    let p = result.document.policy.as_ref().unwrap();
                    assert_eq!(p.verdict, osslscope::evidence::PolicyVerdict::Inconclusive);
                    assert_eq!(p.rules[0].definite, 0);
                    assert_eq!(p.rules[0].possible, None);
                }
            } else {
                assert!(matches!(
                    result.document.status,
                    Completeness::Fatal {
                        kind: FatalKind::Environment(_),
                        ..
                    }
                ));
            }
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|s| s.contains("known-calls=18"))
            );
            assert!(!String::from_utf8_lossy(&diagnostics).contains("SiteExecution"));
            g1_validate_artifacts(&dir, &result);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
#[test]
fn g1_external_open_setup_error_reaches_cli_salvage() {
    use osslscope::capture::{CaptureRuntimeFailure, PreObservationCount, RuntimeBoundaryKind};
    use osslscope::report::*;
    for check in [false, true] {
        let run = g1_host::run(g1_host::Scenario::ExternalOpen);
        let capture = run.result.unwrap();
        assert_eq!(capture.document.total_calls(), 5);
        assert_eq!(capture.document.window.requested_start_ns, 1000);
        assert_eq!(capture.programmed_admission.unwrap().start_ns(), 1300);
        let terminal = match &capture.failure_context.as_ref().unwrap().count {
            PreObservationCount::Terminal(t) => Some(t.clone()),
            _ => None,
        };
        let error = anyhow::Error::new(CaptureRuntimeFailure {
            capture: std::sync::Arc::new(capture),
            terminal,
            kind: RuntimeBoundaryKind::SetupAfterOpen,
        })
        .context("inner boundary")
        .context("outer boundary");
        let (dir, request) = g1_request("external");
        let rules = [PolicyRule::deny_provider("default")];
        let result = consume_capture_result_with_diagnostics(
            Err(error),
            if check {
                CaptureCommand::Check { rules: &rules }
            } else {
                CaptureCommand::Report
            },
            &request,
            false,
            &mut Vec::new(),
        );
        assert_eq!(
            result.document.total_calls(),
            5,
            "completed Open scope must survive the actual production Err consumer"
        );
        assert_eq!(result.exit_code, if check { 10 } else { 1 });
        assert!(matches!(
            result.document.status,
            Completeness::Fatal {
                kind: FatalKind::Runtime(_),
                ..
            }
        ));
        if check {
            let p = result.document.policy.as_ref().unwrap();
            assert_eq!(p.rules[0].definite, 5);
            assert_eq!(p.rules[0].possible, None);
        }
        assert_eq!(
            run.resolved.get(),
            0,
            "external targets are never resolved or signaled"
        );
        g1_validate_artifacts(&dir, &result);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn g1_post_observation_binding_failure_reaches_cli_salvage() {
    use osslscope::{
        capture::{CaptureRuntimeFailure, PreObservationCount},
        report::*,
    };
    for scenario in [g1_host::Scenario::Binding, g1_host::Scenario::Contradictory] {
        for check in [false, true] {
            let host = g1_host::run(scenario);
            let error = host.result.err().unwrap_or_else(|| {
                panic!("a failed fulfilled projection must remain a typed Runtime boundary")
            });
            let runtime = error.downcast_ref::<CaptureRuntimeFailure>().unwrap();
            let expected = if matches!(scenario, g1_host::Scenario::Binding) {
                18
            } else {
                7
            };
            assert_eq!(runtime.capture.document.total_calls(), expected);
            let terminal = runtime.terminal.clone().unwrap();
            assert_eq!(terminal.retained_drain.total_calls(), 18);
            let (dir, request) = g1_request("binding");
            let rules = [PolicyRule::deny_provider("default")];
            let result = consume_capture_result_with_diagnostics(
                Err(error.context("inner boundary").context("outer boundary")),
                if check {
                    CaptureCommand::Check { rules: &rules }
                } else {
                    CaptureCommand::Report
                },
                &request,
                false,
                &mut Vec::new(),
            );
            assert_eq!(result.document.total_calls(), expected);
            assert_eq!(result.document.window.requested_start_ns, 1100);
            assert_eq!(result.document.window.requested_end_ns, 2100);
            assert_eq!(result.exit_code, if check { 10 } else { 1 });
            let context = result.failure_context.as_ref().unwrap();
            let PreObservationCount::Terminal(t) = &context.count else {
                panic!("missing canonical terminal")
            };
            assert!(std::sync::Arc::ptr_eq(t, &terminal));
            assert_eq!(context.rejected.known_calls, Some(18));
            if check {
                assert_eq!(
                    result.document.policy.as_ref().unwrap().rules[0].definite,
                    expected
                );
            }
            if matches!(scenario, g1_host::Scenario::Contradictory) {
                assert_eq!(terminal.retained_drain.fenced[0].sites[0].first_ns, 1050);
                assert!(result.document.fenced.iter().all(|g| g.sites.is_empty()));
                assert!(
                    result
                        .diagnostics
                        .iter()
                        .any(|s| s.contains("PreRequestedRow"))
                );
            }
            g1_validate_artifacts(&dir, &result);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn g1_capture_partial_count_survives_all_salvage_arms() {
    use osslscope::{
        capture::{BoundaryStage, PreObservationCount},
        report::*,
    };
    for (scenario, stage) in [
        (
            g1_host::Scenario::DiscoveryFinishIo,
            BoundaryStage::Discovery,
        ),
        (g1_host::Scenario::CustodyFinishIo, BoundaryStage::Custody),
    ] {
        let host = g1_host::run(scenario);
        let capture = host.result.unwrap();
        assert_eq!(capture.document.total_calls(), 18);
        let context = capture.failure_context.as_ref().unwrap();
        assert_eq!(context.failure.as_ref().unwrap().stage, stage);
        let PreObservationCount::Terminal(t) = &context.count else {
            panic!("missing terminal")
        };
        let terminal = t.clone();
        let (dir, request) = g1_request("salvage");
        let rules = [PolicyRule::deny_provider("default")];
        let result = consume_capture_result_with_diagnostics(
            Ok(capture),
            CaptureCommand::Check { rules: &rules },
            &request,
            false,
            &mut Vec::new(),
        );
        assert_eq!(
            host.finishes.get(),
            1,
            "custody resolution must not be retried by salvage or presentation"
        );
        assert_eq!(host.requests.get(), 1);
        assert_eq!(host.resolved.get(), 0, "a released target is never killed");
        assert_eq!(result.exit_code, 10);
        assert_eq!(terminal.retained_drain.current[0].calls, 7);
        assert_eq!(terminal.retained_drain.fenced[0].sites[0].calls, 11);
        g1_validate_artifacts(&dir, &result);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn g1_known_setup_timeout_retains_typed_origin() {
    use osslscope::capture::{BoundaryFailureClass, BoundaryStage, PreObservationFailure};
    let host = g1_host::run(g1_host::Scenario::Timeout);
    let error = host.result.unwrap_err();
    let failure = error.downcast_ref::<PreObservationFailure>().unwrap();
    let failure = failure.failure.as_ref().unwrap();
    assert_eq!(failure.stage, BoundaryStage::Setup);
    assert_eq!(failure.class, BoundaryFailureClass::Timeout);
    assert_eq!(failure.errno, None);
}

#[test]
fn g1_consumer_bounds_emitted_diagnostic_prefix_too() {
    use osslscope::report::*;
    let (dir, request) = g1_request("long-diagnostic");
    let mut diagnostics = Vec::new();
    let result = consume_capture_result_with_diagnostics(
        Err(anyhow::anyhow!(
            "observer /proc/12345/maps: {}",
            "x".repeat(500)
        )),
        CaptureCommand::Report,
        &request,
        false,
        &mut diagnostics,
    );
    assert_eq!(result.exit_code, 4);
    let emitted = String::from_utf8(diagnostics).unwrap();
    assert!(emitted.lines().count() <= 8);
    assert!(emitted.lines().all(|line| line.chars().count() <= 200));
    assert!(!emitted.contains("12345"));
    g1_validate_artifacts(&dir, &result);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn g1_consumer_artifact_failures_and_stderr_preserve_exit_and_context() {
    use osslscope::report::*;
    for (scenario, report_exit, check_exit) in [
        (g1_host::Scenario::Exit(0), 3, 11),
        (g1_host::Scenario::SetupIo, 4, 4),
        (g1_host::Scenario::ExternalOpen, 1, 10),
    ] {
        for check in [false, true] {
            for fail_primary in [false, true] {
                let host = g1_host::run(scenario);
                let (dir, mut request) = g1_request("delivery");
                if fail_primary {
                    request.primary = OutputDest::File(dir.join("missing/primary.json"));
                } else {
                    request.cbom = Some(OutputDest::File(dir.join("missing/cbom.json")));
                }
                let rules = [PolicyRule::deny_provider("default")];
                let result = consume_capture_result_with_diagnostics(
                    host.result,
                    if check {
                        CaptureCommand::Check { rules: &rules }
                    } else {
                        CaptureCommand::Report
                    },
                    &request,
                    true,
                    &mut FailingWriter,
                );
                let ordinary = if check { check_exit } else { report_exit };
                assert_eq!(
                    result.exit_code,
                    if matches!(ordinary, 3 | 11) {
                        1
                    } else {
                        ordinary
                    }
                );
                assert!(result.failure_context.is_some());
                assert_eq!(result.delivery.primary.ok, !fail_primary);
                assert_eq!(result.delivery.cbom.as_ref().unwrap().ok, fail_primary);
                assert!(
                    result.diagnostics.len() <= 8
                        && result.diagnostics.iter().all(|s| s.chars().count() <= 200)
                );
                let rendered = render_human(&result.document);
                assert!(rendered.contains(if ordinary == 4 {
                    "FATAL"
                } else if ordinary == 3 || ordinary == 11 {
                    "PARTIAL"
                } else {
                    "FATAL"
                }));
                if fail_primary {
                    let _: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(dir.join("cbom.json")).unwrap())
                            .unwrap();
                } else {
                    let v: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(dir.join("primary.json")).unwrap())
                            .unwrap();
                    osslscope::schema::validate_v2(&v).unwrap();
                    osslscope::schema::check_v2_semantics(&v).unwrap();
                }
                g1_keep_artifacts(&dir, &result);
                std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }
}
