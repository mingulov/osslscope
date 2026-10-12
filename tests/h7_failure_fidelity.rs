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
    }
}

fn doc_with(sites: Vec<SiteExecution>, fatal: Option<FatalKind>) -> CaptureDocument {
    finalize(FinalizeInput {
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
        fatal,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
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
fn h7_runtime_human_shape() {
    // Contract: the human renderer names the runtime failure.
    let text = render_human(&runtime_doc());
    assert!(
        text.contains("fatal: runtime: close_and_drain: boom"),
        "unexpected human block:\n{text}"
    );
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

// --- T6: CLI-surface panic audit -----------------------------------------
// Every CLI error-path print goes through the panic-free sink
// helper; production code in the CLI-surface files carries no
// `eprintln!`, `panic!`, `expect(`, or `unwrap(`. (`println!` to
// stdout is out of scope: stdout-EPIPE while piping artifacts is a
// documented residual with Unix-philosophy questions, not a
// diagnostic path. Engine-internal `eprintln!` warnings outside
// these files are likewise out of scope — reviewed, not converted.)

const T6_FILES: &[&str] = &[
    "src/report.rs",
    "src/check.rs",
    "src/cli.rs",
    "src/main.rs",
    "src/doctor.rs",
    "src/inspect.rs",
    "src/aliases.rs",
];

const T6_PATTERNS: &[&str] = &["eprintln!", "panic!", ".expect(", ".unwrap("];

#[test]
fn h7_cli_surface_carries_no_panics() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for rel in T6_FILES {
        let text = std::fs::read_to_string(root.join(rel)).unwrap();
        // Skip `mod tests` bodies (H5 mechanism: rustfmt keeps test
        // modules top-level, so a column-0 `mod tests {` ...
        // column-0 `}` pair delimits them).
        let mut in_tests = false;
        for (i, line) in text.lines().enumerate() {
            if !in_tests && line.starts_with("mod tests {") {
                in_tests = true;
                continue;
            }
            if in_tests {
                if line.starts_with('}') {
                    in_tests = false;
                }
                continue;
            }
            let code = strip_comments_and_strings(line);
            for pat in T6_PATTERNS {
                if code.contains(pat) {
                    violations.push(format!("{rel}:{}: {pat}: {}", i + 1, normalize(line)));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "H7-T6 CLI-surface audit failed:\n{}",
        violations.join("\n")
    );
}
