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
    let dir = std::env::temp_dir().join(format!("osslscope-c3-{}", std::process::id()));
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
            n: usize,
        ) -> std::io::Result<(Arc<[u8]>, (u64, u64))> {
            plan::read_file_bounded(p, n).map(|f| (f.bytes, (f.dev, f.ino)))
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
        let file = plan::read_file_bounded(path.to_str().unwrap(), 128 * 1024 * 1024).unwrap();
        let elf = goblin::elf::Elf::parse(&file.bytes).unwrap();
        let off = elf
            .program_headers
            .iter()
            .find(|p| p.p_type == 1 && p.p_flags & 1 != 0)
            .unwrap()
            .p_offset
            + 16;
        let meta = std::fs::metadata(&path).unwrap();
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
            provider: None,
            builtin: false,
            table: None,
            force_offset: None,
            provider_enrollment: None,
            resolved_provider: None,
            image_digest: String::new(),
        };
        let info = TargetInfo {
            pid: PID,
            owned: !matches!(scenario, Scenario::ExternalOpen),
            comm: "fixture".into(),
            cmdline: String::new(),
            container_id: String::new(),
            kernel_release: "host-model".into(),
            provider_build_id: String::new(),
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
        (Cancelled, 1, 1, 137),
        (Exit(7), 1, 1, 7),
        (Exit(0), 3, 11, 0),
        (SetupIo, 4, 4, 137),
        (ReleaseIo, 4, 4, 137),
        (CustodyIo, 4, 4, 137),
        (CountIo, 4, 4, 137),
        (Pending, 1, 1, 137),
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
