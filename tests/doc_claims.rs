//! SPDX-License-Identifier: GPL-3.0-or-later
//! Doc-text pins for review-wave-1B disclosures (M2 zero-ref
//! shape, M3 version claims). Doc-text assertions are acceptable
//! here because the defects ARE doc text: each test pins the
//! disclosure wording a code test pins the behavior of, so prose
//! and mechanism cannot drift apart silently.

use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_doc(name: &str) -> String {
    let path = manifest_dir().join("docs").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing doc {name}"))
}

/// M2: the zero-ref violation shape (legacy-only deny-engine:
/// definite=N, empty evidence, no engine_evidence) must be
/// disclosed in both auditor docs that tell the reader to
/// resolve site evidence refs. Code side:
/// `check::tests::legacy_only_violation_renders_zero_ref_shape`.
#[test]
fn m2_zero_ref_shape_disclosed_in_triage_docs() {
    for name in ["violation-triage.md", "auditor-story.md"] {
        let text = read_doc(name);
        assert!(
            text.contains("zero-ref"),
            "{name} must name the zero-ref violation shape"
        );
        assert!(
            text.contains("legacy-only"),
            "{name} must scope the shape to legacy-only violations"
        );
    }
    let triage = read_doc("violation-triage.md");
    assert!(
        triage.contains("empty `evidence` and no `engine_evidence`"),
        "violation-triage.md must state the exact zero-ref shape"
    );
}

/// M3 emitter-side pins: `src/evidence.rs` is the canonical
/// emitter of record; these four minors are the only live
/// identities (behavioral triggers are pinned by existing
/// tests: `output_contract::schema_version_gate` for v2.4,
/// `attribution::projection_dedupes_selectors_upgrades_schema_and_carries_bounds`
/// for v2.5,
/// `evidence::stamp_context_upgrades_schema_only_with_sysctls`
/// for v2.6,
/// `output_contract::r33_corpse_retirement_renders_membership_and_validates`
/// for v2.7).
#[test]
fn m3_emitter_minors_are_v2_4_through_v2_7() {
    use osslscope::evidence::{
        CAPTURE_SCHEMA_V2, CAPTURE_SCHEMA_V2_5, CAPTURE_SCHEMA_V2_6, CAPTURE_SCHEMA_V2_7,
    };
    assert_eq!(CAPTURE_SCHEMA_V2, "observed-crypto-v2.4");
    assert_eq!(CAPTURE_SCHEMA_V2_5, "observed-crypto-v2.5");
    assert_eq!(CAPTURE_SCHEMA_V2_6, "observed-crypto-v2.6");
    assert_eq!(CAPTURE_SCHEMA_V2_7, "observed-crypto-v2.7");
}

/// M3: every emission claim names the live v2.4-v2.7 range;
/// no doc claims an exact-only minor the emitters left behind.
#[test]
fn m3_docs_claim_the_live_version_range() {
    for name in [
        "observed-crypto-v2.md",
        "auditor-story.md",
        "partial-runbook.md",
    ] {
        let text = read_doc(name);
        assert!(
            text.contains("observed-crypto-v2.4") && text.contains("observed-crypto-v2.7"),
            "{name} must name the live v2.4-v2.7 emission range"
        );
    }
    let contract = read_doc("observed-crypto-v2.md");
    assert!(
        !contract.contains("Producers emit exactly"),
        "observed-crypto-v2.md must not claim an exact-only minor"
    );
    let story = read_doc("auditor-story.md");
    assert!(
        !story.contains("emit exactly"),
        "auditor-story.md must not claim an exact-only minor"
    );
    let runbook = read_doc("partial-runbook.md");
    assert!(
        !runbook.contains("Current development emits `observed-crypto-v2.2`"),
        "partial-runbook.md must not claim v2.2-only emission"
    );
    // The module docstring is the fifth stale claim.
    let schema_rs = std::fs::read_to_string(manifest_dir().join("src/schema.rs"))
        .expect("src/schema.rs must be readable");
    assert!(
        schema_rs.contains("observed-crypto-v2.4") && schema_rs.contains("observed-crypto-v2.7"),
        "src/schema.rs docstring must name the live v2.4-v2.7 emission range"
    );
}

/// M3: the contract examples that claim verbatim test output
/// carry current-output versions, and the PARTIAL runbook's
/// per-kind tables name the v2.7 `visibility-lost` reason the
/// renderers emit.
#[test]
fn m3_examples_and_response_tables_are_current() {
    let contract = read_doc("observed-crypto-v2.md");
    assert!(
        contract.contains(
            "{\"name\": \"osslscope:schema-version\", \"value\": \"observed-crypto-v2.4\"}"
        ),
        "CBOM example must carry the golden's v2.4 identity"
    );
    assert!(
        contract.contains("osslscope report (observed-crypto-v2.4)"),
        "human example must carry the golden's v2.4 identity"
    );
    assert!(
        !contract.contains("funcid=21"),
        "human example must render funcids as current output does (FUNC21)"
    );
    let runbook = read_doc("partial-runbook.md");
    assert!(
        runbook.contains("`visibility-lost`"),
        "partial-runbook.md must row the v2.7 visibility-lost reason"
    );
    // Fix round 1 (finding 3): the retirement row must quote the
    // exact wire spelling the renderer emits (`report.rs` renders
    // `"retired"`, pinned by
    // `output_contract::r33_corpse_retirement_renders_membership_and_validates`) —
    // never the capitalized prose form.
    assert!(
        runbook.contains("`membership.state=\"retired\"`"),
        "partial-runbook.md must quote the wire spelling membership.state=\"retired\""
    );
    assert!(
        !runbook.contains("reads `Retired`"),
        "partial-runbook.md must not use the capitalized Retired spelling"
    );
}

/// M3: the proof-boundary doc no longer presents v0.3 as
/// current for a v0.5.0 tree.
#[test]
fn m3_proof_boundary_is_not_stuck_at_v03() {
    let text = read_doc("what-it-proves.md");
    assert!(
        !text.contains("## Current v0.3"),
        "what-it-proves.md must not present v0.3 as current"
    );
    assert!(
        text.contains("Historical v0.3"),
        "what-it-proves.md must mark the v0.3 section historical"
    );
}
