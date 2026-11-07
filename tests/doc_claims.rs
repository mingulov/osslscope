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
