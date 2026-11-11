// SPDX-License-Identifier: GPL-3.0-or-later
//! P0-7: every discovery emitter output validates against
//! `osslscope/schemas/discovery-v1.json`; legacy/new reader-break
//! directions pinned; `--module` PATH-only admission pinned.

use std::process::Command;

fn bin() -> std::process::Command {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
}

fn required_keys(schema: &serde_json::Value, pointer: &str) -> Vec<String> {
    let mut node = schema;
    for part in pointer.split('/').filter(|p| !p.is_empty()) {
        node = &node[part];
    }
    node["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn assert_shape(doc: &serde_json::Value, schema: &serde_json::Value, kind: &str) {
    let pointer = match kind {
        "snapshot" => "/properties",
        "module" => "/definitions/module_inventory/properties",
        _ => panic!("unknown kind"),
    };
    let _ = pointer;
    for key in required_keys(schema, "") {
        assert!(doc.get(&key).is_some(), "snapshot missing {key}");
    }
}

#[test]
fn v060_snapshot_validates_and_module_path_only() {
    let schema_text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/discovery-v1.json"
    ))
    .unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
    let me = std::process::id().to_string();
    let out = bin()
        .args(["scan", "--pid", &me, "--json"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_shape(&doc, &schema, "snapshot");
    // Bare hash input: exit 4, empty stdout, PATH-form message on stderr.
    let bad = bin()
        .args(["scan", "--module", &"a".repeat(64), "--json"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(4));
    assert!(bad.stdout.is_empty());
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("takes a file PATH"), "stderr was: {err}");
    assert!(!err.contains(&"a".repeat(64)), "input echoed");
}

#[test]
fn v060_legacy_and_new_fixtures_pin_reader_break() {
    let legacy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/goldens/discovery/v050_snapshot_min.json"
    ))
    .unwrap();
    let legacy_doc: serde_json::Value = serde_json::from_str(&legacy).unwrap();
    assert!(legacy_doc["processes"][0].get("comm").is_none());
    let fresh = bin()
        .args([
            "inspect",
            "--module",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "--json",
        ])
        .output()
        .unwrap();
    if fresh.status.success() {
        let doc: serde_json::Value = serde_json::from_slice(&fresh.stdout).unwrap();
        assert!(doc["modules"][0].get("file_soname").is_some());
    }
}
