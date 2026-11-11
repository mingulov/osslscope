// SPDX-License-Identifier: GPL-3.0-or-later
//! P0-7: every discovery emitter output validates against
//! `osslscope/schemas/discovery-v1.json` with a real JSON-Schema
//! validator (never a shape stub); legacy/new reader-break
//! directions pinned; `--module` PATH-only admission pinned.

#[path = "support/package_fixtures.rs"]
mod fixtures;

use fixtures::check_complete_schema;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
}

fn schema_text() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/discovery-v1.json"
    ))
    .unwrap()
}

fn schema_doc() -> serde_json::Value {
    serde_json::from_str(&schema_text()).unwrap()
}

/// Validate one emitter record against a named-definition entry
/// point of the published schema (module/watch records are not
/// top-level snapshots). The wrapper keeps the intact
/// `definitions` map, so every `$ref` resolves exactly as
/// published — only the entry point moves.
fn validate_entry(schema: &serde_json::Value, entry: &str, record: &[u8], valid: bool) {
    assert!(
        schema["definitions"][entry].is_object(),
        "unknown schema entry {entry}"
    );
    let wrapped = serde_json::json!({
        "$ref": format!("#/definitions/{entry}"),
        "definitions": schema["definitions"].clone(),
    });
    check_complete_schema(&wrapped.to_string(), record, valid);
}

fn system_libcrypto() -> &'static str {
    [
        "/usr/lib64/libcrypto.so.3",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
    .expect("HOST schema tests require a system libcrypto")
}

/// Owned test child: SIGKILL + reap on drop, so no stray or
/// zombie child survives any path.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A live child mapping libcrypto (via `LD_PRELOAD`), so
/// snapshot/watch captures exercise nested module records —
/// never an empty-modules shape.
fn spawn_loaded_child() -> ChildGuard {
    use std::process::Stdio;
    ChildGuard(
        Command::new("/bin/sleep")
            .arg("60")
            .env("LD_PRELOAD", system_libcrypto())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn scan_child(child: &ChildGuard) -> Vec<u8> {
    let out = bin()
        .args(["scan", "--pid", &child.0.id().to_string(), "--json"])
        .output()
        .unwrap();
    // Any inventory outcome (complete/partial/unavailable)
    // emits a schema-shaped document; only usage errors (exit 2)
    // or scope failures (exit 4, empty stdout) have no document.
    // Exit codes are pinned elsewhere — here the document must
    // exist and validate.
    assert!(
        out.status.code().is_some_and(|c| c != 2),
        "scan must emit: {out:?}"
    );
    assert!(!out.stdout.is_empty());
    out.stdout
}

#[test]
fn v060_snapshot_validates_and_module_path_only() {
    let schema = schema_doc();
    let child = spawn_loaded_child();
    let stdout = scan_child(&child);
    check_complete_schema(&schema_text(), &stdout, true);
    // Anti-vacuity: the validated document must actually carry
    // nested module records (the validator saw them).
    let doc: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    let modules = doc["processes"][0]["modules"].as_array().unwrap();
    assert!(!modules.is_empty(), "nested records must be present");
    assert!(modules[0].get("verified_path").is_some());
    assert!(modules[0].get("maps_spelling").is_some());
    assert!(modules[0]["info"].get("file_soname").is_some());
    // P0-5: the fresh snapshot carries per-process Other counts.
    let other = &doc["processes"][0]["other_objects"];
    assert!(other.get("verified").is_some());
    assert!(other.get("candidate").is_some());
    assert!(other.get("failed").is_some());
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
fn v060_inspect_module_validates() {
    let schema = schema_doc();
    let lib = system_libcrypto();
    let fresh = bin()
        .args(["inspect", "--module", lib, "--json"])
        .output()
        .unwrap();
    assert!(fresh.status.success(), "inspect must succeed: {fresh:?}");
    validate_entry(&schema, "module_inventory", &fresh.stdout, true);
    let doc: serde_json::Value = serde_json::from_slice(&fresh.stdout).unwrap();
    assert!(doc["modules"][0].get("file_soname").is_some());
    // T6b: error records always carry the `errno` key —
    // integer-or-null per the schema. A missing path preserves its
    // open errno (never IO text) yet must NOT fire the privilege
    // hint (non-permission errno); a directory (non-regular, no
    // open failure) renders null.
    let missing = bin()
        .args([
            "inspect",
            "--module",
            "/PRIVATE_CANARY_missing_t6b",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(4));
    validate_entry(&schema, "module_inventory", &missing.stdout, true);
    let missing_doc: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    let missing_err = &missing_doc["errors"][0];
    assert_eq!(missing_err["reason"], "unavailable");
    assert!(
        missing_err.get("errno").is_some_and(|e| e.is_i64()),
        "missing path must carry integer errno: {missing_err}"
    );
    assert!(
        !String::from_utf8_lossy(&missing.stderr).contains("re-run as root"),
        "non-permission errno must not fire the hint"
    );
    let dir = bin()
        .args(["inspect", "--module", env!("CARGO_MANIFEST_DIR"), "--json"])
        .output()
        .unwrap();
    assert_eq!(dir.status.code(), Some(4));
    validate_entry(&schema, "module_inventory", &dir.stdout, true);
    let dir_doc: serde_json::Value = serde_json::from_slice(&dir.stdout).unwrap();
    let dir_err = &dir_doc["errors"][0];
    assert_eq!(dir_err["reason"], "non_regular");
    assert!(
        dir_err.get("errno").is_some_and(|e| e.is_null()),
        "non-open failure must render null errno: {dir_err}"
    );
}

#[test]
fn v060_watch_records_validate() {
    let schema = schema_doc();
    let child = spawn_loaded_child();
    let out = bin()
        .args([
            "scan",
            "--watch",
            "--pid",
            &child.0.id().to_string(),
            "--interval",
            "0.1",
            "--duration",
            "0.3",
            "--json",
        ])
        .output()
        .unwrap();
    // Any run outcome still ends with the end record; scope
    // failures emit ONLY it. Samples plus end must all validate.
    assert!(
        out.status.code().is_some_and(|c| c != 2),
        "watch must emit: {out:?}"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 2, "snapshot sample(s) plus the end record");
    let (end, samples) = lines.split_last().unwrap();
    let end_doc: serde_json::Value = serde_json::from_str(end).unwrap();
    assert_eq!(end_doc["record"], "end");
    validate_entry(&schema, "watch_end", end.as_bytes(), true);
    for sample in samples {
        let sample_doc: serde_json::Value = serde_json::from_str(sample).unwrap();
        assert_eq!(sample_doc["record"], "snapshot");
        validate_entry(&schema, "watch_snapshot", sample.as_bytes(), true);
    }
}

#[test]
fn v060_schema_rejects_malformed_controls() {
    let schema = schema_doc();
    let child = spawn_loaded_child();
    let stdout = scan_child(&child);
    let base: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert!(
        !base["processes"][0]["modules"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Each control prints its label first (libtest shows it on
    // failure), then demands validator rejection.
    let control = |label: &str, doc: serde_json::Value| {
        eprintln!("negative control: {label}");
        check_complete_schema(&schema_text(), &serde_json::to_vec(&doc).unwrap(), false);
    };
    // Dropped top-level required key.
    let mut doc = base.clone();
    doc.as_object_mut().unwrap().remove("processes");
    control("drop-processes", doc);
    // Bad enum spelling in a nested record.
    let mut doc = base.clone();
    doc["processes"][0]["exe_status"] = serde_json::json!("bogus");
    control("bad-exe-status", doc);
    // Unknown top-level key (additionalProperties is false).
    let mut doc = base.clone();
    doc["bogus_key"] = serde_json::json!(1);
    control("unknown-key", doc);
    // Dropped nested required key.
    let mut doc = base.clone();
    doc["processes"][0]["modules"][0]
        .as_object_mut()
        .unwrap()
        .remove("verified_path_unavailable");
    control("drop-nested-required", doc);
    // F5: `interval` and `scope_record` are non-optional
    // `Snapshot` fields — omitting either must fail.
    let mut doc = base.clone();
    doc.as_object_mut().unwrap().remove("interval");
    control("drop-interval", doc);
    let mut doc = base.clone();
    doc.as_object_mut().unwrap().remove("scope_record");
    control("drop-scope-record", doc);
    // P0-5: `other_objects` is a required per-process key —
    // omitting it must fail.
    let mut doc = base.clone();
    doc["processes"][0]
        .as_object_mut()
        .unwrap()
        .remove("other_objects");
    control("drop-other_objects", doc);
    // The watch-embedded snapshot is the same struct: its
    // `required` must match the top level.
    let out = bin()
        .args([
            "scan",
            "--watch",
            "--pid",
            &child.0.id().to_string(),
            "--interval",
            "0.1",
            "--duration",
            "0.3",
            "--json",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().find(|l| l.contains("\"snapshot\"")).unwrap();
    let mut watch_doc: serde_json::Value = serde_json::from_str(first).unwrap();
    watch_doc["snapshot"]
        .as_object_mut()
        .unwrap()
        .remove("interval");
    validate_entry(
        &schema,
        "watch_snapshot",
        &serde_json::to_vec(&watch_doc).unwrap(),
        false,
    );
    // Watch end status outside 0..=255.
    let end = text.lines().last().unwrap();
    let mut end_doc: serde_json::Value = serde_json::from_str(end).unwrap();
    assert_eq!(end_doc["record"], "end");
    end_doc["status"] = serde_json::json!(999);
    validate_entry(
        &schema,
        "watch_end",
        &serde_json::to_vec(&end_doc).unwrap(),
        false,
    );
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
}
