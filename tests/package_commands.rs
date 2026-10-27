// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "support/package_observer_fixtures.rs"]
mod fixtures;
use osslscope::{evidence::FatalKind, report, schema};
use serde_json::{Value, json};
fn wire() -> Value {
    let doc = report::setup_failure_document(FatalKind::Recycled);
    serde_json::from_slice(&report::render_json(&doc).unwrap()).unwrap()
}
#[test]
fn package_build_provenance_schema() {
    let mut v = wire();
    v["package_build"] = fixtures::package();
    v["selected_objects"] = fixtures::selection();
    schema::validate_v2(&v).unwrap();
    schema::check_v2_semantics(&v).unwrap();
}
#[test]
fn package_observer_metadata_serialization_canaries() {
    let mut doc = report::setup_failure_document(FatalKind::Recycled);
    doc.schema = "observed-crypto-v2.0".into();
    let v: Value = serde_json::from_slice(&report::render_json(&doc).unwrap()).unwrap();
    assert_eq!(v["schema_version"], json!("observed-crypto-v2.0"));
    assert!(report::render_human(&doc).contains("observed-crypto-v2.0"));
    let cbom = String::from_utf8(report::render_cbom(&doc).unwrap()).unwrap();
    assert!(cbom.contains("observed-crypto-v2.0"));
    assert!(v.get("package_build").is_none());
}
#[test]
fn inspect_object_is_optional_after_usage_admission() {
    let a = ["--pid", "123", "--provider", "/missing/provider"].map(String::from);
    assert!(osslscope::inspect::parse(&a).is_ok());
}
#[test]
fn package_admission_failure_precedes_effects() {
    use std::process::Command;
    let bin = env!("CARGO_BIN_EXE_osslscope");
    for verb in ["doctor", "report", "check"] {
        let mut args = vec![
            verb,
            "--libcrypto",
            "/missing/package/libcrypto.so.3",
            "--count-object",
            "/missing/package/count",
        ];
        if verb == "doctor" {
            args.extend(["--format", "json"]);
        } else {
            if verb == "check" {
                args.extend(["--require-executed", "SHA256"]);
            }
            args.extend(["run", "--", "/bin/true"]);
        }
        let out = Command::new(bin).args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(4),
            "{verb}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if verb == "doctor" {
            let v: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(v["exit"], 4);
            assert!(v["target"].is_null());
            let rows = v["checks"].as_array().unwrap();
            assert!(
                rows.iter()
                    .any(|r| r["id"] == "count-object" && r["status"] == "fail")
            );
            assert!(
                rows.iter()
                    .any(|r| r["id"] == "runtime-permissions" && r["status"] == "degraded")
            );
            assert!(
                !rows
                    .iter()
                    .any(|r| r["id"] == "functional-probes" || r["id"] == "spawn-access")
            );
        }
    }
    let out = Command::new(bin)
        .args(["inspect", "--help"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("inspect --module")
    );
    for (verb, args) in [
        (
            "inspect",
            vec!["--pid", "1", "--provider", "missing", "--timeout", "NaN"],
        ),
        ("report", vec!["--pid", "1", "--duration", "NaN"]),
        ("check", vec!["--pid", "1", "--duration", "NaN"]),
        ("doctor", vec!["--pid", "1", "--force-offset", "bad"]),
    ] {
        let out = Command::new(bin).arg(verb).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{verb}");
    }
}
#[test]
fn package_historical_and_closed_metadata_controls() {
    for version in [
        "observed-crypto-v2.0",
        "observed-crypto-v2.1",
        "observed-crypto-v2.2",
    ] {
        let mut v: Value = serde_json::from_str(fixtures::HISTORICAL_V2_2).unwrap();
        v["schema_version"] = json!(version);
        schema::validate_v2(&v).unwrap();
        schema::check_v2_semantics(&v).unwrap();
        assert!(v.get("package_build").is_none());
    }
    let mut positive = wire();
    positive["package_build"] = fixtures::package();
    positive["selected_objects"] = fixtures::selection();
    schema::validate_v2(&positive).unwrap();
    schema::check_v2_semantics(&positive).unwrap();
    for case in [
        "null",
        "missing-base",
        "missing-count",
        "null-count",
        "missing-role-id",
        "fourth-role",
        "bad-digest",
        "upper-digest",
        "base-id",
        "role-id",
        "explicit-id",
        "selected-hash",
        "members",
        "profile",
        "source",
        "tools",
        "budget",
        "zero",
        "unknown",
    ] {
        let mut v = positive.clone();
        match case {
            "null" => v["package_build"] = Value::Null,
            "missing-base" => {
                v["package_build"]
                    .as_object_mut()
                    .unwrap()
                    .remove("installed_base");
            }
            "null-count" => v["package_build"]["roles"]["count"] = Value::Null,
            "missing-count" => {
                v["package_build"]["roles"]
                    .as_object_mut()
                    .unwrap()
                    .remove("count");
            }
            "missing-role-id" => {
                v["package_build"]["roles"]["harvest"]
                    .as_object_mut()
                    .unwrap()
                    .remove("build_input_id");
            }
            "fourth-role" => v["package_build"]["roles"]["fourth"] = json!({}),
            "bad-digest" => {
                v["package_build"]["installed_base"]["bundle_id"] = json!("x".repeat(64))
            }
            "upper-digest" => {
                v["package_build"]["installed_base"]["tools"]["host_sha256"] = json!("A".repeat(64))
            }
            "base-id" => v["package_build"]["installed_base"]["input_id"] = json!("0".repeat(64)),
            "role-id" => v["package_build"]["roles"]["count"]["build_input_id"] = Value::Null,
            "explicit-id" => {
                v["package_build"]["roles"]["count"]["selection"] = json!("operator-explicit")
            }
            "selected-hash" => v["selected_objects"]["count"]["sha256"] = json!("0".repeat(64)),
            "members" => {
                v["selected_objects"]
                    .as_object_mut()
                    .unwrap()
                    .remove("members");
            }
            "profile" => {
                v["package_build"]["installed_base"]["host_profile"]["abi_profile"] =
                    json!("linux-x86_64-musl")
            }
            "source" => {
                v["package_build"]["installed_base"]["source"]["revision"] = json!("A".repeat(40))
            }
            "tools" => {
                v["package_build"]["installed_base"]["tools"]["components_sha256"] = json!([])
            }
            "budget" => v["package_build"]["roles"]["count"]["bytes"] = json!(536870912u64),
            "zero" => v["package_build"]["roles"]["count"]["bytes"] = json!(0),
            _ => v["package_build"]["installed_base"]["unknown"] = json!(1),
        }
        assert!(schema::check_v2_semantics(&v).is_err(), "accepted {case}");
    }
    let mut op = positive.clone();
    op["package_build"]["selection"] = json!("operator-override");
    op["package_build"]["installed_base"] = Value::Null;
    for role in ["harvest", "count", "members"] {
        op["package_build"]["roles"][role]["selection"] = json!("operator-explicit");
        op["package_build"]["roles"][role]["build_input_id"] = Value::Null;
    }
    schema::validate_v2(&op).unwrap();
    schema::check_v2_semantics(&op).unwrap();
    // Tolerant field extraction demonstrates extraction only, never validation.
    #[derive(serde::Deserialize)]
    struct Known {
        schema_version: String,
    }
    let extracted: Known = serde_json::from_value(positive).unwrap();
    assert_eq!(extracted.schema_version, "observed-crypto-v2.3");
}
#[test]
fn package_real_render_roundtrip_and_offline_identity() {
    let mut doc = report::setup_failure_document(FatalKind::Recycled);
    doc.schema = "observed-crypto-v2.2".into();
    doc.package_build = Some(serde_json::from_value(fixtures::package()).unwrap());
    doc.selected_objects = Some(serde_json::from_value(fixtures::selection()).unwrap());
    let back: osslscope::evidence::CaptureDocument =
        serde_json::from_slice(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert_eq!(back, doc);
    // All renderers consume captured values despite a completely different local selection.
    #[cfg(target_os = "linux")]
    let before = read_syscalls();
    let json: Value = serde_json::from_slice(&report::render_json(&back).unwrap()).unwrap();
    let offline_human = report::render_human(&back);
    let offline_cbom = report::render_cbom(&back).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(
        read_syscalls() - before,
        1,
        "renderers must not resolve/reopen/hash any local object or metadata (one probe read only)"
    );
    assert!(offline_human.contains("observed-crypto-v2.2"));
    assert!(!offline_cbom.is_empty());
    assert_eq!(json["package_build"], fixtures::package());
    assert_eq!(json["selected_objects"], fixtures::selection());
    assert_eq!(json["schema_version"], "observed-crypto-v2.2");
    let human = report::render_human(&back);
    assert!(human.contains("observed-crypto-v2.2"));
    assert!(
        human.contains("input=3333333333333333333333333333333333333333333333333333333333333333")
    );
    doc.package_build
        .as_mut()
        .unwrap()
        .installed_base
        .as_mut()
        .unwrap()
        .product_version = "fixture\n\x1bversion".into();
    let human = report::render_human(&doc);
    assert!(!human.contains("fixture\n\x1bversion"));
    assert!(!human.contains('\x1b'));
    let cbom = String::from_utf8(report::render_cbom(&back).unwrap()).unwrap();
    assert!(cbom.contains("observed-crypto-v2.2"));
    // Supplied historical identity is not a claim about today's producer.
    assert_eq!(
        osslscope::evidence::CAPTURE_SCHEMA_V2,
        "observed-crypto-v2.3"
    );
}

#[cfg(target_os = "linux")]
fn read_syscalls() -> u64 {
    use std::io::Read;
    let tid = unsafe { libc::gettid() };
    let mut file = std::fs::File::open(format!("/proc/self/task/{tid}/io")).unwrap();
    let mut b = [0u8; 4096];
    let n = file.read(&mut b).unwrap();
    assert!(n < b.len());
    std::str::from_utf8(&b[..n])
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("syscr: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn identity_v2_selected_dev_and_installed() {
    use std::process::Command;
    for verb in ["report", "check"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_osslscope"));
        command.args([verb, "--dev-bundle", "/missing/identity-v2", "--pid", "1"]);
        if verb == "check" {
            command.arg("--deny-weak");
        }
        let out = command.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{verb} must reject deferred dev admission before effects: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
