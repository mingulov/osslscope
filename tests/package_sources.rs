// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic source-health controls. None of these fixtures are release inputs.
use osslscope::package::{
    PackageError,
    inventory::{DependencyInventory, verify_closure},
    records::{Digest, ToolInventory, sha256},
    source::{
        RegistryArchiveLimits, ReleaseConfig, SealedSource, SourceTree, seal_source,
        verify_registry_source,
    },
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

#[path = "support/package_source_fixtures.rs"]
mod package_source_fixtures;
use package_source_fixtures::{Fixture, bytes, fixture_tar};

// Rebind every inventory/resource copy while preserving source/acquisition closure.
fn replace_tool_content(fixture: &mut Fixture, role: &str, content: &[u8]) {
    let replacement = fixture.input(&format!("tools/{role}.bin"), content);
    let recipe: Value = serde_json::from_slice(
        &fs::read(fixture.root.join("packaging/builders/gnu.json")).unwrap(),
    )
    .unwrap();
    let index = recipe["resources"]
        .as_array()
        .unwrap()
        .iter()
        .position(|r| r["role"] == role)
        .unwrap();
    fixture.tools["components"][index - 5]["sha256"] = replacement["sha256"].clone();
    for profile in ["gnu", "musl"] {
        let path = format!("packaging/builders/{profile}.json");
        let mut recipe: Value =
            serde_json::from_slice(&fs::read(fixture.root.join(&path)).unwrap()).unwrap();
        recipe["tools"] = fixture.tools.clone();
        recipe["resources"][index]["content"] = replacement.clone();
        recipe["resources"][index]["identity"]["sha256"] = replacement["sha256"].clone();
        fixture.source(&path, &bytes(&recipe));
    }
}

#[test]
fn v2_sealing_binds_exact_commands_and_environment() {
    let mut fixture = Fixture::new();
    for (profile, target) in [
        ("gnu", "x86_64-unknown-linux-gnu"),
        ("musl", "x86_64-unknown-linux-musl"),
    ] {
        fixture.config["selected_profile"] = json!(profile);
        let path = format!("packaging/builders/{profile}.json");
        let recipe_bytes = fs::read(fixture.root.join(path)).unwrap();
        let recipe: Value = serde_json::from_slice(&recipe_bytes).unwrap();
        let sealed = fixture.seal().expect("closed v2 recipe must seal");
        assert_eq!(recipe["schema"], "osslscope-build-recipe-v2");
        assert_eq!(sealed.inputs.schema, "osslscope-build-inputs-v1");
        assert_eq!(sealed.inputs.recipe.recipe_sha256, sha256(&recipe_bytes));
        assert_eq!(
            sealed.inputs.argv,
            [
                "cargo",
                "build",
                "--release",
                "--frozen",
                "--offline",
                "--target",
                target,
                "--jobs",
                "2",
                "--bin",
                "osslscope",
                "--message-format=json-render-diagnostics"
            ]
        );
        assert_eq!(
            recipe["bpf_argv"],
            json!([
                "cargo",
                "build",
                "--release",
                "--frozen",
                "--offline",
                "-Z",
                "build-std=core",
                "--target",
                "bpfel-unknown-none",
                "--jobs",
                "2",
                "--bin",
                "osslscope-harvest",
                "--bin",
                "osslscope-count",
                "--bin",
                "osslscope-members",
                "--message-format=json-render-diagnostics"
            ])
        );
        let environment = serde_json::to_value(&sealed.inputs.environment).unwrap();
        assert_eq!(
            environment,
            json!([{"name":"LC_ALL","value":"C"},{"name":"TZ","value":"UTC"},{"name":"SOURCE_DATE_EPOCH","value":"1792799804"},{"name":"CARGO_NET_OFFLINE","value":"true"},{"name":"CARGO_BUILD_JOBS","value":"2"},{"name":"RUSTFLAGS","value":"--remap-path-prefix=/build=."}])
        );
        assert!(
            !sealed
                .inputs
                .environment
                .iter()
                .any(|e| e.name == "OSSL_PACKAGE_RECORD_DIR")
        );
        verify_closure(&sealed).unwrap();
    }
}

#[test]
fn v1_or_modified_v2_refuses() {
    let mut fixture = Fixture::new();
    fixture.seal().unwrap();
    let path = "packaging/builders/gnu.json";
    let original: Value =
        serde_json::from_slice(&fs::read(fixture.root.join(path)).unwrap()).unwrap();
    let mut variants = Vec::new();
    let mut old = original.clone();
    old["schema"] = json!("osslscope-build-recipe-v1");
    old["argv"].as_array_mut().unwrap().truncate(9);
    old["bpf_argv"].as_array_mut().unwrap().truncate(11);
    old["determinism"]["path_remap"] = json!("--remap-path-prefix=source=.");
    old["environment"][5]["value"] = json!("--remap-path-prefix=source=.");
    old["resources"].as_array_mut().unwrap().truncate(16);
    old["tools"]["components"]
        .as_array_mut()
        .unwrap()
        .truncate(11);
    // Keep the original v1 literals as explicit refusal input, never migrate bytes.
    variants.push(("old v1", old));
    for (name, field, value) in [
        (
            "v1 discriminator",
            "schema",
            json!("osslscope-build-recipe-v1"),
        ),
        ("unknown field", "extra", json!(true)),
        ("jobs", "jobs", json!(1)),
    ] {
        let mut modified = original.clone();
        modified[field] = value;
        variants.push((name, modified));
    }
    for field in ["argv", "bpf_argv", "environment"] {
        for change in ["extra", "missing", "reordered"] {
            let mut modified = original.clone();
            let entries = modified[field].as_array_mut().unwrap();
            match change {
                "extra" => entries.push(entries.last().unwrap().clone()),
                "missing" => {
                    entries.pop().unwrap();
                }
                _ => entries.swap(0, 1),
            }
            variants.push((field, modified));
        }
    }
    for field in ["argv", "bpf_argv"] {
        for change in ["extra bin", "missing bin", "reordered bin"] {
            let mut modified = original.clone();
            let entries = modified[field].as_array_mut().unwrap();
            let index = entries.iter().position(|v| v == "--bin").unwrap();
            match change {
                "extra bin" => {
                    entries.insert(index, json!("--bin"));
                    entries.insert(index + 1, json!("osslscope-package"));
                }
                "missing bin" => {
                    entries.drain(index..index + 2);
                }
                _ => {
                    let pair: Vec<_> = entries.drain(index..index + 2).collect();
                    entries.splice(2..2, pair);
                }
            }
            variants.push((change, modified));
        }
    }
    let mut old_remap = original.clone();
    old_remap["determinism"]["path_remap"] = json!("--remap-path-prefix=source=.");
    old_remap["environment"][5]["value"] = json!("--remap-path-prefix=source=.");
    variants.push(("old remap", old_remap));
    for (name, recipe) in variants {
        fixture.source(path, &bytes(&recipe));
        assert!(fixture.seal().is_err(), "admitted modified recipe: {name}");
    }
}

#[test]
fn v2_build_tools_complete_and_gnu_equal() {
    let fixture = Fixture::new();
    fixture
        .seal()
        .expect("GNU equal selected/build content must seal");
    for role in [
        "build-compiler",
        "build-linker",
        "build-archive",
        "build-sysroot",
    ] {
        for profile in ["gnu", "musl"] {
            for missing in ["role", "acquisition", "source"] {
                let mut fixture = Fixture::new();
                fixture.config["selected_profile"] = json!(profile);
                let path = format!("packaging/builders/{profile}.json");
                let mut recipe: Value =
                    serde_json::from_slice(&fs::read(fixture.root.join(&path)).unwrap()).unwrap();
                let index = recipe["resources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|r| r["role"] == role)
                    .unwrap();
                let expected = match missing {
                    "role" => {
                        recipe["resources"].as_array_mut().unwrap().remove(index);
                        fixture.tools["components"]
                            .as_array_mut()
                            .unwrap()
                            .remove(index - 5);
                        recipe["tools"] = fixture.tools.clone();
                        format!("missing mandatory tool role {role}")
                    }
                    "acquisition" => {
                        fs::remove_file(
                            fixture.inputs.join(
                                recipe["resources"][index]["acquisition"]["path"]
                                    .as_str()
                                    .unwrap(),
                            ),
                        )
                        .unwrap();
                        "unavailable package metadata".into()
                    }
                    _ => {
                        let source = recipe["resources"][index]["source_component"].clone();
                        fixture.inventory["tool_sources"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|s| s != &source);
                        "tool binary/source/component identity mismatch".into()
                    }
                };
                fixture.source(&path, &bytes(&recipe));
                let err = fixture
                    .seal()
                    .err()
                    .expect("modified recipe must refuse")
                    .to_string();
                assert!(
                    err.contains(&expected),
                    "{profile} {role} missing {missing}: {err}"
                );
            }
        }
    }
    for role in [
        "native-compiler",
        "archive",
        "sysroot",
        "build-compiler",
        "build-archive",
        "build-sysroot",
    ] {
        let mut fixture = Fixture::new();
        fixture.seal().unwrap();
        replace_tool_content(
            &mut fixture,
            role,
            b"independently rebound selected/build content\n",
        );
        let err = fixture
            .seal()
            .err()
            .expect("modified recipe must refuse")
            .to_string();
        assert!(
            err.contains("GNU selected/build tool content mismatch"),
            "{role}: {err}"
        );
        fixture.config["selected_profile"] = json!("musl");
        fixture
            .seal()
            .expect("musl selected/build content may differ");
    }
    let mut fixture = Fixture::new();
    let path = "packaging/builders/gnu.json";
    let mut recipe: Value =
        serde_json::from_slice(&fs::read(fixture.root.join(path)).unwrap()).unwrap();
    let index = recipe["resources"]
        .as_array()
        .unwrap()
        .iter()
        .position(|r| r["role"] == "build-compiler")
        .unwrap();
    fixture.tools["components"][index - 5]["name"] = json!("cc");
    recipe["tools"] = fixture.tools.clone();
    recipe["resources"][index]["identity"]["name"] = json!("cc");
    fixture.source(path, &bytes(&recipe));
    assert!(
        fixture
            .seal()
            .err()
            .expect("modified recipe must refuse")
            .to_string()
            .contains("tool binary/source/component identity mismatch")
    );
}

#[test]
fn fresh_archive_identity_is_not_null() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("target")).unwrap();
    fs::write(fixture.root.join("target/attempt.log"), b"derived").unwrap();
    fs::create_dir_all(fixture.root.join(".superpowers")).unwrap();
    fs::write(fixture.root.join(".superpowers/private.md"), b"private").unwrap();
    fs::write(
        fixture.root.join("build-inputs.json"),
        b"generated descriptor",
    )
    .unwrap();
    let sealed = fixture.seal().unwrap();
    let archive = sealed.asset_bytes(&sealed.assets.source_archive).unwrap();
    let extracted = fixture.root.parent().unwrap().join("fresh-no-git");
    let tree = SourceTree::extract_archive(archive, &extracted).unwrap();
    let from_archive = seal_source(
        &tree,
        &fixture.release(),
        &fixture.dependencies(),
        &fixture.tool_inventory(),
    )
    .unwrap();
    assert_eq!(from_archive.inputs.source, sealed.inputs.source);
    assert_eq!(
        sealed.inputs.source.revision,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        fs::read_link(extracted.join("CLAUDE.md")).unwrap(),
        PathBuf::from("AGENTS.md")
    );
    let paths = tree.inventory_paths();
    for name in [
        "scripts/build-dev.sh",
        "scripts/install-dev.sh",
        "scripts/package-release.py",
        "Cargo.lock",
        "crates/ebpf/Cargo.lock",
        "NOTICE.md",
        "LICENSES/README.md",
        "tests/fixtures/example.json",
    ] {
        assert!(paths.contains(&name.to_owned()), "{name}");
    }
    assert!(!paths.iter().any(|p| p.contains("attempt.log")
        || p.contains(".superpowers")
        || p == "build-inputs.json"
        || p == "osslscope-source.json"));
    assert_eq!(from_archive.input_bytes, sealed.input_bytes);
    verify_closure(&from_archive).unwrap();
}
#[test]
fn epoch_one_candidate_uses_actual_cargo_version() {
    let mut fixture = Fixture::new();
    let sealed = fixture.seal().unwrap();
    assert_eq!(sealed.inputs.package_epoch, 1);
    assert_eq!(sealed.inputs.package_revision, 1);
    assert_eq!(sealed.inputs.product_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(sealed.inputs.jobs, 2);
    assert_eq!(sealed.inputs.source_epoch, 1792799804);
    for (field, bad) in [
        ("package_epoch", json!(0)),
        ("package_revision", json!(2)),
        ("jobs", json!(1)),
        ("source_epoch", json!(1792799805_u64)),
        ("product_version", json!("1.0.0")),
        ("selected_profile", json!("")),
    ] {
        let saved = fixture.config[field].clone();
        fixture.config[field] = bad;
        assert!(
            ReleaseConfig::parse_json(&bytes(&fixture.config))
                .and_then(|c| seal_source(
                    &fixture.tree(),
                    &c,
                    &fixture.dependencies(),
                    &fixture.tool_inventory()
                ))
                .is_err(),
            "{field}"
        );
        fixture.config[field] = saved;
    }
    fixture.config["selected_profile"] = json!("musl");
    let musl = fixture.seal().unwrap();
    assert_eq!(musl.inputs.host_profile.target, "x86_64-unknown-linux-musl");
    assert_ne!(
        musl.inputs.recipe.recipe_sha256,
        sealed.inputs.recipe.recipe_sha256
    );
    let mut config = fixture.release();
    config.expected_source = Some(osslscope::package::records::SourceIdentity {
        revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        inventory_sha256: Digest([9; 32]),
    });
    assert!(
        seal_source(
            &fixture.tree(),
            &config,
            &fixture.dependencies(),
            &fixture.tool_inventory()
        )
        .is_err()
    );
}
#[test]
fn closure_rejects_missing_or_changed_input() {
    let fixture = Fixture::new();
    let sealed = fixture.seal().unwrap();
    verify_closure(&sealed).unwrap();
    for path in [
        "tools/host.bin",
        "tools/llvm.bin",
        "tools/sysroot.bin",
        "acquisition/bpf.tar",
        "sources/rust-src.tar",
        "sources/build-compiler.tar",
        "sources/build-linker.tar",
        "sources/build-archive.tar",
        "sources/build-sysroot.tar",
        "terms/contract.txt",
        "notices/host.txt",
        "offers/bpf.txt",
        "abi/gnu.json",
    ] {
        let full = fixture.inputs.join(path);
        let original = fs::read(&full).unwrap();
        fs::write(&full, b"changed").unwrap();
        assert!(verify_closure(&sealed).is_err(), "changed {path}");
        assert!(fixture.seal().is_err(), "seal changed {path}");
        fs::remove_file(&full).unwrap();
        assert!(
            matches!(fixture.seal(), Err(PackageError::Unavailable { .. })),
            "missing {path}"
        );
        fs::write(full, original).unwrap();
    }
    fs::write(fixture.root.join("Cargo.lock"), b"changed lock").unwrap();
    assert!(verify_closure(&sealed).is_err());
}
#[test]
fn legal_inventory_names_actual_components() {
    let mut fixture = Fixture::new();
    let sealed = fixture.seal().unwrap();
    let sbom: Value =
        serde_json::from_slice(sealed.asset_bytes(&sealed.assets.sbom).unwrap()).unwrap();
    assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
    let packages = sbom["packages"].as_array().unwrap();
    for (name, version, license) in [
        ("osslscope", env!("CARGO_PKG_VERSION"), "GPL-3.0-or-later"),
        ("osslscope-ebpf", "0.0.0", "GPL-2.0-only"),
        ("osslscope-bpf-contract", "0.0.0", "GPL-2.0-or-later"),
        ("osslscope-ebpf-common", "0.1.0", "GPL-3.0-or-later"),
    ] {
        let p = packages.iter().find(|p| p["name"] == name).unwrap();
        assert_eq!(p["versionInfo"], version);
        assert_eq!(p["licenseDeclared"], license);
    }
    let bpf_dependency_names = fixture.dependencies().bpf_dependency_names().unwrap();
    assert!(!bpf_dependency_names.contains(&"osslscope-ebpf-common".to_owned()));
    fixture.inventory["bpf"]
        .as_array_mut()
        .unwrap()
        .push(json!("common"));
    assert!(fixture.seal().is_err());
    fixture.inventory["bpf"].as_array_mut().unwrap().pop();
    fixture.inventory["components"][3]["terms"]["license_files"] = json!([]);
    assert!(fixture.seal().is_err());
}
#[test]
fn archive_paths_and_generated_metadata_backedges_refuse() {
    let fixture = Fixture::new();
    for (path, kind, link) in [
        ("/absolute", b'0', ""),
        ("../escape", b'0', ""),
        ("safe/../../escape", b'0', ""),
        ("link", b'2', "../escape"),
        ("hard", b'1', "/outside"),
        ("device", b'3', ""),
    ] {
        let archive = fixture_tar(path, b"", kind, link);
        assert!(
            SourceTree::extract_archive(&archive, &fixture.root.parent().unwrap().join("refused"))
                .is_err(),
            "{path}"
        );
    }
    let mut duplicate = fixture_tar("same", b"a", b'0', "");
    duplicate.truncate(duplicate.len() - 1024);
    duplicate.extend(fixture_tar("same", b"b", b'0', ""));
    assert!(
        SourceTree::extract_archive(&duplicate, &fixture.root.parent().unwrap().join("refused"))
            .is_err()
    );
    let mut through_link = fixture_tar("link", b"", b'2', "safe");
    through_link.truncate(through_link.len() - 1024);
    through_link.extend(fixture_tar("link/child", b"escape", b'0', ""));
    assert!(
        SourceTree::extract_archive(
            &through_link,
            &fixture.root.parent().unwrap().join("refused")
        )
        .is_err()
    );
    let mut deps = fixture.inventory.clone();
    deps["components"][0]["terms"]["source_availability"]["path"] = json!("build-inputs.json");
    let source_graph_with_generated_metadata_backedge =
        DependencyInventory::parse_json(&fixture.inputs, &bytes(&deps)).and_then(|d| {
            seal_source(
                &fixture.tree(),
                &fixture.release(),
                &d,
                &fixture.tool_inventory(),
            )
        });
    assert!(source_graph_with_generated_metadata_backedge.is_err());
    let sealed = fixture.seal().unwrap();
    let archive = sealed.asset_bytes(&sealed.assets.source_archive).unwrap();
    let mut changed = archive.to_vec();
    changed[512] ^= 1;
    assert!(
        SourceTree::extract_archive(&changed, &fixture.root.parent().unwrap().join("refused"))
            .is_err()
    );
}
#[test]
fn closed_config_builder_and_source_records_refuse_unbound_values() {
    let mut fixture = Fixture::new();
    let mut duplicate = bytes(&fixture.config);
    duplicate.pop();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"jobs\":2}\n");
    assert!(ReleaseConfig::parse_json(&duplicate).is_err());
    for bad in [b"{} trailing".as_slice(), &vec![b' '; 1_048_577]] {
        assert!(ReleaseConfig::parse_json(bad).is_err());
    }
    fixture.config["profiles"][0]["unknown"] = json!(1);
    assert!(ReleaseConfig::parse_json(&bytes(&fixture.config)).is_err());
    fixture.config["profiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("unknown");
    let builder = fixture.root.join("packaging/builders/gnu.json");
    let original = fs::read(&builder).unwrap();
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    value["tools"]["llvm"]["version"] = json!("unrecorded fallback");
    fs::write(&builder, bytes(&value)).unwrap();
    assert!(fixture.seal().is_err());
    fs::write(&builder, &original).unwrap();
    value = serde_json::from_slice(&original).unwrap();
    value["environment"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"RUSTC_WRAPPER","value":"unrecorded"}));
    fs::write(&builder, bytes(&value)).unwrap();
    assert!(fixture.seal().is_err());
    fs::write(&builder, &original).unwrap();
    fs::remove_file(&builder).unwrap();
    assert!(matches!(
        fixture.seal(),
        Err(PackageError::Unavailable { .. })
    ));
    assert!(!builder.exists(), "missing builder must not be synthesized");
}
#[test]
fn native_package_tool_seals_owned_fixtures_and_maps_unavailable() {
    let fixture = Fixture::new();
    let manifest = fixture.tree().manifest_bytes();
    fs::write(fixture.root.join("osslscope-source.json"), manifest).unwrap();
    let request = fixture.root.parent().unwrap().join("request.json");
    fs::write(&request,bytes(&json!({"config":fixture.config,"dependencies":fixture.inventory,"tools":fixture.tools}))).unwrap();
    let output = fixture.root.parent().unwrap().join("sealed");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope-package"))
        .args(["seal-source", "--root"])
        .arg(&fixture.root)
        .arg("--inputs")
        .arg(&fixture.inputs)
        .arg("--request")
        .arg(&request)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.join("build-inputs.json").is_file());
    assert!(output.join("source.tar").is_file());
    fs::remove_file(fixture.root.join("packaging/builders/gnu.json")).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope-package"))
        .args(["seal-source", "--root"])
        .arg(&fixture.root)
        .arg("--inputs")
        .arg(&fixture.inputs)
        .arg("--request")
        .arg(&request)
        .arg("--output")
        .arg(fixture.root.parent().unwrap().join("missing-output"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert!(
        !fixture
            .root
            .parent()
            .unwrap()
            .join("missing-output")
            .exists()
    );
}

#[test]
fn omitted_asset_members_cannot_pass_closed_inventory() {
    let fixture = Fixture::new();
    let mut sealed = fixture.seal().unwrap();
    sealed.assets.tool_source_archives.pop().unwrap();
    assert!(
        verify_closure(&sealed).is_err(),
        "omitted source asset must fail"
    );
}
#[test]
fn unlisted_original_source_cannot_pass_closed_inventory() {
    let fixture = Fixture::new();
    let sealed = fixture.seal().unwrap();
    let path = fixture.root.join("unrecorded.rs");
    fs::write(path, b"unlisted source can influence a build\n").unwrap();
    assert!(
        verify_closure(&sealed).is_err(),
        "unlisted original source must fail"
    );
}

#[test]
fn builder_requires_both_cargo_binaries_and_real_llvm_library() {
    for role in [
        "host-cargo",
        "bpf-cargo",
        "llvm-library",
        "host-sysroot",
        "bpf-sysroot",
    ] {
        let mut fixture = Fixture::new();
        let builder = fixture.root.join("packaging/builders/gnu.json");
        let mut recipe: Value = serde_json::from_slice(&fs::read(&builder).unwrap()).unwrap();
        let resources = recipe["resources"].as_array_mut().unwrap();
        let index = resources.iter().position(|r| r["role"] == role).unwrap();
        resources.remove(index);
        let component_index = index - 5;
        recipe["tools"]["components"]
            .as_array_mut()
            .unwrap()
            .remove(component_index);
        fixture.tools["components"]
            .as_array_mut()
            .unwrap()
            .remove(component_index);
        fs::write(builder, bytes(&recipe)).unwrap();
        assert!(fixture.seal().is_err(), "missing mandatory {role}");
    }
}

#[test]
fn original_toml_fields_cannot_disagree_with_typed_adapter_config() {
    let mut fixture = Fixture::new();
    let original = fixture.files["packaging/release.toml"].clone();
    let original = String::from_utf8(original).unwrap();
    for bad in [
        original.replace("package_epoch = 1", "package_epoch = 1\npackage_epoch = 1"),
        format!("{original}\ninjected = 1\n"),
        original.replace("jobs = 2", "jobs = true"),
    ] {
        fixture.source("packaging/release.toml", bad.as_bytes());
        fixture.config["release_toml_sha256"] = json!(sha256(bad.as_bytes()));
        assert!(fixture.seal().is_err());
    }
    fixture.source("packaging/release.toml", original.as_bytes());
    fixture.config["release_toml_sha256"] = json!(sha256(original.as_bytes()));
    fixture.source("Cargo.toml",b"[package]\nname=\"osslscope\"\nversion=\"0.1.0\"\nversion=\"0.1.0\"\nlicense=\"GPL-3.0-or-later\"\n");
    fixture.config["cargo_toml_sha256"] = json!(sha256(&fixture.files["Cargo.toml"]));
    assert!(fixture.seal().is_err());
}

#[test]
fn git_entry_compares_original_blob_bytes_without_filters_or_dirty_diff_authority() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join(".git")).unwrap();
    let private = fixture.root.parent().unwrap();
    let shim = private.join("git-tool");
    fs::create_dir(&shim).unwrap();
    let mut catalogue = fixture
        .files
        .iter()
        .map(|(path, data)| json!({"path":path,"mode":"100644","data":data}))
        .collect::<Vec<_>>();
    catalogue.push(json!({"path":"CLAUDE.md","mode":"120000","data":b"AGENTS.md".to_vec()}));
    fs::write(shim.join("git-fixture.json"), bytes(&json!(catalogue))).unwrap();
    let git = shim.join("git");
    fs::write(&git,br##"#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
rows=json.loads(Path(__file__).with_name('git-fixture.json').read_text())
objects={}
for row in rows:
    data=bytes(row['data']);oid=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    row['oid']=oid;objects[oid]=data
if 'rev-parse' in sys.argv: print('a'*40)
elif 'diff' in sys.argv: pass
elif 'ls-tree' in sys.argv:
    for row in sorted(rows,key=lambda r:r['path']): sys.stdout.buffer.write((row['mode']+' blob '+row['oid']+'\t'+row['path']).encode()+b'\0')
elif 'cat-file' in sys.argv:
    for oid in sys.stdin:
        oid=oid.strip();data=objects[oid]
        sys.stdout.buffer.write((oid+' blob '+str(len(data))+'\n').encode()+data+b'\n')
else: sys.exit(2)
"##).unwrap();
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
    let request = private.join("request.json");
    fs::write(&request,bytes(&json!({"config":fixture.config,"dependencies":fixture.inventory,"tools":fixture.tools}))).unwrap();
    let invoke = |name: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_osslscope-package"))
            .env(
                "PATH",
                format!("{}:{}", shim.display(), std::env::var("PATH").unwrap()),
            )
            .args(["seal-source", "--root"])
            .arg(&fixture.root)
            .arg("--inputs")
            .arg(&fixture.inputs)
            .arg("--request")
            .arg(&request)
            .arg("--output")
            .arg(private.join(name))
            .output()
            .unwrap()
    };
    let good = invoke("git-good");
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    fs::write(
        fixture.root.join("tests/fixtures/example.json"),
        b"{\"changed_after_commit\":true}\n",
    )
    .unwrap();
    let bad = invoke("git-bad");
    assert_eq!(
        bad.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    assert!(!private.join("git-bad").exists());
}

#[test]
fn normalized_archive_rejects_unrecorded_header_metadata() {
    let fixture = Fixture::new();
    let sealed = fixture.seal().unwrap();
    let mut archive = sealed
        .asset_bytes(&sealed.assets.source_archive)
        .unwrap()
        .to_vec();
    archive[329..337].copy_from_slice(b"0000001\0");
    archive[148..156].fill(b' ');
    let sum: u64 = archive[..512].iter().map(|b| *b as u64).sum();
    archive[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert!(
        SourceTree::extract_archive(
            &archive,
            &fixture.root.parent().unwrap().join("unrecorded-header")
        )
        .is_err()
    );
}

#[test]
fn absolute_and_moving_tool_identities_cannot_enter_build_inputs() {
    for bad in ["/tmp/selected/llvm", "latest"] {
        let mut fixture = Fixture::new();
        fixture.tools["llvm"]["version"] = json!(bad);
        let path = fixture.root.join("packaging/builders/gnu.json");
        let mut recipe: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        recipe["tools"] = fixture.tools.clone();
        recipe["resources"][3]["identity"]["version"] = json!(bad);
        fs::write(path, bytes(&recipe)).unwrap();
        assert!(fixture.seal().is_err(), "unbound identity {bad}");
    }
}

#[test]
fn measured_static_abi_requires_explicit_interpreter_absence() {
    let fixture = Fixture::new();
    let abi_path = fixture.inputs.join("abi/gnu.json");
    let mut abi: Value = serde_json::from_slice(&fs::read(&abi_path).unwrap()).unwrap();
    abi["cells"][0]["interpreter"] = json!({"kind":"static"});
    abi["cells"][0]["needed"] = json!([]);
    let receipt = fixture.input("abi/gnu.json", &bytes(&abi));
    let builder = fixture.root.join("packaging/builders/gnu.json");
    let mut recipe: Value = serde_json::from_slice(&fs::read(&builder).unwrap()).unwrap();
    recipe["abi_evidence"] = receipt;
    fs::write(builder, bytes(&recipe)).unwrap();
    let sealed = fixture.seal();
    assert!(
        sealed.is_ok(),
        "explicit measured static receipt refused: {:?}",
        sealed.err()
    );
}

#[test]
fn legal_inventory_distinguishes_native_runtime_from_build_tools() {
    let mut fixture = Fixture::new();
    fixture.inventory["runtime"] = json!(["native-runtime"]);
    fixture.inventory["tool_sources"]
        .as_array_mut()
        .unwrap()
        .retain(|id| id != "native-runtime");
    let sealed = fixture.seal().unwrap();
    let sbom: Value =
        serde_json::from_slice(sealed.asset_bytes(&sealed.assets.sbom).unwrap()).unwrap();
    assert!(
        sbom["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["spdxElementId"] == "SPDXRef-native-runtime"
                && r["relationshipType"] == "RUNTIME_DEPENDENCY_OF")
    );
}

#[test]
fn public_source_fixtures_survive_generated_output_exclusion() {
    let mut fixture = Fixture::new();
    fixture.source(
        "tests/fixtures/build-inputs.json",
        b"{\"literal_source_fixture\":true}\n",
    );
    fixture.source(
        "tests/fixtures/attempt.log",
        b"literal public log-format source fixture\n",
    );
    fixture.source(
        "docs/examples/payload-manifest.json",
        b"{\"public_document_example\":true}\n",
    );
    fs::write(
        fixture.root.join("source.tar"),
        b"derived containing archive must be excluded",
    )
    .unwrap();
    let sealed = fixture.seal().unwrap();
    let tree = SourceTree::extract_archive(
        sealed.asset_bytes(&sealed.assets.source_archive).unwrap(),
        &fixture.root.parent().unwrap().join("public-fixtures"),
    )
    .unwrap();
    let paths = tree.inventory_paths();
    for path in [
        "tests/fixtures/build-inputs.json",
        "tests/fixtures/attempt.log",
        "docs/examples/payload-manifest.json",
    ] {
        assert!(
            paths.contains(&path.to_owned()),
            "dropped public source {path}"
        );
    }
    assert!(!paths.contains(&"source.tar".to_owned()));
}

fn tar_members(members: &[(&str, &[u8], u8, &str)], gnu: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data, kind, link) in members {
        let mut entry = fixture_tar(name, data, *kind, link);
        entry.truncate(entry.len() - 1024);
        if gnu {
            entry[257..265].copy_from_slice(b"ustar  \0");
            entry[136..148].copy_from_slice(b"00000000001\0");
            entry[148..156].fill(b' ');
            let sum: u64 = entry[..512].iter().map(|b| *b as u64).sum();
            entry[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        }
        out.extend(entry);
    }
    out.extend_from_slice(&[0; 1024]);
    out
}
fn crc32_fixture(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320_u32.wrapping_mul(crc & 1));
        }
    }
    !crc
}
// Independent literal gzip framing with uncompressed DEFLATE blocks and FNAME.
// Production uses flate2; this fixture does not use its encoder or decoder.
fn gzip_literal(data: &[u8]) -> Vec<u8> {
    let mut out = b"\x1f\x8b\x08\x08\0\0\0\0\0\xfffixture.crate\0".to_vec();
    let chunks = data.chunks(65535).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(index + 1 == chunks.len()));
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32_fixture(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}
const REGISTRY_FILES: [(&str, &[u8]); 4] = [
    (
        "Cargo.toml",
        b"[package]\nname=\"registry-fixture\"\nversion=\"1.2.3\"\nlicense=\"MIT\"\n",
    ),
    (
        "Cargo.toml.orig",
        b"[package]\nname=\"registry-fixture\"\nversion=\"1.2.3\"\nlicense=\"MIT\"\n",
    ),
    ("LICENSE", b"synthetic upstream license fixture\n"),
    ("src/lib.rs", b"pub const FIXTURE: u32 = 7;\n"),
];
fn registry_archives(gnu: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let names = REGISTRY_FILES
        .iter()
        .map(|(p, _)| format!("registry-fixture-1.2.3/{p}"))
        .collect::<Vec<_>>();
    let original = tar_members(
        &REGISTRY_FILES
            .iter()
            .zip(&names)
            .map(|((_, data), name)| (name.as_str(), *data, b'0', ""))
            .collect::<Vec<_>>(),
        gnu,
    );
    let normalized = tar_members(
        &REGISTRY_FILES
            .iter()
            .map(|(p, data)| (*p, *data, b'0', ""))
            .collect::<Vec<_>>(),
        false,
    );
    (gzip_literal(&original), normalized, original)
}
impl Fixture {
    fn registry(&mut self, original: &[u8], normalized: &[u8]) {
        let archive = self.input("registry/registry-fixture-1.2.3.crate", original);
        let corresponding = self.input("registry/registry-fixture-1.2.3.tar", normalized);
        let terms = self.terms("registry-fixture", "MIT");
        self.inventory["components"].as_array_mut().unwrap().push(json!({"id":"registry-fixture","name":"registry-fixture","version":"1.2.3","source":{"kind":"registry","location":"registry+https://github.com/rust-lang/crates.io-index","checksum":archive["sha256"],"archive":archive,"corresponding_source":corresponding},"terms":terms,"dependencies":[]}));
        self.inventory["host"]
            .as_array_mut()
            .unwrap()
            .push(json!("registry-fixture"));
        let mut lock = self.files["Cargo.lock"].clone();
        lock.extend_from_slice(format!("[[package]]\nname = \"registry-fixture\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",sha256(original)).as_bytes());
        self.source("Cargo.lock", &lock);
        self.inventory["locks"]["host_sha256"] = json!(sha256(&lock));
    }
}
#[test]
fn registry_original_gnu_and_posix_gzip_members_are_owning_sealer_predicates() {
    for gnu in [true, false] {
        let (original, normalized, _) = registry_archives(gnu);
        verify_registry_source(
            &original,
            &normalized,
            "registry-fixture",
            "1.2.3",
            RegistryArchiveLimits::DEFAULT,
        )
        .unwrap();
        let mut fixture = Fixture::new();
        fixture.registry(&original, &normalized);
        let sealed = fixture.seal().unwrap();
        verify_closure(&sealed).unwrap();
        assert!(
            sealed
                .assets
                .dependency_archives
                .iter()
                .any(|e| e.path.as_str().ends_with(".crate"))
        );
        let changed = tar_members(
            &[
                ("Cargo.toml", REGISTRY_FILES[0].1, b'0', ""),
                ("Cargo.toml.orig", REGISTRY_FILES[1].1, b'0', ""),
                ("LICENSE", REGISTRY_FILES[2].1, b'0', ""),
                ("src/lib.rs", b"substituted source\n", b'0', ""),
            ],
            false,
        );
        let entry = fixture.input("registry/registry-fixture-1.2.3.tar", &changed);
        fixture.inventory["components"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["source"]["corresponding_source"] = entry;
        assert!(fixture.seal().is_err());
        assert!(verify_closure(&sealed).is_err());
    }
}
#[test]
fn gzip_crc_isize_checked_eof_and_every_input_byte_are_required() {
    let (original, normalized, tar) = registry_archives(true);
    let mut failures = Vec::new();
    for end in [1, 9, 24, original.len() - 9, original.len() - 1] {
        failures.push(original[..end].to_vec());
    }
    let mut crc = original.clone();
    let index = crc.len() - 8;
    crc[index] ^= 1;
    failures.push(crc);
    let mut size = original.clone();
    let index = size.len() - 4;
    size[index] ^= 1;
    failures.push(size);
    let mut concat = original.clone();
    concat.extend_from_slice(&original);
    failures.push(concat);
    for tail in [b"trailing".as_slice(), &[0_u8]] {
        let mut bytes = original.clone();
        bytes.extend_from_slice(tail);
        failures.push(bytes);
    }
    let mut method = original.clone();
    method[2] = 0;
    failures.push(method);
    let mut flags = original.clone();
    flags[3] |= 0x80;
    failures.push(flags);
    let exact = RegistryArchiveLimits {
        compressed_bytes: original.len() as u64,
        expanded_bytes: tar.len() as u64,
        member_bytes: REGISTRY_FILES
            .iter()
            .map(|(_, d)| d.len() as u64)
            .max()
            .unwrap(),
        members: 4,
    };
    verify_registry_source(&original, &normalized, "registry-fixture", "1.2.3", exact).unwrap();
    for (i, bad) in failures.iter().enumerate() {
        assert!(
            verify_registry_source(
                bad,
                &normalized,
                "registry-fixture",
                "1.2.3",
                RegistryArchiveLimits::DEFAULT
            )
            .is_err(),
            "gzip failure {i}"
        );
        assert!(
            verify_registry_source(bad, &normalized, "registry-fixture", "1.2.3", exact).is_err(),
            "bound must not bypass trailer {i}"
        );
    }
    for limits in [
        RegistryArchiveLimits {
            compressed_bytes: exact.compressed_bytes - 1,
            ..exact
        },
        RegistryArchiveLimits {
            expanded_bytes: exact.expanded_bytes - 1,
            ..exact
        },
        RegistryArchiveLimits {
            member_bytes: exact.member_bytes - 1,
            ..exact
        },
        RegistryArchiveLimits {
            members: 3,
            ..exact
        },
        RegistryArchiveLimits {
            expanded_bytes: u64::MAX,
            ..exact
        },
    ] {
        assert!(
            verify_registry_source(&original, &normalized, "registry-fixture", "1.2.3", limits)
                .is_err()
        );
    }
}

#[test]
fn original_posix_prefix_and_gzip_header_crc_are_preserved() {
    let (gzip, normalized, mut tar) = registry_archives(false);
    tar[..100].fill(0);
    tar[..10].copy_from_slice(b"Cargo.toml");
    let prefix = b"registry-fixture-1.2.3";
    tar[345..345 + prefix.len()].copy_from_slice(prefix);
    tar[148..156].fill(b' ');
    let sum: u64 = tar[..512].iter().map(|b| *b as u64).sum();
    tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    verify_registry_source(
        &gzip_literal(&tar),
        &normalized,
        "registry-fixture",
        "1.2.3",
        RegistryArchiveLimits::DEFAULT,
    )
    .unwrap();
    let end = 10 + gzip[10..].iter().position(|b| *b == 0).unwrap() + 1;
    let mut header = gzip[..end].to_vec();
    header[3] |= 2;
    let crc = crc32_fixture(&header) as u16;
    header.extend_from_slice(&crc.to_le_bytes());
    header.extend_from_slice(&gzip[end..]);
    verify_registry_source(
        &header,
        &normalized,
        "registry-fixture",
        "1.2.3",
        RegistryArchiveLimits::DEFAULT,
    )
    .unwrap();
    header[end] ^= 1;
    assert!(
        verify_registry_source(
            &header,
            &normalized,
            "registry-fixture",
            "1.2.3",
            RegistryArchiveLimits::DEFAULT
        )
        .is_err()
    );
}
#[test]
fn registry_mapping_rejects_omitted_extra_changed_mode_and_manifest_members() {
    let (original, normalized, _) = registry_archives(true);
    let omitted = tar_members(
        &REGISTRY_FILES[..3]
            .iter()
            .map(|(p, d)| (*p, *d, b'0', ""))
            .collect::<Vec<_>>(),
        false,
    );
    assert!(
        verify_registry_source(
            &original,
            &omitted,
            "registry-fixture",
            "1.2.3",
            RegistryArchiveLimits::DEFAULT
        )
        .is_err()
    );
    let mut members = REGISTRY_FILES
        .iter()
        .map(|(p, d)| (*p, *d, b'0', ""))
        .collect::<Vec<_>>();
    members.push(("zzz-extra.rs", b"extra source", b'0', ""));
    assert!(
        verify_registry_source(
            &original,
            &tar_members(&members, false),
            "registry-fixture",
            "1.2.3",
            RegistryArchiveLimits::DEFAULT
        )
        .is_err()
    );
    for field in ["Cargo.toml", "Cargo.toml.orig", "LICENSE", "src/lib.rs"] {
        let changed = tar_members(
            &REGISTRY_FILES
                .iter()
                .map(|(p, d)| {
                    (
                        *p,
                        if *p == field {
                            b"changed source".as_slice()
                        } else {
                            *d
                        },
                        b'0',
                        "",
                    )
                })
                .collect::<Vec<_>>(),
            false,
        );
        assert!(
            verify_registry_source(
                &original,
                &changed,
                "registry-fixture",
                "1.2.3",
                RegistryArchiveLimits::DEFAULT
            )
            .is_err(),
            "changed {field}"
        );
    }
    let mut mode = normalized.clone();
    mode[100..108].copy_from_slice(b"0000755\0");
    mode[148..156].fill(b' ');
    let sum: u64 = mode[..512].iter().map(|b| *b as u64).sum();
    mode[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert!(
        verify_registry_source(
            &original,
            &mode,
            "registry-fixture",
            "1.2.3",
            RegistryArchiveLimits::DEFAULT
        )
        .is_err()
    );
}
#[test]
fn original_tar_refuses_unsafe_gnu_posix_types_paths_encodings_and_remainders() {
    let (_, normalized, valid) = registry_archives(true);
    for gnu in [true, false] {
        for (path, kind, link) in [
            ("/absolute", b'0', ""),
            ("registry-fixture-1.2.3/../escape", b'0', ""),
            ("other-1.2.3/file", b'0', ""),
            ("registry-fixture-1.2.3/link", b'2', "../../outside"),
            ("registry-fixture-1.2.3/hard", b'1', "/outside"),
            ("registry-fixture-1.2.3/device", b'3', ""),
            ("registry-fixture-1.2.3/pax", b'x', ""),
            ("registry-fixture-1.2.3/long", b'L', ""),
            ("registry-fixture-1.2.3/sparse", b'S', ""),
        ] {
            let bad = gzip_literal(&tar_members(&[(path, b"", kind, link)], gnu));
            assert!(
                verify_registry_source(
                    &bad,
                    &normalized,
                    "registry-fixture",
                    "1.2.3",
                    RegistryArchiveLimits::DEFAULT
                )
                .is_err(),
                "{gnu} {path} {kind}"
            );
        }
    }
    let mut failures = vec![
        valid[..511].to_vec(),
        valid[..700].to_vec(),
        valid[..valid.len() - 512].to_vec(),
    ];
    let mut hidden = valid.clone();
    hidden.extend_from_slice(&valid);
    failures.push(hidden);
    let mut checksum = valid.clone();
    checksum[0] ^= 1;
    failures.push(checksum);
    for (offset, value) in [(124, 0x80), (345, 1), (263, b'?'), (108, b'8')] {
        let mut bad = valid.clone();
        bad[offset] = value;
        bad[148..156].fill(b' ');
        let sum: u64 = bad[..512].iter().map(|b| *b as u64).sum();
        bad[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        failures.push(bad);
    }
    let mut padding = valid.clone();
    padding[512 + REGISTRY_FILES[0].1.len()] = 1;
    failures.push(padding);
    let duplicate = tar_members(
        &[
            ("registry-fixture-1.2.3/same", b"a", b'0', ""),
            ("registry-fixture-1.2.3/same", b"b", b'0', ""),
        ],
        true,
    );
    failures.push(duplicate);
    let ancestor = tar_members(
        &[
            ("registry-fixture-1.2.3/path", b"a", b'0', ""),
            ("registry-fixture-1.2.3/path/child", b"b", b'0', ""),
        ],
        true,
    );
    failures.push(ancestor);
    for (i, bad) in failures.iter().enumerate() {
        assert!(
            verify_registry_source(
                &gzip_literal(bad),
                &normalized,
                "registry-fixture",
                "1.2.3",
                RegistryArchiveLimits::DEFAULT
            )
            .is_err(),
            "tar failure {i}"
        );
    }
}

#[test]
fn sealer_applies_archive_size_limits_before_opening_inputs() {
    let (original, normalized, _) = registry_archives(true);
    for (field, limit, path) in [
        (
            "archive",
            RegistryArchiveLimits::DEFAULT.compressed_bytes,
            "registry/registry-fixture-1.2.3.crate",
        ),
        (
            "corresponding_source",
            RegistryArchiveLimits::DEFAULT.expanded_bytes,
            "registry/registry-fixture-1.2.3.tar",
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.registry(&original, &normalized);
        fixture.inventory["components"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["source"][field]["bytes"] = json!(limit + 1);
        fs::remove_file(fixture.inputs.join(path)).unwrap();
        assert!(
            matches!(fixture.seal(), Err(PackageError::Invalid { .. })),
            "declared cap must be checked before opening {field}"
        );
    }
}

#[test]
fn oversized_original_source_manifest_cannot_produce_a_sealable_tree() {
    let fixture = Fixture::new();
    let directory = fixture.root.join("tests/fixtures").join("a".repeat(95));
    fs::create_dir_all(&directory).unwrap();
    for i in 0..3200 {
        fs::write(
            directory.join(format!("{i:04}-{}.rs", "b".repeat(88))),
            b"x",
        )
        .unwrap();
    }
    assert!(matches!(
        SourceTree::snapshot(&fixture.root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Err(PackageError::Invalid { .. })
    ));
}

#[test]
fn native_sealer_rejects_equivalent_toml_duplicates_and_malformed_global_definitions() {
    let base = format!(
        "[package]\nname=\"osslscope\"\nversion=\"{}\"\nlicense=\"GPL-3.0-or-later\"\n",
        env!("CARGO_PKG_VERSION")
    );
    let mut admitted = Vec::new();
    for (name, suffix) in [
        ("quoted package version", "\"version\"=\"9.9.9\"\n"),
        ("literal package name", "'name'=\"other\"\n"),
        ("escaped package version", "\"\\u0076ersion\"=\"9.9.9\"\n"),
        (
            "quoted metadata duplicate",
            "[package.metadata]\nflag=1\n\"flag\"=2\n",
        ),
        (
            "dotted metadata duplicate",
            "[package.metadata]\nitem.value=1\nitem.\"value\"=2\n",
        ),
        (
            "duplicate external table",
            "[dependencies]\nserde=\"1\"\n[dependencies]\nsha2=\"0.11\"\n",
        ),
        (
            "malformed external definition",
            "[package.metadata]\nnot a valid TOML definition\n",
        ),
        ("TOML1.1 escape", "[package.metadata]\nvalue=\"\\e\"\n"),
        (
            "TOML1.1 hex escape",
            "[package.metadata]\nvalue=\"\\x41\"\n",
        ),
        (
            "TOML1.1 multiline inline table",
            "[package.metadata]\nvalue={item=1,\n}\n",
        ),
    ] {
        let mut fixture = Fixture::new();
        let cargo = format!("{base}{suffix}");
        fixture.source("Cargo.toml", cargo.as_bytes());
        fixture.config["cargo_toml_sha256"] = json!(sha256(cargo.as_bytes()));
        if fixture.seal().is_ok() {
            admitted.push(name);
        }
    }
    assert!(
        admitted.is_empty(),
        "native source admission accepted invalid TOML: {admitted:?}"
    );
}

#[test]
fn native_sealer_accepts_structurally_equivalent_valid_package_keys() {
    for cargo in [
        format!(
            "[\"package\"]\n'name'=\"osslscope\"\n\"version\"=\"{}\"\nlicense=\"GPL-3.0-or-later\"\n",
            env!("CARGO_PKG_VERSION")
        ),
        format!(
            "package.name=\"osslscope\"\npackage.\"version\"=\"{}\"\npackage.license=\"GPL-3.0-or-later\"\n",
            env!("CARGO_PKG_VERSION")
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.source("Cargo.toml", cargo.as_bytes());
        fixture.config["cargo_toml_sha256"] = json!(sha256(cargo.as_bytes()));
        assert_eq!(
            fixture.seal().unwrap().inputs.product_version,
            env!("CARGO_PKG_VERSION")
        );
    }
}

#[test]
fn consistently_changed_rust_src_nightly_cannot_enter_sealed_inputs() {
    let mut fixture = Fixture::new();
    fixture.seal().unwrap();
    let version = "nightly-2026-05-19";
    fixture.tools["components"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|t| t["name"] == "rust-src")
        .unwrap()["version"] = json!(version);
    for id in ["gnu", "musl"] {
        let name = format!("packaging/builders/{id}.json");
        let mut recipe: Value =
            serde_json::from_slice(&fs::read(fixture.root.join(&name)).unwrap()).unwrap();
        recipe["tools"] = fixture.tools.clone();
        recipe["resources"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["role"] == "rust-src")
            .unwrap()["identity"]["version"] = json!(version);
        fixture.source(&name, &bytes(&recipe));
    }
    assert!(
        fixture.seal().is_err(),
        "a fully rebound wrong-nightly rust-src selection was admitted"
    );
}

#[test]
fn native_toml_input_envelope_rejects_a_leading_utf8_bom() {
    for (path, field) in [
        ("Cargo.toml", "cargo_toml_sha256"),
        ("packaging/release.toml", "release_toml_sha256"),
    ] {
        let mut fixture = Fixture::new();
        let mut input = b"\xef\xbb\xbf".to_vec();
        input.extend_from_slice(&fixture.files[path]);
        fixture.source(path, &input);
        fixture.config[field] = json!(sha256(&input));
        assert!(
            fixture.seal().is_err(),
            "native TOML envelope accepted BOM in {path}"
        );
    }
}

#[test]
fn native_release_policy_preserves_semantic_keys_and_literal_dot_hierarchy() {
    let mut fixture = Fixture::new();
    let original = String::from_utf8(fixture.files["packaging/release.toml"].clone()).unwrap();
    let equivalent = original
        .replace("[profiles.gnu]", "[profiles.\"gnu\"]")
        .replace(
            "source_epoch = 1792799804",
            "\"source_epoch\" = 1_792_799_804",
        );
    fixture.source("packaging/release.toml", equivalent.as_bytes());
    fixture.config["release_toml_sha256"] = json!(sha256(equivalent.as_bytes()));
    assert_eq!(fixture.seal().unwrap().inputs.source_epoch, 1792799804);
    let different_hierarchy = original.replace("[profiles.gnu]", "[\"profiles.gnu\"]");
    fixture.source("packaging/release.toml", different_hierarchy.as_bytes());
    fixture.config["release_toml_sha256"] = json!(sha256(different_hierarchy.as_bytes()));
    assert!(
        fixture.seal().is_err(),
        "a literal key containing a dot must not become nested policy"
    );
}

// Removing mandatory executor resources or admitting a substitute original source
// must refuse sealing even when the remaining records have internally rebound hashes.
#[test]
fn executor_roles_and_original_presence_required() {
    for profile in ["gnu", "musl"] {
        let mut fixture = Fixture::new();
        fixture.config["selected_profile"] = json!(profile);
        let sealed = fixture.seal().unwrap();
        let input = serde_json::to_value(&sealed.inputs).unwrap();
        assert_eq!(input["jobs"], 2);
        for role in ["executor-host", "executor-layout"] {
            let path = format!("packaging/builders/{profile}.json");
            let original = fs::read(fixture.root.join(&path)).unwrap();
            let recipe: Value = serde_json::from_slice(&original).unwrap();
            let index = recipe["resources"]
                .as_array()
                .unwrap()
                .iter()
                .position(|r| r["role"] == role)
                .unwrap();
            for field in ["role", "identity", "acquisition", "source_component"] {
                let mut changed = recipe.clone();
                changed["resources"][index][field] = changed["resources"][0][field].clone();
                fixture.source(&path, &bytes(&changed));
                assert!(fixture.seal().is_err(), "{profile}/{role}/{field}");
            }
            let mut changed = recipe.clone();
            changed["resources"].as_array_mut().unwrap().remove(index);
            // Remove the matching inventory component too: length/identity
            // mismatch must not mask an omitted mandatory executor role.
            let tools = fixture.tools.clone();
            fixture.tools["components"]
                .as_array_mut()
                .unwrap()
                .remove(index - 5);
            changed["tools"] = fixture.tools.clone();
            fixture.source(&path, &bytes(&changed));
            assert!(fixture.seal().is_err(), "{profile}/{role}/missing");
            fixture.tools = tools;
            fixture.source(&path, &original);
        }
        for path in [
            "scripts/package-executor.py".to_owned(),
            format!("packaging/builders/{profile}.layout.json"),
        ] {
            let original = fs::read(fixture.root.join(&path)).unwrap();
            fs::remove_file(fixture.root.join(&path)).unwrap();
            assert!(fixture.seal().is_err(), "{profile}/{path}/absent");
            fixture.source(&path, &original);
        }
        fixture.source(
            &format!("packaging/builders/{profile}.layout.json"),
            b"substitute source layout\n",
        );
        assert!(
            fixture.seal().is_err(),
            "{profile}/layout original mismatch"
        );
    }
}

#[test]
fn sealing_applies_shared_inner_abi_policy_after_rebinding() {
    for profile in ["gnu", "musl"] {
        let mut fixture = Fixture::new();
        fixture.config["selected_profile"] = json!(profile);
        fixture.seal().unwrap();
        let abi_path = format!("abi/{profile}.json");
        let original = fs::read(fixture.inputs.join(&abi_path)).unwrap();
        let mut abi: Value = serde_json::from_slice(&original).unwrap();
        abi["cells"][0]["symbol_versions"] = json!(["lib-unavailable.so@VERSION_1"]);
        let replacement = fixture.input(&abi_path, &bytes(&abi));
        let recipe_path = format!("packaging/builders/{profile}.json");
        let mut recipe: Value = serde_json::from_slice(&fixture.files[&recipe_path]).unwrap();
        recipe["abi_evidence"] = replacement;
        fixture.source(&recipe_path, &bytes(&recipe));
        assert!(
            fixture.seal().is_err(),
            "{profile}/unavailable ABI provider"
        );
    }
}
