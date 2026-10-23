// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "support/package_fixtures.rs"]
mod package_fixtures;
use osslscope::package::records::*;
use package_fixtures::{INPUT_BYTES, records_fixture};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn edit(bytes: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    f(&mut value);
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn independent_literal_records_bind_all_duplicated_groups() {
    let fixture = records_fixture();
    assert_eq!(
        canonical_bytes(&fixture.inputs),
        fixture.expected_input_bytes
    );
    assert_eq!(
        canonical_bytes(&fixture.contract),
        fixture.expected_contract_bytes
    );
    assert_eq!(
        fixture.verify().unwrap().input_id,
        sha256(&fixture.expected_input_bytes)
    );
    for field in [
        "source",
        "product_version",
        "host_profile",
        "locks",
        "recipe",
        "tools",
    ] {
        assert!(
            matches!(
                fixture.clone().payload_only_mutation(field).verify(),
                Err(PackageError::Invalid { .. })
            ),
            "{field}"
        );
    }
    assert!(matches!(
        fixture.consistent_inputs_and_payload_mutation().verify(),
        Err(PackageError::Invalid { .. })
    ));
}

#[test]
fn canonical_parser_rejects_nested_duplicates_and_noncanonical_bytes() {
    let fixture = records_fixture();
    assert!(
        parse_canonical::<BuildInputs>(&fixture.duplicate_input_member("/tools/host/version"))
            .is_err()
    );
    assert!(parse_canonical::<BuildInputs>(&vec![b' '; 1_048_577]).is_err());
    let mut missing_newline = INPUT_BYTES.as_bytes().to_vec();
    missing_newline.pop();
    assert!(parse_canonical::<BuildInputs>(&missing_newline).is_err());
    let spaced = INPUT_BYTES.replacen(":", ": ", 1);
    assert!(parse_canonical::<BuildInputs>(spaced.as_bytes()).is_err());
    let unsorted = INPUT_BYTES.replacen(
        "{\"argv\":",
        "{\"schema\":\"osslscope-build-inputs-v1\",\"argv\":",
        1,
    );
    assert!(parse_canonical::<BuildInputs>(unsorted.as_bytes()).is_err());
    let payload_duplicate = package_fixtures::PAYLOAD_BYTES.replacen(
        "\"version\":\"fixture-1\"",
        "\"version\":\"fixture-1\",\"version\":\"fixture-1\"",
        1,
    );
    assert!(parse_canonical::<PayloadManifest>(payload_duplicate.as_bytes()).is_err());
    let mut at_limit = records_fixture().inputs;
    at_limit.argv.push(String::new());
    let base = canonical_bytes(&at_limit).len();
    *at_limit.argv.last_mut().unwrap() = "x".repeat(1_048_576 - base);
    let bytes = canonical_bytes(&at_limit);
    assert_eq!(bytes.len(), 1_048_576);
    assert!(parse_canonical::<BuildInputs>(&bytes).is_ok());
    let mut too_large = bytes;
    too_large.insert(too_large.len() - 3, b'x');
    assert!(parse_canonical::<BuildInputs>(&too_large).is_err());
}

#[test]
fn closed_input_fields_types_and_digests() {
    for mutation in [
        edit(INPUT_BYTES.as_bytes(), |v| {
            v["schema"] = json!("osslscope-build-inputs-v2")
        }),
        edit(INPUT_BYTES.as_bytes(), |v| v["extra"] = json!(1)),
        edit(INPUT_BYTES.as_bytes(), |v| v["source"] = Value::Null),
        edit(INPUT_BYTES.as_bytes(), |v| {
            v.as_object_mut().unwrap().remove("source");
        }),
        edit(INPUT_BYTES.as_bytes(), |v| v["package_epoch"] = json!(1.25)),
        edit(INPUT_BYTES.as_bytes(), |v| {
            v["package_epoch"] = json!(u64::MAX)
        }),
        edit(INPUT_BYTES.as_bytes(), |v| {
            v["source"]["inventory_sha256"] = json!("A".repeat(64))
        }),
        edit(INPUT_BYTES.as_bytes(), |v| {
            v["source"]["inventory_sha256"] = json!("a".repeat(63))
        }),
        edit(INPUT_BYTES.as_bytes(), |v| {
            v["tools"]["host"]["extra"] = json!(0)
        }),
        edit(INPUT_BYTES.as_bytes(), |v| v["argv"] = json!("cargo build")),
        edit(INPUT_BYTES.as_bytes(), |v| v["jobs"] = json!(0)),
    ] {
        assert!(
            parse_canonical::<BuildInputs>(&mutation).is_err(),
            "accepted {}",
            String::from_utf8_lossy(&mutation)
        );
    }
    for field in ["host_sha256", "bpf_sha256"] {
        let bytes = edit(INPUT_BYTES.as_bytes(), |v| v["locks"][field] = json!("0"));
        assert!(parse_canonical::<BuildInputs>(&bytes).is_err());
    }
    for field in [
        "host_sha256",
        "bpf_sha256",
        "bundle_id",
        "payload_id",
        "package_id",
    ] {
        let bytes = edit(INPUT_BYTES.as_bytes(), |v| v[field] = json!("a".repeat(64)));
        assert!(parse_canonical::<BuildInputs>(&bytes).is_err(), "{field}");
    }
}

#[test]
fn role_set_is_frozen_and_all_content_entries_are_closed() {
    let fixture = records_fixture();
    let contract = fixture.expected_contract_bytes;
    for changed in [
        edit(&contract, |v| v["roles"][0]["role"] = json!("identity")),
        edit(&contract, |v| v["roles"][0]["file"] = json!("../escape")),
        edit(&contract, |v| v["roles"][0]["file"] = json!("/absolute")),
        edit(&contract, |v| {
            v["roles"][0]["file"] = json!("osslscope//harvest")
        }),
        edit(&contract, |v| {
            v["roles"][0]["sha256"] = json!("A".repeat(64))
        }),
        edit(&contract, |v| v["roles"][0]["bytes"] = json!(0)),
        edit(&contract, |v| {
            v["roles"].as_array_mut().unwrap().push(json!({"role":"identity","file":"osslscope-identity","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":1}))
        }),
        edit(&contract, |v| v["roles"][1] = v["roles"][0].clone()),
    ] {
        assert!(parse_canonical::<BundleContract>(&changed).is_err());
    }
    let payload_bytes = package_fixtures::PAYLOAD_BYTES.as_bytes();
    for field in ["contract", "build_inputs", "sbom"] {
        for member in ["path", "sha256", "bytes"] {
            let changed = edit(payload_bytes, |v| {
                v[field][member] = match member {
                    "path" => json!("../bad"),
                    "sha256" => json!("bad"),
                    _ => json!(0),
                }
            });
            assert!(
                parse_canonical::<PayloadManifest>(&changed).is_err(),
                "{field}/{member}"
            );
        }
    }
    for field in ["docs", "licenses", "notices"] {
        for member in ["path", "sha256", "bytes"] {
            let changed = edit(payload_bytes, |v| {
                v[field][0][member] = match member {
                    "path" => json!("../bad"),
                    "sha256" => json!("bad"),
                    _ => json!(0),
                }
            });
            assert!(
                parse_canonical::<PayloadManifest>(&changed).is_err(),
                "{field}/{member}"
            );
        }
    }
    for member in ["path", "sha256", "bytes"] {
        let changed = edit(payload_bytes, |v| {
            v["host"][member] = match member {
                "path" => json!("../bad"),
                "sha256" => json!("bad"),
                _ => json!(0),
            }
        });
        assert!(
            parse_canonical::<PayloadManifest>(&changed).is_err(),
            "host/{member}"
        );
    }
    for role in 0..3 {
        for member in ["file", "sha256", "bytes"] {
            let changed = edit(payload_bytes, |v| {
                v["roles"][role][member] = match member {
                    "file" => json!("../bad"),
                    "sha256" => json!("bad"),
                    _ => json!(0),
                }
            });
            assert!(
                parse_canonical::<PayloadManifest>(&changed).is_err(),
                "role {role}/{member}"
            );
        }
    }
}

#[test]
fn exact_input_and_contract_entries_are_bound() {
    let fixture = records_fixture();
    for field in ["input_id", "bundle_id"] {
        let mut payload = fixture.payload.clone();
        if field == "input_id" {
            payload.input_id = sha256(b"other");
        } else {
            payload.bundle_id = sha256(b"other");
        }
        assert!(
            verify_metadata(
                &fixture.contract,
                &payload,
                fixture.expected_input_bytes.clone().into()
            )
            .is_err()
        );
    }
    let mut payload = fixture.payload.clone();
    payload.build_inputs.bytes += 1;
    assert!(
        verify_metadata(
            &fixture.contract,
            &payload,
            fixture.expected_input_bytes.clone().into()
        )
        .is_err()
    );
    let mut payload = fixture.payload.clone();
    payload.contract.sha256 = sha256(b"other");
    assert!(
        verify_metadata(
            &fixture.contract,
            &payload,
            fixture.expected_input_bytes.clone().into()
        )
        .is_err()
    );
    let mut contract = fixture.contract.clone();
    contract.roles.swap(0, 1);
    assert!(
        verify_metadata(
            &contract,
            &fixture.payload,
            fixture.expected_input_bytes.into()
        )
        .is_err()
    );
    for field in ["build_inputs", "contract"] {
        let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
            v[field]["path"] = json!("other.json")
        });
        assert!(parse_canonical::<PayloadManifest>(&changed).is_err());
    }
}

#[test]
fn payload_rejects_back_edges_and_duplicate_paths() {
    let bytes = package_fixtures::PAYLOAD_BYTES.as_bytes();
    for changed in [
        edit(bytes, |v| {
            v["docs"][0]["path"] = json!("payload-manifest.json")
        }),
        edit(bytes, |v| {
            v["docs"][0]["path"] = json!("release-index.json")
        }),
        edit(bytes, |v| v["docs"][0]["path"] = v["sbom"]["path"].clone()),
        edit(bytes, |v| v["licenses"][0]["path"] = json!("osslscope.rpm")),
    ] {
        assert!(parse_canonical::<PayloadManifest>(&changed).is_err());
    }
}

#[test]
fn all_nested_input_duplicates_and_array_order_bind() {
    let fixture = records_fixture();
    let mut input = fixture.inputs.clone();
    input.tools.components.swap(0, 1);
    assert!(
        verify_metadata(
            &fixture.contract,
            &fixture.payload,
            canonical_bytes(&input).into()
        )
        .is_err()
    );
    let mut payload = fixture.payload.clone();
    payload.tools.components.swap(0, 1);
    assert!(
        verify_metadata(
            &fixture.contract,
            &payload,
            fixture.expected_input_bytes.clone().into()
        )
        .is_err()
    );
    for field in ["revision", "inventory_sha256"] {
        let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
            v["source"][field] = if field == "revision" {
                json!("a".repeat(40))
            } else {
                json!("a".repeat(64))
            };
        });
        let payload: PayloadManifest = parse_canonical(&changed).unwrap();
        assert!(
            verify_metadata(
                &fixture.contract,
                &payload,
                fixture.expected_input_bytes.clone().into()
            )
            .is_err()
        );
    }
    for group in ["locks", "recipe"] {
        let value = serde_json::to_value(&fixture.payload).unwrap();
        for field in value[group].as_object().unwrap().keys() {
            let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
                v[group][field] = json!("a".repeat(64))
            });
            let payload: PayloadManifest = parse_canonical(&changed).unwrap();
            assert!(
                verify_metadata(
                    &fixture.contract,
                    &payload,
                    fixture.expected_input_bytes.clone().into()
                )
                .is_err()
            );
        }
    }
    let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
        v["host_profile"]["abi_floor"] = json!("other-fixture-floor")
    });
    let payload: PayloadManifest = parse_canonical(&changed).unwrap();
    assert!(
        verify_metadata(
            &fixture.contract,
            &payload,
            fixture.expected_input_bytes.clone().into()
        )
        .is_err()
    );
    let changed = edit(package_fixtures::CONTRACT_BYTES.as_bytes(), |v| {
        v["host_profile"]["abi_floor"] = json!("other-fixture-floor")
    });
    let contract: BundleContract = parse_canonical(&changed).unwrap();
    assert!(
        verify_metadata(
            &contract,
            &fixture.payload,
            fixture.expected_input_bytes.clone().into()
        )
        .is_err()
    );
    let tool = serde_json::to_value(&fixture.payload).unwrap();
    for key in ["host", "bpf", "linker", "llvm", "builder"] {
        for field in tool["tools"][key].as_object().unwrap().keys() {
            let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
                v["tools"][key][field] = if field == "sha256" {
                    json!("a".repeat(64))
                } else {
                    json!("changed")
                }
            });
            let payload: PayloadManifest = parse_canonical(&changed).unwrap();
            assert!(
                verify_metadata(
                    &fixture.contract,
                    &payload,
                    fixture.expected_input_bytes.clone().into()
                )
                .is_err()
            );
        }
    }
    for component in 0..2 {
        for field in ["name", "version", "sha256"] {
            let changed = edit(package_fixtures::PAYLOAD_BYTES.as_bytes(), |v| {
                v["tools"]["components"][component][field] = if field == "sha256" {
                    json!("a".repeat(64))
                } else {
                    json!("changed")
                }
            });
            let payload: PayloadManifest = parse_canonical(&changed).unwrap();
            assert!(
                verify_metadata(
                    &fixture.contract,
                    &payload,
                    fixture.expected_input_bytes.clone().into()
                )
                .is_err()
            );
        }
    }
}

#[test]
fn schema_required_fields_match_closed_rust_records() {
    let cases = [
        (
            include_str!("../schemas/package-build-inputs-v1.json"),
            INPUT_BYTES,
        ),
        (
            include_str!("../schemas/package-bundle-contract-v1.json"),
            package_fixtures::CONTRACT_BYTES,
        ),
        (
            include_str!("../schemas/package-payload-manifest-v1.json"),
            package_fixtures::PAYLOAD_BYTES,
        ),
        (
            include_str!("../schemas/package-release-index-v1.json"),
            package_fixtures::INDEX_BYTES,
        ),
    ];
    for (schema_bytes, record_bytes) in cases {
        let schema: Value = serde_json::from_str(schema_bytes).unwrap();
        let record: Value = serde_json::from_str(record_bytes).unwrap();
        assert_eq!(schema["additionalProperties"], json!(false));
        let required: std::collections::BTreeSet<_> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .map(Option::unwrap)
            .collect();
        let actual: std::collections::BTreeSet<_> = record
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(required, actual);
        for definition in schema["$defs"].as_object().unwrap().values() {
            assert_eq!(definition["additionalProperties"], json!(false));
            let required: std::collections::BTreeSet<_> = definition["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(Value::as_str)
                .map(Option::unwrap)
                .collect();
            let properties: std::collections::BTreeSet<_> = definition["properties"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(required, properties);
        }
    }
}

#[test]
fn release_index_is_closed_and_cannot_hash_itself() {
    let bytes = package_fixtures::INDEX_BYTES.as_bytes();
    let index: ReleaseIndex = parse_canonical(bytes).unwrap();
    assert_eq!(canonical_bytes(&index), bytes);
    for changed in [
        edit(bytes, |v| v["schema"] = json!("osslscope-release-index-v2")),
        edit(bytes, |v| {
            v["support_matrix"]["path"] = json!("release-index.json")
        }),
        edit(bytes, |v| {
            v["source_assets"][0]["path"] = json!("release-index.sig")
        }),
        edit(bytes, |v| v["signing_identity"] = Value::Null),
        edit(bytes, |v| {
            v["profiles"][0]["payload_id"] = json!("A".repeat(64))
        }),
        edit(bytes, |v| v["qualification_receipts"] = json!([])),
        edit(bytes, |v| v["extra"] = json!(1)),
    ] {
        assert!(parse_canonical::<ReleaseIndex>(&changed).is_err());
    }
}

#[test]
fn package_count_loader_policy_hash_binding() {
    let fixture = records_fixture();
    let inventory: Value = serde_json::from_str(package_fixtures::COUNT_POLICY_BYTES).unwrap();
    let maps = inventory["prepared"]["maps"].as_array().unwrap();
    assert_eq!(maps.len(), osslscope::loader::COUNT_MAPS.len());
    for (record, actual) in maps.iter().zip(osslscope::loader::COUNT_MAPS) {
        assert_eq!(record["name"], actual.name);
        assert_eq!(record["map_type"], actual.map_type);
        assert_eq!(record["key_size"], actual.key_size);
        assert_eq!(record["value_size"], actual.value_size);
        assert_eq!(record["max_entries"], actual.max_entries);
        assert_eq!(record["flags"], actual.flags);
    }
    assert_eq!(
        inventory["prepared"]["program"]["name"],
        osslscope::loader::COUNT_PROGS[0].name
    );
    assert_eq!(
        inventory["prepared"]["program"]["section"],
        osslscope::loader::COUNT_PROGS[0].section
    );
    let expected: Digest =
        serde_json::from_str(&format!("\"{}\"", package_fixtures::COUNT_POLICY_SHA256)).unwrap();
    assert_eq!(
        sha256(package_fixtures::COUNT_POLICY_BYTES.as_bytes()),
        expected
    );
    assert_eq!(fixture.contract.loader_contract_sha256, expected);
    let changed = package_fixtures::COUNT_POLICY_BYTES
        .replace("\"callbacks_allowed\":false", "\"callbacks_allowed\":true");
    let parsed: Value = serde_json::from_str(&changed).unwrap();
    let mut canonical = serde_json::to_vec(&parsed).unwrap();
    canonical.push(b'\n');
    assert_eq!(canonical, changed.as_bytes());
    let changed_digest = sha256(changed.as_bytes());
    assert_ne!(changed_digest, expected);
    // The old expected contract rejects a changed policy inventory digest.
    assert_ne!(fixture.contract.loader_contract_sha256, changed_digest);
    let mut changed_contract = fixture.contract.clone();
    changed_contract.loader_contract_sha256 = changed_digest;
    assert!(matches!(
        verify_metadata(
            &changed_contract,
            &fixture.payload,
            fixture.expected_input_bytes.into()
        ),
        Err(PackageError::Invalid { .. })
    ));
}

#[test]
fn descriptor_free_developer_build_has_no_embedded_contract() {
    assert!(osslscope::package::embedded::contract_bytes().is_none());
    let current = std::env::current_exe().unwrap();
    let output = Command::new("readelf")
        .arg("-SW")
        .arg(current)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .matches(".osslscope.bundle_contract")
            .count(),
        0
    );
}

fn with_duplicate_section_header(host: &std::path::Path, duplicate: &std::path::Path) {
    let mut elf = fs::read(host).unwrap();
    assert_eq!(&elf[..6], b"\x7fELF\x02\x01");
    let u16_at = |b: &[u8], i: usize| u16::from_le_bytes(b[i..i + 2].try_into().unwrap()) as usize;
    let u64_at = |b: &[u8], i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) as usize;
    let offset = u64_at(&elf, 40);
    let width = u16_at(&elf, 58);
    let count = u16_at(&elf, 60);
    let names_index = u16_at(&elf, 62);
    assert!(count > 0 && count < u16::MAX as usize && width >= 64);
    let table = elf[offset..offset + width * count].to_vec();
    let names_header = &table[names_index * width..(names_index + 1) * width];
    let names_offset = u64_at(names_header, 24);
    let names_length = u64_at(names_header, 32);
    let names = &elf[names_offset..names_offset + names_length];
    let matching = table
        .chunks_exact(width)
        .find(|header| {
            let name_offset = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            names
                .get(name_offset..)
                .map(|tail| tail.starts_with(b".osslscope.bundle_contract\0"))
                .unwrap_or(false)
        })
        .unwrap()
        .to_vec();
    let new_offset = (elf.len() + 7) & !7;
    elf.resize(new_offset, 0);
    elf.extend_from_slice(&table);
    elf.extend_from_slice(&matching);
    elf[40..48].copy_from_slice(&(new_offset as u64).to_le_bytes());
    elf[60..62].copy_from_slice(&((count + 1) as u16).to_le_bytes());
    fs::write(duplicate, elf).unwrap();
}

fn exactly_one_contract_section(host: &std::path::Path) -> Result<(), PackageError> {
    let output = Command::new("readelf")
        .arg("-SW")
        .arg(host)
        .output()
        .map_err(|e| PackageError::unreadable(e.to_string()))?;
    if !output.status.success() {
        return Err(PackageError::invalid("ELF section table unreadable"));
    }
    let table =
        String::from_utf8(output.stdout).map_err(|e| PackageError::invalid(e.to_string()))?;
    if table.matches(".osslscope.bundle_contract").count() != 1 {
        return Err(PackageError::invalid(
            "host must have exactly one bundle-contract section",
        ));
    }
    Ok(())
}

#[test]
fn embedded_contract_is_same_static_section_bytes() {
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let base = std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let fixture = base.join(format!("embedding-{nonce}"));
    let records = fixture.join("records");
    fs::create_dir_all(fixture.join("src")).unwrap();
    fs::create_dir_all(&records).unwrap();
    fs::write(records.join("build-inputs.json"), INPUT_BYTES).unwrap();
    fs::write(
        records.join("bundle-contract.json"),
        package_fixtures::CONTRACT_BYTES,
    )
    .unwrap();
    let product = env!("CARGO_MANIFEST_DIR").replace('\\', "\\\\");
    fs::write(fixture.join("Cargo.toml"), format!(
        "[package]\nname=\"embedding-control\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[dependencies]\nosslscope={{path=\"{product}\"}}\n"
    )).unwrap();
    fs::write(fixture.join("src/main.rs"),
        "fn main() { let bytes = osslscope::package::embedded::contract_bytes().expect(\"embedded contract\"); println!(\"{}\", bytes.len()); }\n"
    ).unwrap();
    let target_base = std::env::var_os("OSSL_PACKAGE_EMBED_TEST_TARGET")
        .map(PathBuf::from)
        .unwrap_or_else(|| base.join("embedding-target"));
    let target = target_base.join(&nonce);
    let run = |args: &[&str], descriptor: bool| {
        let mut command = Command::new("cargo");
        command
            .args(args)
            .current_dir(&fixture)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_BUILD_JOBS", "2")
            .env("CARGO_TARGET_DIR", &target);
        if descriptor {
            command.env("OSSL_PACKAGE_RECORD_DIR", &records);
        } else {
            command.env_remove("OSSL_PACKAGE_RECORD_DIR");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "cargo {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["+1.88.0", "generate-lockfile", "--offline"], false);
    run(&["+1.88.0", "build", "--locked", "--offline"], true);
    let host = target.join("debug/embedding-control");
    exactly_one_contract_section(&host).unwrap();
    let dump = fixture.join("extracted-contract.bin");
    let output = Command::new("objcopy")
        .arg(format!(
            "--dump-section=.osslscope.bundle_contract={}",
            dump.display()
        ))
        .arg(&host)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&dump).unwrap(),
        package_fixtures::CONTRACT_BYTES.as_bytes()
    );
    // A second same-named section must be rejected by the exact-one section control.
    let duplicate = fixture.join("duplicate-host");
    with_duplicate_section_header(&host, &duplicate);
    assert!(exactly_one_contract_section(&duplicate).is_err());
    assert!(exactly_one_contract_section(&std::env::current_exe().unwrap()).is_err());
    // A changed input digest must fail the build hook before a host is emitted.
    let bad_records = fixture.join("bad-records");
    fs::create_dir_all(&bad_records).unwrap();
    fs::write(
        bad_records.join("build-inputs.json"),
        INPUT_BYTES.replace("fixture-1", "fixture-2"),
    )
    .unwrap();
    fs::write(
        bad_records.join("bundle-contract.json"),
        package_fixtures::CONTRACT_BYTES,
    )
    .unwrap();
    let output = Command::new("cargo")
        .args(["+1.88.0", "build", "--locked", "--offline"])
        .current_dir(&fixture)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_BUILD_JOBS", "2")
        .env("CARGO_TARGET_DIR", target_base.join(format!("{nonce}-bad")))
        .env("OSSL_PACKAGE_RECORD_DIR", bad_records)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "inconsistent input digest accepted"
    );
    let incomplete = fixture.join("incomplete-records");
    fs::create_dir_all(&incomplete).unwrap();
    fs::write(incomplete.join("build-inputs.json"), INPUT_BYTES).unwrap();
    let output = Command::new("cargo")
        .args(["+1.88.0", "build", "--locked", "--offline"])
        .current_dir(&fixture)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_BUILD_JOBS", "2")
        .env(
            "CARGO_TARGET_DIR",
            target_base.join(format!("{nonce}-incomplete")),
        )
        .env("OSSL_PACKAGE_RECORD_DIR", incomplete)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "incomplete descriptor directory accepted"
    );
}
