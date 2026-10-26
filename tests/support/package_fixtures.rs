// SPDX-License-Identifier: GPL-3.0-or-later
// Independent nonsecret, literal canonical fixtures. Python standard-library
// JSON and SHA-256 produced these bytes before the candidate Rust codec.
use osslscope::package::records::*;
use serde_json::json;
use std::sync::Arc;
pub const INPUT_BYTES: &str = r#"{"argv":["cargo","build","--locked"],"environment":[{"name":"CARGO_NET_OFFLINE","value":"true"}],"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"jobs":2,"locks":{"bpf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","host_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"offline_inventory_sha256":"8888888888888888888888888888888888888888888888888888888888888888","package_epoch":0,"package_revision":1,"product_version":"0.1.0","recipe":{"config_sha256":"7777777777777777777777777777777777777777777777777777777777777777","recipe_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},"schema":"osslscope-build-inputs-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"source_epoch":1,"tools":{"bpf":{"name":"clang","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"builder":{"name":"builder","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"components":[{"name":"cargo","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},{"name":"rust-std","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}],"host":{"name":"rust","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"linker":{"name":"ld","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"llvm":{"name":"llvm","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}}}
"#;
pub const CONTRACT_BYTES: &str = r#"{"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"input_id":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d","loader_contract_sha256":"941f74f673bbeeee3d21de716c4646cd5ab17a44f021f97c5c600b846db05627","product_version":"0.1.0","roles":[{"bytes":11,"file":"osslscope-harvest","role":"harvest","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"bytes":12,"file":"osslscope-count","role":"count","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"bytes":13,"file":"osslscope-members","role":"members","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"schema":"osslscope-bundle-contract-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"wire_abi":2}
"#;
pub const COUNT_POLICY_BYTES: &str = r#"{"executable_sections":[".text","uprobe"],"prepared":{"map_count":7,"maps":[{"flags":0,"key_size":8,"map_type":5,"max_entries":8192,"name":"COUNTS","value_size":24},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"ADMITTED","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":16,"name":"LATC","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"GEN","value_size":4},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"TARGET","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":2,"name":"WINDOW","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"DROPFAIL","value_size":8}],"program":{"callbacks_allowed":false,"first_subprogram":{"insn_off":0,"name":"count_entry"},"instruction_alignment_bytes":8,"instructions_nonempty":true,"map_fixups":{"count_map_membership":true,"exact_ld_imm64_site":true},"name":"count_entry","pseudo_func_allowed":false,"return":false,"section":"uprobe","tail_call_helper_12_allowed":false},"program_count":1},"role":"count","schema":"osslscope-loader-policy-inventory-v1-fixture","uprobe_root":{"exactly":1,"name":"count_entry","nonempty":true}}
"#;
pub const COUNT_POLICY_SHA256: &str =
    "941f74f673bbeeee3d21de716c4646cd5ab17a44f021f97c5c600b846db05627";
pub const INDEX_BYTES: &str = r#"{"builder_assets":[{"bytes":17,"path":"builder.tar.zst","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"dependency_assets":[{"bytes":17,"path":"dependencies.tar.zst","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],"package_epoch":0,"package_revision":1,"product_version":"0.1.0","profiles":[{"abi_profile":"linux-x86_64-gnu","bundle_id":"11804848c4ca8421f3eed0356ca1da299fd3db1441fad31732a73e30eb61bb37","payload_id":"13b361c892d10fad6fdd93c53340882cdc46450ad5c6f6d793999f6f04c0ee69"}],"provenance_assets":[{"bytes":17,"path":"provenance.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}],"qualification_receipts":[{"bytes":17,"path":"qualification.json","sha256":"3333333333333333333333333333333333333333333333333333333333333333"}],"reproducibility_assets":[{"bytes":17,"path":"reproduction.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222"}],"sbom_assets":[{"bytes":17,"path":"sbom.json","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"schema":"osslscope-release-index-v1","signed_packages":[{"bytes":17,"path":"osslscope-signed.deb","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"signing_identity":"fixture-only-owner-identity","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"source_assets":[{"bytes":17,"path":"source.tar.zst","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"source_epoch":1,"support_matrix":{"bytes":17,"path":"support-matrix.json","sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"unsigned_packages":[{"bytes":17,"path":"osslscope-unsigned.deb","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"verification_instructions":"fixture-only-verification"}
"#;
pub const PAYLOAD_BYTES: &str = r#"{"build_inputs":{"bytes":1806,"path":"build-inputs.json","sha256":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"},"bundle_id":"11804848c4ca8421f3eed0356ca1da299fd3db1441fad31732a73e30eb61bb37","contract":{"bytes":925,"path":"bundle-contract.json","sha256":"11804848c4ca8421f3eed0356ca1da299fd3db1441fad31732a73e30eb61bb37"},"docs":[{"bytes":5,"path":"share/doc/osslscope/README","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"host":{"bytes":123,"elf_build_id":null,"elf_machine":62,"path":"bin/osslscope","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"input_id":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d","install":{"directory_mode":493,"executable_mode":493,"file_mode":420,"group":"root","owner":"root"},"licenses":[{"bytes":5,"path":"share/licenses/osslscope/LICENSE","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"locks":{"bpf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","host_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"notices":[{"bytes":5,"path":"share/doc/osslscope/NOTICE","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}],"product_version":"0.1.0","recipe":{"config_sha256":"7777777777777777777777777777777777777777777777777777777777777777","recipe_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},"roles":[{"bytes":11,"file":"osslscope-harvest","role":"harvest","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"bytes":12,"file":"osslscope-count","role":"count","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"bytes":13,"file":"osslscope-members","role":"members","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"sbom":{"bytes":5,"path":"share/doc/osslscope/SBOM.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"schema":"osslscope-payload-manifest-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"tools":{"bpf":{"name":"clang","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"builder":{"name":"builder","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"components":[{"name":"cargo","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},{"name":"rust-std","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}],"host":{"name":"rust","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"linker":{"name":"ld","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"llvm":{"name":"llvm","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}}}
"#;

#[derive(Clone)]
pub struct RecordFixture {
    pub inputs: BuildInputs,
    pub contract: BundleContract,
    pub payload: PayloadManifest,
    pub expected_input_bytes: Vec<u8>,
    pub expected_contract_bytes: Vec<u8>,
}
pub fn records_fixture() -> RecordFixture {
    RecordFixture {
        inputs: parse_canonical(INPUT_BYTES.as_bytes()).unwrap(),
        contract: parse_canonical(CONTRACT_BYTES.as_bytes()).unwrap(),
        payload: parse_canonical(PAYLOAD_BYTES.as_bytes()).unwrap(),
        expected_input_bytes: INPUT_BYTES.as_bytes().to_vec(),
        expected_contract_bytes: CONTRACT_BYTES.as_bytes().to_vec(),
    }
}
impl RecordFixture {
    pub fn verify(&self) -> Result<AdmittedMetadata, PackageError> {
        verify_metadata(
            &self.contract,
            &self.payload,
            Arc::from(canonical_bytes(&self.inputs)),
        )
    }
    pub fn payload_only_mutation(mut self, field: &str) -> Self {
        let mut value = serde_json::to_value(&self.payload).unwrap();
        match field {
            "source" => {
                value["source"]["revision"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            }
            "product_version" => value["product_version"] = json!("0.2.0"),
            "host_profile" => value["host_profile"]["abi_profile"] = json!("linux-x86_64-musl"),
            "locks" => {
                value["locks"]["host_sha256"] =
                    json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            }
            "recipe" => {
                value["recipe"]["config_sha256"] =
                    json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            }
            "tools" => value["tools"]["host"]["version"] = json!("fixture-2"),
            _ => panic!("unsupported field"),
        }
        self.payload = serde_json::from_value(value).unwrap();
        self
    }
    pub fn consistent_inputs_and_payload_mutation(mut self) -> Self {
        self.inputs.product_version = "0.2.0".to_string();
        self.payload.product_version = "0.2.0".to_string();
        self
    }
    pub fn duplicate_input_member(&self, path: &str) -> Vec<u8> {
        assert_eq!(path, "/tools/host/version");
        INPUT_BYTES
            .replacen(
                "\"host\":{\"name\":\"rust\",\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"version\":\"fixture-1\"}",
                "\"host\":{\"name\":\"rust\",\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"version\":\"fixture-1\",\"version\":\"fixture-1\"}",
                1,
            )
            .into_bytes()
    }
}

fn literal_maps_v1(role: Role) -> Vec<(&'static str, [u32; 5])> {
    match role {
        Role::Identity => panic!("v1 fixture excludes identity"),
        Role::Count => vec![
            ("COUNTS", [5, 8, 24, 8192, 0]),
            ("ADMITTED", [6, 4, 8, 1, 0]),
            ("LATC", [6, 4, 8, 16, 0]),
            ("GEN", [2, 4, 4, 1, 0]),
            ("TARGET", [2, 4, 8, 1, 0]),
            ("WINDOW", [2, 4, 8, 2, 0]),
            ("DROPFAIL", [6, 4, 8, 1, 0]),
        ],
        Role::Harvest => vec![
            ("EVENTS", [27, 0, 0, 2097152, 0]),
            ("PENDING_INIT", [1, 8, 8, 1024, 0]),
            ("PENDING_QUERY", [1, 8, 16, 1024, 0]),
            ("TERMD", [1, 8, 8, 1024, 0]),
            ("GEN", [1, 8, 8, 1024, 0]),
            ("LOSS", [5, 4, 8, 32, 0]),
            ("QUERY_NEXT", [1, 16, 8, 4096, 0]),
            ("TRUNC", [5, 4, 8, 64, 0]),
            ("CALLS", [5, 4, 8, 64, 0]),
            ("TRIP", [5, 8, 8, 128, 0]),
            ("LGCALLS", [5, 4, 8, 64, 0]),
            ("ALG_CLASS", [1, 8, 42, 1024, 0]),
            ("TRIP_CLASS", [1, 8, 22, 64, 0]),
            ("JUMPS", [3, 4, 4, 8, 0]),
        ],
        Role::Members => vec![
            ("EVENTS", [27, 0, 0, 16777216, 0]),
            ("BUCKET", [1, 4, 8, 4096, 0]),
            ("GEN", [1, 8, 8, 1024, 0]),
            ("LOSS", [5, 4, 8, 32, 0]),
            ("TRUNC", [5, 4, 8, 64, 0]),
            ("CALLS", [5, 4, 8, 64, 0]),
            ("ALG_CLASS", [1, 8, 42, 1024, 0]),
            ("SCAN", [9, 4, 40, 1024, 0]),
            ("SEQ", [1, 4, 8, 4096, 0]),
            ("BIRTH", [1, 4, 2, 4096, 0]),
            ("RCOUNT", [1, 4, 8, 4096, 0]),
            ("T_CACHE", [1, 8, 16, 1024, 0]),
            ("CTRL", [2, 4, 24, 1, 0]),
            ("ATTEMPT", [6, 4, 8, 1, 0]),
            ("TRUNC_SEQ", [5, 4, 8, 64, 0]),
        ],
    }
}

/// Independent HOST shape fixture, never a production identity artifact/proof.
pub fn identity_v2_bpf(role: Role) -> Vec<u8> {
    let mut maps = if role == Role::Identity {
        Vec::new()
    } else {
        literal_maps_v1(role)
    };
    maps.extend([
        ("ID_CONTROL", [2, 4, 128, 1, 1024]),
        ("ID_GROUP", [1, 16, 64, 2, 0]),
        ("ID_CLAIM", [1, 8, 32, 8192, 0]),
        ("ID_TASK", [1, 8, 64, 8192, 0]),
        ("ID_IMAGE", [1, 8, 64, 8192, 0]),
        ("ID_AUDIT", [2, 4, 64, 1, 0]),
    ]);
    let mut programs: Vec<(String, &str)> = match role {
        Role::Identity => vec![
            ("identity_newtask".into(), "raw_tracepoint/task_newtask"),
            ("identity_exit".into(), "raw_tracepoint/sched_process_exit"),
            ("identity_sys_enter".into(), "raw_tracepoint/sys_enter"),
            ("identity_exec".into(), "raw_tracepoint/sched_process_exec"),
        ],
        Role::Count => vec![("count_entry".into(), "uprobe")],
        Role::Harvest => vec![
            ("init_entry".into(), "uprobe"),
            ("init_return".into(), "uretprobe"),
            ("query_entry".into(), "uprobe"),
            ("query_return".into(), "uretprobe"),
            ("trip_count".into(), "uprobe"),
            ("trip_str0".into(), "uprobe"),
            ("trip_str1".into(), "uprobe"),
        ],
        Role::Members => vec![("member_entry".into(), "uprobe")],
    };
    if role == Role::Harvest {
        for i in 0..8 {
            programs.push((format!("c{i}"), "uretprobe"));
        }
    }
    if role == Role::Members {
        for i in 0..512 {
            programs.push((format!("member_{i:03}"), "uretprobe"));
        }
    }
    fn put(b: &mut [u8], at: usize, value: u64, width: usize) {
        b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    let mut strings = vec![0];
    let mut symbols = vec![0; 24];
    let mut defs = Vec::new();
    for (name, dims) in maps {
        let off = strings.len();
        strings.extend(name.as_bytes());
        strings.push(0);
        let at = symbols.len();
        symbols.resize(at + 24, 0);
        put(&mut symbols, at, off as u64, 4);
        symbols[at + 4] = 0x11;
        put(&mut symbols, at + 6, 3, 2);
        put(&mut symbols, at + 8, defs.len() as u64, 8);
        put(&mut symbols, at + 16, 28, 8);
        for d in dims.into_iter().chain([0, 0]) {
            defs.extend(d.to_le_bytes());
        }
    }
    let mut sections: Vec<(&str, u32, u64, Vec<u8>, u32, u32, u64)> = vec![
        (".strtab", 3, 0, Vec::new(), 0, 0, 0),
        (".symtab", 2, 0, Vec::new(), 1, 1, 24),
        ("maps", 1, 0, defs, 0, 0, 0),
    ];
    for (name, section) in programs {
        let idx = if let Some(idx) = sections.iter().position(|s| s.0 == section) {
            idx
        } else {
            sections.push((section, 1, 6, Vec::new(), 0, 0, 0));
            sections.len() - 1
        };
        let offset = sections[idx].3.len();
        sections[idx].3.extend([0x95, 0, 0, 0, 0, 0, 0, 0]);
        let off = strings.len();
        strings.extend(name.as_bytes());
        strings.push(0);
        let at = symbols.len();
        symbols.resize(at + 24, 0);
        put(&mut symbols, at, off as u64, 4);
        symbols[at + 4] = 0x12;
        put(&mut symbols, at + 6, (idx + 1) as u64, 2);
        put(&mut symbols, at + 8, offset as u64, 8);
        put(&mut symbols, at + 16, 8, 8);
    }
    sections[0].3 = strings;
    sections[1].3 = symbols;
    let mut names = vec![0];
    let mut offsets = Vec::new();
    for s in &sections {
        offsets.push(names.len());
        names.extend(s.0.as_bytes());
        names.push(0);
    }
    let shname = names.len();
    names.extend(b".shstrtab\0");
    offsets.push(shname);
    sections.push((".shstrtab", 3, 0, names, 0, 0, 0));
    let mut elf = vec![0; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put(&mut elf, 16, 1, 2);
    put(&mut elf, 18, 247, 2);
    put(&mut elf, 20, 1, 4);
    put(&mut elf, 52, 64, 2);
    put(&mut elf, 58, 64, 2);
    put(&mut elf, 60, (sections.len() + 1) as u64, 2);
    put(&mut elf, 62, sections.len() as u64, 2);
    let mut headers = vec![0; 64];
    for (i, s) in sections.iter().enumerate() {
        let offset = elf.len();
        elf.extend(&s.3);
        let at = headers.len();
        headers.resize(at + 64, 0);
        put(&mut headers, at, offsets[i] as u64, 4);
        put(&mut headers, at + 4, s.1 as u64, 4);
        put(&mut headers, at + 8, s.2, 8);
        put(&mut headers, at + 24, offset as u64, 8);
        put(&mut headers, at + 32, s.3.len() as u64, 8);
        put(&mut headers, at + 40, s.4 as u64, 4);
        put(&mut headers, at + 44, s.5 as u64, 4);
        put(&mut headers, at + 56, s.6, 8);
    }
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let offset = elf.len();
    put(&mut elf, 40, offset as u64, 8);
    elf.extend(headers);
    elf
}
pub fn identity_v2_inputs() -> BuildInputsV2 {
    let mut value: serde_json::Value = serde_json::from_str(INPUT_BYTES).unwrap();
    value["schema"] = serde_json::json!("osslscope-build-inputs-v2");
    value["identity_abi"] = serde_json::json!(4);
    value["custody_protocol"] = serde_json::json!(1);
    value["identity_profile_sha256"] = serde_json::json!("77".repeat(32));
    serde_json::from_value(value).unwrap()
}
