// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent nonsecret, literal canonical fixtures. Python standard-library
//! JSON and SHA-256 produced these bytes before the candidate Rust codec.
use osslscope::package::records::*;
use serde_json::json;
use std::sync::Arc;
pub const INPUT_BYTES: &str = r#"{"argv":["cargo","build","--locked"],"environment":[{"name":"CARGO_NET_OFFLINE","value":"true"}],"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"jobs":2,"locks":{"bpf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","host_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"offline_inventory_sha256":"8888888888888888888888888888888888888888888888888888888888888888","package_epoch":0,"package_revision":1,"product_version":"0.1.0","recipe":{"config_sha256":"7777777777777777777777777777777777777777777777777777777777777777","recipe_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},"schema":"osslscope-build-inputs-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"source_epoch":1,"tools":{"bpf":{"name":"clang","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"builder":{"name":"builder","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"components":[{"name":"cargo","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},{"name":"rust-std","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}],"host":{"name":"rust","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"linker":{"name":"ld","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"llvm":{"name":"llvm","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}}}
"#;
pub const CONTRACT_BYTES: &str = r#"{"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"input_id":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d","loader_contract_sha256":"941f74f673bbeeee3d21de716c4646cd5ab17a44f021f97c5c600b846db05627","product_version":"0.1.0","roles":[{"bytes":11,"file":"osslscope-harvest","role":"harvest","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"bytes":12,"file":"osslscope-count","role":"count","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"bytes":13,"file":"osslscope-members","role":"members","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"schema":"osslscope-bundle-contract-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"wire_abi":1}
"#;
pub const COUNT_POLICY_BYTES: &str = r#"{"executable_sections":[".text","uprobe"],"prepared":{"map_count":7,"maps":[{"flags":0,"key_size":8,"map_type":5,"max_entries":8192,"name":"COUNTS","value_size":24},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"ADMITTED","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":16,"name":"LATC","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"GEN","value_size":4},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"TARGET","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":2,"name":"WINDOW","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"DROPFAIL","value_size":8}],"program":{"callbacks_allowed":false,"first_subprogram":{"insn_off":0,"name":"count_entry"},"instruction_alignment_bytes":8,"instructions_nonempty":true,"map_fixups":{"count_map_membership":true,"exact_ld_imm64_site":true},"name":"count_entry","pseudo_func_allowed":false,"return":false,"section":"uprobe","tail_call_helper_12_allowed":false},"program_count":1},"role":"count","schema":"osslscope-loader-policy-inventory-v1-fixture","uprobe_root":{"exactly":1,"name":"count_entry","nonempty":true}}
"#;
pub const COUNT_POLICY_SHA256: &str =
    "941f74f673bbeeee3d21de716c4646cd5ab17a44f021f97c5c600b846db05627";
pub const INDEX_BYTES: &str = r#"{"builder_assets":[{"bytes":17,"path":"builder.tar.zst","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"dependency_assets":[{"bytes":17,"path":"dependencies.tar.zst","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],"package_epoch":0,"package_revision":1,"product_version":"0.1.0","profiles":[{"abi_profile":"linux-x86_64-gnu","bundle_id":"a1e5b6e4e9f4157b39f8663c81b57645097ccbb3f066be7127d54f46cc00be8a","payload_id":"5e164579cb9556525d5aee857a966a27fbac21e1156423ce162a888a4eece61c"}],"provenance_assets":[{"bytes":17,"path":"provenance.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}],"qualification_receipts":[{"bytes":17,"path":"qualification.json","sha256":"3333333333333333333333333333333333333333333333333333333333333333"}],"reproducibility_assets":[{"bytes":17,"path":"reproduction.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222"}],"sbom_assets":[{"bytes":17,"path":"sbom.json","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"schema":"osslscope-release-index-v1","signed_packages":[{"bytes":17,"path":"osslscope-signed.deb","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"signing_identity":"fixture-only-owner-identity","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"source_assets":[{"bytes":17,"path":"source.tar.zst","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"source_epoch":1,"support_matrix":{"bytes":17,"path":"support-matrix.json","sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"unsigned_packages":[{"bytes":17,"path":"osslscope-unsigned.deb","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"verification_instructions":"fixture-only-verification"}
"#;
pub const PAYLOAD_BYTES: &str = r#"{"build_inputs":{"bytes":1806,"path":"build-inputs.json","sha256":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"},"bundle_id":"a1e5b6e4e9f4157b39f8663c81b57645097ccbb3f066be7127d54f46cc00be8a","contract":{"bytes":925,"path":"bundle-contract.json","sha256":"a1e5b6e4e9f4157b39f8663c81b57645097ccbb3f066be7127d54f46cc00be8a"},"docs":[{"bytes":5,"path":"share/doc/osslscope/README","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"host":{"bytes":123,"elf_build_id":null,"elf_machine":62,"path":"bin/osslscope","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"input_id":"164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d","install":{"directory_mode":493,"executable_mode":493,"file_mode":420,"group":"root","owner":"root"},"licenses":[{"bytes":5,"path":"share/licenses/osslscope/LICENSE","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"locks":{"bpf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","host_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"notices":[{"bytes":5,"path":"share/doc/osslscope/NOTICE","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}],"product_version":"0.1.0","recipe":{"config_sha256":"7777777777777777777777777777777777777777777777777777777777777777","recipe_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},"roles":[{"bytes":11,"file":"osslscope-harvest","role":"harvest","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"bytes":12,"file":"osslscope-count","role":"count","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"bytes":13,"file":"osslscope-members","role":"members","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"sbom":{"bytes":5,"path":"share/doc/osslscope/SBOM.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"schema":"osslscope-payload-manifest-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"tools":{"bpf":{"name":"clang","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"builder":{"name":"builder","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"components":[{"name":"cargo","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},{"name":"rust-std","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}],"host":{"name":"rust","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"linker":{"name":"ld","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"llvm":{"name":"llvm","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}}}
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
                "\"version\":\"fixture-1\"",
                "\"version\":\"fixture-1\",\"version\":\"fixture-1\"",
                1,
            )
            .into_bytes()
    }
}
