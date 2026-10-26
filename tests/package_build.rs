// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "support/package_fixtures.rs"]
mod fixtures;
use osslscope::package::build::extract_host_contract;
use osslscope::package::records::{BundleContract, parse_canonical};
// Literal contract fixture is independent of the ELF parser and policy generator.
const CONTRACT: &str = concat!(
    r#"{"host_profile":{"abi_floor":"fixture","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"input_id":"1111111111111111111111111111111111111111111111111111111111111111","loader_contract_sha256":"3333333333333333333333333333333333333333333333333333333333333333","product_version":"0.1.0","roles":[{"bytes":1,"file":"osslscope-harvest","role":"harvest","sha256":"4444444444444444444444444444444444444444444444444444444444444444"},{"bytes":2,"file":"osslscope-count","role":"count","sha256":"5555555555555555555555555555555555555555555555555555555555555555"},{"bytes":3,"file":"osslscope-members","role":"members","sha256":"6666666666666666666666666666666666666666666666666666666666666666"}],"schema":"osslscope-bundle-contract-v1","source":{"inventory_sha256":"2222222222222222222222222222222222222222222222222222222222222222","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"wire_abi":2}"#,
    "\n"
);
fn put(b: &mut [u8], at: usize, n: u64, width: usize) {
    b[at..at + width].copy_from_slice(&n.to_le_bytes()[..width]);
}
fn host(name: &str, data: &[u8], duplicate: bool) -> Vec<u8> {
    let names = format!("\0.shstrtab\0{name}\0");
    let n = if duplicate { 4 } else { 3 };
    let mut b = vec![0; 120];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put(&mut b, 16, 3, 2);
    put(&mut b, 18, 62, 2);
    put(&mut b, 20, 1, 4);
    put(&mut b, 32, 64, 8);
    put(&mut b, 52, 64, 2);
    put(&mut b, 54, 56, 2);
    put(&mut b, 56, 1, 2);
    put(&mut b, 58, 64, 2);
    put(&mut b, 60, n, 2);
    put(&mut b, 62, 1, 2);
    let strings = b.len();
    b.extend(names.as_bytes());
    let body = b.len();
    b.extend(data);
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let sh = b.len();
    put(&mut b, 40, sh as u64, 8);
    b.resize(sh + n as usize * 64, 0);
    put(&mut b, sh + 64, 1, 4);
    put(&mut b, sh + 68, 3, 4);
    put(&mut b, sh + 88, strings as u64, 8);
    put(&mut b, sh + 96, names.len() as u64, 8);
    for i in 2..n as usize {
        let at = sh + i * 64;
        put(&mut b, at, 11, 4);
        put(&mut b, at + 4, 1, 4);
        put(&mut b, at + 8, 2, 8);
        put(&mut b, at + 16, 0x400000 + body as u64, 8);
        put(&mut b, at + 24, body as u64, 8);
        put(&mut b, at + 32, data.len() as u64, 8);
    }
    let len = b.len() as u64;
    put(&mut b, 64, 1, 4);
    put(&mut b, 68, 5, 4);
    put(&mut b, 80, 0x400000, 8);
    put(&mut b, 96, len, 8);
    put(&mut b, 104, len, 8);
    put(&mut b, 112, 0x1000, 8);
    b
}
#[test]
fn public_extraction_unique_canonical_contract() {
    let b = host(".osslscope.bundle_contract", CONTRACT.as_bytes(), false);
    assert_eq!(
        extract_host_contract(&b).unwrap(),
        osslscope::package::records::AdmittedContract::V1(
            parse_canonical::<BundleContract>(CONTRACT.as_bytes()).unwrap()
        )
    );
}
#[test]
fn public_extraction_missing_duplicate_overlapping_truncated_noncanonical_unrelated() {
    let b = host(".osslscope.bundle_contract", CONTRACT.as_bytes(), false);
    for bad in [
        host(".unrelated", CONTRACT.as_bytes(), false),
        host(".osslscope.bundle_contract", CONTRACT.as_bytes(), true),
        host(
            ".osslscope.bundle_contract",
            CONTRACT.trim_end().as_bytes(),
            false,
        ),
        host(".osslscope.bundle_contract", b"{}\n", false),
        b[..b.len() - 1].to_vec(),
    ] {
        assert!(extract_host_contract(&bad).is_err());
    }
    let mut overlap = b.clone();
    let sh = u64::from_le_bytes(b[40..48].try_into().unwrap()) as usize;
    put(&mut overlap, sh + 128 + 24, 120, 8);
    assert!(extract_host_contract(&overlap).is_err());
    let mut range = b;
    put(&mut range, sh + 128 + 32, u64::MAX, 8);
    assert!(extract_host_contract(&range).is_err());
}

#[test]
fn public_extraction_from_independent_host_compile_fixture() {
    let base = std::path::PathBuf::from(std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").unwrap());
    let root = base.join(format!(
        "host-extraction-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("contract.bin"), CONTRACT).unwrap();
    let program = format!(
        "#[used]\n#[unsafe(link_section = \".osslscope.bundle_contract\")]\nstatic CONTRACT: [u8; {}] = *include_bytes!(\"contract.bin\");\nfn main() {{ std::hint::black_box(&CONTRACT); }}\n",
        CONTRACT.len()
    );
    std::fs::write(root.join("fixture.rs"), program).unwrap();
    let output = std::process::Command::new("rustc")
        .args(["--edition=2024", "--crate-name", "host_extraction_fixture"])
        .arg(root.join("fixture.rs"))
        .arg("-o")
        .arg(root.join("fixture"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(root.join("fixture")).unwrap();
    assert_eq!(
        extract_host_contract(&bytes).unwrap(),
        osslscope::package::records::AdmittedContract::V1(
            parse_canonical::<BundleContract>(CONTRACT.as_bytes()).unwrap()
        )
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_v2_graph_and_embedding() {
    let mut value: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
    value["schema"] = serde_json::json!("osslscope-bundle-contract-v2");
    value["identity_abi"] = serde_json::json!(4);
    value["custody_protocol"] = serde_json::json!(1);
    value["identity_profile_sha256"] = serde_json::json!("77".repeat(32));
    value["custody_host"] = serde_json::json!({"path":"osslscope-identity-custodian","bytes":1,"sha256":"88".repeat(32),"elf_machine":62,"elf_build_id":null});
    value["roles"].as_array_mut().unwrap().push(serde_json::json!({"role":"identity","file":"osslscope-identity","bytes":1,"sha256":"99".repeat(32)}));
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    let elf = host(".osslscope.bundle_contract", &bytes, false);
    assert!(
        extract_host_contract(&elf).is_ok(),
        "actual host extraction must admit canonical flat v2 contract"
    );
    assert!(extract_host_contract(&host(".osslscope.bundle_contract", &bytes, true)).is_err());
}

#[test]
fn identity_v2_real_dev_producer_refuses_missing_elf() {
    use osslscope::package::records::*;
    let base = std::path::PathBuf::from(std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").unwrap());
    let root = base.join(format!("v2-missing-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut inputs = fixtures::identity_v2_inputs();
    inputs.product_version = env!("CARGO_PKG_VERSION").into();
    std::fs::write(root.join("seed.json"), canonical_bytes(&inputs)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope-dev-admission"))
        .args(["contract", "--inputs"])
        .arg(root.join("seed.json"))
        .arg("--root")
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("development artifact"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("bundle-contract.json").exists());
    assert!(!root.join("dev-admission.json").exists());
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-dev.sh");
    for mode in ["--host-only", "--bpf-only"] {
        let out = std::process::Command::new("sh")
            .arg(&script)
            .arg(mode)
            .arg("--identity-v2-inputs")
            .arg(root.join("seed.json"))
            .arg("--identity-v2-dir")
            .arg(root.join("unused"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("full mode"));
        assert!(!root.join("unused").exists());
    }
    std::fs::remove_dir_all(root).unwrap();
}
