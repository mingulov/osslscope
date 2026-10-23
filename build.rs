// SPDX-License-Identifier: GPL-3.0-or-later
#[allow(dead_code)]
mod package {
    pub mod error {
        include!("src/package/error.rs");
    }
    pub mod records {
        include!("src/package/records.rs");
    }
}
use package::records::{
    BuildInputs, BundleContract, PackageRecord, canonical_bytes, parse_canonical, sha256,
};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/package/error.rs");
    println!("cargo:rerun-if-changed=src/package/records.rs");
    println!("cargo:rerun-if-env-changed=OSSL_PACKAGE_RECORD_DIR");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let generated = out.join("osslscope_embedded_contract.rs");
    let Some(directory) = env::var_os("OSSL_PACKAGE_RECORD_DIR") else {
        fs::write(
            generated,
            "pub fn contract_bytes() -> Option<&'static [u8]> { None }\n",
        )
        .expect("write descriptor-free hook");
        return;
    };
    let directory = PathBuf::from(directory);
    let input_path = directory.join("build-inputs.json");
    let contract_path = directory.join("bundle-contract.json");
    println!("cargo:rerun-if-changed={}", input_path.display());
    println!("cargo:rerun-if-changed={}", contract_path.display());
    let input_bytes = fs::read(&input_path).expect("required canonical build-inputs.json");
    let contract_bytes = fs::read(&contract_path).expect("required canonical bundle-contract.json");
    let inputs: BuildInputs = parse_canonical(&input_bytes).expect("canonical build input");
    let contract: BundleContract =
        parse_canonical(&contract_bytes).expect("canonical bundle contract");
    let target = env::var("TARGET").expect("TARGET");
    assert_eq!(
        inputs.host_profile.target, target,
        "build input target mismatch"
    );
    assert_eq!(
        contract.host_profile.target, target,
        "contract target mismatch"
    );
    assert_eq!(
        contract.input_id,
        sha256(&input_bytes),
        "input digest mismatch"
    );
    assert_eq!(contract.source, inputs.source, "source mismatch");
    assert_eq!(
        contract.product_version, inputs.product_version,
        "version mismatch"
    );
    assert_eq!(
        inputs.product_version,
        env!("CARGO_PKG_VERSION"),
        "root Cargo package version mismatch"
    );
    assert_eq!(
        contract.host_profile, inputs.host_profile,
        "host profile mismatch"
    );
    assert_eq!(
        contract_bytes,
        canonical_bytes(&contract),
        "contract changed during parse"
    );
    inputs.validate().expect("valid build inputs");
    fs::write(out.join("bundle-contract.bin"), &contract_bytes).expect("write embedded bytes");
    fs::write(generated, format!(
        "#[used]\n#[unsafe(link_section = \".osslscope.bundle_contract\")]\nstatic BUNDLE_CONTRACT: [u8; {}] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bundle-contract.bin\"));\npub fn contract_bytes() -> Option<&'static [u8]> {{ Some(&BUNDLE_CONTRACT) }}\n",
        contract_bytes.len()
    )).expect("write embedding module");
}
