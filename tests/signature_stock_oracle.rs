//! Signature stock-workload oracle (RUNS in CI: no caps, no BPF, no observer).
//!
//! T2 S3a freezes the signature positive-control workload argv and its
//! pinned signature BEFORE the typed signature probes exist: the future
//! S3b native reuses [`SIGN_ARGV`] verbatim, so any argv drift fails
//! here first. Per the KDF precedent (pinned HKDF vector), the oracle
//! is a pinned RSA PKCS#1 v1.5 signature (deterministic) plus a verify
//! round-trip — no second implementation is vendored for S3a. The key
//! is a synthetic throwaway generated for this fixture, plainly not a
//! secret; it is embedded so the workload needs no keygen step.
//!
//! Graceful SKIP only when the stock binary is absent; a
//! present-but-broken binary FAILS (never silent).

use osslscope::provider_observation::signature_workload::{
    EXPECTED_SIGNATURE_HEX, SIGN_ARGV, SIGNATURE_INPUT_SHA256_HEX, SIGNATURE_VEHICLE_BIN,
    TEST_PRIVATE_KEY_PEM, TEST_PUBLIC_KEY_PEM, signature_workload_input,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

enum VehicleProbe {
    Ready,
    Absent,
    Broken(String),
}

fn probe_vehicle(path: &str) -> VehicleProbe {
    match Command::new(path).arg("version").output() {
        Ok(o) if o.status.success() => VehicleProbe::Ready,
        Ok(o) => VehicleProbe::Broken(format!("`{path} version` exits {o:?}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::path::Path::new(path).exists() {
                VehicleProbe::Broken(format!("`{path}` exists but cannot execute: {e}"))
            } else {
                VehicleProbe::Absent
            }
        }
        Err(e) => VehicleProbe::Broken(format!("`{path}` unusable: {e}")),
    }
}

/// Pure freeze checks run BEFORE any prerequisite: a missing binary
/// must not bypass the argv/input/key pins.
fn frozen_shape() {
    // `dgst -sha256 -sign <key> -out <sig> <input>`: paths appended by
    // the caller, so the const pins the flag words around them.
    assert_eq!(SIGN_ARGV, &["dgst", "-sha256", "-sign"]);
    let input = signature_workload_input();
    assert_eq!(input.len(), 256);
    let digest: [u8; 32] = Sha256::digest(&input).into();
    let input_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(input_hex, SIGNATURE_INPUT_SHA256_HEX);
    assert!(TEST_PRIVATE_KEY_PEM.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(TEST_PUBLIC_KEY_PEM.starts_with("-----BEGIN PUBLIC KEY-----"));
}

fn stage() -> Option<PathBuf> {
    match probe_vehicle(SIGNATURE_VEHICLE_BIN) {
        VehicleProbe::Absent => {
            eprintln!("SKIP signature stock oracle: no {SIGNATURE_VEHICLE_BIN}");
            return None;
        }
        VehicleProbe::Broken(msg) => panic!("stock binary broken: {msg}"),
        VehicleProbe::Ready => {}
    }
    let dir = std::env::temp_dir().join(format!("osslscope-sigoracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn signature_stock_workload_matches_pinned_signature() {
    frozen_shape();
    let Some(dir) = stage() else {
        return;
    };
    let input = signature_workload_input();
    let input_path = dir.join("input.bin");
    let key_path = dir.join("key.pem");
    let pub_path = dir.join("pub.pem");
    let sig_path = dir.join("sig.bin");
    std::fs::write(&input_path, &input).unwrap();
    std::fs::write(&key_path, TEST_PRIVATE_KEY_PEM).unwrap();
    std::fs::write(&pub_path, TEST_PUBLIC_KEY_PEM).unwrap();

    let sign = Command::new(SIGNATURE_VEHICLE_BIN)
        .args(SIGN_ARGV)
        .arg(&key_path)
        .args(["-out", sig_path.to_str().unwrap()])
        .arg(&input_path)
        .output()
        .expect("run stock signature workload");
    assert!(sign.status.success(), "stock sign must exit 0");
    let signature = std::fs::read(&sig_path).unwrap();
    let signature_hex: String = signature.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        signature_hex, EXPECTED_SIGNATURE_HEX,
        "stock `openssl dgst -sign` must match the pinned signature"
    );

    // Round-trip: the pinned signature must verify against the input.
    let verify = Command::new(SIGNATURE_VEHICLE_BIN)
        .args([
            "dgst",
            "-sha256",
            "-verify",
            pub_path.to_str().unwrap(),
            "-signature",
            sig_path.to_str().unwrap(),
        ])
        .arg(&input_path)
        .output()
        .expect("run stock signature verify");
    assert!(verify.status.success(), "stock verify must exit 0");
    let out = String::from_utf8(verify.stdout).unwrap();
    assert!(out.contains("Verified OK"), "verify must report OK: {out}");
    let _ = std::fs::remove_dir_all(&dir);
}
