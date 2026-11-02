//! Cipher stock-workload oracle (RUNS in CI: no caps, no BPF, no observer).
//!
//! T2 S2a freezes the cipher positive-control workload argv and its
//! pinned ciphertext BEFORE the typed cipher probes exist: the future
//! S2b native reuses [`CIPHER_ENC_ARGV`] verbatim, so any argv drift
//! fails here first. Per the KDF precedent (pinned HKDF vector), the
//! oracle is a pinned ciphertext plus a decrypt round-trip — no second
//! AES implementation is vendored for S2a. The key/IV are synthetic
//! counters, plainly not secrets.
//!
//! Graceful SKIP only when the stock binary is absent; a
//! present-but-broken binary FAILS (never silent).

use osslscope::provider_observation::cipher_workload::{
    CIPHER_DEC_ARGV, CIPHER_ENC_ARGV, CIPHER_IV_HEX, CIPHER_KEY_HEX, CIPHER_VEHICLE_BIN,
    EXPECTED_CIPHERTEXT_HEX, cipher_workload_input,
};
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
/// must not bypass the argv/input pins.
fn frozen_shape() {
    assert_eq!(
        CIPHER_ENC_ARGV,
        &[
            "enc",
            "-aes-256-cbc",
            "-K",
            CIPHER_KEY_HEX,
            "-iv",
            CIPHER_IV_HEX,
            "-in",
        ]
    );
    assert_eq!(
        CIPHER_DEC_ARGV,
        &[
            "enc",
            "-d",
            "-aes-256-cbc",
            "-K",
            CIPHER_KEY_HEX,
            "-iv",
            CIPHER_IV_HEX,
            "-in",
        ]
    );
    assert_eq!(cipher_workload_input().len(), 256);
}

fn stage() -> Option<PathBuf> {
    match probe_vehicle(CIPHER_VEHICLE_BIN) {
        VehicleProbe::Absent => {
            eprintln!("SKIP cipher stock oracle: no {CIPHER_VEHICLE_BIN}");
            return None;
        }
        VehicleProbe::Broken(msg) => panic!("stock binary broken: {msg}"),
        VehicleProbe::Ready => {}
    }
    let dir = std::env::temp_dir().join(format!("osslscope-cipheroracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn cipher_stock_workload_matches_pinned_ciphertext() {
    frozen_shape();
    let Some(dir) = stage() else {
        return;
    };
    let input = cipher_workload_input();
    let input_path = dir.join("input.bin");
    let enc_path = dir.join("enc.bin");
    let dec_path = dir.join("dec.bin");
    std::fs::write(&input_path, &input).unwrap();

    let enc = Command::new(CIPHER_VEHICLE_BIN)
        .args(CIPHER_ENC_ARGV)
        .arg(&input_path)
        .args(["-out", enc_path.to_str().unwrap()])
        .output()
        .expect("run stock cipher workload");
    assert!(enc.status.success(), "stock enc must exit 0");
    let ciphertext = std::fs::read(&enc_path).unwrap();
    let ciphertext_hex: String = ciphertext.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        ciphertext_hex, EXPECTED_CIPHERTEXT_HEX,
        "stock `openssl enc` must match the pinned ciphertext"
    );

    // Round-trip: decrypting the pinned ciphertext must recover the input.
    let dec = Command::new(CIPHER_VEHICLE_BIN)
        .args(CIPHER_DEC_ARGV)
        .arg(&enc_path)
        .args(["-out", dec_path.to_str().unwrap()])
        .output()
        .expect("run stock cipher decrypt");
    assert!(dec.status.success(), "stock dec must exit 0");
    assert_eq!(
        std::fs::read(&dec_path).unwrap(),
        input,
        "decrypt(enc(input)) must equal input"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
