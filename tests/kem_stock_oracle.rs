//! KEM stock-workload oracle (RUNS in CI: no caps, no BPF, no observer).
//!
//! T2 S4a freezes the KEM positive-control workload argv BEFORE the typed
//! KEM probes exist: the future S4b native reuses [`ENCAP_ARGV`] verbatim,
//! so any argv drift fails here first. Encapsulation is randomized, so
//! there is deliberately NO pinned ciphertext: the oracle is the
//! encap/decap round-trip property (decap(encap(pub)) == secret) plus
//! pinned key material and pinned output lengths. The key is a synthetic
//! X25519 throwaway generated for this fixture, plainly not a secret; it
//! is embedded so the workload needs no keygen step.
//!
//! Graceful SKIP only when the stock binary is absent or its pkeyutl
//! lacks the KEM options (3.0.x, e.g. the ubuntu-24.04 CI lane); a
//! present-but-broken binary FAILS (never silent).

use osslscope::provider_observation::kem_workload::{
    DECAP_ARGV, ENCAP_ARGV, EXPECTED_CIPHERTEXT_LEN, EXPECTED_SECRET_LEN, KEM_VEHICLE_BIN,
    TEST_PRIVATE_KEY_PEM, TEST_PRIVATE_KEY_SHA256_HEX, TEST_PUBLIC_KEY_PEM,
    TEST_PUBLIC_KEY_SHA256_HEX,
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
/// must not bypass the argv/key/length pins.
fn frozen_shape() {
    // `pkeyutl -encap -inkey <pub> -secret <sec> -out <ct>` /
    // `pkeyutl -decap -inkey <priv> -in <ct> -secret <sec>`: paths
    // appended by the caller, so the consts pin the flag words.
    assert_eq!(ENCAP_ARGV, &["pkeyutl", "-encap", "-inkey"]);
    assert_eq!(DECAP_ARGV, &["pkeyutl", "-decap", "-inkey"]);
    assert_eq!(EXPECTED_SECRET_LEN, 32);
    assert_eq!(EXPECTED_CIPHERTEXT_LEN, 32);
    let priv_digest: [u8; 32] = Sha256::digest(TEST_PRIVATE_KEY_PEM.as_bytes()).into();
    let priv_hex: String = priv_digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(priv_hex, TEST_PRIVATE_KEY_SHA256_HEX);
    let pub_digest: [u8; 32] = Sha256::digest(TEST_PUBLIC_KEY_PEM.as_bytes()).into();
    let pub_hex: String = pub_digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(pub_hex, TEST_PUBLIC_KEY_SHA256_HEX);
}

/// Capability probe: `pkeyutl -encap/-decap/-secret` exist only on
/// newer OpenSSL (3.5 here); 3.0.x (e.g. the ubuntu-24.04 CI lane's
/// 3.0.13, whose pkeyutl.c has no encap surface) must skip the live
/// leg instead of failing the suite. Freeze pins above still run.
fn pkeyutl_supports_kem(vehicle: &str) -> bool {
    Command::new(vehicle)
        .args(["pkeyutl", "-help"])
        .output()
        .map(|o| {
            // Usage goes to stderr on some versions: scan both streams.
            let help = String::from_utf8_lossy(&o.stdout).into_owned()
                + &String::from_utf8_lossy(&o.stderr);
            help.contains("-encap") && help.contains("-decap") && help.contains("-secret")
        })
        .unwrap_or(false)
}

fn stage() -> Option<PathBuf> {
    match probe_vehicle(KEM_VEHICLE_BIN) {
        VehicleProbe::Absent => {
            eprintln!("SKIP KEM stock oracle: no {KEM_VEHICLE_BIN}");
            return None;
        }
        VehicleProbe::Broken(msg) => panic!("stock binary broken: {msg}"),
        VehicleProbe::Ready => {}
    }
    if !pkeyutl_supports_kem(KEM_VEHICLE_BIN) {
        eprintln!(
            "SKIP KEM stock oracle: pkeyutl lacks -encap/-decap/-secret (needs KEM CLI, e.g. OpenSSL 3.5; 3.0.x unsupported)"
        );
        return None;
    }
    let dir = std::env::temp_dir().join(format!("osslscope-kemoracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn kem_capability_probe_detects_missing_kem_cli() {
    // This host's stock openssl has the KEM CLI (3.5.5).
    assert!(
        pkeyutl_supports_kem(KEM_VEHICLE_BIN),
        "host openssl must offer pkeyutl -encap/-decap/-secret"
    );
    // A vehicle whose help lacks the KEM options (e.g. OpenSSL 3.0.x,
    // as on the ubuntu-24.04 CI lane) must probe unsupported so the
    // live leg skips instead of failing the suite.
    let dir = std::env::temp_dir().join(format!("osslscope-kemprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join("old-openssl");
    std::fs::write(&fake, "#!/bin/sh\necho 'options: -sign -verify -derive'\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        !pkeyutl_supports_kem(fake.to_str().unwrap()),
        "help without KEM options must probe unsupported"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kem_stock_workload_roundtrips_shared_secret() {
    frozen_shape();
    let Some(dir) = stage() else {
        return;
    };
    let priv_path = dir.join("priv.pem");
    let pub_path = dir.join("pub.pem");
    let secret1_path = dir.join("secret1.bin");
    let ct_path = dir.join("ct.bin");
    let secret2_path = dir.join("secret2.bin");
    std::fs::write(&priv_path, TEST_PRIVATE_KEY_PEM).unwrap();
    std::fs::write(&pub_path, TEST_PUBLIC_KEY_PEM).unwrap();

    let encap = Command::new(KEM_VEHICLE_BIN)
        .args(ENCAP_ARGV)
        .arg(&pub_path)
        .args(["-secret", secret1_path.to_str().unwrap()])
        .args(["-out", ct_path.to_str().unwrap()])
        .output()
        .expect("run stock KEM encap");
    assert!(encap.status.success(), "stock encap must exit 0");
    let secret1 = std::fs::read(&secret1_path).unwrap();
    let ct = std::fs::read(&ct_path).unwrap();
    assert_eq!(secret1.len(), EXPECTED_SECRET_LEN);
    assert_eq!(ct.len(), EXPECTED_CIPHERTEXT_LEN);

    // Round-trip property: decap(ct) must recover the same secret.
    // (Encap is randomized: no byte pin, the property is the oracle.)
    let decap = Command::new(KEM_VEHICLE_BIN)
        .args(DECAP_ARGV)
        .arg(&priv_path)
        .args(["-in", ct_path.to_str().unwrap()])
        .args(["-secret", secret2_path.to_str().unwrap()])
        .output()
        .expect("run stock KEM decap");
    assert!(decap.status.success(), "stock decap must exit 0");
    assert_eq!(
        std::fs::read(&secret2_path).unwrap(),
        secret1,
        "decap(encap(pub)) must recover the shared secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
