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

enum KemCapability {
    Supported,
    Unsupported,
    Broken(String),
}

/// Capability probe: `pkeyutl -encap/-decap/-secret` exist only on
/// newer OpenSSL (3.5 here); 3.0.x (e.g. the ubuntu-24.04 CI lane's
/// 3.0.13, whose pkeyutl.c has no encap surface) probes Unsupported
/// so the live leg skips instead of failing the suite. A binary that
/// fails help execution probes Broken (present-but-broken fails, never
/// silently skips). Freeze pins above still run in all cases.
fn probe_kem_capability(vehicle: &str) -> KemCapability {
    let output = match Command::new(vehicle).args(["pkeyutl", "-help"]).output() {
        Err(e) => return KemCapability::Broken(format!("pkeyutl -help unusable: {e}")),
        Ok(o) => o,
    };
    // Usage goes to stderr on some versions: scan both streams.
    let help = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    if help.contains("-encap") && help.contains("-decap") && help.contains("-secret") {
        return KemCapability::Supported;
    }
    if output.status.success() {
        KemCapability::Unsupported
    } else {
        KemCapability::Broken(format!("pkeyutl -help exits {}", output.status))
    }
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
    match probe_kem_capability(KEM_VEHICLE_BIN) {
        KemCapability::Supported => {}
        KemCapability::Unsupported => {
            eprintln!(
                "SKIP KEM stock oracle: pkeyutl lacks -encap/-decap/-secret (needs KEM CLI, e.g. OpenSSL 3.5; 3.0.x unsupported)"
            );
            return None;
        }
        KemCapability::Broken(msg) => panic!("stock binary broken: {msg}"),
    }
    let dir = std::env::temp_dir().join(format!("osslscope-kemoracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

fn fake_vehicle(dir: &std::path::Path, name: &str, body: &str) -> String {
    let fake = dir.join(name);
    std::fs::write(&fake, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    fake.to_str().unwrap().to_string()
}

#[test]
fn kem_capability_probe_classifies_help_fixtures() {
    // Fully hermetic: no assertion on the host openssl (3.0.x CI lanes
    // must pass this test too — only the live leg gates on the probe).
    let dir = std::env::temp_dir().join(format!("osslscope-kemprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // KEM options on stdout only.
    let out_only = fake_vehicle(&dir, "kem-out.sh", "echo 'options: -encap -decap -secret'");
    assert!(matches!(
        probe_kem_capability(&out_only),
        KemCapability::Supported
    ));
    // KEM options on stderr only (real `pkeyutl -help` shape).
    let err_only = fake_vehicle(
        &dir,
        "kem-err.sh",
        "echo 'options: -encap -decap -secret' >&2",
    );
    assert!(matches!(
        probe_kem_capability(&err_only),
        KemCapability::Supported
    ));
    // KEM options split across streams.
    let split = fake_vehicle(
        &dir,
        "kem-split.sh",
        "echo 'options: -encap'; echo 'options: -decap -secret' >&2",
    );
    assert!(matches!(
        probe_kem_capability(&split),
        KemCapability::Supported
    ));
    // No KEM options, clean exit (OpenSSL 3.0.x shape): unsupported,
    // so the live leg skips instead of failing the suite.
    let old = fake_vehicle(
        &dir,
        "old-openssl.sh",
        "echo 'options: -sign -verify -derive'",
    );
    assert!(matches!(
        probe_kem_capability(&old),
        KemCapability::Unsupported
    ));
    // Crashing help is broken, never a silent unsupported skip.
    let crash = fake_vehicle(&dir, "crash.sh", "echo boom >&2; exit 3");
    assert!(matches!(
        probe_kem_capability(&crash),
        KemCapability::Broken(_)
    ));
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
