//! Digest stock-workload oracle (RUNS in CI: no caps, no BPF, no observer).
//!
//! T2 S1a freezes the digest positive-control workload argv and its
//! independent oracle BEFORE the typed digest probes exist: the future
//! S1b native reuses [`DIGEST_WORKLOAD_ARGV`] verbatim, so any argv drift
//! fails here first. The oracle is the pure-Rust `sha2` crate —
//! OpenSSL-independent (Python `hashlib` is NOT used: it is
//! OpenSSL-backed on this host and proves nothing).
//!
//! The expected digest is hardcoded: the input generator cannot drift
//! without failing here. Graceful SKIP only when the stock binary is
//! absent; a present-but-broken binary FAILS (never silent).

use osslscope::provider_observation::digest_workload::{
    DIGEST_VEHICLE_BIN, DIGEST_WORKLOAD_ARGV, EXPECTED_SHA256_HEX, digest_workload_input,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

/// Pure freeze checks run BEFORE any prerequisite: a missing binary
/// must not bypass the argv/input pins.
fn frozen_shape() {
    // The frozen argv pins exactly two words before the input path:
    // `dgst -sha256`. Any S1b drift (extra flags, reordered words)
    // changes this const and fails here first.
    assert_eq!(DIGEST_WORKLOAD_ARGV, &["dgst", "-sha256"]);
    let input = digest_workload_input();
    assert_eq!(input.len(), 65536, "frozen input length must not drift");
    let digest: [u8; 32] = Sha256::digest(&input).into();
    let oracle_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        oracle_hex, EXPECTED_SHA256_HEX,
        "frozen input bytes must hash to the pinned digest"
    );
}

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
            // ENOENT also means a missing ELF/script interpreter for an
            // EXISTING file: present-but-broken must fail, never skip.
            if std::path::Path::new(path).exists() {
                VehicleProbe::Broken(format!("`{path}` exists but cannot execute: {e}"))
            } else {
                VehicleProbe::Absent
            }
        }
        Err(e) => VehicleProbe::Broken(format!("`{path}` unusable: {e}")),
    }
}

fn stage() -> Option<PathBuf> {
    match probe_vehicle(DIGEST_VEHICLE_BIN) {
        VehicleProbe::Absent => {
            eprintln!("SKIP digest stock oracle: no {DIGEST_VEHICLE_BIN}");
            return None;
        }
        VehicleProbe::Broken(msg) => panic!("stock binary broken: {msg}"),
        VehicleProbe::Ready => {}
    }
    let dir = std::env::temp_dir().join(format!("osslscope-digestoracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn vehicle_probe_classifies_absent_ready_and_broken() {
    assert!(
        matches!(
            probe_vehicle("/nonexistent-osslscope-vehicle-xyz"),
            VehicleProbe::Absent
        ),
        "missing path must skip"
    );
    assert!(
        matches!(probe_vehicle("/bin/true"), VehicleProbe::Ready),
        "/bin/true must probe ready"
    );
    // Present-but-broken: an existing file whose interpreter is missing
    // raises ENOENT too; it must FAIL, never silently skip.
    let dir = std::env::temp_dir().join(format!("osslscope-vehicleprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("badinterp.sh");
    std::fs::write(&script, "#!/nonexistent-interp-xyz-123\ntrue\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(
            probe_vehicle(script.to_str().unwrap()),
            VehicleProbe::Broken(_)
        ),
        "existing file with missing interpreter must fail, not skip"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn digest_stock_workload_matches_sha2_oracle() {
    frozen_shape();
    let Some(dir) = stage() else {
        return;
    };
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, digest_workload_input()).unwrap();

    let stock = Command::new(DIGEST_VEHICLE_BIN)
        .args(DIGEST_WORKLOAD_ARGV)
        .arg(&input_path)
        .output()
        .expect("run stock digest workload");
    assert!(stock.status.success(), "stock workload must exit 0");
    let stock_hex = String::from_utf8(stock.stdout)
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap_or("?")
        .to_lowercase();

    assert_eq!(
        stock_hex, EXPECTED_SHA256_HEX,
        "stock `openssl dgst -sha256` must match the pinned sha2 oracle"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
