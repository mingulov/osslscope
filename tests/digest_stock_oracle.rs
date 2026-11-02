//! Digest stock-workload oracle (RUNS in CI: no caps, no BPF, no observer).
//!
//! T2 S1a freezes the digest positive-control workload argv and its
//! independent oracle BEFORE the typed digest probes exist: the future
//! S1b native reuses [`DIGEST_WORKLOAD_ARGV`] verbatim, so any argv drift
//! fails here first. The oracle is Python hashlib — a second SHA-256
//! implementation, not an unobserved re-run of the same OpenSSL binary.
//!
//! Graceful SKIP (repo convention) when /usr/bin/openssl or python3 is
//! absent: CI lanes carry both, but the test must not hard-fail elsewhere.

use osslscope::provider_observation::digest_workload::{
    DIGEST_VEHICLE_BIN, DIGEST_WORKLOAD_ARGV, digest_workload_input,
};
use std::path::PathBuf;
use std::process::Command;

fn prereqs() -> Option<PathBuf> {
    if !Command::new(DIGEST_VEHICLE_BIN)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP digest stock oracle: no {DIGEST_VEHICLE_BIN}");
        return None;
    }
    if !Command::new("python3")
        .args(["-c", "import hashlib"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP digest stock oracle: no python3+hashlib");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("osslscope-digestoracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn digest_stock_workload_matches_hashlib_oracle() {
    let Some(dir) = prereqs() else {
        return;
    };
    // The frozen argv pins exactly two words before the input path:
    // `dgst -sha256`. Any S1b drift (extra flags, reordered words)
    // changes this const and fails here first.
    assert_eq!(DIGEST_WORKLOAD_ARGV, &["dgst", "-sha256"]);
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

    let oracle = Command::new("python3")
        .args([
            "-c",
            "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())",
            input_path.to_str().unwrap(),
        ])
        .output()
        .expect("run hashlib oracle");
    assert!(oracle.status.success(), "oracle must exit 0");
    let oracle_hex = String::from_utf8(oracle.stdout).unwrap();
    let oracle_hex = oracle_hex.trim().to_lowercase();

    assert_eq!(
        stock_hex, oracle_hex,
        "stock `openssl dgst -sha256` must match hashlib on the frozen input"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
