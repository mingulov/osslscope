//! Frozen digest positive-control workload (T2 S1a).
//!
//! The argv and input below are the single definition shared by the
//! standalone stock oracle (`tests/digest_stock_oracle.rs`, runs in CI
//! with no caps and no BPF) and the future S1b typed digest native.
//! The S1b native reuses [`DIGEST_WORKLOAD_ARGV`] verbatim; any drift
//! fails the oracle test first. The input generator mirrors the live
//! digest leg's deterministic 64 KiB pattern (stable across runs).

/// Stock OpenSSL vehicle for the digest positive control.
pub const DIGEST_VEHICLE_BIN: &str = "/usr/bin/openssl";

/// Frozen workload argv words before the input path: `dgst -sha256`.
pub const DIGEST_WORKLOAD_ARGV: &[&str] = &["dgst", "-sha256"];

/// Pinned SHA-256 of [`digest_workload_input`], established three ways
/// (stock `openssl dgst`, Python hashlib, Rust `sha2`) before hardcoding.
/// The input generator cannot drift a byte without failing the oracle.
pub const EXPECTED_SHA256_HEX: &str =
    "55928607572270ea0eafc10865d705adcf4483fc86166136b687ad06e5dc14ff";

/// Deterministic 64 KiB input (pattern, not random: stable across runs).
pub fn digest_workload_input() -> Vec<u8> {
    (0..65536u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}
