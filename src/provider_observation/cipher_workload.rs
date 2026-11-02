//! Frozen cipher positive-control workload (T2 S2a).
//!
//! The argv and input below are the single definition shared by the
//! standalone stock oracle (`tests/cipher_stock_oracle.rs`, runs in CI
//! with no caps and no BPF) and the future S2b typed cipher native.
//! The S2b native reuses [`CIPHER_ENC_ARGV`] verbatim; any drift fails
//! the oracle test first. The key/IV are synthetic counters, plainly
//! not secrets; the pinned ciphertext was established by two
//! identical stock enc runs plus a decrypt round-trip.

/// Stock OpenSSL vehicle for the cipher positive control.
pub const CIPHER_VEHICLE_BIN: &str = "/usr/bin/openssl";

/// Synthetic 256-bit key (byte counter 0x00-0x1f): NOT a secret.
pub const CIPHER_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Synthetic 128-bit IV (byte counter 0x00-0x0f): NOT a secret.
pub const CIPHER_IV_HEX: &str = "000102030405060708090a0b0c0d0e0f";

/// Frozen enc argv words: `enc -aes-256-cbc -K <key> -iv <iv> -in`
/// (input path appended by the caller, `-out` follows it).
pub const CIPHER_ENC_ARGV: &[&str] = &[
    "enc",
    "-aes-256-cbc",
    "-K",
    CIPHER_KEY_HEX,
    "-iv",
    CIPHER_IV_HEX,
    "-in",
];

/// Frozen dec argv words (same shape with `-d`).
pub const CIPHER_DEC_ARGV: &[&str] = &[
    "enc",
    "-d",
    "-aes-256-cbc",
    "-K",
    CIPHER_KEY_HEX,
    "-iv",
    CIPHER_IV_HEX,
    "-in",
];

/// Deterministic 256-byte input (pattern, not random: stable across runs).
pub fn cipher_workload_input() -> Vec<u8> {
    (0..256u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

/// Pinned ciphertext of [`cipher_workload_input`] under the frozen
/// key/IV, established by two identical stock enc runs plus a decrypt
/// round-trip before hardcoding.
pub const EXPECTED_CIPHERTEXT_HEX: &str = "ee14d06bcd363368372091a5283d30d33bf9cbf5926420334c37f89a2e720321410a02d67e687194b0ba01dfeffc0d7c355383290f189fbb332b34ad17566c66ccd05aee5ac6d5e446929ee9398ce0288f1eeac678e87d6ad744422103f672da7b2b9755a52032b2f9869135f261a46372a0576dc7c7ff2687b120c7247f8cc2f42364cc75145c8d39970edf4e430b60d3f94b3bd0f5a6fa073df336058644b5e20781da84c8f3e174c923c060876f8ef3c1d9e6a2854292baa8f11aac896fe03468625842ae41f5b420d5b5f481eeaa904f207223346462d292488b7b6f156c019736b243cb0b4095a97f6fd8f3086bad7716fbbd7d62b47f228dfbedacbebbf9941807fcb5851e194473c31486e020";
