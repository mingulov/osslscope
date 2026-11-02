//! Frozen KEM positive-control workload (T2 S4a).
//!
//! The argv and key below are the single definition shared by the
//! standalone stock oracle (`tests/kem_stock_oracle.rs`, runs in CI
//! with no caps and no BPF) and the future S4b typed KEM native. The
//! S4b native reuses [`ENCAP_ARGV`] verbatim; any drift fails the oracle
//! test first. Encapsulation is randomized, so there is deliberately NO
//! pinned ciphertext: the oracle is the encap/decap round-trip property
//! plus pinned key material and pinned output lengths. The key is a
//! synthetic X25519 throwaway generated for this fixture and embedded
//! so the workload needs no keygen step: it is plainly NOT a secret
//! and must never be used elsewhere.

/// Stock OpenSSL vehicle for the KEM positive control.
pub const KEM_VEHICLE_BIN: &str = "/usr/bin/openssl";

/// Synthetic throwaway X25519 key (PEM): NOT a secret.
pub const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEILBOKs0JBUlO0Wt9FgieOMzmIQcMWtMXjkzgqEZ10W5t
-----END PRIVATE KEY-----
"#;

/// Matching public key (PEM): NOT a secret.
pub const TEST_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAqnogPOiX0R6RppTq5aVChCow/DVd3xGNMceHNKO13UU=
-----END PUBLIC KEY-----
"#;

/// SHA-256 of [`TEST_PRIVATE_KEY_PEM`]: key replacement or corruption
/// fails the oracle even on the absent-binary path.
pub const TEST_PRIVATE_KEY_SHA256_HEX: &str =
    "57d3eaba47694e31636a78cbaa62d0a9973bf718c949470945fe6bd9b8c76a4b";

/// SHA-256 of [`TEST_PUBLIC_KEY_PEM`]: same absent-path pin.
pub const TEST_PUBLIC_KEY_SHA256_HEX: &str =
    "442f0e6f21cc9875b9c145ade469130bd3c75b3fc88a4c8f9c457e362fdf17c1";

/// Frozen encap argv words: `pkeyutl -encap -inkey <pub> -secret <sec>`
/// (expression continues with `-out <ct>`, appended by the caller).
pub const ENCAP_ARGV: &[&str] = &["pkeyutl", "-encap", "-inkey"];

/// Frozen decap argv words: `pkeyutl -decap -inkey <priv> -in <ct>`
/// (expression continues with `-secret <sec>`, appended by the caller).
pub const DECAP_ARGV: &[&str] = &["pkeyutl", "-decap", "-inkey"];

/// X25519 shared-secret length in bytes.
pub const EXPECTED_SECRET_LEN: usize = 32;

/// X25519 encapsulation length in bytes.
pub const EXPECTED_CIPHERTEXT_LEN: usize = 32;
