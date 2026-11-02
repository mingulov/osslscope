//! Frozen signature positive-control workload (T2 S3a).
//!
//! The argv, input, and key below are the single definition shared by the
//! standalone stock oracle (`tests/signature_stock_oracle.rs`, runs in CI
//! with no caps and no BPF) and the future S3b typed signature native.
//! The S3b native reuses [`SIGN_ARGV`] verbatim; any drift fails the
//! oracle test first. RSA PKCS#1 v1.5 signatures are deterministic, so
//! the pinned vector plus a verify round-trip is the oracle (KDF
//! precedent). The key is a synthetic throwaway generated for this
//! fixture and embedded so the workload needs no keygen step: it is
//! plainly NOT a secret and must never be used elsewhere.

/// Stock OpenSSL vehicle for the signature positive control.
pub const SIGNATURE_VEHICLE_BIN: &str = "/usr/bin/openssl";

/// Synthetic throwaway 2048-bit RSA key (PEM): NOT a secret.
pub const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgApzxr7hwCLU8
3iV670Xafyc4TPPw69FxTBXxq7wZDu/zGuylPf0eg1dotT3AK7p1RDFy4zW2XO0y
vyYMMm+pvOaxRqlx8cPbKTaJkraoLHd3sd/RBGjzuazKrcY1wibTEN6tUi4u2abG
3ZoPYeeWtaP8V7GE7fpw0s7kNLERHJLvYBsT25oO7Ihnwf11YAxt8q8yvzSeF3C1
hqotTiRdmNuBMQnYoWFMW9Iqi8/PdZAxIpIadFQi9B+CfO9UUYDCmm/OJEjgJT5J
Dn4WjnQgWpwu+YG5R8ot/xDIO6HeJs77Vnmmk6ThWMrSoPweuSljUrIKG+Yz8WQX
n1t3ntbhAgMBAAECggEARdv+M5L5nohewH1otbyjrdqX//+w/X2nyqRibEoDbJlV
77jQmvBug5TqY7/FfxJYbPxh7nv+pmj58o78CJU4pU3hFoL4VdQtI5Fhyzyv3MrV
OgAB7NrVC5wEMdUe1be3ha0220sm+LN0Gh0ENzUSjH0vZGvRCG1ySzHuvDm5GPPE
5ZiOotTvl+0dd+DdHWdZ4+62c11qJsIWRss54D94nQILOSTgTke/bQKntFE6RjsY
ESEKyOX/mc/HbRRXruXieENit/EuHDz3QF4X1IRbHRNa2DFSm2igaFRK28GAaIuA
l+HHboFqRnXC7XrdZeIOUqsJC5Qye+0sqhii0yPaFQKBgQDSBADbYfMSevK+catR
Hp/NbULnge9EjB6f3TAW6FBPQEP/9XDv6pKr9x4WHsRWTFORvtWsKJnCouLAfjpt
cuuGoxplLZlXZHgbpWQGi8Mp32w+lPaCzW90zLoVC0ahpWre/91+kdQxQ3YjYLLR
VUaQzfyMR75cKIsfbZ2z7R2q1wKBgQDDC6hciVsAn3vyMifXr0JgmJeQ6qNHXUbM
IY5IOhdL/SSvWuYjzAphcHUHingVMc90kk2B5CPW9RdKvC9annOyy9+/XwHLZqi/
NWHej6slmA/D8z9WBcV0/724oFmuBniFS4kpvvcvMPt8yJ6YAUXS0BH7pjUCQ5bv
PGKmPufNBwKBgAvZsfqvEjouudfJLjOLmNTMn4PUrx2dEnVO09HXFgECzVN6E/9V
qyUM8qOo5MdB001cCU6Hk/WJn2XhOYbHf0a/mVOwOQDXaHeW44gDBuYr9z2oxign
U2yxyKY7Vqb0YI1ovqTPsbt95QKmCDELsMmm9eMsgS9OEluZodZvQMdNAoGADVIy
gX9wE67QzE3YosZ5hhdl4qPj2u/n8fEowo4VIT98ze0rYq6A1v7TP1yZrvjj7lY/
rOtj9z5uBNCte0bvJ/r8oRlgCgBM7iI7OPQfAEZObVejr8BdKAx/bKim91fBy3jJ
OWytfS+fPXqGOmN73VYQpFtJq4nqORSquCf7tOkCgYBOO80RcrbW4FB3dRP9FMx2
PsqZkBRgXt3SPRfnBRcJ2Ph+jpAE3Rz22PUmGuR/O6BgWD6sQbxLR4KBU09xUTIs
wYDVNRMxnCGI4O2/hYLKLCMW2+Mi7YhfXjGw5iTUUuFzIwqXy4obiwXd3kpRpB53
AzQQ2FkmbKcFIvXqMKJ12Q==
-----END PRIVATE KEY-----
"#;

/// Matching public key (PEM): NOT a secret.
pub const TEST_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoAKc8a+4cAi1PN4leu9F
2n8nOEzz8OvRcUwV8au8GQ7v8xrspT39HoNXaLU9wCu6dUQxcuM1tlztMr8mDDJv
qbzmsUapcfHD2yk2iZK2qCx3d7Hf0QRo87msyq3GNcIm0xDerVIuLtmmxt2aD2Hn
lrWj/FexhO36cNLO5DSxERyS72AbE9uaDuyIZ8H9dWAMbfKvMr80nhdwtYaqLU4k
XZjbgTEJ2KFhTFvSKovPz3WQMSKSGnRUIvQfgnzvVFGAwppvziRI4CU+SQ5+Fo50
IFqcLvmBuUfKLf8QyDuh3ibO+1Z5ppOk4VjK0qD8HrkpY1KyChvmM/FkF59bd57W
4QIDAQAB
-----END PUBLIC KEY-----
"#;

/// Frozen sign argv words: `dgst -sha256 -sign <key> -out <sig> <input>`
/// (key path, `-out`, sig path, input path appended by the caller).
pub const SIGN_ARGV: &[&str] = &["dgst", "-sha256", "-sign"];

/// Deterministic 256-byte input (pattern, not random: stable across runs).
pub fn signature_workload_input() -> Vec<u8> {
    (0..256u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

/// Pinned SHA-256 of [`signature_workload_input`]: a same-length
/// generator change fails the oracle even on the absent-binary path.
pub const SIGNATURE_INPUT_SHA256_HEX: &str =
    "e051c20c2cb90863f3f6b70a9aefe0169f1abeff45fc83f259aab5c15b49c823";

/// Pinned RSA/SHA-256 signature of [`signature_workload_input`],
/// established by two identical stock sign runs plus a verify
/// round-trip before hardcoding.
pub const EXPECTED_SIGNATURE_HEX: &str = "30312e0578fdafb100e3357aaf3495faeb7bc1c450798cc916d20b9bed79eb41cf62f6eddefabfa14a049401c1d0ea803334eaf8c8e6b2ccff63168b12b23b1b31274573dc24fa42b8c7ed01cda5cce6a77340806c0fd82d4c8a1e43558cb9677541f6150af69fc319ea85095b79794905074d309e603853c9fab90e6eb495fd21c21db2ef7d96cd4245bc14240dac79c2b56ba77a583429eb1c0a2228f484482afd54bc9f0b14a75400ddb1ae53d1d06ce8a9482f76e71ab873425e2bdae284a1734e9a8ec367550c3219db430877285616ccdbbc3d8a6618774901186d3aa911a5aecd5dba481a7537f43e8a4785c69ea6ce7554e257d2aac05935f9a08810";
