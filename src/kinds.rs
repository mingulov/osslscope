//! SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen version-keyed registries (P1-0 freeze, `REGISTRY_VERSION = 1`).
//!
//! Sources (all verified 2026-09-17; re-freeze = re-run the same greps):
//! - `OSSL_OP_*` / `OSSL_FUNC_*`: `openssl/core_dispatch.h` from
//!   3.0.22 (lane A), 3.5.8 (lane C), 3.6.0 (openssl.org tarball),
//!   4.0.2 (`/opt/openssl-4.0.2`). Evolution is purely additive: 230 →
//!   274 → 277 → 280 funcids, zero removals, zero renumbers.
//! - `ENGINE_*`: `openssl/engine.h` 3.0/3.5/3.6 — 132 decls, byte-identical
//!   sets; 4.0 ships deprecation stubs only (0 `ENGINE_*` in 4.0 dynsym).
//! - Low-level families: defined `.dynsym` FUNC exports of the three lane
//!   libcryptos (5377/5873/5673 symbols), bucketed by prefix.
//! - Fetch/SKEY: `evp.h` + `kdf.h` + `encoder.h` + `decoder.h` per version.
//! - Struct shapes: `openssl/core.h` — identical all four versions.
//! - 4.0 KDF/digest names: 4.0.2 source tree (`core_names.h`, `names.h`).
//!
//! Invariant: every table is `&'static` data. `since` is (major, minor).

/// Registry schema version. Bumped only by a recorded re-freeze.
pub const REGISTRY_VERSION: u32 = 1;

use osslscope_ebpf_common::OTHER_CLASS;

/// (major, minor) OpenSSL version key.
pub type Version = (u32, u32);

/// `addr_hash` (frozen P1-0): low 64 bits of SHA-256 over the ATTESTED
/// backing triple — NOT the runtime address (ASLR-unstable) — rendered
/// as 16 lowercase hex chars.
///
/// Preimage: `b"osslscope-addr-v1" || dev_str || 0x00 || le64(ino) ||
/// le64(file_offset)`, where `dev_str` is the `/proc/pid/maps` device
/// field verbatim (e.g. `"08:01"`). Output: the LAST 8 digest bytes hex
/// (low 64 bits of the big-endian digest integer).
///
/// Properties: stable across runs for the same provider build (goldens
/// compare it byte-exact after redacting raw `addr`); one-way (no ASLR
/// slide leaks); 64-bit collision space is ample for inventory row
/// counts. Unbacked rows (`dev=""`, `ino=0`, `off=0`) share one
/// degenerate hash by construction — standard-fixture goldens require
/// `addr_backed=true` (P1 exit 1), so the degenerate value never
/// decides a gate.
pub fn addr_hash(dev: &str, ino: u64, file_offset: u64) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"osslscope-addr-v1");
    h.update(dev.as_bytes());
    h.update([0u8]);
    h.update(ino.to_le_bytes());
    h.update(file_offset.to_le_bytes());
    let d = h.finalize();
    hex_low64(&d)
}

/// `prov_hash` (frozen P1-0): hex SHA-256 of the provider FILE bytes
/// (64 lowercase chars; p11scope whole-file precedent). Binds emitted
/// rows to exact object bytes; a build-id→offset table mismatch fails
/// closed to count-only + PARTIAL (P1 exit 2), never a wrong hash.
pub fn prov_hash(file_bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(file_bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_low64(digest: &[u8]) -> String {
    digest[digest.len() - 8..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// --- Operation + function-id tables (generated; see header) ---

/// One `OSSL_OP_*` operation id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpDef {
    pub name: &'static str,
    pub id: u32,
    pub since: Version,
}

/// One `OSSL_FUNC_*` function id. `op` is `None` for the 68 core-dispatch
/// ids (BIO/CORE/CRYPTO/PROVIDER/...) that are not op-qualified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FuncDef {
    pub op: Option<&'static str>,
    pub name: &'static str,
    pub id: u32,
    pub since: Version,
}

/// One `ENGINE_*` symbol (3.x only; 4.x has zero `ENGINE_*` exports).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EngineDef {
    pub name: &'static str,
    pub class: EngineClass,
}

/// ENGINE finding classes (P1 exit 3 tripwire design).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EngineClass {
    /// `ENGINE_by_id` / `ENGINE_init` — presence tripwire.
    Tripwire,
    /// `ENGINE_register_*` — method-table registration.
    Register,
    /// `ENGINE_set_default_*` — the interception class (P0-11 proved
    /// `ENGINE_set_default_digests` redirects execution).
    Interception,
    /// Remaining ENGINE API (reference, control, load helpers).
    Other,
}

/// One `EVP_*_fetch` / `OSSL_*_fetch` entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FetchDef {
    pub name: &'static str,
    pub since: Version,
}

/// One `EVP_SKEY_*` entry point (absent in 3.0).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SkeyDef {
    pub name: &'static str,
    pub since: Version,
}

pub const OPS: &[OpDef] = &[
    OpDef {
        name: "OSSL_OP_DIGEST",
        id: 1,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_CIPHER",
        id: 2,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_MAC",
        id: 3,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_KDF",
        id: 4,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_RAND",
        id: 5,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_KEYMGMT",
        id: 10,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_KEYEXCH",
        id: 11,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_SIGNATURE",
        id: 12,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_ASYM_CIPHER",
        id: 13,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_KEM",
        id: 14,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_SKEYMGMT",
        id: 15,
        since: (3, 5),
    },
    OpDef {
        name: "OSSL_OP_ENCODER",
        id: 20,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_DECODER",
        id: 21,
        since: (3, 0),
    },
    OpDef {
        name: "OSSL_OP_STORE",
        id: 22,
        since: (3, 0),
    },
];

pub const FUNCS: &[FuncDef] = &[
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_GETTABLE_PARAMS",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_GET_PARAMS",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_THREAD_START",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_GET_LIBCTX",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_NEW_ERROR",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_SET_ERROR_DEBUG",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_VSET_ERROR",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_SET_ERROR_MARK",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_POP_ERROR_TO_MARK",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_OBJ_ADD_SIGID",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_OBJ_CREATE",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_MALLOC",
        id: 20,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_ZALLOC",
        id: 21,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_FREE",
        id: 22,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_CLEAR_FREE",
        id: 23,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_REALLOC",
        id: 24,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_CLEAR_REALLOC",
        id: 25,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_SECURE_MALLOC",
        id: 26,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_SECURE_ZALLOC",
        id: 27,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_SECURE_FREE",
        id: 28,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE",
        id: 29,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CRYPTO_SECURE_ALLOCATED",
        id: 30,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_OPENSSL_CLEANSE",
        id: 31,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_NEW_FILE",
        id: 40,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_NEW_MEMBUF",
        id: 41,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_READ_EX",
        id: 42,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_WRITE_EX",
        id: 43,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_UP_REF",
        id: 44,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_FREE",
        id: 45,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_VPRINTF",
        id: 46,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_VSNPRINTF",
        id: 47,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_PUTS",
        id: 48,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_GETS",
        id: 49,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_BIO_CTRL",
        id: 50,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_INDICATOR_CB",
        id: 95,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CLEANUP_USER_ENTROPY",
        id: 96,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CLEANUP_USER_NONCE",
        id: 97,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_GET_USER_ENTROPY",
        id: 98,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_GET_USER_NONCE",
        id: 99,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SELF_TEST_CB",
        id: 100,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_GET_ENTROPY",
        id: 101,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CLEANUP_ENTROPY",
        id: 102,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_GET_NONCE",
        id: 103,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CLEANUP_NONCE",
        id: 104,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB",
        id: 105,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB",
        id: 106,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_NAME",
        id: 107,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX",
        id: 108,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GET0_DISPATCH",
        id: 109,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_UP_REF",
        id: 110,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_FREE",
        id: 111,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_CORE_COUNT_TO_MARK",
        id: 120,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_TEARDOWN",
        id: 1024,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GETTABLE_PARAMS",
        id: 1025,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GET_PARAMS",
        id: 1026,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_QUERY_OPERATION",
        id: 1027,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_UNQUERY_OPERATION",
        id: 1028,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GET_REASON_STRINGS",
        id: 1029,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_GET_CAPABILITIES",
        id: 1030,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_SELF_TEST",
        id: 1031,
        since: (3, 0),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_PROVIDER_RANDOM_BYTES",
        id: 1032,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND",
        id: 2001,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD",
        id: 2002,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD",
        id: 2003,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET",
        id: 2004,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS",
        id: 2005,
        since: (3, 5),
    },
    FuncDef {
        op: None,
        name: "OSSL_FUNC_SSL_QUIC_TLS_ALERT",
        id: 2006,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_ENCRYPT",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_DECRYPT",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_FREECTX",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_DUPCTX",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ASYM_CIPHER"),
        name: "OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_ENCRYPT_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_DECRYPT_INIT",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_UPDATE",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_FINAL",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_CIPHER",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_FREECTX",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_DUPCTX",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_GET_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_GET_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_SET_CTX_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_GETTABLE_PARAMS",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS",
        id: 13,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS",
        id: 14,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT",
        id: 15,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT",
        id: 16,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_PIPELINE_UPDATE",
        id: 17,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_PIPELINE_FINAL",
        id: 18,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT",
        id: 19,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_CIPHER"),
        name: "OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT",
        id: 20,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_FREECTX",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_GET_PARAMS",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_GETTABLE_PARAMS",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_SET_CTX_PARAMS",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_DOES_SELECTION",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_DECODE",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DECODER"),
        name: "OSSL_FUNC_DECODER_EXPORT_OBJECT",
        id: 20,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_UPDATE",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_FINAL",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_DIGEST",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_FREECTX",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_DUPCTX",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_GET_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_SET_CTX_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_GET_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_GETTABLE_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS",
        id: 13,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_SQUEEZE",
        id: 14,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_COPYCTX",
        id: 15,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_SERIALIZE",
        id: 16,
        since: (4, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_DIGEST"),
        name: "OSSL_FUNC_DIGEST_DESERIALIZE",
        id: 17,
        since: (4, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_FREECTX",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_GET_PARAMS",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_GETTABLE_PARAMS",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_SET_CTX_PARAMS",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_DOES_SELECTION",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_ENCODE",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_IMPORT_OBJECT",
        id: 20,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_ENCODER"),
        name: "OSSL_FUNC_ENCODER_FREE_OBJECT",
        id: 21,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_DUPCTX",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_FREECTX",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_RESET",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_DERIVE",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_GETTABLE_PARAMS",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_GET_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_GET_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_SET_CTX_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_SET_SKEY",
        id: 12,
        since: (3, 6),
    },
    FuncDef {
        op: Some("OSSL_OP_KDF"),
        name: "OSSL_FUNC_KDF_DERIVE_SKEY",
        id: 13,
        since: (3, 6),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_ENCAPSULATE_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_ENCAPSULATE",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_DECAPSULATE_INIT",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_DECAPSULATE",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_FREECTX",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_DUPCTX",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_GET_CTX_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_SET_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT",
        id: 12,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_KEM"),
        name: "OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT",
        id: 13,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_DERIVE",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_SET_PEER",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_FREECTX",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_DUPCTX",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYEXCH"),
        name: "OSSL_FUNC_KEYEXCH_DERIVE_SKEY",
        id: 11,
        since: (3, 6),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_NEW",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_CLEANUP",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_LOAD",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_FREE",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GET_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_SET_PARAMS",
        id: 13,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS",
        id: 14,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS",
        id: 15,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS",
        id: 16,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_NEW_EX",
        id: 17,
        since: (4, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME",
        id: 20,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_HAS",
        id: 21,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_VALIDATE",
        id: 22,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_MATCH",
        id: 23,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_IMPORT",
        id: 40,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_IMPORT_TYPES",
        id: 41,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_EXPORT",
        id: 42,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_EXPORT_TYPES",
        id: 43,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_DUP",
        id: 44,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX",
        id: 45,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_KEYMGMT"),
        name: "OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX",
        id: 46,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_DUPCTX",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_FREECTX",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_INIT",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_UPDATE",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_FINAL",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_GET_PARAMS",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_GET_CTX_PARAMS",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_SET_CTX_PARAMS",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_GETTABLE_PARAMS",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_MAC"),
        name: "OSSL_FUNC_MAC_INIT_SKEY",
        id: 13,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_FREECTX",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_INSTANTIATE",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_UNINSTANTIATE",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GENERATE",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_RESEED",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_NONCE",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_ENABLE_LOCKING",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_LOCK",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_UNLOCK",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GETTABLE_PARAMS",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS",
        id: 13,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GET_PARAMS",
        id: 14,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GET_CTX_PARAMS",
        id: 15,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_SET_CTX_PARAMS",
        id: 16,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_VERIFY_ZEROIZATION",
        id: 17,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_GET_SEED",
        id: 18,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_RAND"),
        name: "OSSL_FUNC_RAND_CLEAR_SEED",
        id: 19,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_NEWCTX",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SIGN_INIT",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SIGN",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_INIT",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_RECOVER",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE",
        id: 9,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL",
        id: 10,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_SIGN",
        id: 11,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT",
        id: 12,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE",
        id: 13,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL",
        id: 14,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DIGEST_VERIFY",
        id: 15,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_FREECTX",
        id: 16,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_DUPCTX",
        id: 17,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS",
        id: 18,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS",
        id: 19,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS",
        id: 20,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS",
        id: 21,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS",
        id: 22,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS",
        id: 23,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS",
        id: 24,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS",
        id: 25,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES",
        id: 26,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT",
        id: 27,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE",
        id: 28,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL",
        id: 29,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT",
        id: 30,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE",
        id: 31,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SIGNATURE"),
        name: "OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL",
        id: 32,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_FREE",
        id: 1,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_IMPORT",
        id: 2,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_EXPORT",
        id: 3,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_GENERATE",
        id: 4,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_GET_KEY_ID",
        id: 5,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS",
        id: 6,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_SKEYMGMT"),
        name: "OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS",
        id: 7,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_OPEN",
        id: 1,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_ATTACH",
        id: 2,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS",
        id: 3,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_SET_CTX_PARAMS",
        id: 4,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_LOAD",
        id: 5,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_EOF",
        id: 6,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_CLOSE",
        id: 7,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_EXPORT_OBJECT",
        id: 8,
        since: (3, 0),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_DELETE",
        id: 9,
        since: (3, 5),
    },
    FuncDef {
        op: Some("OSSL_OP_STORE"),
        name: "OSSL_FUNC_STORE_OPEN_EX",
        id: 10,
        since: (3, 5),
    },
];

pub const ENGINE: &[EngineDef] = &[
    EngineDef {
        name: "ENGINE_add",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_add_conf_module",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_by_id",
        class: EngineClass::Tripwire,
    },
    EngineDef {
        name: "ENGINE_cleanup",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_clear_defaults",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_cmd_is_executable",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_ctrl",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_ctrl_cmd",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_ctrl_cmd_string",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_finish",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_free",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_DH",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_DSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_EC",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_RAND",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_RSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_cipher",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_cipher_engine",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_ciphers",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_cmd_defns",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_ctrl_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_default_DH",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_default_DSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_default_EC",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_default_RAND",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_default_RSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_destroy_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_digest",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_digest_engine",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_digests",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_ex_data",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_ex_new_index",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_finish_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_first",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_flags",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_id",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_init_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_last",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_load_privkey_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_load_pubkey_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_name",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_next",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_asn1_meth",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_asn1_meth_engine",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_asn1_meth_str",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_asn1_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_meth",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_meth_engine",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_pkey_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_prev",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_ssl_client_cert_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_static_state",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_get_table_flags",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_init",
        class: EngineClass::Tripwire,
    },
    EngineDef {
        name: "ENGINE_load_afalg",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_builtin_engines",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_capi",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_cryptodev",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_dynamic",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_openssl",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_padlock",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_private_key",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_public_key",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_rdrand",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_load_ssl_client_cert",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_new",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_pkey_asn1_find_str",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_register_DH",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_DSA",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_EC",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_RAND",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_RSA",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_DH",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_DSA",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_EC",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_RAND",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_RSA",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_ciphers",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_complete",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_digests",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_pkey_asn1_meths",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_all_pkey_meths",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_ciphers",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_complete",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_digests",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_pkey_asn1_meths",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_register_pkey_meths",
        class: EngineClass::Register,
    },
    EngineDef {
        name: "ENGINE_remove",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_DH",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_DSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_EC",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_RAND",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_RSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_ciphers",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_cmd_defns",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_ctrl_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_default",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_default_DH",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_DSA",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_EC",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_RAND",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_RSA",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_ciphers",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_digests",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_pkey_asn1_meths",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_pkey_meths",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_default_string",
        class: EngineClass::Interception,
    },
    EngineDef {
        name: "ENGINE_set_destroy_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_digests",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_ex_data",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_finish_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_flags",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_id",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_init_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_load_privkey_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_load_pubkey_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_load_ssl_client_cert_function",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_name",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_pkey_asn1_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_pkey_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_set_table_flags",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_setup_bsd_cryptodev",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_DH",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_DSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_EC",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_RAND",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_RSA",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_ciphers",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_digests",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_pkey_asn1_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_unregister_pkey_meths",
        class: EngineClass::Other,
    },
    EngineDef {
        name: "ENGINE_up_ref",
        class: EngineClass::Other,
    },
];

pub const FETCH: &[FetchDef] = &[
    FetchDef {
        name: "EVP_ASYM_CIPHER_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_CIPHER_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_KDF_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_KEM_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_KEYEXCH_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_KEYMGMT_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_MAC_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_MD_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_RAND_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_SIGNATURE_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "EVP_SKEYMGMT_fetch",
        since: (3, 5),
    },
    FetchDef {
        name: "OSSL_DECODER_fetch",
        since: (3, 0),
    },
    FetchDef {
        name: "OSSL_ENCODER_fetch",
        since: (3, 0),
    },
];

pub const SKEY: &[SkeyDef] = &[
    SkeyDef {
        name: "EVP_SKEY_export",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_free",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_generate",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_get0_key_id",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_get0_provider_name",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_get0_raw_key",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_get0_skeymgmt_name",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_import",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_import_SKEYMGMT",
        since: (3, 6),
    },
    SkeyDef {
        name: "EVP_SKEY_import_raw_key",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_is_a",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_to_provider",
        since: (3, 5),
    },
    SkeyDef {
        name: "EVP_SKEY_up_ref",
        since: (3, 5),
    },
];

/// One `*_meth_new` custom-method constructor: name, version introduced,
/// version removed (`None` = still present in 4.0). Sources: `rsa.h`,
/// `dsa.h`, `dh.h`, `ec.h`, `evp.h` per version (NOT `engine.h`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MethNewDef {
    pub name: &'static str,
    pub since: Version,
    pub removed: Option<Version>,
}

pub const METH_NEW: &[MethNewDef] = &[
    MethNewDef {
        name: "DH_meth_new",
        since: (3, 0),
        removed: None,
    },
    MethNewDef {
        name: "DSA_meth_new",
        since: (3, 0),
        removed: None,
    },
    MethNewDef {
        name: "EVP_CIPHER_meth_new",
        since: (3, 0),
        removed: Some((4, 0)),
    },
    MethNewDef {
        name: "EVP_MD_meth_new",
        since: (3, 0),
        removed: Some((4, 0)),
    },
    MethNewDef {
        name: "EVP_PKEY_meth_new",
        since: (3, 0),
        removed: Some((4, 0)),
    },
    MethNewDef {
        name: "RSA_meth_new",
        since: (3, 0),
        removed: None,
    },
];

// --- Low-level families (empirical dynsym buckets) ---

/// One low-level family: dynsym symbol prefixes observed on lane
/// libcryptos. Counts below are per-lane defined-FUNC exports
/// (3.0/3.5/4.0); deltas are spelled out, never hidden in ranges.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FamilyDef {
    pub family: &'static str,
    pub prefixes: &'static [&'static str],
}

pub const LOWLEVEL: &[FamilyDef] = &[
    FamilyDef {
        family: "digest/sha",
        prefixes: &["SHA1_", "SHA224_", "SHA256_", "SHA384_", "SHA512_"],
    },
    FamilyDef {
        family: "digest/md",
        prefixes: &["MD4_", "MD5_"],
    },
    FamilyDef {
        family: "digest/legacy",
        prefixes: &["MDC2_", "RIPEMD160_", "WHIRLPOOL_"],
    },
    FamilyDef {
        family: "cipher/block",
        prefixes: &["DES_", "CAST_", "IDEA_", "SEED_", "BF_", "Camellia_"],
    },
    FamilyDef {
        family: "cipher/stream",
        prefixes: &["RC4_", "RC2_"],
    },
    FamilyDef {
        family: "cipher/aes",
        prefixes: &["AES_"],
    },
    FamilyDef {
        family: "pkey/rsa",
        prefixes: &["RSA_"],
    },
    FamilyDef {
        family: "pkey/dsa",
        prefixes: &["DSA_"],
    },
    FamilyDef {
        family: "pkey/dh",
        prefixes: &["DH_"],
    },
    FamilyDef {
        family: "pkey/ec",
        prefixes: &["EC_", "ECDSA_", "ECDH_"],
    },
    FamilyDef {
        family: "mac",
        prefixes: &["HMAC_", "CMAC_"],
    },
    FamilyDef {
        family: "rand",
        prefixes: &["RAND_"],
    },
    FamilyDef {
        family: "srp",
        prefixes: &["SRP_"],
    },
    FamilyDef {
        family: "bn",
        prefixes: &["BN_"],
    },
];

/// Low-level symbols removed in 4.x (all ENGINE-bound).
pub const LOWLEVEL_REMOVED_40: &[&str] = &[
    "RSA_get0_engine",
    "DSA_get0_engine",
    "DH_get0_engine",
    "EC_KEY_get0_engine",
    "RAND_set_rand_engine",
];

/// Low-level symbols added after 3.0 (version pins from dynsym tags).
pub const LOWLEVEL_ADDED: &[(&str, Version)] = &[
    ("RAND_set0_private", (3, 1)),
    ("RAND_set0_public", (3, 1)),
    ("EC_GROUP_to_params", (3, 2)),
    ("BN_are_coprime", (3, 5)),
    ("BN_signed_bin2bn", (3, 5)),
    ("BN_signed_bn2bin", (3, 5)),
    ("BN_signed_bn2lebin", (3, 5)),
    ("BN_signed_bn2native", (3, 5)),
    ("BN_signed_lebin2bn", (3, 5)),
    ("BN_signed_native2bn", (3, 5)),
    ("RAND_set1_random_provider", (3, 5)),
    ("EC_GROUP_security_bits", (4, 0)),
];

/// Low-level families with public headers but zero lane exports: the
/// lane builds disable them (`no-md2`, `no-rc5`). Tripwire probes must
/// report "absent", never error.
pub const LOWLEVEL_BUILD_DISABLED: &[&str] = &["MD2_", "RC5_"];

/// Families with no public low-level API upstream (EVP/provider-only;
/// observed via dispatch, never via `*_Init` symbols).
pub const LOWLEVEL_EVP_ONLY: &[&str] = &[
    "ChaCha", "Poly1305", "SipHash", "SM3", "SM4", "ARIA", "BLAKE2",
];

// --- Weak algorithms (judgment list, rationale per entry) ---

/*
 * WEAK_ALGS rationale (conservative; base names only — callers split
 * provider alias lists before matching):
 * BROKEN (practical break): MD4, MD5 (collision), SHA1 (collision),
 *   DES (56-bit brute force), RC4 (biases), MD2 (preimage-class age).
 * SWEET32 (64-bit block, birthday bound): 3DES/DES-EDE3, Blowfish/BF,
 *   RC2, IDEA, CAST/CAST5, SEED — still widely executed; the finding is
 *   "weak", not "broken".
 * OBSOLESCENT DES variants: DESX (whitened DES, obsolete lineage).
 * ANCESTOR (kept for inventory honesty, never recommended): SHA0, MDC2.
 * Deliberately NOT weak: SHA2/SHA3/BLAKE2 (unbroken), HMAC-MD5/HMAC-SHA1
 * (unbroken constructions — the base name never appears alone there).
 */
pub const WEAK_ALGS: &[&str] = &[
    "MD4", "MD5", "MD2", "SHA0", "SHA1", "MDC2", "DES", "DESX", "3DES", "DES-EDE3", "RC2", "RC4",
    "Blowfish", "BF", "IDEA", "CAST", "CAST5", "SEED",
];

// --- 4.0 algorithm-name additions ---

/// Provider algorithm names new in 4.0 (fetchable; P1 parse lanes).
pub const ALG_NAMES_ADDED_40: &[&str] = &[
    "SNMPKDF",
    "SRTPKDF", // KDF (core_names.h)
    "CSHAKE-128",
    "CSHAKE128",
    "CSHAKE-256",
    "CSHAKE256", // digest/XOF (names.h)
];

/// ML-DSA-MU is internal only (`ossl_ml_dsa_mu_*` helpers inside the
/// ML-DSA provider): no `OSSL_ALGORITHM` entry, not fetchable, not
/// observable via dispatch. Tracked here so nobody probes for it.
pub const INTERNAL_ONLY_MU: &str = "ML-DSA-MU";

// --- Provider load tripwire (P1 exit 3) ---

/// `OSSL_PROVIDER_*` load entrypoints: executed>0 trips the deny rule.
pub const PROVIDER_LOAD: &[&str] = &["OSSL_PROVIDER_load", "OSSL_PROVIDER_try_load"];
/// Lifecycle pair for load accounting (never a tripwire by itself).
pub const PROVIDER_UNLOAD: &str = "OSSL_PROVIDER_unload";

// --- Struct shapes (R12; LP64; identical 3.0/3.5/3.6/4.0) ---

/// One struct field: name, byte offset, byte size (LP64).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FieldDef {
    pub name: &'static str,
    pub offset: u64,
    pub size: u64,
}

/// One touched struct: total size + fields. Layouts are asserted
/// fail-closed by `ossl-discover/tests/fixture/layout_assert.c`,
/// compiled against each lane's real headers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShapeDef {
    pub name: &'static str,
    pub size: u64,
    pub fields: &'static [FieldDef],
}

pub const SHAPES: &[ShapeDef] = &[
    ShapeDef {
        name: "OSSL_DISPATCH",
        size: 16,
        fields: &[
            FieldDef {
                name: "function_id",
                offset: 0,
                size: 4,
            },
            FieldDef {
                name: "function",
                offset: 8,
                size: 8,
            },
        ],
    },
    ShapeDef {
        name: "OSSL_ITEM",
        size: 16,
        fields: &[
            FieldDef {
                name: "id",
                offset: 0,
                size: 4,
            },
            FieldDef {
                name: "ptr",
                offset: 8,
                size: 8,
            },
        ],
    },
    ShapeDef {
        name: "OSSL_ALGORITHM",
        size: 32,
        fields: &[
            FieldDef {
                name: "algorithm_names",
                offset: 0,
                size: 8,
            },
            FieldDef {
                name: "property_definition",
                offset: 8,
                size: 8,
            },
            FieldDef {
                name: "implementation",
                offset: 16,
                size: 8,
            },
            FieldDef {
                name: "algorithm_description",
                offset: 24,
                size: 8,
            },
        ],
    },
    ShapeDef {
        name: "OSSL_PARAM",
        size: 40,
        fields: &[
            FieldDef {
                name: "key",
                offset: 0,
                size: 8,
            },
            FieldDef {
                name: "data_type",
                offset: 8,
                size: 4,
            },
            FieldDef {
                name: "data",
                offset: 16,
                size: 8,
            },
            FieldDef {
                name: "data_size",
                offset: 24,
                size: 8,
            },
            FieldDef {
                name: "return_size",
                offset: 32,
                size: 8,
            },
        ],
    },
];

/// One provider algorithm-name segment: exact registry spelling, the
/// `PROV_NAMES_*` family it came from (`group` is a macro family, NOT an
/// `OSSL_OP_*` — op/name consistency rules are P1 exit 4's job), and the
/// first version whose tree contains it. Union across 3.0/3.5/3.6/4.0
/// (`names.h` + public `core_names.h`); 625 frozen entries plus the
/// T09 live-census appendix (67) — see the module header for the
/// re-freeze procedure and the appendix comment for its basis.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlgDef {
    pub name: &'static str,
    pub group: &'static str,
    pub since: Version,
}

pub const ALG_NAMES: &[AlgDef] = &[
    AlgDef {
        name: "0.3.4401.5.3.1.9.1",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.21",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.23",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.24",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.29",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.3",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.4",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.41",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.43",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.44",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.49",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "0.3.4401.5.3.1.9.9",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.1",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.10",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.2",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.3",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.4",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.7",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.8",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.156.10197.1.104.9",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.156.10197.1.504",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.392.200011.61.1.1.1.2",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.392.200011.61.1.1.1.3",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.392.200011.61.1.1.1.4",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200004.1.3",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200004.1.4",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200004.1.5",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200004.1.6",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.1",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.10",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.11",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.12",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.13",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.14",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.15",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.2",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.3",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.34",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.35",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.36",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.37",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.38",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.39",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.4",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.5",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.6",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.7",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.8",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.410.200046.1.1.9",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.1.101.3.4.3.3",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.1.101.3.4.3.4",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10040.4.3",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.4.1",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.4.3.1",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.4.3.2",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.4.3.3",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.4.3.4",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113533.7.66.10",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.10",
        group: "RSA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.11",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.12",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.13",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.14",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.15",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.16",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.2",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.3",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.4",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.5",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.9.16.3.28",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "1.2.840.113549.1.9.16.3.29",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "1.2.840.113549.1.9.16.3.30",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "1.2.840.113549.1.9.16.3.6",
        group: "DES3",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.113549.3.2",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.113549.3.7",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.2.840.113549.3.8",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.111.2.1619.0.1.1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.111.2.1619.0.1.2",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.14.3.2.17",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.14.3.2.6",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.14.3.2.7",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.14.3.2.8",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.14.3.2.9",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.36.3.2.1",
        group: "RIPEMD",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.36.3.3.1.2",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.6.1.4.1.1722.12.2.1.16",
        group: "BLAKE2B",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.6.1.4.1.1722.12.2.2.8",
        group: "BLAKE2S",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.6.1.4.1.188.7.1.1.2",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "1.3.6.1.4.1.3029.1.2",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.2",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.21",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.22",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.23",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.24",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.25",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.26",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.27",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.28",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.3",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.4",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.41",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.42",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.43",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.44",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.45",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.46",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.47",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.48",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.5",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.6",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.7",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1.8",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.1",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.10",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.11",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.12",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.19",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.2",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.20",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.3",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.4",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.5",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.6",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.7",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.8",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.2.9",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.1",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.10",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.11",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.12",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.13",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.14",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.15",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.16",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.17",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.18",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.19",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.2",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.20",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.21",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.22",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.23",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.24",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.25",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.26",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.27",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.28",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.29",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.30",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.31",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.5",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.6",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.7",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.8",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.3.9",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.4.1",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.4.2",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.4.3",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "AES-128-CBC",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CBC-CTS",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CBC-HMAC-SHA1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CBC-HMAC-SHA1-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-128-CBC-HMAC-SHA256",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CBC-HMAC-SHA256-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-128-CBC-HMAC-SHA512-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-128-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CFB1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CFB8",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-CTR",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-ECB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-GCM-SIV",
        group: "AES",
        since: (3, 5),
    },
    AlgDef {
        name: "AES-128-OCB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-OFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-SIV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-128-XTS",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CBC",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CBC-CTS",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CBC-HMAC-SHA1-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-192-CBC-HMAC-SHA256-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-192-CBC-HMAC-SHA512-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-192-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CFB1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CFB8",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-CTR",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-ECB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-GCM-SIV",
        group: "AES",
        since: (3, 5),
    },
    AlgDef {
        name: "AES-192-OCB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-OFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-SIV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-192-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CBC",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CBC-CTS",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CBC-HMAC-SHA1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CBC-HMAC-SHA1-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-256-CBC-HMAC-SHA256",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CBC-HMAC-SHA256-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-256-CBC-HMAC-SHA512-ETM",
        group: "AES",
        since: (3, 6),
    },
    AlgDef {
        name: "AES-256-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CFB1",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CFB8",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-CTR",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-ECB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-GCM-SIV",
        group: "AES",
        since: (3, 5),
    },
    AlgDef {
        name: "AES-256-OCB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-OFB",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-SIV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES-256-XTS",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES128",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES128-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES128-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES128-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES128-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES192",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES192-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES192-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES192-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES192-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES256",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES256-WRAP",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES256-WRAP-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES256-WRAP-PAD",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "AES256-WRAP-PAD-INV",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CBC",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CFB1",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CFB8",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-CTR",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-ECB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-GCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-128-OFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CBC",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CFB1",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CFB8",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-CTR",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-ECB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-GCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-192-OFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CBC",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CFB1",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CFB8",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-CTR",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-ECB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-GCM",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA-256-OFB",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA128",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA192",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "ARIA256",
        group: "ARIA",
        since: (3, 0),
    },
    AlgDef {
        name: "BF",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "BF-CBC",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "BF-CFB",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "BF-ECB",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "BF-OFB",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2B-512",
        group: "BLAKE2B",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2BMAC",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2S-256",
        group: "BLAKE2S",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2SMAC",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2b512",
        group: "BLAKE2B",
        since: (3, 0),
    },
    AlgDef {
        name: "BLAKE2s256",
        group: "BLAKE2S",
        since: (3, 0),
    },
    AlgDef {
        name: "BLOWFISH",
        group: "BF",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CBC",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CBC-CTS",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CFB1",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CFB8",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-CTR",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-ECB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-128-OFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CBC",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CBC-CTS",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CFB1",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CFB8",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-CTR",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-ECB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-192-OFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CBC",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CBC-CTS",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CFB1",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CFB8",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-CTR",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-ECB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA-256-OFB",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA128",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA192",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAMELLIA256",
        group: "CAMELLIA",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST-CBC",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST5-CBC",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST5-CFB",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST5-ECB",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CAST5-OFB",
        group: "CAST5",
        since: (3, 0),
    },
    AlgDef {
        name: "CMAC",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "CRNG-TEST",
        group: "CRNG",
        since: (3, 5),
    },
    AlgDef {
        name: "CSHAKE-128",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CSHAKE-256",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CSHAKE-KECCAK-128",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CSHAKE-KECCAK-256",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CSHAKE128",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CSHAKE256",
        group: "CSHAKE",
        since: (4, 0),
    },
    AlgDef {
        name: "CTR-DRBG",
        group: "CTR",
        since: (3, 0),
    },
    AlgDef {
        name: "DES",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-CBC",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-CFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-CFB1",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-CFB8",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-ECB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE-CBC",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE-CFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE-ECB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE-OFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-CBC",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-CFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-CFB1",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-CFB8",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-ECB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-EDE3-OFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES-OFB",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES3",
        group: "DES",
        since: (3, 0),
    },
    AlgDef {
        name: "DES3-WRAP",
        group: "DES3",
        since: (3, 0),
    },
    AlgDef {
        name: "DESX",
        group: "DESX",
        since: (3, 0),
    },
    AlgDef {
        name: "DESX-CBC",
        group: "DESX",
        since: (3, 0),
    },
    AlgDef {
        name: "DSA-SHA-1",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA1",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA2-224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA2-256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA2-384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA2-512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA3-224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA3-256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA3-384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA3-512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA-SHA512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA-1",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA1",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA2-224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA2-256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA2-384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA2-512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA3-224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA3-256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA3-384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA3-512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDSA-SHA512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "GMAC",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "HASH-DRBG",
        group: "HASH",
        since: (3, 0),
    },
    AlgDef {
        name: "HKDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "HKDF-SHA256",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "HKDF-SHA384",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "HKDF-SHA512",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "HMAC",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "HMAC-DRBG",
        group: "HMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "HMAC-DRBG-KDF",
        group: "HMAC",
        since: (3, 5),
    },
    AlgDef {
        name: "IDEA",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-CBC",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-CFB",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-CFB64",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-ECB",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-OFB",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "IDEA-OFB64",
        group: "IDEA",
        since: (3, 0),
    },
    AlgDef {
        name: "KBKDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "KECCAK-224",
        group: "KECCAK",
        since: (3, 5),
    },
    AlgDef {
        name: "KECCAK-256",
        group: "KECCAK",
        since: (3, 5),
    },
    AlgDef {
        name: "KECCAK-384",
        group: "KECCAK",
        since: (3, 5),
    },
    AlgDef {
        name: "KECCAK-512",
        group: "KECCAK",
        since: (3, 5),
    },
    AlgDef {
        name: "KECCAK-KMAC-128",
        group: "KECCAK",
        since: (3, 0),
    },
    AlgDef {
        name: "KECCAK-KMAC-256",
        group: "KECCAK",
        since: (3, 0),
    },
    AlgDef {
        name: "KECCAK-KMAC128",
        group: "KECCAK",
        since: (3, 0),
    },
    AlgDef {
        name: "KECCAK-KMAC256",
        group: "KECCAK",
        since: (3, 0),
    },
    AlgDef {
        name: "KMAC-128",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "KMAC-256",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "KMAC128",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "KMAC256",
        group: "KMAC",
        since: (3, 0),
    },
    AlgDef {
        name: "KRB5KDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "MD2",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "MD4",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "MD5",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "MD5-SHA1",
        group: "MD5",
        since: (3, 0),
    },
    AlgDef {
        name: "MDC2",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "ML-DSA-44",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "ML-DSA-65",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "ML-DSA-87",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "ML-DSA-MU",
        group: "ML",
        since: (4, 0),
    },
    AlgDef {
        name: "ML-KEM-1024",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "ML-KEM-512",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "ML-KEM-768",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLDSA44",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLDSA65",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLDSA87",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLKEM1024",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLKEM512",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "MLKEM768",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "PBKDF1",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "PBKDF2",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "POLY1305",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-128",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-40",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-40-CBC",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-64",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-64-CBC",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-CBC",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-CFB",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-ECB",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC2-OFB",
        group: "RC2",
        since: (3, 0),
    },
    AlgDef {
        name: "RC4-40",
        group: "RC4",
        since: (3, 0),
    },
    AlgDef {
        name: "RC4-HMAC-MD5",
        group: "RC4",
        since: (3, 0),
    },
    AlgDef {
        name: "RC5",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "RC5-CBC",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "RC5-CFB",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "RC5-ECB",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "RC5-OFB",
        group: "RC5",
        since: (3, 0),
    },
    AlgDef {
        name: "RIPEMD",
        group: "RIPEMD",
        since: (3, 0),
    },
    AlgDef {
        name: "RIPEMD-160",
        group: "RIPEMD",
        since: (3, 0),
    },
    AlgDef {
        name: "RIPEMD160",
        group: "RIPEMD",
        since: (3, 0),
    },
    AlgDef {
        name: "RMD160",
        group: "RIPEMD",
        since: (3, 0),
    },
    AlgDef {
        name: "RSA-MD2",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-MD4",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-MD5",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-PSS",
        group: "RSA",
        since: (3, 0),
    },
    AlgDef {
        name: "RSA-RIPEMD160",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA-1",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA1",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-384",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-512",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-512/224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA2-512/256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA3-224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA3-256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA3-384",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA3-512",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA384",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA512",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA512-224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SHA512-256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA-SM3",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSASSA-PSS",
        group: "RSA",
        since: (3, 0),
    },
    AlgDef {
        name: "SCRYPT",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-CBC",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-CFB",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-CFB128",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-ECB",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-OFB",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-OFB128",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SEED-SRC",
        group: "SEED",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-256/192",
        group: "SHA2",
        since: (3, 5),
    },
    AlgDef {
        name: "SHA-384",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-512",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-512/224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA-512/256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA1",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-256/192",
        group: "SHA2",
        since: (3, 5),
    },
    AlgDef {
        name: "SHA2-384",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-512",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-512/224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA2-512/256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA256-192",
        group: "SHA2",
        since: (3, 5),
    },
    AlgDef {
        name: "SHA3-224",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA3-256",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA3-384",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA3-512",
        group: "SHA3",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA384",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA512",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA512-224",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHA512-256",
        group: "SHA2",
        since: (3, 0),
    },
    AlgDef {
        name: "SHAKE-128",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "SHAKE-256",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "SHAKE128",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "SHAKE256",
        group: "SHAKE",
        since: (3, 0),
    },
    AlgDef {
        name: "SIPHASH",
        group: "MAC",
        since: (3, 0),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-128f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-128s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-192f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-192s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-256f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHA2-256s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-128f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-128s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-192f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-192s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-256f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SLH-DSA-SHAKE-256s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "SM3",
        group: "DIGEST",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-CBC",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-CCM",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "SM4-CFB",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-CFB128",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-CTR",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-ECB",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-GCM",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "SM4-OFB",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-OFB128",
        group: "SM4",
        since: (3, 0),
    },
    AlgDef {
        name: "SM4-XTS",
        group: "SM4",
        since: (3, 5),
    },
    AlgDef {
        name: "SNMPKDF",
        group: "KDF",
        since: (4, 0),
    },
    AlgDef {
        name: "SRTPKDF",
        group: "KDF",
        since: (4, 0),
    },
    AlgDef {
        name: "SSHKDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "SSKDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "TLS1-PRF",
        group: "TLS1",
        since: (3, 0),
    },
    AlgDef {
        name: "TLS13-KDF",
        group: "TLS1",
        since: (3, 0),
    },
    AlgDef {
        name: "X942KDF",
        group: "X942KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "X942KDF-ASN1",
        group: "X942KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "X942KDF-CONCAT",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "X963KDF",
        group: "KDF",
        since: (3, 0),
    },
    AlgDef {
        name: "dsaWithSHA1",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA3-224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA3-256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA3-384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA3-512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsa_with_SHA512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa-with-SHA1",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa-with-SHA224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa-with-SHA256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa-with-SHA384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa-with-SHA512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa_with_SHA3-224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa_with_SHA3-256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa_with_SHA3-384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ecdsa_with_SHA3-512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-aes128-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes128-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes128-wrap",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes128-wrap-pad",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes192-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes192-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes192-wrap",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes192-wrap-pad",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes256-CCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes256-GCM",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes256-wrap",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-aes256-wrap-pad",
        group: "AES",
        since: (3, 0),
    },
    AlgDef {
        name: "id-alg-hkdf-with-sha256",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "id-alg-hkdf-with-sha384",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "id-alg-hkdf-with-sha512",
        group: "HKDF",
        since: (3, 6),
    },
    AlgDef {
        name: "id-alg-ml-kem-1024",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-alg-ml-kem-512",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-alg-ml-kem-768",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha3-224",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha3-256",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha3-384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha3-512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha384",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-dsa-with-sha512",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ecdsa-with-sha3-224",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ecdsa-with-sha3-256",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ecdsa-with-sha3-384",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ecdsa-with-sha3-512",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ml-dsa-44",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ml-dsa-65",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ml-dsa-87",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-rsassa-pkcs1-v1_5-with-sha3-224",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-rsassa-pkcs1-v1_5-with-sha3-256",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-rsassa-pkcs1-v1_5-with-sha3-384",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-rsassa-pkcs1-v1_5-with-sha3-512",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-128f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-128s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-192f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-192s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-256f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-sha2-256s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-128f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-128s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-192f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-192s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-256f",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-slh-dsa-shake-256s",
        group: "SLH",
        since: (3, 5),
    },
    AlgDef {
        name: "id-smime-alg-CMS3DESwrap",
        group: "DES3",
        since: (3, 0),
    },
    AlgDef {
        name: "md2WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "md4WithEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "md5WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ripemd160WithRSA",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "rsassaPss",
        group: "RSA",
        since: (3, 6),
    },
    AlgDef {
        name: "sha1WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha224WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha256WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha384WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha512-224WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha512-256WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sha512WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "sm3WithRSAEncryption",
        group: "RSA",
        since: (3, 5),
    },
    // --- T09 appendix (67): ordinary default/legacy names missing
    // from the P1-0 freeze, verified against a live
    // OSSL_PROVIDER_query_operation census of the default and
    // legacy providers on host OpenSSL 3.5.5 (`query_dump` oracle;
    // 401 distinct (op, alias-list) rows, zero implementation-less
    // slots). Appended — never inserted — so every pre-existing
    // class id is stable. `since` is uniformly (3, 5): verified
    // present in 3.5; earlier presence is plausible for carried-over
    // names but was NOT re-confirmed on this lane (no 3.0 oracle;
    // T14's 3.0 lane can tighten with a census diff).
    AlgDef {
        name: "ECDSA",
        group: "ECDSA",
        since: (3, 5),
    },
    AlgDef {
        name: "ECDH",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "EC",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "X25519",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "X448",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "ED25519",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "ED25519ctx",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "ED25519ph",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "ED448",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "ED448ph",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "DH",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "DHX",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "X9.42 DH",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "dhKeyAgreement",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "dhpublicnumber",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "DSA",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "dsaEncryption",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "RSA",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "rsaEncryption",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "SM2",
        group: "SM2",
        since: (3, 5),
    },
    AlgDef {
        name: "id-ecPublicKey",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10040.4.1",
        group: "DSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10045.2.1",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.10046.2.1",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.1.1",
        group: "RSA",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.3.1",
        group: "DH",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.101.110",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.101.111",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.101.112",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.101.113",
        group: "EC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.156.10197.1.301",
        group: "SM2",
        since: (3, 5),
    },
    AlgDef {
        name: "ARGON2D",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "ARGON2I",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "ARGON2ID",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "PKCS12KDF",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "PVKKDF",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "SecP256r1MLKEM768",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "SecP384r1MLKEM1024",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "X25519MLKEM768",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "X448MLKEM1024",
        group: "ML",
        since: (3, 5),
    },
    AlgDef {
        name: "id-scrypt",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.6.1.4.1.11591.4.11",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.1.5.12",
        group: "KDF",
        since: (3, 5),
    },
    AlgDef {
        name: "ChaCha20",
        group: "CHACHA",
        since: (3, 5),
    },
    AlgDef {
        name: "ChaCha20-Poly1305",
        group: "CHACHA",
        since: (3, 5),
    },
    AlgDef {
        name: "RC4",
        group: "RC4",
        since: (3, 5),
    },
    AlgDef {
        name: "AES",
        group: "AES",
        since: (3, 5),
    },
    AlgDef {
        name: "GENERIC-SECRET",
        group: "SKEY",
        since: (3, 5),
    },
    AlgDef {
        name: "2.16.840.1.101.3.4.1",
        group: "AES",
        since: (3, 5),
    },
    AlgDef {
        name: "WHIRLPOOL",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "SHA-1",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "SSL3-MD5",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "SSL3-SHA1",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "NULL",
        group: "NULL",
        since: (3, 5),
    },
    AlgDef {
        name: "DER",
        group: "CODEC",
        since: (3, 5),
    },
    AlgDef {
        name: "file",
        group: "STORE",
        since: (3, 5),
    },
    AlgDef {
        name: "JITTER",
        group: "CRNG",
        since: (3, 5),
    },
    AlgDef {
        name: "TEST-RAND",
        group: "CRNG",
        since: (3, 5),
    },
    AlgDef {
        name: "1.0.10118.3.0.55",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "1.0.9797.3.4",
        group: "MAC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.156.10197.1.401",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.2.4",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.2.5",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "1.2.840.113549.3.4",
        group: "RC4",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.14.3.2.26",
        group: "DIGEST",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.6.1.4.1.1722.12.2.1",
        group: "MAC",
        since: (3, 5),
    },
    AlgDef {
        name: "1.3.6.1.4.1.1722.12.2.2",
        group: "MAC",
        since: (3, 5),
    },
];

// --- Lookups (linear; discovery-time only, never hot) ---

/// Operation id by `OSSL_OP_*` name.
pub fn op_id(name: &str) -> Option<u32> {
    OPS.iter().find(|o| o.name == name).map(|o| o.id)
}

/// Function id by op + `OSSL_FUNC_*` name. Core-dispatch ids (op `None`)
/// are found by name alone via [`core_func_id`].
pub fn func_id(op: &str, name: &str) -> Option<u32> {
    FUNCS
        .iter()
        .find(|f| f.op == Some(op) && f.name == name)
        .map(|f| f.id)
}

/// Core-dispatch (non-op-qualified) function id by name.
pub fn core_func_id(name: &str) -> Option<u32> {
    FUNCS
        .iter()
        .find(|f| f.op.is_none() && f.name == name)
        .map(|f| f.id)
}

/// ENGINE finding class by symbol name (3.x only).
pub fn engine_class(name: &str) -> Option<EngineClass> {
    ENGINE.iter().find(|e| e.name == name).map(|e| e.class)
}

/// True iff the symbol is a `*_meth_new` custom-method constructor
/// (P1 exit 3 distinct finding class; spans 3.x–4.x per [`METH_NEW`]).
pub fn is_meth_new(name: &str) -> bool {
    METH_NEW.iter().any(|m| m.name == name)
}

/// Low-level family by dynsym symbol name (prefix match).
pub fn lowlevel_family(symbol: &str) -> Option<&'static str> {
    LOWLEVEL
        .iter()
        .find(|f| f.prefixes.iter().any(|p| symbol.starts_with(p)))
        .map(|f| f.family)
}

/// Exact weak-name match. Callers split provider alias lists first.
pub fn is_weak_alg(base_name: &str) -> bool {
    WEAK_ALGS.contains(&base_name)
}

/// Emission classifier: split a provider `algorithm_names` alias list on
/// `:` and classify. Returns `(class, weak)` where `class` is the
/// canonical minimum — the lowest-index registry spelling over ALL
/// recognized segments (F-A/A5), else `"other"` when none is
/// recognized; alias order never changes the label. `weak` is true
/// iff ANY segment exactly matches [`WEAK_ALGS`]. Raw provider
/// bytes never leave this function except as `"other"`.
///
/// Since T02 the kernel classifies first (same rules, shared-table
/// backend) and userspace only decodes class ids; this function
/// remains the agreement oracle for the protocol tests.
pub fn classify_alg(names: &str) -> (&'static str, bool) {
    let mut best: Option<usize> = None;
    let mut weak = false;
    for seg in names.split(':') {
        if let Some(idx) = ALG_NAMES.iter().position(|a| a.name == seg) {
            best = Some(best.map_or(idx, |b| b.min(idx)));
        }
        if is_weak_alg(seg) {
            weak = true;
        }
    }
    (best.map_or("other", |b| ALG_NAMES[b].name), weak)
}

/// True iff the exact spelling is a registered algorithm name.
pub fn is_known_alg(name: &str) -> bool {
    ALG_NAMES.iter().any(|a| a.name == name)
}

/// The registry group of an exact spelling (`None` when
/// unregistered). Groups are `PROV_NAMES_*` macro families, NOT
/// semantic equivalence (R01): same-group distinct algorithms
/// (e.g. ML-KEM-512 vs ML-KEM-768, SHA2-256 vs SHA2-512) are
/// different algorithms. Mixed detection uses
/// [`algorithm_semantic_id`], never this.
pub fn alg_group(name: &str) -> Option<&'static str> {
    ALG_NAMES.iter().find(|a| a.name == name).map(|a| a.group)
}

/// Verified semantic-equivalence sets (R01, F01/F02): each inner
/// slice lists provider alias spellings proven to name one
/// algorithm. Provenance: verbatim `OSSL_ALGORITHM.algorithm_names`
/// rows from a live `OSSL_PROVIDER_query_operation` census over
/// every operation id on host OpenSSL 3.5.5 (default + legacy
/// providers, 2026-10-13; 660 rows): every row shape carrying ≥2
/// registered spellings contributes exactly one set (188 sets,
/// zero cross-row chains — each set is one row's alias family),
/// cross-checked against `openssl list` alias groups. Row
/// spellings rule: fetch conveniences (`aes128 => AES-128-CBC`)
/// and display spellings (`aes-128-gcm`) that never occur as a
/// row segment stay unmerged. Every member is present in the
/// frozen [`ALG_NAMES`] registry; unregistered row companions
/// are omitted (they can never classify or admit). Members
/// within one set share one semantic identity; names in
/// different sets — even in one macro `group` — are distinct
/// (sizes/modes stay split: ML-KEM-512 ≠ 768, SHA2-256 ≠ 512,
/// AES-128 ≠ 256, SM3 ≠ RSA-SM3). Unlisted names are singleton
/// identities. Never infer equivalence from `group`, name
/// similarity, or a provider assertion: only this table merges.
pub const ALG_SEMANTIC_EQUIV: &[&[&str]] = &[
    &["0.3.4401.5.3.1.9.1", "CAMELLIA-128-ECB"],
    &["0.3.4401.5.3.1.9.21", "CAMELLIA-192-ECB"],
    &["0.3.4401.5.3.1.9.23", "CAMELLIA-192-OFB"],
    &["0.3.4401.5.3.1.9.24", "CAMELLIA-192-CFB"],
    &["0.3.4401.5.3.1.9.29", "CAMELLIA-192-CTR"],
    &["0.3.4401.5.3.1.9.3", "CAMELLIA-128-OFB"],
    &["0.3.4401.5.3.1.9.4", "CAMELLIA-128-CFB"],
    &["0.3.4401.5.3.1.9.41", "CAMELLIA-256-ECB"],
    &["0.3.4401.5.3.1.9.43", "CAMELLIA-256-OFB"],
    &["0.3.4401.5.3.1.9.44", "CAMELLIA-256-CFB"],
    &["0.3.4401.5.3.1.9.49", "CAMELLIA-256-CTR"],
    &["0.3.4401.5.3.1.9.9", "CAMELLIA-128-CTR"],
    &["1.0.10118.3.0.55", "WHIRLPOOL"],
    &["1.0.9797.3.4", "GMAC"],
    &["1.2.156.10197.1.104.1", "SM4-ECB"],
    &["1.2.156.10197.1.104.10", "SM4-XTS"],
    &["1.2.156.10197.1.104.2", "SM4", "SM4-CBC"],
    &["1.2.156.10197.1.104.3", "SM4-OFB", "SM4-OFB128"],
    &["1.2.156.10197.1.104.4", "SM4-CFB", "SM4-CFB128"],
    &["1.2.156.10197.1.104.7", "SM4-CTR"],
    &["1.2.156.10197.1.104.8", "SM4-GCM"],
    &["1.2.156.10197.1.104.9", "SM4-CCM"],
    &["1.2.156.10197.1.301", "SM2"],
    &["1.2.156.10197.1.401", "SM3"],
    &["1.2.156.10197.1.504", "RSA-SM3", "sm3WithRSAEncryption"],
    &[
        "1.2.392.200011.61.1.1.1.2",
        "CAMELLIA-128-CBC",
        "CAMELLIA128",
    ],
    &[
        "1.2.392.200011.61.1.1.1.3",
        "CAMELLIA-192-CBC",
        "CAMELLIA192",
    ],
    &[
        "1.2.392.200011.61.1.1.1.4",
        "CAMELLIA-256-CBC",
        "CAMELLIA256",
    ],
    &["1.2.410.200004.1.3", "SEED-ECB"],
    &["1.2.410.200004.1.4", "SEED", "SEED-CBC"],
    &["1.2.410.200004.1.5", "SEED-CFB", "SEED-CFB128"],
    &["1.2.410.200004.1.6", "SEED-OFB", "SEED-OFB128"],
    &["1.2.410.200046.1.1.1", "ARIA-128-ECB"],
    &["1.2.410.200046.1.1.10", "ARIA-192-CTR"],
    &["1.2.410.200046.1.1.11", "ARIA-256-ECB"],
    &["1.2.410.200046.1.1.12", "ARIA-256-CBC", "ARIA256"],
    &["1.2.410.200046.1.1.13", "ARIA-256-CFB"],
    &["1.2.410.200046.1.1.14", "ARIA-256-OFB"],
    &["1.2.410.200046.1.1.15", "ARIA-256-CTR"],
    &["1.2.410.200046.1.1.2", "ARIA-128-CBC", "ARIA128"],
    &["1.2.410.200046.1.1.3", "ARIA-128-CFB"],
    &["1.2.410.200046.1.1.34", "ARIA-128-GCM"],
    &["1.2.410.200046.1.1.35", "ARIA-192-GCM"],
    &["1.2.410.200046.1.1.36", "ARIA-256-GCM"],
    &["1.2.410.200046.1.1.37", "ARIA-128-CCM"],
    &["1.2.410.200046.1.1.38", "ARIA-192-CCM"],
    &["1.2.410.200046.1.1.39", "ARIA-256-CCM"],
    &["1.2.410.200046.1.1.4", "ARIA-128-OFB"],
    &["1.2.410.200046.1.1.5", "ARIA-128-CTR"],
    &["1.2.410.200046.1.1.6", "ARIA-192-ECB"],
    &["1.2.410.200046.1.1.7", "ARIA-192-CBC", "ARIA192"],
    &["1.2.410.200046.1.1.8", "ARIA-192-CFB"],
    &["1.2.410.200046.1.1.9", "ARIA-192-OFB"],
    &[
        "1.2.840.1.101.3.4.3.3",
        "DSA-SHA2-384",
        "DSA-SHA384",
        "dsa_with_SHA384",
        "id-dsa-with-sha384",
    ],
    &[
        "1.2.840.1.101.3.4.3.4",
        "DSA-SHA2-512",
        "DSA-SHA512",
        "dsa_with_SHA512",
        "id-dsa-with-sha512",
    ],
    &["1.2.840.10040.4.1", "DSA", "dsaEncryption"],
    &["1.2.840.10040.4.3", "DSA-SHA-1", "DSA-SHA1", "dsaWithSHA1"],
    &["1.2.840.10045.2.1", "EC", "id-ecPublicKey"],
    &[
        "1.2.840.10045.4.1",
        "ECDSA-SHA-1",
        "ECDSA-SHA1",
        "ecdsa-with-SHA1",
    ],
    &[
        "1.2.840.10045.4.3.1",
        "ECDSA-SHA2-224",
        "ECDSA-SHA224",
        "ecdsa-with-SHA224",
    ],
    &[
        "1.2.840.10045.4.3.2",
        "ECDSA-SHA2-256",
        "ECDSA-SHA256",
        "ecdsa-with-SHA256",
    ],
    &[
        "1.2.840.10045.4.3.3",
        "ECDSA-SHA2-384",
        "ECDSA-SHA384",
        "ecdsa-with-SHA384",
    ],
    &[
        "1.2.840.10045.4.3.4",
        "ECDSA-SHA2-512",
        "ECDSA-SHA512",
        "ecdsa-with-SHA512",
    ],
    &["1.2.840.10046.2.1", "DHX", "X9.42 DH", "dhpublicnumber"],
    &["1.2.840.113533.7.66.10", "CAST", "CAST-CBC", "CAST5-CBC"],
    &["1.2.840.113549.1.1.1", "RSA", "rsaEncryption"],
    &["1.2.840.113549.1.1.10", "RSA-PSS", "RSASSA-PSS"],
    &[
        "1.2.840.113549.1.1.11",
        "RSA-SHA2-256",
        "RSA-SHA256",
        "sha256WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.12",
        "RSA-SHA2-384",
        "RSA-SHA384",
        "sha384WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.13",
        "RSA-SHA2-512",
        "RSA-SHA512",
        "sha512WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.14",
        "RSA-SHA2-224",
        "RSA-SHA224",
        "sha224WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.15",
        "RSA-SHA2-512/224",
        "RSA-SHA512-224",
        "sha512-224WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.16",
        "RSA-SHA2-512/256",
        "RSA-SHA512-256",
        "sha512-256WithRSAEncryption",
    ],
    &[
        "1.2.840.113549.1.1.5",
        "RSA-SHA-1",
        "RSA-SHA1",
        "sha1WithRSAEncryption",
    ],
    &["1.2.840.113549.1.3.1", "DH", "dhKeyAgreement"],
    &["1.2.840.113549.1.5.12", "PBKDF2"],
    &[
        "1.2.840.113549.1.9.16.3.6",
        "DES3-WRAP",
        "id-smime-alg-CMS3DESwrap",
    ],
    &["1.2.840.113549.2.4", "MD4"],
    &["1.2.840.113549.2.5", "MD5", "SSL3-MD5"],
    &["1.2.840.113549.3.2", "RC2", "RC2-128", "RC2-CBC"],
    &["1.2.840.113549.3.4", "RC4"],
    &["1.2.840.113549.3.7", "DES-EDE3-CBC", "DES3"],
    &["1.3.101.110", "X25519"],
    &["1.3.101.111", "X448"],
    &["1.3.101.112", "ED25519"],
    &["1.3.101.113", "ED448"],
    &["1.3.111.2.1619.0.1.1", "AES-128-XTS"],
    &["1.3.111.2.1619.0.1.2", "AES-256-XTS"],
    &["1.3.14.3.2.17", "DES-EDE", "DES-EDE-ECB"],
    &["1.3.14.3.2.26", "SHA-1", "SHA1", "SSL3-SHA1"],
    &["1.3.14.3.2.6", "DES-ECB"],
    &["1.3.14.3.2.7", "DES", "DES-CBC"],
    &["1.3.14.3.2.8", "DES-OFB"],
    &["1.3.14.3.2.9", "DES-CFB"],
    &[
        "1.3.36.3.2.1",
        "RIPEMD",
        "RIPEMD-160",
        "RIPEMD160",
        "RMD160",
    ],
    &["1.3.36.3.3.1.2", "RSA-RIPEMD160", "ripemd160WithRSA"],
    &["1.3.6.1.4.1.11591.4.11", "SCRYPT", "id-scrypt"],
    &["1.3.6.1.4.1.1722.12.2.1", "BLAKE2BMAC"],
    &["1.3.6.1.4.1.1722.12.2.1.16", "BLAKE2B-512", "BLAKE2b512"],
    &["1.3.6.1.4.1.1722.12.2.2", "BLAKE2SMAC"],
    &["1.3.6.1.4.1.1722.12.2.2.8", "BLAKE2S-256", "BLAKE2s256"],
    &["1.3.6.1.4.1.3029.1.2", "BF", "BF-CBC", "BLOWFISH"],
    &["2.16.840.1.101.3.4.1", "AES"],
    &["2.16.840.1.101.3.4.1.1", "AES-128-ECB"],
    &["2.16.840.1.101.3.4.1.2", "AES-128-CBC", "AES128"],
    &["2.16.840.1.101.3.4.1.21", "AES-192-ECB"],
    &["2.16.840.1.101.3.4.1.22", "AES-192-CBC", "AES192"],
    &["2.16.840.1.101.3.4.1.23", "AES-192-OFB"],
    &["2.16.840.1.101.3.4.1.24", "AES-192-CFB"],
    &[
        "2.16.840.1.101.3.4.1.25",
        "AES-192-WRAP",
        "AES192-WRAP",
        "id-aes192-wrap",
    ],
    &["2.16.840.1.101.3.4.1.26", "AES-192-GCM", "id-aes192-GCM"],
    &["2.16.840.1.101.3.4.1.27", "AES-192-CCM", "id-aes192-CCM"],
    &[
        "2.16.840.1.101.3.4.1.28",
        "AES-192-WRAP-PAD",
        "AES192-WRAP-PAD",
        "id-aes192-wrap-pad",
    ],
    &["2.16.840.1.101.3.4.1.3", "AES-128-OFB"],
    &["2.16.840.1.101.3.4.1.4", "AES-128-CFB"],
    &["2.16.840.1.101.3.4.1.41", "AES-256-ECB"],
    &["2.16.840.1.101.3.4.1.42", "AES-256-CBC", "AES256"],
    &["2.16.840.1.101.3.4.1.43", "AES-256-OFB"],
    &["2.16.840.1.101.3.4.1.44", "AES-256-CFB"],
    &[
        "2.16.840.1.101.3.4.1.45",
        "AES-256-WRAP",
        "AES256-WRAP",
        "id-aes256-wrap",
    ],
    &["2.16.840.1.101.3.4.1.46", "AES-256-GCM", "id-aes256-GCM"],
    &["2.16.840.1.101.3.4.1.47", "AES-256-CCM", "id-aes256-CCM"],
    &[
        "2.16.840.1.101.3.4.1.48",
        "AES-256-WRAP-PAD",
        "AES256-WRAP-PAD",
        "id-aes256-wrap-pad",
    ],
    &[
        "2.16.840.1.101.3.4.1.5",
        "AES-128-WRAP",
        "AES128-WRAP",
        "id-aes128-wrap",
    ],
    &["2.16.840.1.101.3.4.1.6", "AES-128-GCM", "id-aes128-GCM"],
    &["2.16.840.1.101.3.4.1.7", "AES-128-CCM", "id-aes128-CCM"],
    &[
        "2.16.840.1.101.3.4.1.8",
        "AES-128-WRAP-PAD",
        "AES128-WRAP-PAD",
        "id-aes128-wrap-pad",
    ],
    &["2.16.840.1.101.3.4.2.1", "SHA-256", "SHA2-256", "SHA256"],
    &["2.16.840.1.101.3.4.2.10", "SHA3-512"],
    &["2.16.840.1.101.3.4.2.11", "SHAKE-128", "SHAKE128"],
    &["2.16.840.1.101.3.4.2.12", "SHAKE-256", "SHAKE256"],
    &["2.16.840.1.101.3.4.2.19", "KMAC-128", "KMAC128"],
    &["2.16.840.1.101.3.4.2.2", "SHA-384", "SHA2-384", "SHA384"],
    &["2.16.840.1.101.3.4.2.20", "KMAC-256", "KMAC256"],
    &["2.16.840.1.101.3.4.2.3", "SHA-512", "SHA2-512", "SHA512"],
    &["2.16.840.1.101.3.4.2.4", "SHA-224", "SHA2-224", "SHA224"],
    &[
        "2.16.840.1.101.3.4.2.5",
        "SHA-512/224",
        "SHA2-512/224",
        "SHA512-224",
    ],
    &[
        "2.16.840.1.101.3.4.2.6",
        "SHA-512/256",
        "SHA2-512/256",
        "SHA512-256",
    ],
    &["2.16.840.1.101.3.4.2.7", "SHA3-224"],
    &["2.16.840.1.101.3.4.2.8", "SHA3-256"],
    &["2.16.840.1.101.3.4.2.9", "SHA3-384"],
    &[
        "2.16.840.1.101.3.4.3.1",
        "DSA-SHA2-224",
        "DSA-SHA224",
        "dsa_with_SHA224",
    ],
    &[
        "2.16.840.1.101.3.4.3.10",
        "ECDSA-SHA3-256",
        "ecdsa_with_SHA3-256",
        "id-ecdsa-with-sha3-256",
    ],
    &[
        "2.16.840.1.101.3.4.3.11",
        "ECDSA-SHA3-384",
        "ecdsa_with_SHA3-384",
        "id-ecdsa-with-sha3-384",
    ],
    &[
        "2.16.840.1.101.3.4.3.12",
        "ECDSA-SHA3-512",
        "ecdsa_with_SHA3-512",
        "id-ecdsa-with-sha3-512",
    ],
    &[
        "2.16.840.1.101.3.4.3.13",
        "RSA-SHA3-224",
        "id-rsassa-pkcs1-v1_5-with-sha3-224",
    ],
    &[
        "2.16.840.1.101.3.4.3.14",
        "RSA-SHA3-256",
        "id-rsassa-pkcs1-v1_5-with-sha3-256",
    ],
    &[
        "2.16.840.1.101.3.4.3.15",
        "RSA-SHA3-384",
        "id-rsassa-pkcs1-v1_5-with-sha3-384",
    ],
    &[
        "2.16.840.1.101.3.4.3.16",
        "RSA-SHA3-512",
        "id-rsassa-pkcs1-v1_5-with-sha3-512",
    ],
    &[
        "2.16.840.1.101.3.4.3.17",
        "ML-DSA-44",
        "MLDSA44",
        "id-ml-dsa-44",
    ],
    &[
        "2.16.840.1.101.3.4.3.18",
        "ML-DSA-65",
        "MLDSA65",
        "id-ml-dsa-65",
    ],
    &[
        "2.16.840.1.101.3.4.3.19",
        "ML-DSA-87",
        "MLDSA87",
        "id-ml-dsa-87",
    ],
    &[
        "2.16.840.1.101.3.4.3.2",
        "DSA-SHA2-256",
        "DSA-SHA256",
        "dsa_with_SHA256",
    ],
    &[
        "2.16.840.1.101.3.4.3.20",
        "SLH-DSA-SHA2-128s",
        "id-slh-dsa-sha2-128s",
    ],
    &[
        "2.16.840.1.101.3.4.3.21",
        "SLH-DSA-SHA2-128f",
        "id-slh-dsa-sha2-128f",
    ],
    &[
        "2.16.840.1.101.3.4.3.22",
        "SLH-DSA-SHA2-192s",
        "id-slh-dsa-sha2-192s",
    ],
    &[
        "2.16.840.1.101.3.4.3.23",
        "SLH-DSA-SHA2-192f",
        "id-slh-dsa-sha2-192f",
    ],
    &[
        "2.16.840.1.101.3.4.3.24",
        "SLH-DSA-SHA2-256s",
        "id-slh-dsa-sha2-256s",
    ],
    &[
        "2.16.840.1.101.3.4.3.25",
        "SLH-DSA-SHA2-256f",
        "id-slh-dsa-sha2-256f",
    ],
    &[
        "2.16.840.1.101.3.4.3.26",
        "SLH-DSA-SHAKE-128s",
        "id-slh-dsa-shake-128s",
    ],
    &[
        "2.16.840.1.101.3.4.3.27",
        "SLH-DSA-SHAKE-128f",
        "id-slh-dsa-shake-128f",
    ],
    &[
        "2.16.840.1.101.3.4.3.28",
        "SLH-DSA-SHAKE-192s",
        "id-slh-dsa-shake-192s",
    ],
    &[
        "2.16.840.1.101.3.4.3.29",
        "SLH-DSA-SHAKE-192f",
        "id-slh-dsa-shake-192f",
    ],
    &[
        "2.16.840.1.101.3.4.3.30",
        "SLH-DSA-SHAKE-256s",
        "id-slh-dsa-shake-256s",
    ],
    &[
        "2.16.840.1.101.3.4.3.31",
        "SLH-DSA-SHAKE-256f",
        "id-slh-dsa-shake-256f",
    ],
    &[
        "2.16.840.1.101.3.4.3.5",
        "DSA-SHA3-224",
        "dsa_with_SHA3-224",
        "id-dsa-with-sha3-224",
    ],
    &[
        "2.16.840.1.101.3.4.3.6",
        "DSA-SHA3-256",
        "dsa_with_SHA3-256",
        "id-dsa-with-sha3-256",
    ],
    &[
        "2.16.840.1.101.3.4.3.7",
        "DSA-SHA3-384",
        "dsa_with_SHA3-384",
        "id-dsa-with-sha3-384",
    ],
    &[
        "2.16.840.1.101.3.4.3.8",
        "DSA-SHA3-512",
        "dsa_with_SHA3-512",
        "id-dsa-with-sha3-512",
    ],
    &[
        "2.16.840.1.101.3.4.3.9",
        "ECDSA-SHA3-224",
        "ecdsa_with_SHA3-224",
        "id-ecdsa-with-sha3-224",
    ],
    &[
        "2.16.840.1.101.3.4.4.1",
        "ML-KEM-512",
        "MLKEM512",
        "id-alg-ml-kem-512",
    ],
    &[
        "2.16.840.1.101.3.4.4.2",
        "ML-KEM-768",
        "MLKEM768",
        "id-alg-ml-kem-768",
    ],
    &[
        "2.16.840.1.101.3.4.4.3",
        "ML-KEM-1024",
        "MLKEM1024",
        "id-alg-ml-kem-1024",
    ],
    &["AES-128-WRAP-INV", "AES128-WRAP-INV"],
    &["AES-128-WRAP-PAD-INV", "AES128-WRAP-PAD-INV"],
    &["AES-192-WRAP-INV", "AES192-WRAP-INV"],
    &["AES-192-WRAP-PAD-INV", "AES192-WRAP-PAD-INV"],
    &["AES-256-WRAP-INV", "AES256-WRAP-INV"],
    &["AES-256-WRAP-PAD-INV", "AES256-WRAP-PAD-INV"],
    &["DES-EDE3", "DES-EDE3-ECB"],
    &["DESX", "DESX-CBC"],
    &["KECCAK-KMAC-128", "KECCAK-KMAC128"],
    &["KECCAK-KMAC-256", "KECCAK-KMAC256"],
    &["RC2-40", "RC2-40-CBC"],
    &["RC2-64", "RC2-64-CBC"],
    &["SHA-256/192", "SHA2-256/192", "SHA256-192"],
    &["X942KDF", "X942KDF-ASN1"],
    &["X942KDF-CONCAT", "X963KDF"],
];

/// Finite semantic identity for one algorithm spelling (R01).
/// Merged names share their equivalence set's minimum registry
/// index; unlisted-but-registered names are singleton identities
/// (their own index); unregistered names are `None`. The id is
/// stable (frozen registry order), never [`OTHER_CLASS`], and
/// shared by classifier construction ([`crate::discovery::harvest`])
/// and policy predicate matching ([`crate::policy`]).
pub fn algorithm_semantic_id(name: &str) -> Option<u16> {
    let idx = ALG_NAMES.iter().position(|a| a.name == name)? as u16;
    for set in ALG_SEMANTIC_EQUIV {
        if set.contains(&name) {
            let mut min = idx;
            for member in *set {
                if let Some(i) = ALG_NAMES.iter().position(|a| a.name == *member) {
                    min = min.min(i as u16);
                }
            }
            return Some(min);
        }
    }
    Some(idx)
}

/// Decode a kernel algorithm class id to its registry label (T02
/// discovery wire ABI v2). `OTHER_CLASS` is `"other"`; anything past
/// the registry is `None` (fail closed to a dropped event, never to
/// a wrong label). Index order is the frozen `ALG_NAMES` order.
pub fn alg_class_label(id: u16) -> Option<&'static str> {
    if id == OTHER_CLASS {
        return Some("other");
    }
    ALG_NAMES.get(id as usize).map(|a| a.name)
}

/// Struct shape by type name.
pub fn shape(name: &str) -> Option<&ShapeDef> {
    SHAPES.iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn version_pinned() {
        assert_eq!(REGISTRY_VERSION, 1);
    }

    #[test]
    fn ops_unique_and_spotted() {
        let ids: HashSet<u32> = OPS.iter().map(|o| o.id).collect();
        assert_eq!(ids.len(), OPS.len());
        assert_eq!(op_id("OSSL_OP_DIGEST"), Some(1));
        assert_eq!(op_id("OSSL_OP_SKEYMGMT"), Some(15));
        assert_eq!(op_id("OSSL_OP_NOPE"), None);
        assert_eq!(OPS.len(), 14);
    }

    #[test]
    fn funcs_unique_per_op_and_spotted() {
        let keys: HashSet<(Option<&str>, u32)> = FUNCS.iter().map(|f| (f.op, f.id)).collect();
        assert_eq!(keys.len(), FUNCS.len());
        for f in FUNCS {
            if let Some(op) = f.op {
                assert!(op_id(op).is_some(), "func {} cites unknown {op}", f.name);
            }
        }
        assert_eq!(
            func_id("OSSL_OP_DIGEST", "OSSL_FUNC_DIGEST_NEWCTX"),
            Some(1)
        );
        assert_eq!(func_id("OSSL_OP_DIGEST", "OSSL_FUNC_DIGEST_INIT"), Some(2));
        assert_eq!(
            core_func_id("OSSL_FUNC_PROVIDER_QUERY_OPERATION"),
            Some(1027)
        );
        assert_eq!(core_func_id("OSSL_FUNC_DIGEST_INIT"), None);
        assert_eq!(FUNCS.len(), 280);
    }

    #[test]
    fn engine_classes_shaped() {
        let n = |c| ENGINE.iter().filter(|e| e.class == c).count();
        assert_eq!(n(EngineClass::Tripwire), 2);
        assert!(
            ENGINE
                .iter()
                .filter(|e| e.class == EngineClass::Register)
                .count()
                > 0
        );
        assert_eq!(n(EngineClass::Interception), 10);
        assert_eq!(ENGINE.len(), 132);
        assert_eq!(
            engine_class("ENGINE_set_default_digests"),
            Some(EngineClass::Interception)
        );
        assert_eq!(engine_class("ENGINE_by_id"), Some(EngineClass::Tripwire));
        assert_eq!(engine_class("NOT_AN_ENGINE_FN"), None);
        assert_eq!(METH_NEW.len(), 6);
        assert!(is_meth_new("RSA_meth_new") && is_meth_new("EVP_MD_meth_new"));
        assert!(!is_meth_new("RSA_new") && !is_meth_new("ENGINE_by_id"));
    }

    #[test]
    fn fetch_and_skey_shaped() {
        assert_eq!(FETCH.len(), 13);
        assert!(
            FETCH
                .iter()
                .any(|f| f.name == "EVP_MD_fetch" && f.since == (3, 0))
        );
        assert!(
            FETCH
                .iter()
                .any(|f| f.name == "EVP_SKEYMGMT_fetch" && f.since == (3, 5))
        );
        assert_eq!(SKEY.len(), 13);
        assert!(SKEY.iter().all(|s| s.since == (3, 5) || s.since == (3, 6)));
        assert!(
            SKEY.iter()
                .any(|s| s.name == "EVP_SKEY_import_SKEYMGMT" && s.since == (3, 6))
        );
    }

    #[test]
    fn lowlevel_families_cover_and_split() {
        assert_eq!(lowlevel_family("SHA256_Init"), Some("digest/sha"));
        assert_eq!(lowlevel_family("RSA_new"), Some("pkey/rsa"));
        assert_eq!(lowlevel_family("EC_KEY_new"), Some("pkey/ec"));
        assert_eq!(lowlevel_family("BN_new"), Some("bn"));
        assert_eq!(LOWLEVEL.len(), 14);
        assert_eq!(lowlevel_family("EVP_MD_fetch"), None);
        assert_eq!(lowlevel_family("printf"), None);
        assert!(LOWLEVEL_REMOVED_40.contains(&"RSA_get0_engine"));
        assert!(LOWLEVEL_BUILD_DISABLED.contains(&"MD2_"));
        assert!(LOWLEVEL_EVP_ONLY.contains(&"SM3"));
    }

    #[test]
    fn weak_and_added_names_sane() {
        assert!(is_weak_alg("MD5") && is_weak_alg("SHA1") && is_weak_alg("DES"));
        assert!(!is_weak_alg("SHA256") && !is_weak_alg("AES-256-GCM"));
        assert!(ALG_NAMES_ADDED_40.contains(&"SNMPKDF"));
        assert!(ALG_NAMES_ADDED_40.contains(&"CSHAKE-128"));
        assert_eq!(INTERNAL_ONLY_MU, "ML-DSA-MU");
        assert_eq!(PROVIDER_LOAD.len(), 2);
    }

    #[test]
    fn shapes_monotonic_and_spotted() {
        for s in SHAPES {
            let mut end = 0;
            for f in s.fields {
                assert!(f.offset >= end, "{} field {} overlaps", s.name, f.name);
                end = f.offset + f.size;
            }
            assert!(s.size >= end, "{} size too small", s.name);
        }
        let a = shape("OSSL_ALGORITHM").unwrap();
        assert_eq!((a.size, a.fields.len()), (32, 4));
        assert_eq!(shape("OSSL_NOPE"), None);
    }

    #[test]
    fn alg_table_shaped_and_spotted() {
        assert_eq!(ALG_NAMES.len(), 625 + 67);
        assert!(is_known_alg("SHA2-256"));
        assert!(is_known_alg("AES-256-GCM"));
        assert!(is_known_alg("CSHAKE-128"));
        assert!(is_known_alg("SNMPKDF"));
        assert!(!is_known_alg("SPIKE-SHA"));
        // TEST-RAND is registry since T09 (verified default-provider
        // RAND); the unknown canary moves to a still-absent name.
        assert!(is_known_alg("TEST-RAND"));
        assert!(!is_known_alg("NOPE-XYZ-9Q"));
        assert!(!is_known_alg(""));
    }

    #[test]
    fn classify_alg_rules() {
        assert_eq!(classify_alg("SHA2-256:SHA256"), ("SHA2-256", false));
        assert_eq!(classify_alg("SHA1:SHA-1"), ("SHA1", true));
        assert_eq!(classify_alg("MD5"), ("MD5", true));
        assert_eq!(classify_alg("SPIKE-SHA"), ("other", false));
        assert_eq!(classify_alg("canary-DOOM-7QZ"), ("other", false));
        assert_eq!(classify_alg("AES-256-GCM:MD5"), ("AES-256-GCM", true));
        assert_eq!(classify_alg(""), ("other", false));
        // F-A/A5: canonical minimum — order-free, non-primary
        // aliases identify the list.
        assert_eq!(classify_alg("SHA256:SHA2-256"), ("SHA2-256", false));
        assert_eq!(classify_alg("MD5:AES-256-GCM"), ("AES-256-GCM", true));
        assert_eq!(classify_alg("RC4:SHA2-256"), ("SHA2-256", true));
        assert_eq!(classify_alg("nope:MD5"), ("MD5", true));
        assert_eq!(classify_alg(":SHA2-256"), ("SHA2-256", false));
    }

    #[test]
    fn semantic_equiv_sets_verified_and_disjoint() {
        // R01 fix: 188 row-proven sets (pinned census 2026-10-13).
        // Every member registered, every set disjoint, distinct
        // sizes/modes never merged.
        assert_eq!(ALG_SEMANTIC_EQUIV.len(), 188);
        let mut seen: HashSet<&str> = HashSet::new();
        for set in ALG_SEMANTIC_EQUIV {
            assert!(set.len() >= 2, "set must merge: {set:?}");
            let mut inner: HashSet<&str> = HashSet::new();
            for member in *set {
                assert!(is_known_alg(member), "unregistered member: {member:?}");
                assert!(inner.insert(member), "dup in set: {member:?}");
                assert!(seen.insert(member), "member in two sets: {member:?}");
            }
            let first = algorithm_semantic_id(set[0]).unwrap();
            for member in &set[1..] {
                assert_eq!(
                    algorithm_semantic_id(member),
                    Some(first),
                    "set must share one id: {set:?}"
                );
            }
        }
        // Reviewer exemplars: stock rows share one id.
        assert_eq!(
            algorithm_semantic_id("AES-128-GCM"),
            algorithm_semantic_id("id-aes128-GCM")
        );
        assert_eq!(
            algorithm_semantic_id("AES-128-GCM"),
            algorithm_semantic_id("2.16.840.1.101.3.4.1.6")
        );
        assert_eq!(
            algorithm_semantic_id("AES-128-CBC"),
            algorithm_semantic_id("AES128")
        );
        assert_eq!(
            algorithm_semantic_id("SM3"),
            algorithm_semantic_id("1.2.156.10197.1.401")
        );
        assert_eq!(
            algorithm_semantic_id("RSA"),
            algorithm_semantic_id("rsaEncryption")
        );
        // F01-distinct algorithms stay split, never merged.
        for (a, b) in [
            ("ML-KEM-512", "ML-KEM-768"),
            ("SHA2-256", "SHA2-512"),
            ("SHA1", "MD5"),
            ("AES-128-CBC", "AES-256-CBC"),
            ("AES-128-GCM", "AES-256-GCM"),
            ("SM3", "RSA-SM3"),
            ("SM3", "sm3WithRSAEncryption"),
            ("DES-EDE3-CBC", "DES-EDE3-ECB"),
            ("RC2-40", "RC2-64"),
        ] {
            assert_ne!(
                algorithm_semantic_id(a),
                algorithm_semantic_id(b),
                "distinct algorithms must stay split: {a} vs {b}"
            );
        }
        assert_eq!(algorithm_semantic_id("NOPE-XYZ-9Q"), None);
    }

    #[test]
    fn addr_hash_vector() {
        // Independent vector (python hashlib): tag || "08:01" || 0x00 ||
        // le64(1234) || le64(0x1000) → low64 hex.
        assert_eq!(addr_hash("08:01", 1234, 0x1000), "80d7552b021f6097");
        // Shape: 16 lowercase hex chars, and the degenerate triple hashes.
        let d = addr_hash("", 0, 0);
        assert_eq!(d.len(), 16);
        assert!(d.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn prov_hash_vector() {
        assert_eq!(
            prov_hash(b"test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    /// Lane-anchored invariant: the local 4.0 libcrypto exports zero
    /// `ENGINE_*` (P1-0 proved it; this test re-proves it wherever a
    /// 4.0 lane checkout exists, and skips loudly elsewhere).
    #[test]
    fn engine_absent_in_local_40() {
        let dir = "/opt/openssl-4.0.2/lib64";
        if !std::path::Path::new(dir).exists() {
            eprintln!("SKIP: no {dir} (non-lane host)");
            return;
        }
        let bytes = std::fs::read(format!("{dir}/libcrypto.so")).unwrap();
        let obj = goblin::Object::parse(&bytes).unwrap();
        let goblin::Object::Elf(elf) = obj else {
            panic!("not ELF")
        };
        let mut n = 0;
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name.starts_with("ENGINE_") {
                    n += 1;
                }
            }
        }
        assert_eq!(n, 0, "4.0 libcrypto exports ENGINE_*");
    }
}
