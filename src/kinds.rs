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

/// (major, minor) OpenSSL version key.
pub type Version = (u32, u32);

/// `addr_hash` preimage (frozen P1-0): the 8-byte little-endian
/// dispatch-callback address, hashed with FNV-1a/64. Goldens compare
/// hash fields after redacting raw `addr` (P1 exit 1).
pub fn addr_hash(addr: u64) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in addr.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
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
        assert_eq!(
            ENGINE
                .iter()
                .filter(|e| e.class == EngineClass::Register)
                .count()
                > 0,
            true
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
    fn addr_hash_stable() {
        // Preimage lock: le64(0x1000) under FNV-1a/64.
        assert_eq!(addr_hash(0x1000), 0x53a03f8d0add0c15);
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
