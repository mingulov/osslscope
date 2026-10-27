// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive, file-backed interface inventory. Compatibility is a candidate
//! property; it proves neither vendor authenticity nor provider activation.

pub mod elf;

use serde::{Deserialize, Serialize};

/// Recognized dynamic code exports. Unknown symbol names are discarded.
/// Declaration order also gives the stable, deduplicated export order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Api {
    OsslProviderInit,
    OsslProviderLoad,
    OsslProviderTryLoad,
    OsslProviderUnload,
    OsslProviderLoadEx,
    OsslProviderTryLoadEx,
    OsslProviderAddBuiltin,
    OsslProviderGet0Dispatch,
    OsslProviderQueryOperation,
    #[serde(rename = "openssl_init_crypto")]
    OpenSslInitCrypto,
    #[serde(rename = "openssl_version_major")]
    OpenSslVersionMajor,
    EvpMdFetch,
    EvpCipherFetch,
    EvpMacFetch,
    EvpKdfFetch,
    EvpSignatureFetch,
    EvpKemFetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Other,
}

/// Interface/dependency evidence only, with no vendor or runtime claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    #[serde(rename = "openssl_compatible")]
    OpenSslCompatible,
    ProviderModule,
    #[serde(rename = "openssl_consumer")]
    OpenSslConsumer,
    Other,
}

/// Finite failure labels: underlying IO/parser messages never escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    Unavailable,
    NonRegular,
    TooLarge,
    NotElf,
    MalformedElf,
    Changed,
    UnsupportedArchitecture,
    ProcessUnavailable,
    IdentityUnverified,
    ReadLimit,
    ProcessLimit,
    ObjectLimit,
    MalformedMaps,
    Deadline,
}

/// File identity plus finite interface evidence; never paths or raw symbols.
/// `device` is the native Linux `st_dev` value, paired with `st_ino`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub architecture: Architecture,
    pub kind: ObjectKind,
    pub exports: Vec<Api>,
    pub depends_on_libcrypto: bool,
    pub depends_on_libssl: bool,
}
