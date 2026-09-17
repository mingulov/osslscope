//! Frozen version-keyed registries (P1-0 freezes content; see kinds
//! tables + hash preimages + struct-shape assertions as P1-0 lands).
//!
//! Invariant: every table is `&'static` data with a per-entry source
//! comment (OpenSSL header + version). No runtime mutation.

/// Registry schema version. Bumped only by a P1-0-recorded re-freeze.
pub const REGISTRY_VERSION: u32 = 0;
