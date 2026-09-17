//! Frozen version-keyed registries (P1-0 freezes content; see kinds
//! tables + hash preimages + struct-shape assertions as P1-0 lands).
//!
//! Invariant: every table is `&'static` data with a per-entry source
//! comment (OpenSSL header + version). No runtime mutation.

/// Registry schema version. Bumped only by a P1-0-recorded re-freeze.
pub const REGISTRY_VERSION: u32 = 0;

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
