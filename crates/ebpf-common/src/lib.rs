//! SPDX-License-Identifier: GPL-3.0-or-later
//! Key/value structs shared between `crates/ebpf` and userspace.
//! Single source of truth for the P2 capture-map wire format; both
//! sides `include` this crate, so drift is a compile error, not a
//! golden mismatch. `no_std`-compatible; the `user` feature gates
//! userspace-only impls (drain-side aggregation helpers).
#![no_std]

/// COUNTS key: plan cookie (u32) in the high half, generation epoch
/// (u32) in the low half. Cookies are attach-time plan indices (<
/// 2^32 by construction); the generation fences re-plans (§5).
pub const fn make_key(cookie: u32, generation: u32) -> u64 {
    ((cookie as u64) << 32) | (generation as u64)
}

/// Split a COUNTS key back into (cookie, generation).
pub const fn split_key(key: u64) -> (u32, u32) {
    ((key >> 32) as u32, key as u32)
}

/// Per-key aggregate. `count` saturates (never wraps);
/// `first_ns`/`last_ns` are `bpf_ktime_get_ns` window bounds, NOT
/// latency (latency is v2+). 24 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountValue {
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

const _: () = assert!(size_of::<CountValue>() == 24);
const _: () = assert!(align_of::<CountValue>() == 8);

/// Typed map reads over the drain path. Sound: `repr(C)`, all-`u64`,
/// zero padding (size 24 = 3×8, asserted above), `Copy`.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CountValue {}

/// Userspace drain-side fold: saturating sum + min/max bounds.
#[cfg(feature = "user")]
impl CountValue {
    pub fn fold(&mut self, other: &CountValue) {
        if other.count == 0 {
            return;
        }
        let was_empty = self.count == 0;
        self.count = self.count.saturating_add(other.count);
        if was_empty || other.first_ns < self.first_ns {
            self.first_ns = other.first_ns;
        }
        if was_empty || other.last_ns > self.last_ns {
            self.last_ns = other.last_ns;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let (c, g) = (0xDEAD_BEEF, 0x1234_5678);
        assert_eq!(split_key(make_key(c, g)), (c, g));
        assert_eq!(make_key(1, 0), 1 << 32);
    }

    #[cfg(feature = "user")]
    #[test]
    fn fold_bounds() {
        let mut a = CountValue {
            count: 2,
            first_ns: 10,
            last_ns: 20,
        };
        a.fold(&CountValue {
            count: 3,
            first_ns: 5,
            last_ns: 15,
        });
        assert_eq!(
            a,
            CountValue {
                count: 5,
                first_ns: 5,
                last_ns: 20
            }
        );
        a.fold(&CountValue {
            count: u64::MAX,
            first_ns: 0,
            last_ns: 99,
        });
        assert_eq!(a.count, u64::MAX);
        assert_eq!((a.first_ns, a.last_ns), (0, 99));
    }
}
