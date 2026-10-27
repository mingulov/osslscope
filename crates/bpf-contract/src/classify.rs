// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{AlgClassValue, TripClassValue, ALG_WINDOW};

const FNV_BASIS: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

#[inline]
fn hash_octet(hash: u64, octet: u8) -> u64 {
    (hash ^ u64::from(octet)).wrapping_mul(FNV_PRIME)
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = FNV_BASIS;
    for &octet in bytes {
        hash = hash_octet(hash, octet);
    }
    hash
}

#[derive(Copy, Clone)]
pub struct AlgVerdict {
    pub class: u16,
    pub weak: bool,
    pub status: u8,
}

#[derive(Copy, Clone)]
pub struct TripVerdict {
    pub class: u16,
    pub status: u8,
}

#[derive(Copy, Clone)]
pub enum TripTaxonomy {
    Engine,
    Load,
}

struct AlgEvidence(crate::provider_observation::FiniteEvidence);
impl AlgEvidence {
    fn new() -> Self {
        Self(crate::provider_observation::FiniteEvidence::new())
    }
    fn include<F: Fn(u64) -> Option<AlgClassValue>>(&mut self, hash: u64, len: usize, lookup: &F) {
        if len > 36 {
            return;
        }
        let Some(entry) = lookup(hash) else { return };
        if usize::from(entry.len) == len {
            self.0.include(entry.class, entry.weak, entry.canon);
        }
    }
    fn verdict(self, truncated: bool) -> AlgVerdict {
        let (class, weak, status) = self.0.finish(truncated);
        AlgVerdict {
            class,
            weak,
            status,
        }
    }
}

pub fn classify_alg_with<F>(
    buf: &[u8; ALG_WINDOW],
    len: usize,
    saturated: bool,
    lookup: F,
) -> AlgVerdict
where
    F: Fn(u64) -> Option<AlgClassValue>,
{
    if saturated || len >= ALG_WINDOW {
        return AlgVerdict {
            class: u16::MAX,
            weak: false,
            status: 2,
        };
    }

    let mut evidence = AlgEvidence::new();
    let mut hash = FNV_BASIS;
    let mut segment_len = 0;
    let mut completed = 0;
    for &octet in &buf[..len] {
        if octet == b':' {
            evidence.include(hash, segment_len, &lookup);
            completed += 1;
            if completed == 8 {
                return evidence.verdict(true);
            }
            hash = FNV_BASIS;
            segment_len = 0;
        } else {
            hash = hash_octet(hash, octet);
            segment_len += 1;
        }
    }
    evidence.include(hash, segment_len, &lookup);
    evidence.verdict(false)
}

pub fn classify_trip_with<F>(
    arg: &[u8],
    saturated: bool,
    taxonomy: TripTaxonomy,
    lookup: F,
) -> TripVerdict
where
    F: Fn(u64) -> Option<TripClassValue>,
{
    if saturated || arg.len() >= 32 {
        return TripVerdict {
            class: 0,
            status: 2,
        };
    }
    if arg.len() > 16 {
        return TripVerdict {
            class: 0,
            status: 0,
        };
    }
    let Some(entry) = lookup(hash_bytes(arg)) else {
        return TripVerdict {
            class: 0,
            status: 0,
        };
    };
    if usize::from(entry.len) != arg.len() || entry.name[..arg.len()] != *arg {
        return TripVerdict {
            class: 0,
            status: 0,
        };
    }
    let class = match taxonomy {
        TripTaxonomy::Engine => entry.engine,
        TripTaxonomy::Load => entry.load,
    };
    TripVerdict { class, status: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_parameters_and_octet_order() {
        assert_eq!(hash_bytes(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(hash_bytes(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(hash_bytes(b"b"), 0xaf63_df4c_8601_f1a5);
        assert_eq!(hash_bytes(b"\0"), 0xaf63_bd4c_8601_b7df);
        assert_eq!(hash_bytes(b"a\0b"), 0xe5d2_9919_0426_66b2);
    }
}
