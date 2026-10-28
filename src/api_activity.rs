// SPDX-License-Identifier: GPL-3.0-or-later
//! Public scalar API activity, independent of algorithm and callback attribution.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ApiId(u32);
impl TryFrom<u32> for ApiId {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (20..=48).contains(&value) {
            Ok(Self(value))
        } else {
            Err("unsupported_public_api")
        }
    }
}
impl From<ApiId> for u32 {
    fn from(value: ApiId) -> Self {
        value.0
    }
}
impl ApiId {
    pub(crate) const fn constant(value: u32) -> Self {
        assert!(value >= 20 && value <= 48);
        Self(value)
    }
    pub fn export_name(self) -> &'static str {
        API_NAMES[(self.0 - 20) as usize]
    }
    pub fn all() -> impl Iterator<Item = Self> {
        (20..=48).map(Self)
    }
}
pub const API_NAMES: [&str; 29] = [
    "EVP_DigestInit_ex",
    "EVP_DigestInit_ex2",
    "EVP_DigestUpdate",
    "EVP_DigestFinal_ex",
    "EVP_EncryptInit_ex",
    "EVP_EncryptInit_ex2",
    "EVP_EncryptUpdate",
    "EVP_EncryptFinal_ex",
    "EVP_DecryptInit_ex",
    "EVP_DecryptInit_ex2",
    "EVP_DecryptUpdate",
    "EVP_DecryptFinal_ex",
    "EVP_CipherInit_ex",
    "EVP_CipherUpdate",
    "EVP_CipherFinal_ex",
    "EVP_MAC_init",
    "EVP_MAC_update",
    "EVP_MAC_final",
    "EVP_KDF_derive",
    "EVP_PKEY_sign",
    "EVP_PKEY_verify",
    "EVP_PKEY_encrypt",
    "EVP_PKEY_decrypt",
    "EVP_PKEY_derive",
    "EVP_DigestSignFinal",
    "EVP_DigestVerifyFinal",
    "EVP_DigestSign",
    "EVP_DigestVerify",
    "EVP_RAND_generate",
];
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiActivityGaps {
    pub map: u64,
    pub depth: u64,
    pub unpaired: u64,
    pub tail: u64,
    pub unsupported_return: u64,
    pub saturated: bool,
    /// No operational export was successfully attached for this ID.
    pub not_attached: bool,
    /// Available prefix only: attachment cannot establish first call coverage.
    pub attachment: bool,
    /// Detachment does not prove a synchronized terminal cut.
    pub finality: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiActivityRow {
    pub api: ApiId,
    pub entries: u64,
    pub observed_success: u64,
    pub observed_failure: u64,
    /// Subset of observed failure returns from verification APIs only.
    pub verification_mismatch: u64,
    /// Documented -2 subset of observed PKEY failure returns.
    pub unsupported: u64,
    pub gaps: ApiActivityGaps,
}

/// Fold disjoint attachment lifetimes once, never repeated map snapshots.
pub(crate) fn merge(rows: Vec<ApiActivityRow>) -> anyhow::Result<Vec<ApiActivityRow>> {
    let mut result: std::collections::BTreeMap<_, _> = ApiId::all()
        .map(|api| (api, ApiActivityRow::unavailable(api)))
        .collect();
    for row in rows {
        if let Some(total) = result.get_mut(&row.api) {
            macro_rules! add {
                ($a:expr, $b:expr) => {
                    $a = $a
                        .checked_add($b)
                        .ok_or_else(|| anyhow::anyhow!("API activity overflow"))?;
                };
            }
            add!(total.entries, row.entries);
            add!(total.observed_success, row.observed_success);
            add!(total.observed_failure, row.observed_failure);
            add!(total.verification_mismatch, row.verification_mismatch);
            add!(total.unsupported, row.unsupported);
            add!(total.gaps.map, row.gaps.map);
            add!(total.gaps.depth, row.gaps.depth);
            add!(total.gaps.unpaired, row.gaps.unpaired);
            add!(total.gaps.tail, row.gaps.tail);
            add!(total.gaps.unsupported_return, row.gaps.unsupported_return);
            total.gaps.saturated |= row.gaps.saturated;
            total.gaps.not_attached &= row.gaps.not_attached;
            total.gaps.attachment |= row.gaps.attachment;
            total.gaps.finality |= row.gaps.finality;
        } else {
            result.insert(row.api, row);
        }
    }
    Ok(result.into_values().collect())
}

impl ApiActivityRow {
    pub(crate) fn unavailable(api: ApiId) -> Self {
        Self {
            api,
            entries: 0,
            observed_success: 0,
            observed_failure: 0,
            verification_mismatch: 0,
            unsupported: 0,
            gaps: ApiActivityGaps {
                not_attached: true,
                attachment: true,
                finality: true,
                ..Default::default()
            },
        }
    }
}
