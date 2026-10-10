//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned provider-class enrollment (T09): map a verified object
//! identity (GNU build-id) to a finite provider class, or resolve to
//! unknown. This is the sole provider-class authority for discovery;
//! filenames, display locators, and load-request strings are never
//! inputs (a renamed `fips.so` or a decoy provider loaded under
//! another name resolves to unknown unless its exact bytes are
//! enrolled).
//!
//! Precedence (first hit wins):
//! 1. Pinned enrollment hit: the live object's build-id is recorded
//!    in the explicitly selected table with a class.
//! 2. Operator builtin assertion (`--builtin`): the observed arrays
//!    are the in-libcrypto default provider by OpenSSL architecture
//!    and operator attestation, not by filename.
//! 3. Otherwise unknown (`None`): file-provider mode without
//!    enrollment. Callers keep their existing opaque third-party
//!    identity synthesis; absence of a class is not absence of code.
//!
//! A pinned `fips` class is provenance metadata (these exact bytes
//! were recorded as the FIPS module by the operator). It is never a
//! FIPS 140 certification claim, and it says nothing about
//! provider honesty or KAT coverage: parameter-only digest identity
//! and unlabeled KATs stay honest policy-layer limits (spec R06).
//!
//! Format (reviewed local enrollment, `table_version: 1`):
//! ```json
//! {"table_version": 1, "entries": [
//!   {"build_id": "<lowercase hex, 16..=128 chars>",
//!    "provider_class": "default|legacy|fips|third-party",
//!    "openssl": "3.5.5 (display only)",
//!    "note": "lab build 2026-10-01 (display only)"}]}
//! ```
//! `openssl`/`note` are operator display hints, never authority.
//! Unknown JSON fields are ignored (forward tolerance); unknown
//! classes, malformed ids, and duplicate ids fail closed.
use anyhow::{Context as _, anyhow, bail};
use std::collections::HashMap;

/// Enrollment schema version. Bump only with a recorded review.
pub const TABLE_VERSION: u32 = 1;

/// Finite provider classes. No other spelling is representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderClass {
    Default,
    Legacy,
    Fips,
    ThirdParty,
}

impl ProviderClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderClass::Default => "default",
            ProviderClass::Legacy => "legacy",
            ProviderClass::Fips => "fips",
            ProviderClass::ThirdParty => "third-party",
        }
    }

    /// Strict parse: exact lowercase finite vocabulary only.
    /// `fips.so`, `FIPS`, and every other near-miss are `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(ProviderClass::Default),
            "legacy" => Some(ProviderClass::Legacy),
            "fips" => Some(ProviderClass::Fips),
            "third-party" => Some(ProviderClass::ThirdParty),
            _ => None,
        }
    }
}

/// One reviewed enrollment entry.
#[derive(Debug, Clone)]
pub struct ProviderEntry {
    pub class: ProviderClass,
    /// Display only (provenance hint, never authority).
    pub openssl: String,
    /// Display only (operator note, never authority).
    pub note: String,
}

/// Explicitly selected local enrollment table (empty = none).
#[derive(Debug, Clone, Default)]
pub struct ProviderTable {
    by_id: HashMap<String, ProviderEntry>,
}

impl ProviderTable {
    pub fn empty() -> Self {
        ProviderTable::default()
    }

    pub fn by_build_id(&self, id: &str) -> Option<&ProviderEntry> {
        self.by_id.get(id)
    }

    pub fn entry_count(&self) -> usize {
        self.by_id.len()
    }
}

/// Build-id shape: even-length lowercase hex, 16..=128 chars
/// (sha1 note = 40, sha256 = 64). Shared by the offset table
/// (builtin ladder) and this enrollment table: one home, no drift.
pub fn validate_build_id(id: &str) -> anyhow::Result<()> {
    if !(16..=128).contains(&id.len()) || !id.len().is_multiple_of(2) {
        bail!("build_id has bad length (want even hex, 16..=128 chars)");
    }
    if !id.bytes().all(|b| b.is_ascii_hexdigit()) || id.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("build_id is not lowercase hex");
    }
    Ok(())
}

/// Parse enrollment JSON (schema `table_version: 1`).
pub fn load_table_str(s: &str) -> anyhow::Result<ProviderTable> {
    let v: serde_json::Value = serde_json::from_str(s).context("provider table JSON parse")?;
    if v.get("table_version").and_then(|n| n.as_u64()) != Some(TABLE_VERSION as u64) {
        bail!("unsupported table_version (want 1)");
    }
    let mut t = ProviderTable::empty();
    for e in v
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let id = e
            .get("build_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("provider entry lacks build_id"))?;
        validate_build_id(id)?;
        let class = e
            .get("provider_class")
            .and_then(|s| s.as_str())
            .and_then(ProviderClass::parse)
            .ok_or_else(|| anyhow!("provider entry lacks a known provider_class"))?;
        if t.by_id.contains_key(id) {
            bail!("provider entry duplicates build_id {id}");
        }
        t.by_id.insert(
            id.to_string(),
            ProviderEntry {
                class,
                openssl: e
                    .get("openssl")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string(),
                note: e
                    .get("note")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
            },
        );
    }
    Ok(t)
}

/// Resolution inputs. Deliberately three fields: there is no
/// filename, locator, or load-string input to misuse.
pub struct ResolutionInputs<'a> {
    /// Live object's verified GNU build-id (`None` = unreadable).
    pub build_id: Option<&'a str>,
    /// Explicitly selected enrollment (empty = none enrolled).
    pub table: &'a ProviderTable,
    /// Operator `--builtin` assertion: observing the in-libcrypto
    /// default provider.
    pub builtin_asserted: bool,
}

/// Resolve the provider class: pinned hit, else builtin assertion,
/// else unknown (`None`). Total: never errors, never guesses.
pub fn resolve_provider_class(inputs: &ResolutionInputs) -> Option<ProviderClass> {
    if let Some(id) = inputs.build_id
        && let Some(e) = inputs.table.by_build_id(id)
    {
        return Some(e.class);
    }
    if inputs.builtin_asserted {
        return Some(ProviderClass::Default);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_shapes() {
        validate_build_id("b12cd44337cb70619dd290b2396ab5dfcaea230f").unwrap();
        validate_build_id(&"ab".repeat(64)).unwrap();
        for bad in [
            "",
            "abc",
            "ab",
            &"ab".repeat(7),
            "zz00000000000000000000000000000000000000",
            "B12CD44337CB70619DD290B2396AB5DFCAEA230F",
            "0xb12cd44337cb70619dd290b2396ab5dfcaea230f",
        ] {
            assert!(validate_build_id(bad).is_err(), "accepted {bad:?}");
        }
        // Odd length fails even when otherwise hex.
        assert!(validate_build_id(&"a".repeat(17)).is_err());
    }

    #[test]
    fn pin_beats_builtin() {
        let t = load_table_str(
            r#"{"table_version": 1, "entries": [
                {"build_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "provider_class": "third-party"}]}"#,
        )
        .unwrap();
        assert_eq!(
            resolve_provider_class(&ResolutionInputs {
                build_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                table: &t,
                builtin_asserted: true,
            }),
            Some(ProviderClass::ThirdParty)
        );
    }
}
