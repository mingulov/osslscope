//! SPDX-License-Identifier: GPL-3.0-or-later
//! libcrypto flavor classifier (P1-0): OpenSSL vs BoringSSL/AWS-LC
//! lookalikes, from disk-ELF bytes only (dynsym + rodata scan; the tool
//! never links libcrypto).
//!
//! Anchor rationale (verified on all three lane libcryptos 2026-09-17):
//! - `OSSL_PROVIDER_load` = the provider-model anchor. Neither BoringSSL
//!   nor AWS-LC implements the provider model, so this is fork-proof.
//! - `OPENSSL_version_major` = the 3.x version-API anchor (the 1.1.x
//!   `OPENSSL_version_num` is gone from 3.x AND shimmed by some forks,
//!   so v1 deliberately never uses it as an OpenSSL signal).
//! - `ENGINE_by_id` splits 3.x (present) from 4.x (zero `ENGINE_*`
//!   exports) once OpenSSL is established.
//! - Fork split: `BORINGSSL_`/`bcm_` vs `AWSLC_` symbol prefixes; a
//!   crypto-ish library with neither is `UnknownLookalike` (fail-closed:
//!   never mislabeled OpenSSL). P5 qualifies against real fork builds.

use std::collections::HashSet;

/// Classification result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    /// Genuine OpenSSL, major.minor from the rodata version string
    /// (minor `None` when the string is absent/unparseable).
    OpenSSL {
        major: u32,
        minor: Option<u32>,
    },
    BoringSSL,
    AwsLc,
    /// Crypto-shaped (EVP/low-level symbols) but no OpenSSL anchors and
    /// no fork prefix: fail closed, never call it OpenSSL.
    UnknownLookalike,
    /// Not a crypto library at all.
    NotCrypto,
}

/// The evidence behind a classification (for `doctor` output at P1).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Evidence {
    pub has_provider_load: bool,
    pub has_version_major: bool,
    pub has_engine_by_id: bool,
    pub has_evp_fetch: bool,
    pub has_any_evp: bool,
    pub has_lowlevel_sha256: bool,
    pub has_boring_prefix: bool,
    pub has_awslc_prefix: bool,
    pub version_string: Option<(u32, u32)>,
}

fn parse_version_string(rodata: &[u8]) -> Option<(u32, u32)> {
    // Scan for "OpenSSL X.Y" (e.g. "OpenSSL 4.0.2 25 Aug 2026").
    const TAG: &[u8] = b"OpenSSL ";
    let mut i = 0;
    while i + TAG.len() < rodata.len() {
        if &rodata[i..i + TAG.len()] == TAG {
            let rest = &rodata[i + TAG.len()..];
            let mut nums = Vec::new();
            let mut cur: Option<u32> = None;
            for &b in rest.iter().take(16) {
                if b.is_ascii_digit() {
                    cur = Some(cur.unwrap_or(0) * 10 + u32::from(b - b'0'));
                } else if b == b'.' {
                    if let Some(n) = cur.take() {
                        nums.push(n);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if let Some(n) = cur.take() {
                nums.push(n);
            }
            if nums.len() >= 2 {
                return Some((nums[0], nums[1]));
            }
            // "OpenSSL X" without minor: keep scanning for a fuller tag.
        }
        i += 1;
    }
    None
}

/// Classify from a dynsym name set + raw rodata bytes.
pub fn classify_symbols<'a>(
    symbols: impl Iterator<Item = &'a str>,
    rodata: &[u8],
) -> (Flavor, Evidence) {
    let set: HashSet<&str> = symbols.collect();
    let ev = Evidence {
        has_provider_load: set.contains("OSSL_PROVIDER_load"),
        has_version_major: set.contains("OPENSSL_version_major"),
        has_engine_by_id: set.contains("ENGINE_by_id"),
        has_evp_fetch: set.contains("EVP_MD_fetch"),
        has_any_evp: set.iter().any(|s| s.starts_with("EVP_")),
        has_lowlevel_sha256: set.contains("SHA256_Init"),
        has_boring_prefix: set
            .iter()
            .any(|s| s.starts_with("BORINGSSL_") || s.starts_with("bcm_")),
        has_awslc_prefix: set.iter().any(|s| s.starts_with("AWSLC_")),
        version_string: parse_version_string(rodata),
    };
    let crypto_shaped = ev.has_any_evp || ev.has_lowlevel_sha256;
    let flavor = if ev.has_provider_load && ev.has_version_major {
        match ev.version_string {
            Some((major, minor)) => Flavor::OpenSSL {
                major,
                minor: Some(minor),
            },
            // Anchors prove OpenSSL 3+; without the string the minor is unknown.
            None => Flavor::OpenSSL {
                major: 3,
                minor: None,
            },
        }
    } else if ev.has_boring_prefix && crypto_shaped {
        Flavor::BoringSSL
    } else if ev.has_awslc_prefix && crypto_shaped {
        Flavor::AwsLc
    } else if crypto_shaped {
        Flavor::UnknownLookalike
    } else {
        Flavor::NotCrypto
    };
    (flavor, ev)
}

/// OpenSSL major line from evidence: 3.x keeps `ENGINE_by_id`, 4.x dropped it.
pub fn openssl_line(ev: &Evidence) -> Option<&'static str> {
    if !(ev.has_provider_load && ev.has_version_major) {
        return None;
    }
    Some(if ev.has_engine_by_id { "3.x" } else { "4.x" })
}

/// Classify a candidate libcrypto's disk-ELF bytes.
pub fn classify_elf(bytes: &[u8]) -> anyhow::Result<(Flavor, Evidence)> {
    let obj = goblin::Object::parse(bytes)?;
    let goblin::Object::Elf(elf) = obj else {
        anyhow::bail!("not an ELF object")
    };
    let names: Vec<&str> = elf
        .dynsyms
        .iter()
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .collect();
    // Scan all PROGBITS sections for the version string (cheap; discovery-time only).
    let mut rodata = Vec::new();
    for sh in elf.section_headers.iter() {
        if sh.sh_type == goblin::elf::section_header::SHT_PROGBITS && sh.sh_size < (1 << 26) {
            let start = sh.sh_offset as usize;
            let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
            if start < bytes.len() {
                rodata.extend_from_slice(&bytes[start..end]);
            }
        }
    }
    Ok(classify_symbols(names.into_iter(), &rodata))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syms(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn openssl_30_synthetic() {
        let s = syms(&[
            "OSSL_PROVIDER_load",
            "OPENSSL_version_major",
            "ENGINE_by_id",
            "EVP_MD_fetch",
        ]);
        let (f, ev) = classify_symbols(
            s.iter().map(String::as_str),
            b"xx OpenSSL 3.0.22 15 Aug 2023 yy",
        );
        assert_eq!(
            f,
            Flavor::OpenSSL {
                major: 3,
                minor: Some(0)
            }
        );
        assert_eq!(openssl_line(&ev), Some("3.x"));
    }

    #[test]
    fn openssl_40_synthetic_no_engine() {
        let s = syms(&[
            "OSSL_PROVIDER_load",
            "OPENSSL_version_major",
            "EVP_MD_fetch",
            "SHA256_Init",
        ]);
        let (f, ev) = classify_symbols(s.iter().map(String::as_str), b"OpenSSL 4.0.2 25 Aug 2026");
        assert_eq!(
            f,
            Flavor::OpenSSL {
                major: 4,
                minor: Some(0)
            }
        );
        assert_eq!(openssl_line(&ev), Some("4.x"));
    }

    #[test]
    fn openssl_without_version_string() {
        let s = syms(&["OSSL_PROVIDER_load", "OPENSSL_version_major"]);
        let (f, _) = classify_symbols(s.iter().map(String::as_str), b"no tag here");
        assert_eq!(
            f,
            Flavor::OpenSSL {
                major: 3,
                minor: None
            }
        );
    }

    #[test]
    fn forks_split_by_prefix() {
        let b = syms(&["EVP_DigestInit", "BORINGSSL_self_test"]);
        assert_eq!(
            classify_symbols(b.iter().map(String::as_str), b"").0,
            Flavor::BoringSSL
        );
        let a = syms(&["EVP_DigestInit", "AWSLC_some_fn"]);
        assert_eq!(
            classify_symbols(a.iter().map(String::as_str), b"").0,
            Flavor::AwsLc
        );
    }

    #[test]
    fn unknown_lookalike_and_not_crypto() {
        let u = syms(&["EVP_DigestInit", "SHA256_Init"]);
        assert_eq!(
            classify_symbols(u.iter().map(String::as_str), b"").0,
            Flavor::UnknownLookalike
        );
        let n = syms(&["printf", "malloc"]);
        assert_eq!(
            classify_symbols(n.iter().map(String::as_str), b"").0,
            Flavor::NotCrypto
        );
    }

    #[test]
    fn version_num_shim_does_not_confuse() {
        // A fork shimming the 1.1.x version symbol must NOT read as OpenSSL.
        let s = syms(&["OPENSSL_version_num", "EVP_DigestInit"]);
        assert_eq!(
            classify_symbols(s.iter().map(String::as_str), b"").0,
            Flavor::UnknownLookalike
        );
    }

    /// Lane-anchored positive: the local 4.0 libcrypto classifies OpenSSL
    /// 4.0 (skips loudly off-lane, like the kinds anchor test).
    #[test]
    fn real_40_libcrypto() {
        let path = "/opt/openssl-4.0.2/lib64/libcrypto.so";
        if !std::path::Path::new(path).exists() {
            eprintln!("SKIP: no {path} (non-lane host)");
            return;
        }
        let bytes = std::fs::read(path).unwrap();
        let (f, ev) = classify_elf(&bytes).unwrap();
        assert_eq!(
            f,
            Flavor::OpenSSL {
                major: 4,
                minor: Some(0)
            }
        );
        assert_eq!(openssl_line(&ev), Some("4.x"));
        assert!(ev.has_evp_fetch && ev.has_lowlevel_sha256);
    }
}
