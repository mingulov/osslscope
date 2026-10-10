//! SPDX-License-Identifier: GPL-3.0-or-later
//! T09 normal-provider coverage gates: the finite registry covers the
//! ordinary single-fetch names a default/legacy application advertises
//! (ECDSA/KEYEXCH/KDF/KEM, MD4/legacy, TLS helpers), provider class
//! derives only from pinned metadata or the operator builtin
//! assertion (never a filename), and address-taken (GLOB_DAT)
//! low-level imports resolve to precise diagnosed gaps — never to
//! silent coverage or a removed `lowlevel-fallback-uninstrumented`.
//!
//! Name spellings below are verified against a live
//! `OSSL_PROVIDER_query_operation` census of the default and legacy
//! providers (host OpenSSL 3.5.5; `query_dump` oracle). Class ids are
//! append-only: existing ids never renumber.

use osslscope::discovery::elf;
use osslscope::discovery::harvest::build_alg_entries;
use osslscope::discovery::legacy::{self, Module};
use osslscope::discovery::provider::{
    ProviderClass, ProviderTable, ResolutionInputs, load_table_str, resolve_provider_class,
};
use osslscope::kinds;
use osslscope_ebpf_common as wire;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Registry coverage: every spelling below was observed in the live
// default+legacy census (see module docs). Fetched names alone are
// not the oracle; these pins only stop the registry from silently
// dropping an ordinary name back to `other`.
// ---------------------------------------------------------------------------

/// Ordinary signature/key-exchange/keymgmt names (single-fetch ECDSA,
/// X25519/X448, Edwards, DH/DSA/RSA/SM2 families + OIDs/aliases).
const VERIFIED_ASYM: &[&str] = &[
    "ECDSA",
    "ECDH",
    "EC",
    "X25519",
    "X448",
    "ED25519",
    "ED25519ctx",
    "ED25519ph",
    "ED448",
    "ED448ph",
    "DH",
    "DHX",
    "X9.42 DH",
    "dhKeyAgreement",
    "dhpublicnumber",
    "DSA",
    "dsaEncryption",
    "RSA",
    "rsaEncryption",
    "SM2",
    "id-ecPublicKey",
    "1.2.840.10040.4.1",
    "1.2.840.10045.2.1",
    "1.2.840.10046.2.1",
    "1.2.840.113549.1.1.1",
    "1.2.840.113549.1.3.1",
    "1.3.101.110",
    "1.3.101.111",
    "1.3.101.112",
    "1.3.101.113",
    "1.2.156.10197.1.301",
];

/// Ordinary KDF/KEM names (single-fetch HKDF-family, Argon2, hybrid
/// ML-KEM, scrypt OID alias).
const VERIFIED_KDF_KEM: &[&str] = &[
    "ARGON2D",
    "ARGON2I",
    "ARGON2ID",
    "PKCS12KDF",
    "PVKKDF",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519MLKEM768",
    "X448MLKEM1024",
    "id-scrypt",
    "1.3.6.1.4.1.11591.4.11",
    "1.2.840.113549.1.5.12",
];

/// Ordinary cipher/digest/MAC/RAND/STORE names incl. legacy MD4
/// surroundings (single-fetch ChaCha20, RC4, WHIRLPOOL, JITTER,
/// TEST-RAND, NULL, file/DER achievability helpers + OIDs/aliases).
const VERIFIED_SYM: &[&str] = &[
    "ChaCha20",
    "ChaCha20-Poly1305",
    "RC4",
    "AES",
    "GENERIC-SECRET",
    "2.16.840.1.101.3.4.1",
    "WHIRLPOOL",
    "SHA-1",
    "SSL3-MD5",
    "SSL3-SHA1",
    "NULL",
    "DER",
    "file",
    "JITTER",
    "TEST-RAND",
    "1.0.10118.3.0.55",
    "1.0.9797.3.4",
    "1.2.156.10197.1.401",
    "1.2.840.113549.2.4",
    "1.2.840.113549.2.5",
    "1.2.840.113549.3.4",
    "1.3.14.3.2.26",
    "1.3.6.1.4.1.1722.12.2.1",
    "1.3.6.1.4.1.1722.12.2.2",
];

#[test]
fn registry_covers_verified_ordinary_names() {
    for n in VERIFIED_ASYM
        .iter()
        .chain(VERIFIED_KDF_KEM)
        .chain(VERIFIED_SYM)
    {
        assert!(kinds::is_known_alg(n), "registry dropped verified {n:?}");
        assert_eq!(kinds::classify_alg(n).0, *n, "primary class for {n:?}");
    }
}

fn class_id(name: &str) -> u16 {
    kinds::ALG_NAMES
        .iter()
        .position(|a| a.name == name)
        .unwrap_or_else(|| panic!("{name:?} not registered")) as u16
}

#[test]
fn registry_ids_are_append_only() {
    // Pre-T09 ids (frozen census order): appending the T09 appendix
    // must not renumber a single existing class.
    assert_eq!(kinds::ALG_NAMES.len(), 625 + 67);
    assert_eq!(class_id("SHA2-256"), 490);
    assert_eq!(class_id("AES-256-GCM"), 215);
    assert_eq!(class_id("MD4"), 406);
    assert_eq!(class_id("HKDF"), 377);
    assert_eq!(class_id("ML-KEM-768"), 416);
    assert_eq!(class_id("SNMPKDF"), 536);
    // New ids decode back through the wire label map.
    for n in [
        "ECDSA",
        "X25519",
        "ChaCha20",
        "ARGON2ID",
        "SM2",
        "TEST-RAND",
    ] {
        assert_eq!(kinds::alg_class_label(class_id(n)), Some(n));
    }
}

#[test]
fn unknown_fallback_preserved() {
    assert_eq!(kinds::classify_alg("NOPE-XYZ-9Q"), ("other", false));
    assert_eq!(kinds::classify_alg(""), ("other", false));
    assert_eq!(kinds::classify_alg("ECDSA:NOPE-XYZ"), ("ECDSA", false));
    assert_eq!(kinds::alg_class_label(wire::OTHER_CLASS), Some("other"));
    assert_eq!(kinds::alg_class_label(kinds::ALG_NAMES.len() as u16), None);
}

#[test]
fn kernel_classifier_table_fits_map_cap() {
    // ALG_CLASS holds 1024 entries (frozen loader shape); the
    // extended registry + weak-alias extras must fit with margin,
    // with no hash collision (builder bails on collision).
    let entries = build_alg_entries().unwrap();
    assert_eq!(entries.len(), kinds::ALG_NAMES.len() + weak_extra_count());
    assert!(
        entries.len() < 1024,
        "registry outgrew ALG_CLASS: {}",
        entries.len()
    );
    // Every new name classifies through the shared kernel logic to
    // its own id (agreement, not just table presence).
    let table: std::collections::HashMap<u64, wire::AlgClassValue> = entries.into_iter().collect();
    for n in VERIFIED_ASYM
        .iter()
        .chain(VERIFIED_KDF_KEM)
        .chain(VERIFIED_SYM)
    {
        let v = wire::classify_alg_with(n.as_bytes(), false, |h| table.get(&h).copied());
        assert_eq!(v.class, class_id(n), "kernel class for {n:?}");
        assert_eq!(v.status, wire::ALG_OK, "status for {n:?}");
    }
}

fn weak_extra_count() -> usize {
    kinds::WEAK_ALGS
        .iter()
        .filter(|w| !kinds::is_known_alg(w))
        .count()
}

// ---------------------------------------------------------------------------
// Provider class: pinned metadata or operator assertion only.
// ---------------------------------------------------------------------------

const ENROLL_SAMPLE: &str = r#"{
    "table_version": 1,
    "entries": [
        {"build_id": "b12cd44337cb70619dd290b2396ab5dfcaea230f",
         "openssl": "3.0.22", "provider_class": "default"},
        {"build_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "openssl": "3.5.5", "provider_class": "fips",
         "note": "lab FIPS module build"}
    ]
}"#;

#[test]
fn enrollment_format_validates_shape() {
    let t = load_table_str(ENROLL_SAMPLE).unwrap();
    assert_eq!(t.entry_count(), 2);
    assert!(load_table_str("{bad json").is_err());
    assert!(load_table_str(r#"{"table_version": 2, "entries": []}"#).is_err());
    // Missing class fails closed.
    assert!(
        load_table_str(
            r#"{"table_version": 1, "entries": [
                {"build_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}"#
        )
        .is_err()
    );
    // Typo class fails closed (never a silent new class).
    assert!(
        load_table_str(
            r#"{"table_version": 1, "entries": [
                {"build_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                 "provider_class": "defualt"}]}"#
        )
        .is_err()
    );
    // Malformed build-ids fail closed (empty, short, non-hex, upper).
    for bad in [
        "",
        "abc",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "B12CD44337CB70619DD290B2396AB5DFCAEA230F",
    ] {
        let s = format!(
            r#"{{"table_version": 1, "entries": [
                {{"build_id": "{bad}", "provider_class": "default"}}]}}"#
        );
        assert!(load_table_str(&s).is_err(), "accepted bad id {bad:?}");
    }
    // Duplicate build-id with conflicting classes fails closed.
    assert!(
        load_table_str(
            r#"{"table_version": 1, "entries": [
                {"build_id": "cccccccccccccccccccccccccccccccccccccccc",
                 "provider_class": "default"},
                {"build_id": "cccccccccccccccccccccccccccccccccccccccc",
                 "provider_class": "fips"}]}"#
        )
        .is_err()
    );
}

#[test]
fn provider_class_prefers_pin_then_builtin_then_unknown() {
    let t = load_table_str(ENROLL_SAMPLE).unwrap();
    // Pinned hit wins over everything (exact build bytes recorded).
    assert_eq!(
        resolve_provider_class(&ResolutionInputs {
            build_id: Some("b12cd44337cb70619dd290b2396ab5dfcaea230f"),
            table: &t,
            builtin_asserted: false,
        }),
        Some(ProviderClass::Default)
    );
    assert_eq!(
        resolve_provider_class(&ResolutionInputs {
            build_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            table: &t,
            builtin_asserted: false,
        }),
        Some(ProviderClass::Fips)
    );
    // Builtin operator assertion: in-libcrypto default provider.
    assert_eq!(
        resolve_provider_class(&ResolutionInputs {
            build_id: None,
            table: &ProviderTable::empty(),
            builtin_asserted: true,
        }),
        Some(ProviderClass::Default)
    );
    // No pin, no assertion: unknown (file-provider mode).
    assert_eq!(
        resolve_provider_class(&ResolutionInputs {
            build_id: Some("dddddddddddddddddddddddddddddddddddddddd"),
            table: &t,
            builtin_asserted: false,
        }),
        None
    );
    // Unreadable build-id never resolves (absence is not a pin).
    assert_eq!(
        resolve_provider_class(&ResolutionInputs {
            build_id: None,
            table: &t,
            builtin_asserted: false,
        }),
        None
    );
}

#[test]
fn provider_class_never_from_filename() {
    // The resolver takes no filename, locator, or load-string input
    // by construction: a renamed fips-shaped module (or a decoy
    // provider file named `fips.so`) without a pinned enrollment
    // resolves to unknown even in builtin-unasserted mode. This test
    // pins the rule at the type level: only build-id + table +
    // operator assertion exist as inputs.
    let t = ProviderTable::empty();
    let input = ResolutionInputs {
        build_id: Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        table: &t,
        builtin_asserted: false,
    };
    assert_eq!(resolve_provider_class(&input), None);
    assert_eq!(
        ProviderClass::parse("default"),
        Some(ProviderClass::Default)
    );
    assert_eq!(ProviderClass::parse("legacy"), Some(ProviderClass::Legacy));
    assert_eq!(ProviderClass::parse("fips"), Some(ProviderClass::Fips));
    assert_eq!(
        ProviderClass::parse("third-party"),
        Some(ProviderClass::ThirdParty)
    );
    assert_eq!(ProviderClass::parse("fips.so"), None);
    assert_eq!(ProviderClass::parse("FIPS"), None);
    assert_eq!(ProviderClass::Default.as_str(), "default");
}

// ---------------------------------------------------------------------------
// Address-taken (GLOB_DAT) low-level imports.
// ---------------------------------------------------------------------------

fn host_lib(paths: &[&str]) -> Option<Vec<u8>> {
    paths.iter().find_map(|p| std::fs::read(p).ok())
}

fn libssl_bytes() -> Option<Vec<u8>> {
    host_lib(&[
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
    ])
}

fn libcrypto_bytes() -> Option<Vec<u8>> {
    host_lib(&[
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/lib/x86_64-linux-gnu/libcrypto.so.3",
    ])
}

#[test]
fn glob_dat_imports_find_libssl_transforms() {
    let (Some(ssl), Some(lc)) = (libssl_bytes(), libcrypto_bytes()) else {
        eprintln!("SKIP: no host libssl/libcrypto pair (non-lane host)");
        return;
    };
    let imports = elf::glob_dat_imports(&ssl).unwrap();
    // The four documented address-taken digest Transforms (no PLT
    // stub by construction: GLOB_DAT slots are data).
    for t in [
        "MD5_Transform",
        "SHA1_Transform",
        "SHA256_Transform",
        "SHA512_Transform",
    ] {
        assert!(imports.contains(&t.to_string()), "missing {t}");
    }
    // Closed loop: every reported import is an UND FUNC/NOTYPE
    // symbol with a real GLOB_DAT reloc (independent goblin walk).
    let parsed = elf::parse_elf(&ssl).unwrap();
    let mut relocd: HashSet<String> = HashSet::new();
    for r in parsed.dynrelas.iter().chain(parsed.dynrels.iter()) {
        if r.r_type != goblin::elf::reloc::R_X86_64_GLOB_DAT {
            continue;
        }
        if let Some(s) = parsed.dynsyms.get(r.r_sym)
            && s.st_shndx == 0
            && let Some(n) = parsed.dynstrtab.get_at(s.st_name)
        {
            relocd.insert(n.to_string());
        }
    }
    for n in &imports {
        assert!(relocd.contains(n), "{n} lacks a GLOB_DAT reloc");
    }
    // And the defining side: libcrypto exports each Transform as
    // defined FUNC in an executable segment.
    for t in [
        "MD5_Transform",
        "SHA1_Transform",
        "SHA256_Transform",
        "SHA512_Transform",
    ] {
        let off = elf::dynsym_file_offset(&lc, t).unwrap();
        let lc_elf = elf::parse_elf(&lc).unwrap();
        assert!(elf::offset_in_x_segment(&lc_elf, off), "{t} not in X");
    }
}

#[test]
fn address_taken_resolves_absent_and_shared() {
    let (Some(ssl), Some(lc)) = (libssl_bytes(), libcrypto_bytes()) else {
        eprintln!("SKIP: no host libssl/libcrypto pair (non-lane host)");
        return;
    };
    let imports = elf::glob_dat_imports(&ssl).unwrap();
    let definers = [Module {
        path: "libcrypto.so.3",
        bytes: &lc,
    }];
    let r = legacy::resolve_address_taken(&imports, &definers).unwrap();
    // The four Transforms resolve to exactly one libcrypto FUNC
    // definition each, with file-backed in-X offsets.
    let lc_elf = elf::parse_elf(&lc).unwrap();
    for t in [
        "MD5_Transform",
        "SHA1_Transform",
        "SHA256_Transform",
        "SHA512_Transform",
    ] {
        let hit = r
            .resolved
            .iter()
            .find(|h| h.symbol == t)
            .unwrap_or_else(|| {
                panic!("{t} unresolved: {r:?}");
            });
        assert_eq!(hit.object, "libcrypto.so.3");
        assert!(hit.offset < lc.len() as u64);
        assert!(elf::offset_in_x_segment(&lc_elf, hit.offset));
    }
    // Absent symbol: imported by name nowhere defined.
    let r =
        legacy::resolve_address_taken(&["OSSLscope_NoSuch_Xyz".to_string()], &definers).unwrap();
    assert!(r.resolved.is_empty());
    assert_eq!(r.absent, vec!["OSSLscope_NoSuch_Xyz".to_string()]);
    // Shared implementation: the same FUNC defined in two objects is
    // ambiguous (attaching to either would misattribute the other).
    let both = [
        Module {
            path: "libcrypto.so.3",
            bytes: &lc,
        },
        Module {
            path: "libcrypto-copy.so.3",
            bytes: &lc,
        },
    ];
    let r = legacy::resolve_address_taken(&["MD5_Transform".to_string()], &both).unwrap();
    assert!(r.resolved.is_empty());
    assert_eq!(r.ambiguous.len(), 1);
    assert_eq!(r.ambiguous[0].symbol, "MD5_Transform");
    assert_eq!(r.ambiguous[0].objects.len(), 2);
    // Versioned duplicates inside ONE object (libc defines e.g.
    // cfgetispeed at two FUNC addresses) are ambiguous too — never
    // a silent last-wins resolution.
    let libc = host_lib(&["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"]).unwrap();
    let one = [Module {
        path: "libc.so.6",
        bytes: &libc,
    }];
    let r = legacy::resolve_address_taken(&["cfgetispeed".to_string()], &one).unwrap();
    assert!(r.resolved.is_empty(), "last-wins resolution: {r:?}");
    assert_eq!(r.ambiguous.len(), 1);
    assert_eq!(r.ambiguous[0].objects, vec!["libc.so.6".to_string()]);
}

#[test]
fn address_taken_gaps_stay_uninstrumented() {
    // Resolution never mints coverage: every address-taken
    // low-level import stays in `lowlevel_uninstrumented` with a
    // precise finding, so `lowlevel-fallback-uninstrumented` cannot
    // be resolved away.
    let (Some(ssl), Some(lc)) = (libssl_bytes(), libcrypto_bytes()) else {
        eprintln!("SKIP: no host libssl/libcrypto pair (non-lane host)");
        return;
    };
    let modules = [Module {
        path: "libssl.so.3",
        bytes: &ssl,
    }];
    let set = legacy::probes_for("libcrypto.so.3", &lc, &modules).unwrap();
    assert!(
        set.lowlevel_uninstrumented >= 4,
        "Transform gaps lost: {}",
        set.lowlevel_uninstrumented
    );
    assert!(
        set.unprobed_lowlevel_syms
            .contains(&"MD5_Transform".to_string()),
        "missing precise gap: {:?}",
        set.unprobed_lowlevel_syms
    );
    assert!(
        set.findings
            .iter()
            .any(|f| f.contains("MD5_Transform") && f.contains("address-taken")),
        "missing precise finding: {:?}",
        set.findings
    );
}

#[test]
fn incapable_targets_keep_coarse_gap() {
    // Static/shape-less bytes: no GLOB_DAT scan, existing coarse
    // finding, never a fabricated empty import list presented as
    // "none address-taken".
    let mut hdr = vec![0u8; 64];
    hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    hdr[4] = 2;
    hdr[5] = 1;
    hdr[6] = 1;
    assert_eq!(elf::glob_dat_imports(&hdr).unwrap(), Vec::<String>::new());
    assert!(elf::glob_dat_imports(b"definitely not an ELF file").is_err());
    let blind = legacy::blind_probe_set();
    assert!(blind.lowlevel_uninstrumented > 0);
    assert!(
        blind
            .findings
            .contains(&legacy::FINDING_LOWLEVEL_NODYNSYM.to_string())
    );
}
