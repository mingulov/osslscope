//! SPDX-License-Identifier: GPL-3.0-or-later
//! T12 onboarding gates (R09): normal `report|check run -- cmd` and
//! `--pid` discovery resolves installed BPF objects from trusted
//! defaults and supported target anchors automatically; explicit
//! `--provider`/`--object`/`--count-object`/`--table`/`--force-offset`
//! overrides and explicitly selected local enrollment keep working.
//! Unsupported targets (wrong arch, non-OpenSSL flavor) and unknown
//! builds (stripped, unenrolled) fail closed with actionable
//! enrollment remediation — offsets for the wrong object are never
//! used silently. `doctor` agrees with this backend path.
//!
//! Hermetic fixtures are compiled at test time with gcc when
//! available (loud skip otherwise); a few cases additionally pin
//! the host's real system libcrypto when present (loud skip when
//! absent). Nothing here needs privilege, BPF, or a live lane.

use osslscope::discovery::builtin::{self, Resolution};
use osslscope::discovery::elf;
use osslscope::discovery::flavor::{self, Flavor};
use osslscope::discovery::legacy::{self, Module};
use osslscope::discovery::maps::parse_maps;
use osslscope::discovery::onboard::{
    self, LibcryptoMaps, QualifyOpts, TargetQualification, default_object_dirs, resolve_objects,
};
use osslscope::discovery::provider::{ProviderClass, ProviderTable, load_table_str};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Fake OpenSSL-shaped sources: every anchor the flavor classifier
/// and the offset ladder need, with none of OpenSSL's code.
const FAKE_LIBC_SRC: &str = r#"
const char ossl_version_anchor[] = "OpenSSL 3.5.9-fake 01 Jan 2026";
int OSSL_PROVIDER_available(void) { return 1; }
int OSSL_PROVIDER_load(void) { return 1; }
int OPENSSL_version_major(void) { return 3; }
int ENGINE_by_id(void) { return 1; }
int EVP_MD_fetch(void) { return 1; }
int ossl_provider_query_operation(void) { return 1; }
int SHA256_Init(void) { return 1; }
"#;

const FAKE_CALLER_SRC: &str = r#"
extern int SHA256_Init(void);
int drive_calls(void) { return SHA256_Init(); }
"#;

const FAKE_EXE_SRC: &str = r#"
const char ossl_version_anchor[] = "OpenSSL 3.0.9-fake 01 Jan 2026";
int OSSL_PROVIDER_available(void) { return 1; }
int OSSL_PROVIDER_load(void) { return 1; }
int OPENSSL_version_major(void) { return 3; }
int ENGINE_by_id(void) { return 1; }
int EVP_MD_fetch(void) { return 1; }
int ossl_provider_query_operation(void) { return 1; }
int main(void) { return 0; }
"#;

/// Unique scratch dir for one fixture build.
fn scratch(test: &str) -> PathBuf {
    let n = FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "osslscope-onboarding-{}-{}-{}",
        std::process::id(),
        test,
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have_gcc() -> bool {
    Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Compile `src` with `args`; loud skip when gcc is absent.
fn build_fixture(
    test: &str,
    src_name: &str,
    src: &str,
    out: &str,
    args: &[&str],
) -> Option<PathBuf> {
    if !have_gcc() {
        eprintln!("SKIP {test}: no gcc (fixture build unavailable)");
        return None;
    }
    let dir = scratch(test);
    let src_path = dir.join(src_name);
    std::fs::write(&src_path, src).unwrap();
    let out_path = dir.join(out);
    let mut cmd = Command::new("gcc");
    cmd.args(args).arg("-o").arg(&out_path).arg(&src_path);
    let st = cmd.output().unwrap();
    assert!(
        st.status.success(),
        "gcc fixture build failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    Some(out_path)
}

fn system_libcrypto() -> Option<PathBuf> {
    for p in [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib64/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
    ] {
        if Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

fn qualify_opts<'a>(table: &'a builtin::Table, enrollment: &'a ProviderTable) -> QualifyOpts<'a> {
    QualifyOpts {
        offset_table: table,
        offset_table_explicit: false,
        force_offset: None,
        enrollment,
        builtin_asserted: true,
    }
}

fn shipped() -> builtin::Table {
    builtin::shipped_table()
}

/// Fixture trust: our own uid (production demands root, which tests
/// cannot fabricate), no ancestry walk (fixtures live under /tmp,
/// whose sticky ancestry can never satisfy production).
fn test_trust() -> onboard::TrustPolicy {
    onboard::TrustPolicy {
        // SAFETY: getuid takes no arguments and always succeeds.
        trusted_uids: vec![unsafe { libc::getuid() }],
        check_ancestry: false,
    }
}

// ---------------------------------------------------------------------------
// Trusted BPF-object defaults.
// ---------------------------------------------------------------------------

#[test]
fn trusted_default_dirs_are_pinned_system_paths() {
    // The exact implicit search set a privileged invocation
    // accepts: operator-local prefix first, then the distro tree.
    // No cwd, no environment-derived, and no user-writable paths.
    assert_eq!(
        default_object_dirs(),
        vec![
            PathBuf::from("/usr/local/lib/osslscope"),
            PathBuf::from("/usr/local/lib64/osslscope"),
            PathBuf::from("/usr/lib/osslscope"),
            PathBuf::from("/usr/lib64/osslscope"),
        ]
    );
}

#[test]
fn missing_objects_fail_closed_with_flag_remediation() {
    let empty = scratch("missing-objects");
    let err = resolve_objects(None, None, &[empty], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("no BPF objects found"),
        "message: {}",
        err.message
    );
    // Pair remediation names both flags.
    assert!(
        err.remediation.contains("--object") && err.remediation.contains("--count-object"),
        "remediation: {}",
        err.remediation
    );
    // No dirs at all is the same failure, not a panic.
    let err = resolve_objects(None, None, &[], &test_trust()).unwrap_err();
    assert!(err.message.contains("no BPF objects found"));
}

#[test]
fn explicit_non_bpf_object_is_incompatible() {
    // A real ELF that is not a BPF object can never be selected,
    // explicitly or implicitly.
    let exe = std::env::current_exe().unwrap();
    let err = resolve_objects(Some(&exe), Some(&exe), &[], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("incompatible"),
        "message: {}",
        err.message
    );
    let missing = scratch("missing-explicit").join("nope-harvest");
    let err = resolve_objects(Some(&missing), None, &[], &test_trust()).unwrap_err();
    assert!(err.message.contains("missing"), "message: {}", err.message);
}

#[test]
fn writable_untrusted_search_path_is_skipped() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("writable-untrusted");
    // Populate with correctly named files: the resolver must still
    // refuse the directory for trust, not select by name.
    std::fs::write(dir.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(dir.join("osslscope-count"), b"fake").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!onboard::is_trusted_dir(&dir));
    let err = resolve_objects(None, None, &[dir.clone()], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("no BPF objects found"),
        "message: {}",
        err.message
    );
    // Restore so the temp dir can be cleaned up.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn implicit_search_prefers_first_trusted_dir() {
    // Order proof without real BPF bytes: dummy files fail
    // compatibility, and the error names the file from the FIRST
    // directory — proving search order, not just failure.
    let first = scratch("order-first");
    let second = scratch("order-second");
    std::fs::write(first.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(first.join("osslscope-count"), b"fake").unwrap();
    std::fs::write(second.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(second.join("osslscope-count"), b"fake").unwrap();
    let err = resolve_objects(None, None, &[first.clone(), second], &test_trust()).unwrap_err();
    assert!(err.message.contains("incompatible"), "{}", err.message);
    assert!(
        err.message.contains(&first.to_string_lossy().into_owned()),
        "first dir should win: {}",
        err.message
    );
}

#[test]
fn implicit_pair_skips_incomplete_dirs() {
    // Partial installs never donate one role: the first dir holds
    // only harvest, so the pair must come from the second dir
    // (dummy files fail compatibility there — proving the skip,
    // not just failure).
    let first = scratch("pair-first");
    let second = scratch("pair-second");
    std::fs::write(first.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(second.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(second.join("osslscope-count"), b"fake").unwrap();
    let err = resolve_objects(None, None, &[first, second.clone()], &test_trust()).unwrap_err();
    assert!(err.message.contains("incompatible"), "{}", err.message);
    assert!(
        err.message.contains(&second.to_string_lossy().into_owned()),
        "complete second dir should win: {}",
        err.message
    );
}

#[test]
fn writable_object_file_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("writable-file");
    let harvest = dir.join("osslscope-harvest");
    std::fs::write(&harvest, b"fake").unwrap();
    std::fs::write(dir.join("osslscope-count"), b"fake").unwrap();
    std::fs::set_permissions(&harvest, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!onboard::is_trusted_file(&harvest));
    let err = resolve_objects(None, None, &[dir], &test_trust()).unwrap_err();
    assert!(err.message.contains("refused"), "{}", err.message);
}

#[test]
fn production_trust_demands_root_ownership() {
    // A 0755 dir we own is NOT production-trusted (mode bits alone
    // never suffice: the owner could swap files under a privileged
    // invocation). The same dir resolves under the fixture policy —
    // proving the ownership gate is what differs.
    let dir = scratch("ownership-gate");
    std::fs::write(dir.join("osslscope-harvest"), b"fake").unwrap();
    std::fs::write(dir.join("osslscope-count"), b"fake").unwrap();
    assert!(!onboard::is_trusted_dir(&dir));
    let prod = onboard::TrustPolicy::production();
    let err = resolve_objects(None, None, &[dir.clone()], &prod).unwrap_err();
    assert!(
        err.message.contains("no BPF objects found"),
        "{}",
        err.message
    );
    let err = resolve_objects(None, None, &[dir], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("incompatible"),
        "fixture policy must attempt the pair: {}",
        err.message
    );
}

#[test]
fn bounded_reads_refuse_oversize_files() {
    let dir = scratch("bounded-read");
    let big = dir.join("big.bin");
    std::fs::write(&big, vec![0x7fu8; 129]).unwrap();
    assert!(matches!(
        onboard::read_bounded(&big, 128),
        Err(onboard::ReadBoundedError::TooLarge(_))
    ));
    assert_eq!(onboard::read_bounded(&big, 129).unwrap().len(), 129);
    assert!(matches!(
        onboard::read_bounded(&dir.join("missing"), 128),
        Err(onboard::ReadBoundedError::Io(_))
    ));
}

// ---------------------------------------------------------------------------
// Supported target anchors: dynamic libcrypto, static exe.
// ---------------------------------------------------------------------------

#[test]
fn dynamic_libcrypto_supported_via_enrolled_table() {
    let Some(so) = build_fixture(
        "dynamic-enrolled",
        "fake.c",
        FAKE_LIBC_SRC,
        // Realistic basename: maps discovery matches libcrypto.so*.
        "libcrypto.so.3",
        &["-shared", "-fPIC", "-g"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&so).unwrap();
    // Sanity: the fake really is OpenSSL-shaped to the classifier.
    let (flavor, _) = osslscope::discovery::flavor::classify_elf(&bytes).unwrap();
    assert_eq!(
        flavor,
        osslscope::discovery::flavor::Flavor::OpenSSL {
            major: 3,
            minor: Some(5)
        }
    );
    // Enroll THIS build with live-measured offsets: the table hit
    // must verify against the object's own anchor.
    let build_id = elf::read_build_id(&bytes).unwrap();
    let anchor_off = elf::dynsym_file_offset(&bytes, "OSSL_PROVIDER_available").unwrap();
    let query_off = elf::symtab_file_offset(&bytes, "ossl_provider_query_operation").unwrap();
    let table_src = format!(
        r#"{{"table_version":1,"entries":[{{"build_id":"{build_id}","openssl":"3.5-fake",
            "query_offset":{query_off},"anchor":"OSSL_PROVIDER_available",
            "anchor_offset":{anchor_off}}}]}}"#
    );
    let table = builtin::load_table_str(&table_src).unwrap();
    let enrollment = ProviderTable::empty();
    let opts = QualifyOpts {
        offset_table_explicit: true,
        ..qualify_opts(&table, &enrollment)
    };
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Supported(t) => {
            assert_eq!(t.resolution, Some(Resolution::Table));
            assert_eq!(t.query_offset, Some(query_off));
            assert_eq!(t.build_id.as_deref(), Some(build_id.as_str()));
            assert!(t.builtin && !t.static_exe);
            // No pinned enrollment + builtin assertion = default class.
            assert_eq!(t.provider_class, Some(ProviderClass::Default));
        }
        other => panic!("want Supported(Table), got {other:?}"),
    }
    // maps routing: a dynamic libcrypto mapping is found by basename.
    let maps = parse_maps(&format!(
        "7f00-7f10 r-xp 00000000 08:01 99 {}\n7f10-7f20 r-xp 00000000 08:01 7 /lib/libc.so.6\n",
        so.display()
    ));
    match onboard::libcrypto_from_maps(&maps) {
        LibcryptoMaps::One { path } => assert_eq!(Path::new(&path), so),
        other => panic!("want One, got {other:?}"),
    }
}

#[test]
fn unstripped_static_supported_via_symtab() {
    // Plain -g, deliberately NOT -rdynamic: a real static exe keeps
    // its anchors only in .symtab (static-aware classification).
    let Some(exe) = build_fixture(
        "static-symtab",
        "fake_exe.c",
        FAKE_EXE_SRC,
        "fake_static",
        &["-g"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&exe).unwrap();
    // No libcrypto mapped: the static exe itself is the candidate.
    let maps = parse_maps(&format!(
        "400000-401000 r-xp 00000000 08:01 42 {}\n7f00-7f10 r-xp 00000000 08:01 7 /lib/libc.so.6\n",
        exe.display()
    ));
    assert_eq!(onboard::libcrypto_from_maps(&maps), LibcryptoMaps::None);
    // Unknown build, shipped table, automatic mode: the symtab rung
    // resolves from the object's own debug info — supported.
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    match onboard::qualify_libcrypto_bytes(&bytes, &exe, true, &opts) {
        TargetQualification::Supported(t) => {
            assert_eq!(t.resolution, Some(Resolution::Symtab));
            assert!(t.query_offset.unwrap() < bytes.len() as u64);
            assert!(t.static_exe);
        }
        other => panic!("want Supported(Symtab), got {other:?}"),
    }
}

#[test]
fn stripped_unknown_build_needs_explicit_enrollment() {
    let Some(so) = build_fixture(
        "stripped-unknown",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_stripped.so",
        &["-shared", "-fPIC", "-s", "-Wl,--soname,OPENSSL_3.0"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&so).unwrap();
    assert!(elf::read_build_id(&bytes).is_some());
    assert!(
        elf::symtab_file_offset(&bytes, "ossl_provider_query_operation").is_err(),
        "fixture must be stripped"
    );
    // The soname plants OPENSSL_3.0 in .dynstr and the shipped table
    // carries a (3,0) delta — automatic mode must STILL refuse: the
    // anchor+delta rung is explicit-only, never a silent guess.
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Unknown {
            reason,
            remediation,
        } => {
            assert!(
                reason.contains("stripped") || reason.contains("symtab"),
                "{reason}"
            );
            assert!(
                remediation.contains("--table") || remediation.contains("enroll"),
                "{remediation}"
            );
        }
        other => panic!("want Unknown (explicit enrollment required), got {other:?}"),
    }
    // ...while an explicitly selected table carrying a fallback delta
    // for this version resolves (operator-selected offsets).
    let explicit_src = r#"{"table_version":1,"entries":[],
        "fallback":[{"openssl":"3.0","anchor":"OSSL_PROVIDER_available","delta":16}]}"#;
    let explicit = builtin::load_table_str(explicit_src).unwrap();
    let opts = QualifyOpts {
        offset_table_explicit: true,
        ..qualify_opts(&explicit, &enrollment)
    };
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Supported(t) => {
            assert_eq!(t.resolution, Some(Resolution::AnchorFallback));
        }
        other => panic!("want Supported(AnchorFallback) via explicit table, got {other:?}"),
    }
}

#[test]
fn system_libcrypto_stripped_unknown_is_not_silently_supported() {
    let Some(path) = system_libcrypto() else {
        eprintln!("SKIP system-libcrypto: no system libcrypto.so.3");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let build_id = elf::read_build_id(&bytes).expect("system libcrypto has a build-id");
    // Guard the test's premise: the system build is unknown to the
    // shipped table (ten historical rows never imply this binary).
    assert!(
        shipped().by_build_id(&build_id).is_none(),
        "premise broken: system build {build_id} is enrolled?"
    );
    let enrollment = ProviderTable::empty();
    let table = shipped();
    let opts = qualify_opts(&table, &enrollment);
    match onboard::qualify_libcrypto_bytes(&bytes, &path, false, &opts) {
        TargetQualification::Unknown { remediation, .. } => {
            assert!(remediation.contains("--table") || remediation.contains("enroll"));
        }
        TargetQualification::Supported(t) => {
            // Only a symtab hit may save it (some distros ship
            // debug info); a version-delta guess never may.
            assert_eq!(
                t.resolution,
                Some(Resolution::Symtab),
                "system build must not resolve via Table/AnchorFallback"
            );
        }
        other => panic!("unexpected qualification: {other:?}"),
    }
}

#[test]
fn explicit_local_table_identity_mismatch_fails_closed() {
    let Some(so) = build_fixture(
        "table-mismatch",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_libcrypto.so",
        &["-shared", "-fPIC", "-g"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&so).unwrap();
    let build_id = elf::read_build_id(&bytes).unwrap();
    let anchor_off = elf::dynsym_file_offset(&bytes, "OSSL_PROVIDER_available").unwrap();
    // Correct build-id, WRONG anchor offset: the table describes a
    // different build. The recorded query offset must never be used.
    let table_src = format!(
        r#"{{"table_version":1,"entries":[{{"build_id":"{build_id}","openssl":"3.5-fake",
            "query_offset":12345,"anchor":"OSSL_PROVIDER_available",
            "anchor_offset":{}}}]}}"#,
        anchor_off + 0x1000
    );
    let table = builtin::load_table_str(&table_src).unwrap();
    let enrollment = ProviderTable::empty();
    let opts = QualifyOpts {
        offset_table_explicit: true,
        ..qualify_opts(&table, &enrollment)
    };
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Unknown {
            reason,
            remediation,
        } => {
            assert!(reason.contains("mismatch"), "{reason}");
            assert!(remediation.contains("re-enroll"), "{remediation}");
        }
        other => panic!("want Unknown (identity mismatch), got {other:?}"),
    }
    // The underlying ladder errors too (no silent offset).
    assert!(builtin::resolve_query_offset(&bytes, &table, None).is_err());
}

// ---------------------------------------------------------------------------
// Unsupported targets: never supportable, distinct from unknown.
// ---------------------------------------------------------------------------

#[test]
fn unsupported_arch_is_refused_not_unknown() {
    // 32-bit header.
    let mut x86 = vec![0u8; 64];
    x86[0..4].copy_from_slice(b"\x7fELF");
    x86[4] = 1; // ELFCLASS32
    x86[18] = 3; // EM_386
    // AArch64 64-bit header.
    let mut arm = vec![0u8; 64];
    arm[0..4].copy_from_slice(b"\x7fELF");
    arm[4] = 2; // ELFCLASS64
    arm[18] = 183; // EM_AARCH64
    arm[19] = 0;
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    for (bytes, want) in [(&x86, "32-bit"), (&arm, "AArch64")] {
        match onboard::qualify_libcrypto_bytes(bytes, Path::new("/fake/libcrypto.so"), false, &opts)
        {
            TargetQualification::Unsupported {
                reason,
                remediation,
            } => {
                assert!(reason.contains(want), "{reason}");
                assert!(remediation.contains("x86-64"), "{remediation}");
            }
            other => panic!("want Unsupported for {want}, got {other:?}"),
        }
    }
    // The shared arch gate agrees (doctor renders the same verdict).
    assert!(onboard::check_arch(&x86).is_err());
    assert!(onboard::check_arch(&arm).is_err());
}

#[test]
fn no_libcrypto_non_crypto_process_is_unsupported() {
    // A live process shape with no libcrypto: exe + libc only.
    let exe = std::env::current_exe().unwrap();
    let maps = parse_maps(&format!(
        "400000-401000 r-xp 00000000 08:01 42 {}\n7f00-7f10 r-xp 00000000 08:01 7 /lib/libc.so.6\n",
        exe.display()
    ));
    assert_eq!(onboard::libcrypto_from_maps(&maps), LibcryptoMaps::None);
    // The test binary is not OpenSSL: static candidacy fails as
    // unsupported (actionable), never as a guessed Unknown.
    let bytes = std::fs::read(&exe).unwrap();
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    match onboard::qualify_libcrypto_bytes(&bytes, &exe, true, &opts) {
        TargetQualification::Unsupported { reason, .. } => {
            assert!(
                reason.contains("not OpenSSL") || reason.contains("crypto"),
                "{reason}"
            );
        }
        other => panic!("want Unsupported for a non-crypto exe, got {other:?}"),
    }
    // Dual-loaded libcryptos stay refused (ambiguous identity).
    let maps = parse_maps(
        "7f00-7f10 r-xp 00000000 08:01 11 /a/libcrypto.so.3\n\
         7f10-7f20 r-xp 00000000 08:01 22 /b/libcrypto.so.3\n",
    );
    assert!(matches!(
        onboard::libcrypto_from_maps(&maps),
        LibcryptoMaps::Multi { .. }
    ));
}

// ---------------------------------------------------------------------------
// Provider class (T09 interface) inside onboarding.
// ---------------------------------------------------------------------------

#[test]
fn provider_class_flows_through_qualification() {
    let Some(so) = build_fixture(
        "provider-class",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_libcrypto.so",
        &["-shared", "-fPIC", "-g"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&so).unwrap();
    let build_id = elf::read_build_id(&bytes).unwrap();
    let table = shipped();
    // Pinned enrollment wins over the builtin assertion.
    let enrolled_src = format!(
        r#"{{"table_version":1,"entries":[{{"build_id":"{build_id}",
            "provider_class":"fips","openssl":"3.5-fake"}}]}}"#
    );
    let enrolled = load_table_str(&enrolled_src).unwrap();
    let opts = qualify_opts(&table, &enrolled);
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Supported(t) => {
            assert_eq!(t.provider_class, Some(ProviderClass::Fips));
        }
        other => panic!("want Supported, got {other:?}"),
    }
    // Without enrollment and without the assertion: unknown class,
    // while offsets still resolve (identity vs attach separated).
    let empty = ProviderTable::empty();
    let opts = QualifyOpts {
        builtin_asserted: false,
        ..qualify_opts(&table, &empty)
    };
    match onboard::qualify_libcrypto_bytes(&bytes, &so, false, &opts) {
        TargetQualification::Supported(t) => {
            assert_eq!(t.resolution, Some(Resolution::Symtab));
            assert_eq!(t.provider_class, None);
        }
        other => panic!("want Supported with unknown class, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Address-taken (GLOB_DAT) coverage caveats (T09 interfaces).
// ---------------------------------------------------------------------------

#[test]
fn address_taken_summary_consumes_t09_resolution() {
    let Some(definer) = build_fixture(
        "addr-definer",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_libcrypto.so",
        &["-shared", "-fPIC", "-g"],
    ) else {
        return;
    };
    let caller_dir = scratch("addr-caller");
    let caller_src = caller_dir.join("caller.c");
    std::fs::write(&caller_src, FAKE_CALLER_SRC).unwrap();
    let caller_so = caller_dir.join("caller_noplt.so");
    let st = Command::new("gcc")
        .args(["-shared", "-fPIC", "-g", "-fno-plt", "-o"])
        .arg(&caller_so)
        .arg(&caller_src)
        .output()
        .unwrap();
    assert!(st.status.success());
    let def_bytes = std::fs::read(&definer).unwrap();
    let caller_bytes = std::fs::read(&caller_so).unwrap();
    // Direct T09 consumption first: the caller really takes the
    // address of a low-level import the PLT scan cannot see.
    let imports = elf::glob_dat_imports(&caller_bytes).unwrap();
    assert!(
        imports.iter().any(|n| n == "SHA256_Init"),
        "GLOB_DAT imports: {imports:?}"
    );
    let lib_mod = Module {
        path: &definer.to_string_lossy(),
        bytes: &def_bytes,
    };
    let caller_mod = Module {
        path: &caller_so.to_string_lossy(),
        bytes: &caller_bytes,
    };
    let summary = legacy::address_taken_summary(&lib_mod, &[caller_mod]);
    assert_eq!(summary.scanned_modules, 1);
    assert!(summary.skipped_modules.is_empty());
    assert!(summary.taxonomy_imports >= 1, "summary: {summary:?}");
    assert_eq!(
        summary.resolved + summary.ambiguous + summary.absent + summary.unknown,
        summary.taxonomy_imports,
        "every taxonomy import lands in exactly one bucket: {summary:?}"
    );
    assert!(
        summary.resolved >= 1,
        "SHA256_Init defines in the fake libcrypto: {summary:?}"
    );
}

// ---------------------------------------------------------------------------
// Spawn prediction (pre-exec `run --` discovery).
// ---------------------------------------------------------------------------

const FAKE_APP_SRC: &str = r#"
extern int OSSL_PROVIDER_load(void);
int main(void) { return OSSL_PROVIDER_load(); }
"#;

fn spawn_env<'a>(path: &'a str, ld: Option<&'a str>) -> onboard::SpawnEnv<'a> {
    onboard::SpawnEnv {
        path,
        ld_library_path: ld,
    }
}

/// Build a fake app linked against a fake libcrypto `soname`;
/// `link_args` tune the link (rpath variants, or none).
/// Returns (app, lib).
fn build_linked_app(test: &str, soname: &str, link_args: &[&str]) -> Option<(PathBuf, PathBuf)> {
    if !have_gcc() {
        eprintln!("SKIP {test}: no gcc (fixture build unavailable)");
        return None;
    }
    let dir = scratch(test);
    let libdir = dir.join("fakelib");
    std::fs::create_dir_all(&libdir).unwrap();
    let libc_src = dir.join("fake.c");
    std::fs::write(&libc_src, FAKE_LIBC_SRC).unwrap();
    let lib = libdir.join(soname);
    let st = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-g",
            &format!("-Wl,--soname,{soname}"),
            "-o",
        ])
        .arg(&lib)
        .arg(&libc_src)
        .output()
        .unwrap();
    assert!(st.status.success());
    let app_src = dir.join("app.c");
    std::fs::write(&app_src, FAKE_APP_SRC).unwrap();
    let app = dir.join("app");
    let st = Command::new("gcc")
        .args(["-g", "-o"])
        .arg(&app)
        .arg(&app_src)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l:{soname}"))
        .args(link_args)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "app link failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    Some((app, lib))
}

#[test]
fn spawn_dynamic_predicts_rpath_libcrypto() {
    for (tag, args) in [
        ("runpath", vec!["-Wl,-rpath,$ORIGIN/fakelib"]),
        (
            "rpath",
            vec!["-Wl,-rpath,$ORIGIN/fakelib", "-Wl,--disable-new-dtags"],
        ),
    ] {
        let Some((app, lib)) = build_linked_app("spawn-rpath", "libcrypto.so.3", &args) else {
            return;
        };
        // Sanity: NEEDED + rpath really are there.
        let exe_bytes = std::fs::read(&app).unwrap();
        let needed = elf::needed_libraries(&exe_bytes).unwrap();
        assert!(needed.iter().any(|n| n == "libcrypto.so.3"), "{needed:?}");
        let (rpath, runpath) = elf::rpath_runpath(&exe_bytes).unwrap();
        assert!(
            rpath.is_some() || runpath.is_some(),
            "no rpath/runpath ({tag})"
        );
        // Predict + qualify (no environment involved).
        let table = shipped();
        let enrollment = ProviderTable::empty();
        let opts = qualify_opts(&table, &enrollment);
        let env = spawn_env("/bin:/usr/bin", None);
        let argv = vec![app.to_string_lossy().into_owned()];
        match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
            TargetQualification::Supported(t) => {
                assert_eq!(t.provider_path, lib, "({tag})");
                // The fake is unstripped: symtab rung.
                assert_eq!(t.resolution, Some(Resolution::Symtab), "({tag})");
                assert!(!t.static_exe);
            }
            other => panic!("want Supported ({tag}), got {other:?}"),
        }
    }
}

#[test]
fn spawn_ld_library_path_resolves_without_rpath() {
    let Some((app, lib)) = build_linked_app("spawn-ldpath", "libcrypto.so.3", &[]) else {
        return;
    };
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    // Injected search path (no process-environment mutation).
    let ld = lib.parent().unwrap().to_string_lossy().into_owned();
    let env = spawn_env("/bin:/usr/bin", Some(&ld));
    let argv = vec![app.to_string_lossy().into_owned()];
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Supported(t) => assert_eq!(t.provider_path, lib),
        other => panic!("want Supported, got {other:?}"),
    }
}

#[test]
fn spawn_unresolvable_libcrypto_is_unknown() {
    // NEEDED libcrypto.so.9: no host ships it, so rpath-nowhere +
    // empty env + fixed defaults all miss deterministically.
    let Some((app, _)) = build_linked_app(
        "spawn-unresolved",
        "libcrypto.so.9",
        &["-Wl,-rpath,/nonexistent-osslscope-xyz"],
    ) else {
        return;
    };
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let env = spawn_env(
        "/nonexistent-osslscope-xyz",
        Some("/nonexistent-osslscope-xyz"),
    );
    let argv = vec![app.to_string_lossy().into_owned()];
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Unknown {
            reason,
            remediation,
        } => {
            assert!(reason.contains("libcrypto.so.9"), "{reason}");
            assert!(remediation.contains("--provider"), "{remediation}");
        }
        other => panic!("want Unknown, got {other:?}"),
    }
}

#[test]
fn spawn_rpath_beats_ld_library_path() {
    // glibc order (empirically pinned): RPATH-only wins over
    // LD_LIBRARY_PATH. Two distinct libcrypto files exist; the
    // prediction must pick the RPATH one — never the LD one, never
    // both (dual-load).
    let Some((app, lib)) = build_linked_app(
        "spawn-rpath-wins",
        "libcrypto.so.3",
        &["-Wl,-rpath,$ORIGIN/fakelib", "-Wl,--disable-new-dtags"],
    ) else {
        return;
    };
    // Precondition: the link really produced RPATH (old dtags).
    let exe_bytes = std::fs::read(&app).unwrap();
    let (rpath, runpath) = elf::rpath_runpath(&exe_bytes).unwrap();
    assert!(
        rpath.is_some() && runpath.is_none(),
        "want RPATH-only, got {rpath:?}/{runpath:?}"
    );
    // Shadow copy under LD_LIBRARY_PATH (same bytes, distinct file).
    let shadow_dir = scratch("spawn-rpath-wins-shadow");
    let shadow = shadow_dir.join("libcrypto.so.3");
    std::fs::copy(&lib, &shadow).unwrap();
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let ld = shadow_dir.to_string_lossy().into_owned();
    let env = spawn_env("/bin:/usr/bin", Some(&ld));
    let argv = vec![app.to_string_lossy().into_owned()];
    let pred = onboard::predict_spawn_lib(&argv, &env).unwrap();
    assert_eq!(pred.libs, vec![lib.clone()]);
    assert!(!pred.incomplete);
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Supported(t) => assert_eq!(t.provider_path, lib),
        other => panic!("want Supported via RPATH, got {other:?}"),
    }
}

#[test]
fn spawn_runpath_yields_to_ld_library_path() {
    // RUNPATH present: RPATH ignored, LD_LIBRARY_PATH wins.
    let Some((app, lib)) = build_linked_app(
        "spawn-runpath-yields",
        "libcrypto.so.3",
        &["-Wl,-rpath,$ORIGIN/fakelib", "-Wl,--enable-new-dtags"],
    ) else {
        return;
    };
    // Precondition: the link really produced RUNPATH (new dtags).
    let exe_bytes = std::fs::read(&app).unwrap();
    let (rpath, runpath) = elf::rpath_runpath(&exe_bytes).unwrap();
    assert!(
        rpath.is_none() && runpath.is_some(),
        "want RUNPATH-only, got {rpath:?}/{runpath:?}"
    );
    let shadow_dir = scratch("spawn-runpath-yields-shadow");
    let shadow = shadow_dir.join("libcrypto.so.3");
    std::fs::copy(&lib, &shadow).unwrap();
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let ld = shadow_dir.to_string_lossy().into_owned();
    let env = spawn_env("/bin:/usr/bin", Some(&ld));
    let argv = vec![app.to_string_lossy().into_owned()];
    let pred = onboard::predict_spawn_lib(&argv, &env).unwrap();
    assert_eq!(pred.libs, vec![shadow.clone()]);
    assert!(!pred.incomplete);
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Supported(t) => assert_eq!(t.provider_path, shadow),
        other => panic!("want Supported via LD_LIBRARY_PATH, got {other:?}"),
    }
}

const FAKE_MID_SRC: &str = r#"
extern int OSSL_PROVIDER_load(void);
int mid_drive(void) { return OSSL_PROVIDER_load(); }
"#;

const FAKE_MID_APP_SRC: &str = r#"
extern int mid_drive(void);
int main(void) { return mid_drive(); }
"#;

/// app -> libmid.so.0 -> libcrypto.so.3, all under one dir; the app
/// links libmid only. `app_link` tunes the app link (rpath flavor).
fn build_transitive_app(test: &str, app_link: &[&str]) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if !have_gcc() {
        eprintln!("SKIP {test}: no gcc (fixture build unavailable)");
        return None;
    }
    let dir = scratch(test);
    let libdir = dir.join("libs");
    std::fs::create_dir_all(&libdir).unwrap();
    let cc = |args: &[&str]| {
        let st = Command::new("gcc").args(args).output().unwrap();
        assert!(
            st.status.success(),
            "gcc fixture build failed: {}",
            String::from_utf8_lossy(&st.stderr)
        );
    };
    let libc_src = dir.join("fake.c");
    std::fs::write(&libc_src, FAKE_LIBC_SRC).unwrap();
    let lib = libdir.join("libcrypto.so.3");
    cc(&[
        "-shared",
        "-fPIC",
        "-g",
        "-Wl,--soname,libcrypto.so.3",
        "-o",
        lib.to_str().unwrap(),
        libc_src.to_str().unwrap(),
    ]);
    let mid_src = dir.join("mid.c");
    std::fs::write(&mid_src, FAKE_MID_SRC).unwrap();
    let mid = libdir.join("libmid.so.0");
    cc(&[
        "-shared",
        "-fPIC",
        "-g",
        "-Wl,--soname,libmid.so.0",
        "-o",
        mid.to_str().unwrap(),
        mid_src.to_str().unwrap(),
        "-L",
        libdir.to_str().unwrap(),
        "-l:libcrypto.so.3",
    ]);
    let app_src = dir.join("app.c");
    std::fs::write(&app_src, FAKE_MID_APP_SRC).unwrap();
    let app = dir.join("app");
    let mut args = vec![
        "-g".to_string(),
        "-o".to_string(),
        app.to_string_lossy().into_owned(),
        app_src.to_string_lossy().into_owned(),
        "-L".to_string(),
        libdir.to_string_lossy().into_owned(),
        "-l:libmid.so.0".to_string(),
    ];
    args.extend(app_link.iter().map(|s| s.to_string()));
    cc(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    Some((app, mid, lib))
}

#[test]
fn spawn_transitive_libcrypto_found_via_exe_rpath() {
    // libcrypto reachable only transitively (app -> libmid ->
    // libcrypto); the exe's old-dtags RPATH applies to the deeper
    // level (glibc transitive-RPATH rule) — and beats the system
    // libcrypto in the fixed defaults.
    let Some((app, mid, lib)) = build_transitive_app(
        "spawn-transitive",
        &["-Wl,-rpath,$ORIGIN/libs", "-Wl,--disable-new-dtags"],
    ) else {
        return;
    };
    // Preconditions: no direct libcrypto NEEDED on the app; the mid
    // lib needs it and carries no rpath of its own.
    let app_needed = elf::needed_libraries(&std::fs::read(&app).unwrap()).unwrap();
    assert!(
        app_needed.iter().any(|n| n == "libmid.so.0")
            && !app_needed.iter().any(|n| n == "libcrypto.so.3"),
        "{app_needed:?}"
    );
    let mid_bytes = std::fs::read(&mid).unwrap();
    let mid_needed = elf::needed_libraries(&mid_bytes).unwrap();
    assert!(
        mid_needed.iter().any(|n| n == "libcrypto.so.3"),
        "{mid_needed:?}"
    );
    let (mid_rpath, mid_runpath) = elf::rpath_runpath(&mid_bytes).unwrap();
    assert!(
        mid_rpath.is_none() && mid_runpath.is_none(),
        "{mid_rpath:?}/{mid_runpath:?}"
    );
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let env = spawn_env("/bin:/usr/bin", None);
    let argv = vec![app.to_string_lossy().into_owned()];
    let pred = onboard::predict_spawn_lib(&argv, &env).unwrap();
    assert_eq!(pred.libs, vec![lib.clone()], "libs: {:?}", pred.libs);
    assert!(pred.unresolved.is_empty());
    assert!(!pred.incomplete);
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Supported(t) => assert_eq!(t.provider_path, lib),
        other => panic!("want Supported(transitive), got {other:?}"),
    }
}

#[test]
fn spawn_dual_load_refused_and_doctor_agrees() {
    // The loader would map two distinct libcryptos (exe RPATH dirA
    // for the direct NEEDED, plus libother's own RPATH dirB for its
    // NEEDED): refused fail-closed, and doctor --exe reports the
    // same refusal (exit 4, dispatch-anchor names dual-load).
    if !have_gcc() {
        eprintln!("SKIP spawn-dual-load: no gcc (fixture build unavailable)");
        return;
    }
    let dir = scratch("spawn-dual-load");
    let dir_a = dir.join("dirA");
    let dir_b = dir.join("dirB");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let cc = |args: &[&str]| {
        let st = Command::new("gcc").args(args).output().unwrap();
        assert!(
            st.status.success(),
            "gcc fixture build failed: {}",
            String::from_utf8_lossy(&st.stderr)
        );
    };
    let libc_src = dir.join("fake.c");
    std::fs::write(&libc_src, FAKE_LIBC_SRC).unwrap();
    for d in [&dir_a, &dir_b] {
        let lib = d.join("libcrypto.so.3");
        cc(&[
            "-shared",
            "-fPIC",
            "-g",
            "-Wl,--soname,libcrypto.so.3",
            "-o",
            lib.to_str().unwrap(),
            libc_src.to_str().unwrap(),
        ]);
    }
    // libother: NEEDED libcrypto.so.3, own RPATH dirB (old dtags).
    let mid_src = dir.join("mid.c");
    std::fs::write(&mid_src, FAKE_MID_SRC).unwrap();
    let other = dir_a.join("libother.so.0");
    cc(&[
        "-shared",
        "-fPIC",
        "-g",
        "-Wl,--soname,libother.so.0",
        "-o",
        other.to_str().unwrap(),
        mid_src.to_str().unwrap(),
        "-L",
        dir_b.to_str().unwrap(),
        "-l:libcrypto.so.3",
        &format!("-Wl,-rpath,{}", dir_b.display()),
        "-Wl,--disable-new-dtags",
    ]);
    // app: NEEDED libcrypto.so.3 + libother.so.0, RPATH dirA.
    let app_src = dir.join("app.c");
    std::fs::write(
        &app_src,
        "extern int mid_drive(void);\nextern int OSSL_PROVIDER_load(void);\nint main(void) { return mid_drive() + OSSL_PROVIDER_load(); }\n",
    )
    .unwrap();
    let app = dir.join("app");
    cc(&[
        "-g",
        "-o",
        app.to_str().unwrap(),
        app_src.to_str().unwrap(),
        "-L",
        dir_a.to_str().unwrap(),
        "-l:libcrypto.so.3",
        "-l:libother.so.0",
        &format!("-Wl,-rpath,{}", dir_a.display()),
        "-Wl,--disable-new-dtags",
    ]);
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let env = spawn_env("/bin:/usr/bin", None);
    let argv = vec![app.to_string_lossy().into_owned()];
    let pred = onboard::predict_spawn_lib(&argv, &env).unwrap();
    assert_eq!(pred.libs.len(), 2, "libs: {:?}", pred.libs);
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Unsupported {
            reason,
            remediation,
        } => {
            assert!(reason.contains("dual-load"), "{reason}");
            assert!(remediation.contains("dual-load"), "{remediation}");
        }
        other => panic!("want Unsupported(dual-load), got {other:?}"),
    }
    // doctor --exe agrees: exit 4, dispatch-anchor names dual-load.
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let out = Command::new(bin)
        .arg("doctor")
        .arg("--exe")
        .arg(&app)
        .arg("--format")
        .arg("json")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .expect("run doctor");
    assert_eq!(out.status.code(), Some(4));
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("doctor json parses");
    let anchor = check_row(&doc, "dispatch-anchor");
    assert_eq!(anchor["status"], "fail");
    assert!(
        anchor["message"].as_str().unwrap().contains("dual-load"),
        "{anchor}"
    );
}

/// Anchor functions, no rodata version string: a non-rdynamic exe
/// keeps these names in .symtab only (.dynsym holds imports).
const NO_VERSION_EXE_SRC: &str = r#"
int OSSL_PROVIDER_available(void) { return 1; }
int OSSL_PROVIDER_load(void) { return 1; }
int OPENSSL_version_major(void) { return 3; }
int ENGINE_by_id(void) { return 1; }
int EVP_MD_fetch(void) { return 1; }
int main(void) { return 0; }
"#;

#[test]
fn static_symtab_only_anchors_need_symtab_union() {
    // The dynsym-only rule sees a non-rdynamic exe as NotCrypto
    // (imports only); unioning .symtab recovers the OpenSSL anchors.
    // Static-exe qualification and the doctor flavor row must use the
    // union rule — this pins the divergence that makes it load-bearing.
    let Some(exe) = build_fixture(
        "spawn-symtab-union",
        "noversion_exe.c",
        NO_VERSION_EXE_SRC,
        "noversion_static",
        &["-g"],
    ) else {
        return;
    };
    let bytes = std::fs::read(&exe).unwrap();
    let (dynsym_flavor, _) = flavor::classify_elf(&bytes).unwrap();
    assert_eq!(dynsym_flavor, Flavor::NotCrypto);
    let (union_flavor, ev) = flavor::classify_elf_with_symtab(&bytes).unwrap();
    assert!(
        matches!(
            union_flavor,
            Flavor::OpenSSL {
                major: 3,
                minor: None
            }
        ),
        "{union_flavor:?}"
    );
    assert!(ev.has_provider_load && ev.has_version_major);
}

#[test]
fn spawn_static_exe_supported_without_rdynamic() {
    let Some(exe) = build_fixture(
        "spawn-static",
        "fake_exe.c",
        FAKE_EXE_SRC,
        "fake_static",
        &["-g"],
    ) else {
        return;
    };
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    let env = spawn_env("/bin:/usr/bin", None);
    let argv = vec![exe.to_string_lossy().into_owned()];
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Supported(t) => {
            assert_eq!(t.resolution, Some(Resolution::Symtab));
            assert!(t.static_exe);
            assert_eq!(t.provider_path, exe);
        }
        other => panic!("want Supported(Symtab), got {other:?}"),
    }
}

#[test]
fn spawn_path_lookup_and_scripts() {
    if !have_gcc() {
        eprintln!("SKIP spawn-path: no gcc");
        return;
    }
    let dir = scratch("spawn-path");
    let src = dir.join("fake_exe.c");
    std::fs::write(&src, FAKE_EXE_SRC).unwrap();
    let exe = dir.join("myapp");
    let st = Command::new("gcc")
        .args(["-g", "-o"])
        .arg(&exe)
        .arg(&src)
        .output()
        .unwrap();
    assert!(st.status.success());
    let table = shipped();
    let enrollment = ProviderTable::empty();
    let opts = qualify_opts(&table, &enrollment);
    // Bare argv[0] resolves via injected PATH (execvp rules).
    let path = dir.to_string_lossy().into_owned();
    let env = spawn_env(&path, None);
    let pred = onboard::predict_spawn_lib(&["myapp".to_string()], &env).unwrap();
    assert_eq!(pred.exe, exe);
    match onboard::discover_spawn(&["myapp".to_string()], &opts, &env).unwrap() {
        TargetQualification::Supported(t) => assert!(t.static_exe),
        other => panic!("want Supported, got {other:?}"),
    }
    // Scripts cannot be predicted: Unknown, never a guess.
    let script = dir.join("run.sh");
    std::fs::write(&script, "#!/bin/sh\nexec /bin/true\n").unwrap();
    let argv = vec![script.to_string_lossy().into_owned()];
    match onboard::discover_spawn(&argv, &opts, &env).unwrap() {
        TargetQualification::Unknown { reason, .. } => {
            assert!(reason.contains("not an ELF binary"), "{reason}");
        }
        other => panic!("want Unknown for a script, got {other:?}"),
    }
    // A missing command is an I/O error (loud), not a qualification.
    let err = onboard::discover_spawn(&["definitely-not-a-command-xyz".to_string()], &opts, &env)
        .unwrap_err();
    assert!(err.message.contains("cannot read"), "{}", err.message);
}

// ---------------------------------------------------------------------------
// doctor agrees with the backend (same resolver, same qualification).
// ---------------------------------------------------------------------------

fn doctor_json(args: &[&str]) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let out = Command::new(bin)
        .arg("doctor")
        .args(args)
        // Deterministic prediction: a polluted environment must not
        // shadow fixture rpaths.
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).expect("doctor --format json parses")
}

fn check_row<'a>(doc: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("doctor row {id} missing in {doc}"))
}

#[test]
fn doctor_supported_target_reports_dispatch_anchor() {
    let Some(so) = build_fixture(
        "doctor-supported",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_libcrypto.so",
        &["-shared", "-fPIC", "-g"],
    ) else {
        return;
    };
    let doc = doctor_json(&["--libcrypto", &so.to_string_lossy(), "--format", "json"]);
    assert_eq!(check_row(&doc, "arch")["status"], "pass");
    assert_eq!(check_row(&doc, "flavor")["status"], "pass");
    let anchor = check_row(&doc, "dispatch-anchor");
    assert_eq!(anchor["status"], "pass", "anchor row: {anchor}");
    assert!(
        anchor["message"].as_str().unwrap().contains("symtab"),
        "anchor row: {anchor}"
    );
    // Privilege rows stay independent: caps may fail unprivileged
    // without changing the target-support verdict above.
    assert!(check_row(&doc, "caps").get("status").is_some());
}

#[test]
fn doctor_exe_predicts_spawn_target() {
    let Some((app, _)) = build_linked_app(
        "doctor-exe",
        "libcrypto.so.3",
        &["-Wl,-rpath,$ORIGIN/fakelib"],
    ) else {
        return;
    };
    // doctor --exe runs the same prediction as `run --` auto:
    // NEEDED libcrypto via rpath, symtab rung, dispatch pass.
    let doc = doctor_json(&["--exe", &app.to_string_lossy(), "--format", "json"]);
    assert_eq!(check_row(&doc, "target-access")["status"], "pass");
    assert_eq!(check_row(&doc, "libcrypto-found")["status"], "pass");
    let anchor = check_row(&doc, "dispatch-anchor");
    assert_eq!(anchor["status"], "pass", "anchor row: {anchor}");
    assert_eq!(
        check_row(&doc, "coverage-spawn")["status"],
        "info",
        "spawn coverage note present"
    );
    // F-G/B7: the spawn note must state requested-vs-effective
    // observation, never unqualified exec-anchored observation.
    let spawn_note = check_row(&doc, "coverage-spawn")["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        spawn_note.contains("requests observation from exec") && spawn_note.contains("effective"),
        "spawn note states requested-vs-effective: {spawn_note}"
    );
    assert!(
        !spawn_note.contains("no cold-start gap"),
        "spawn note must not overpromise exec-anchored observation: {spawn_note}"
    );
}

#[test]
fn doctor_exe_script_fails_arch_with_clear_message() {
    if !have_gcc() {
        eprintln!("SKIP doctor-exe-script: no gcc");
        return;
    }
    let dir = scratch("doctor-exe-script");
    let script = dir.join("run.sh");
    std::fs::write(&script, "#!/bin/sh\nexec /bin/true\n").unwrap();
    let doc = doctor_json(&["--exe", &script.to_string_lossy(), "--format", "json"]);
    let arch = check_row(&doc, "arch");
    assert_eq!(arch["status"], "fail", "arch row: {arch}");
    assert!(
        arch["message"].as_str().unwrap().contains("not an ELF"),
        "arch row: {arch}"
    );
    assert_eq!(doc["verdict"], "fail-closed");
}

#[test]
fn doctor_unknown_build_points_at_enrollment() {
    let Some(so) = build_fixture(
        "doctor-unknown",
        "fake.c",
        FAKE_LIBC_SRC,
        "fake_stripped.so",
        &["-shared", "-fPIC", "-s", "-Wl,--soname,OPENSSL_3.0"],
    ) else {
        return;
    };
    let doc = doctor_json(&["--libcrypto", &so.to_string_lossy(), "--format", "json"]);
    let anchor = check_row(&doc, "dispatch-anchor");
    assert_eq!(anchor["status"], "fail", "anchor row: {anchor}");
    let remediation = anchor["remediation"].as_str().unwrap();
    assert!(
        remediation.contains("enroll") || remediation.contains("--table"),
        "remediation: {remediation}"
    );
    assert_eq!(doc["verdict"], "fail-closed");
    assert_eq!(doc["exit"], 4);
}

#[test]
fn built_objects_pass_loader_shape_check() {
    // Loader-fix regression (F-C/A8 follow-up): the per-CPU
    // helpers took `&0u64`, which LLVM folds into .rodata with an
    // R_BPF_64_64 reloc — the fail-closed loader rejects non-map
    // 64-bit relocs, so E2E loading broke while C1/C2 (build-only
    // gates) stayed green. This test runs the same pure shape
    // check the backend runs at attach over the just-built
    // objects (no caps needed). Loud skip when the BPF objects
    // were not built (C2 builds them; a host-only checkout has
    // nothing to check).
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates/ebpf/target/bpfel-unknown-none/release");
    let harvest = dir.join("osslscope-harvest");
    let count = dir.join("osslscope-count");
    if !harvest.exists() || !count.exists() {
        eprintln!(
            "SKIP built_objects_pass_loader_shape_check: BPF objects not built \
             (run the C2 BPF build; host-only checkouts skip)"
        );
        return;
    }
    let h = std::fs::read(&harvest).unwrap();
    let c = std::fs::read(&count).unwrap();
    onboard::check_object_compatible(onboard::ObjectRole::Harvest, &h)
        .unwrap_or_else(|e| panic!("built harvest object fails loader shape check: {e}"));
    onboard::check_object_compatible(onboard::ObjectRole::Count, &c)
        .unwrap_or_else(|e| panic!("built count object fails loader shape check: {e}"));
}

// ---------------------------------------------------------------------------
// Traversal triple resolution (R19 integration).
// ---------------------------------------------------------------------------

/// Just-built BPF objects (C2 builds them; host-only checkouts skip
/// loud — same rule as `built_objects_pass_loader_shape_check` —
/// except in required mode, where a missing triple fails closed
/// like the shape suite: no skips under `OSSL_MEMBERS_REQUIRED=1`).
fn built_objects() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates/ebpf/target/bpfel-unknown-none/release");
    let h = dir.join("osslscope-harvest");
    let c = dir.join("osslscope-count");
    let m = dir.join("osslscope-members");
    if !h.exists() || !c.exists() || !m.exists() {
        if matches!(std::env::var("OSSL_MEMBERS_REQUIRED").as_deref(), Ok("1")) {
            panic!(
                "FAIL(members-required): BPF triple not built; \
                 required mode refuses silent skips"
            );
        }
        eprintln!("SKIP triple test: BPF objects not built (run the C2 BPF build)");
        return None;
    }
    Some((h, c, m))
}

fn chmod_trusted(p: &Path, dir: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if dir { 0o755 } else { 0o644 };
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Install a triple (or pair) into `$prefix/lib/osslscope/`
/// (trusted perms), optionally writing a receipt under
/// `$prefix/share/osslscope/`.
fn install_fixture(
    prefix: &Path,
    objs: &(PathBuf, PathBuf, PathBuf),
    with_members: bool,
    receipt: Option<&[(String, String)]>,
) -> PathBuf {
    let objdir = prefix.join("lib").join("osslscope");
    std::fs::create_dir_all(&objdir).unwrap();
    chmod_trusted(prefix, true);
    chmod_trusted(&prefix.join("lib"), true);
    chmod_trusted(&objdir, true);
    let names = [("osslscope-harvest", &objs.0), ("osslscope-count", &objs.1)];
    for (name, src) in names {
        let dst = objdir.join(name);
        std::fs::copy(src, &dst).unwrap();
        chmod_trusted(&dst, false);
    }
    if with_members {
        let dst = objdir.join("osslscope-members");
        std::fs::copy(&objs.2, &dst).unwrap();
        chmod_trusted(&dst, false);
    }
    if let Some(entries) = receipt {
        let rdir = prefix.join("share").join("osslscope");
        std::fs::create_dir_all(&rdir).unwrap();
        let arts: Vec<serde_json::Value> = entries
            .iter()
            .map(|(dest, sha)| {
                serde_json::json!({"role": "bpf-object", "dest": dest, "sha256": sha})
            })
            .collect();
        let manifest = serde_json::json!({
            "schema": "osslscope-install-manifest-v1",
            "artifacts": arts,
        });
        std::fs::write(
            rdir.join("install-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
    }
    objdir
}

#[test]
fn triple_explicit_all_wins() {
    let Some((h, c, m)) = built_objects() else {
        return;
    };
    // The Members compat arm accepts the built object (and
    // rejects a wrong-role object).
    onboard::check_object_compatible(onboard::ObjectRole::Members, &std::fs::read(&m).unwrap())
        .unwrap_or_else(|e| panic!("built members object fails loader shape check: {e}"));
    assert!(
        onboard::check_object_compatible(onboard::ObjectRole::Members, &std::fs::read(&h).unwrap())
            .is_err()
    );
    let (set, _) = onboard::resolve_set(Some(&h), Some(&c), Some(&m), &[], &test_trust())
        .expect("all-explicit triple resolves");
    assert_eq!(set.harvest, h);
    assert_eq!(set.count, c);
    assert_eq!(set.members, m);
}

/// Receipt dests for a fixture prefix (all three roles, honest
/// hashes — mirrors what install-dev.sh writes).
fn receipt_dests(prefix: &Path, objs: &(PathBuf, PathBuf, PathBuf)) -> Vec<(String, String)> {
    let objdir = prefix.join("lib").join("osslscope");
    ["osslscope-harvest", "osslscope-count", "osslscope-members"]
        .iter()
        .map(|n| {
            let src = match *n {
                "osslscope-harvest" => &objs.0,
                "osslscope-count" => &objs.1,
                _ => &objs.2,
            };
            (
                objdir.join(n).display().to_string(),
                onboard::file_sha256_hex(src).unwrap(),
            )
        })
        .collect()
}

#[test]
fn triple_implicit_receiptless_members_refused() {
    let Some(objs) = built_objects() else {
        return;
    };
    // No receipt: the pair roles stay compatible (old installs),
    // but the members role refuses — a receiptless members file
    // is a hand-placed object whose matched-build identity is not
    // established (explicit --members-object operator-trusts it).
    let prefix = scratch("triple-no-receipt");
    let objdir = install_fixture(&prefix, &objs, true, None);
    let err = onboard::resolve_set(None, None, None, &[objdir], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("no install receipt"),
        "message: {}",
        err.message
    );
    assert!(
        err.remediation.contains("install-dev.sh"),
        "remediation: {}",
        err.remediation
    );
    assert!(
        err.remediation.contains("--members-object"),
        "remediation: {}",
        err.remediation
    );
    // Found-but-broken is never not-found (the ordinary run
    // refuses a receiptless-members triple — no harvest-only
    // fallback for unproven matched-build identity).
    assert!(!err.is_not_found());
}

#[test]
fn triple_skips_old_pair_dir() {
    let Some(objs) = built_objects() else {
        return;
    };
    // First dir: old pair (no members) — skipped, not an error.
    let pair_pfx = scratch("triple-pair-first");
    let pair_dir = install_fixture(&pair_pfx, &objs, false, None);
    let triple_pfx = scratch("triple-triple-second");
    let triple_dests = receipt_dests(&triple_pfx, &objs);
    let triple_dir = install_fixture(&triple_pfx, &objs, true, Some(&triple_dests));
    let (set, _) = onboard::resolve_set(
        None,
        None,
        None,
        &[pair_dir, triple_dir.clone()],
        &test_trust(),
    )
    .expect("old-pair dir skipped for the triple");
    assert_eq!(set.members, triple_dir.join("osslscope-members"));
}

#[test]
fn triple_missing_members_refused() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Only pair dirs: the triple cannot resolve — actionable
    // refusal naming the members role (never a silent
    // harvest-only fallback).
    let prefix = scratch("triple-missing");
    let pair_dir = install_fixture(&prefix, &objs, false, None);
    let err = onboard::resolve_set(None, None, None, &[pair_dir], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("harvest+count+members triple"),
        "message: {}",
        err.message
    );
    assert!(
        err.remediation.contains("--members-object"),
        "remediation: {}",
        err.remediation
    );
    // Pair-only is not-found (the ordinary run stays harvest-only
    // here — the only silent-fallback-free branch).
    assert!(err.is_not_found());
}

#[test]
fn onboard_error_kind_is_typed_not_prefix() {
    // Spoof-proof: a found-but-broken error whose message happens
    // to start with the not-found wording must NOT classify as
    // not-found (classification is a typed kind, never a prefix).
    let spoof = onboard::OnboardError::new(
        "no BPF objects found (spoofed wording)".to_string(),
        "fix".to_string(),
    );
    assert!(!spoof.is_not_found());
    // And a not-found error classifies by kind whatever its
    // wording (rewording the message must not flip the run-set
    // decision).
    let genuine = onboard::OnboardError::not_found(
        "custom wording, still nothing found".to_string(),
        "fix".to_string(),
    );
    assert!(genuine.is_not_found());
}

#[test]
fn triple_receipt_verified_and_stale_refused() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Receipted prefix, all hashes match: resolves.
    let prefix = scratch("triple-receipt-ok");
    let objdir = prefix.join("lib").join("osslscope");
    let dests: Vec<(String, String)> =
        ["osslscope-harvest", "osslscope-count", "osslscope-members"]
            .iter()
            .map(|n| {
                let src = match *n {
                    "osslscope-harvest" => &objs.0,
                    "osslscope-count" => &objs.1,
                    _ => &objs.2,
                };
                (
                    objdir.join(n).display().to_string(),
                    onboard::file_sha256_hex(src).unwrap(),
                )
            })
            .collect();
    let objdir = install_fixture(&prefix, &objs, true, Some(&dests));
    onboard::resolve_set(None, None, None, &[objdir], &test_trust())
        .expect("receipt-matching triple resolves");
    // Same prefix, receipt claims the WRONG hash for members
    // (stale receipt): refused as stale.
    let prefix2 = scratch("triple-receipt-stale");
    let objdir2 = prefix2.join("lib").join("osslscope");
    let mut stale = dests.clone();
    for (dest, sha) in stale.iter_mut() {
        if dest.ends_with("osslscope-members") {
            *dest = objdir2.join("osslscope-members").display().to_string();
            *sha = "0".repeat(64);
        } else {
            let name = if dest.ends_with("osslscope-harvest") {
                "osslscope-harvest"
            } else {
                "osslscope-count"
            };
            *dest = objdir2.join(name).display().to_string();
        }
    }
    // Re-mint the two honest hashes for prefix2's dests (same
    // bytes, so the recorded hashes still match the files).
    let objdir2 = install_fixture(&prefix2, &objs, true, Some(&stale));
    let err = onboard::resolve_set(None, None, None, &[objdir2], &test_trust()).unwrap_err();
    assert!(err.message.contains("stale"), "message: {}", err.message);
    assert!(
        err.remediation.contains("install-dev.sh"),
        "remediation: {}",
        err.remediation
    );
    // Stale is found-but-broken (refuse, never harvest-only).
    assert!(!err.is_not_found());
}

#[test]
fn triple_unlisted_role_is_mixed_set() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Receipt lists only the pair; members.o is hand-placed
    // (present but unlisted): mixed set, refused.
    let prefix = scratch("triple-mixed");
    let objdir = prefix.join("lib").join("osslscope");
    let pair_only: Vec<(String, String)> = ["osslscope-harvest", "osslscope-count"]
        .iter()
        .map(|n| {
            let src = if *n == "osslscope-harvest" {
                &objs.0
            } else {
                &objs.1
            };
            (
                objdir.join(n).display().to_string(),
                onboard::file_sha256_hex(src).unwrap(),
            )
        })
        .collect();
    let objdir = install_fixture(&prefix, &objs, true, Some(&pair_only));
    let err = onboard::resolve_set(None, None, None, &[objdir], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("mixed set"),
        "message: {}",
        err.message
    );
    // Mixed is found-but-broken (refuse, never harvest-only).
    assert!(!err.is_not_found());
}

#[test]
fn triple_mixed_explicit_implicit_allowed() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Members explicit + pair implicit (operator's stated mix):
    // resolves (explicit roles bypass receipts — operator-trusted).
    let prefix = scratch("triple-mixed-ok");
    let pair_dir = install_fixture(&prefix, &objs, false, None);
    let (set, _) = onboard::resolve_set(
        None,
        None,
        Some(&objs.2),
        &[pair_dir.clone()],
        &test_trust(),
    )
    .expect("explicit-members + implicit pair resolves");
    assert_eq!(set.members, objs.2);
    assert_eq!(set.harvest, pair_dir.join("osslscope-harvest"));
}

// ---------------------------------------------------------------------------
// Shared run-set decision (round-2 F9): capture and doctor resolve
// through ONE function, so missing/mixed/stale sets behave
// identically in both — no silent pair fallback where doctor
// rejects, no receiptless matched-build claims.
// ---------------------------------------------------------------------------

#[test]
fn fix2_run_set_pair_only_when_members_absent_everywhere() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Old-pair install (no members file anywhere): the run stays
    // harvest-only — the only pair-fallback branch.
    let prefix = scratch("runset-pair-only");
    let pair_dir = install_fixture(&prefix, &objs, false, None);
    let (run, _) = onboard::resolve_run_set(None, None, None, &[pair_dir.clone()], &test_trust())
        .expect("pair-only install stays harvest-only");
    match run {
        onboard::RunSet::PairOnly(pair) => {
            assert_eq!(pair.harvest, pair_dir.join("osslscope-harvest"));
            assert_eq!(pair.count, pair_dir.join("osslscope-count"));
        }
        onboard::RunSet::Triple(_) => panic!("pair-only install must not claim a triple"),
        onboard::RunSet::NoObjects(e) => panic!("pair resolves here: {}", e.full()),
    }
}

#[test]
fn fix2_run_set_members_elsewhere_refuses() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Pair in A, members alone in B: a mixed set — the run
    // refuses (never a quiet pair while doctor rejects the same
    // set). This is the F9 capture/doctor agreement case.
    let pair_pfx = scratch("runset-mixed-pair");
    let pair_dir = install_fixture(&pair_pfx, &objs, false, None);
    let mem_pfx = scratch("runset-mixed-members");
    let mem_objdir = mem_pfx.join("lib").join("osslscope");
    std::fs::create_dir_all(&mem_objdir).unwrap();
    chmod_trusted(&mem_pfx, true);
    chmod_trusted(&mem_pfx.join("lib"), true);
    chmod_trusted(&mem_objdir, true);
    let mem_dst = mem_objdir.join("osslscope-members");
    std::fs::copy(&objs.2, &mem_dst).unwrap();
    chmod_trusted(&mem_dst, false);
    let err = onboard::resolve_run_set(None, None, None, &[pair_dir, mem_objdir], &test_trust())
        .unwrap_err();
    assert!(
        err.message.contains("harvest+count+members triple"),
        "mixed set refuses with the triple error: {}",
        err.message
    );
}

#[test]
fn fix2_run_set_stale_refuses_without_fallback() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Complete triple, one role swapped after install: stale is
    // found-but-broken (never not-found) — no pair fallback.
    let prefix = scratch("runset-stale");
    let dests = receipt_dests(&prefix, &objs);
    let objdir = install_fixture(&prefix, &objs, true, Some(&dests));
    std::fs::write(objdir.join("osslscope-count"), b"swapped-bytes").unwrap();
    let err = onboard::resolve_run_set(None, None, None, &[objdir], &test_trust()).unwrap_err();
    assert!(
        err.message.contains("stale"),
        "stale triple refuses: {}",
        err.message
    );
}

#[test]
fn fix2_run_set_explicit_members_never_falls_back() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Explicit members demanded but pair unresolvable: the
    // operator demanded traversal — refuse, never harvest-only.
    let missing = scratch("runset-explicit-missing").join("nope-count");
    let err = onboard::resolve_run_set(None, Some(&missing), Some(&objs.2), &[], &test_trust())
        .unwrap_err();
    assert!(
        err.message.contains("missing"),
        "explicit-members failure refuses: {}",
        err.message
    );
}

#[test]
fn fix2_run_set_explicit_pair_provenance_kept() {
    let Some(objs) = built_objects() else {
        return;
    };
    // Provenance rides the set: explicit roles are flagged so the
    // snapshot never receipt-checks operator-trusted bytes.
    let mix_pfx = scratch("runset-prov-mixed");
    let mix_dir = install_fixture(&mix_pfx, &objs, false, None);
    let (set, _) = onboard::resolve_set(
        Some(&objs.0),
        None,
        Some(&objs.2),
        &[mix_dir],
        &test_trust(),
    )
    .expect("mixed set resolves");
    assert_eq!(set.explicit, [true, false, true]);
    let prefix = scratch("runset-prov-implicit");
    let dests = receipt_dests(&prefix, &objs);
    let objdir = install_fixture(&prefix, &objs, true, Some(&dests));
    let (set, _) = onboard::resolve_set(None, None, None, &[objdir], &test_trust())
        .expect("implicit triple resolves");
    assert_eq!(set.explicit, [false, false, false]);
}

#[test]
fn doctor_pid_reports_cold_gap_preflight() {
    // v0.2 cold-gap preflight: doctor --pid must surface the
    // late-attach blindness warning (degraded, never a refusal).
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let out = Command::new(bin)
        .arg("doctor")
        .arg("--pid")
        .arg(format!("{}", std::process::id()))
        .arg("--format")
        .arg("json")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .expect("run doctor");
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("doctor json parses");
    let pre = check_row(&doc, "cold-gap-preflight");
    assert_eq!(pre["status"], "degraded", "{pre}");
    assert!(
        pre["message"].as_str().unwrap().contains("pre-attach"),
        "{pre}"
    );
    assert!(
        pre["remediation"].as_str().unwrap().contains("run --"),
        "{pre}"
    );
}
