// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic ELF controls: interface evidence, never release qualification.
use osslscope::inventory::elf::{inspect_file, inspect_module};
use osslscope::inventory::{Api, Architecture, GapReason, ObjectKind};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const LIMIT: u64 = 134_217_728;
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-inventory-elf-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn build(&self, name: &str, source: &str, extra: &[&str]) -> PathBuf {
        let c = self.0.join(format!("{name}.c"));
        let so = self.0.join(name);
        fs::write(&c, source).unwrap();
        let output = Command::new("cc")
            .args(["-shared", "-fPIC", "-Wl,--build-id=none", "-o"])
            .arg(&so)
            .arg(&c)
            .args(extra)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new("strip")
                .arg("--strip-all")
                .arg(&so)
                .status()
                .unwrap()
                .success()
        );
        so
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// Catches pathname/vendor heuristics and failure to inspect stripped dynsym.
#[test]
fn independently_built_arbitrary_names_have_finite_interfaces_and_distinct_hashes() {
    let f = Fixture::new();
    let provider = f.build(
        "cloud.dat",
        "int OSSL_provider_init(void) { return 11; }",
        &[],
    );
    let crypto = f.build(
        "rain.bin",
        "int OPENSSL_init_crypto(void) { return 22; }\nint EVP_MD_fetch(void) { return 23; }",
        &[],
    );
    let first = inspect_module(&provider, LIMIT).unwrap();
    let second = inspect_module(&crypto, LIMIT).unwrap();
    assert_eq!(first.kind, ObjectKind::ProviderModule);
    assert_eq!(first.exports, vec![Api::OsslProviderInit]);
    assert_eq!(second.kind, ObjectKind::OpenSslCompatible);
    assert_eq!(
        second.exports,
        vec![Api::OpenSslInitCrypto, Api::EvpMdFetch]
    );
    assert_ne!(first.sha256, second.sha256);
    assert_eq!(first.sha256.len(), 64);
    assert!(
        first
            .sha256
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    let metadata = fs::metadata(provider).unwrap();
    assert_eq!(
        (first.device, first.inode, first.size_bytes),
        (metadata.dev(), metadata.ino(), metadata.len())
    );
    assert_eq!(first.architecture, Architecture::X86_64);
}

// Catches dlopen or target-derived strings entering serialized evidence.
#[test]
fn constructor_is_never_executed_and_strings_are_not_emitted() {
    let f = Fixture::new();
    let marker = f.0.join("PRIVATE_CANARY_marker");
    let dependency = f.build(
        "PRIVATE_CANARY_dependency.so",
        "int private_dependency(void) { return 7; }",
        &["-Wl,-soname,PRIVATE_CANARY_dependency.so"],
    );
    let source = format!(
        r#"
        #include <stdio.h>
        extern int private_dependency(void);
        __attribute__((constructor)) static void create_marker(void) {{
            FILE *f = fopen("{}", "w"); if (f) fclose(f);
        }}
        int PRIVATE_CANARY_unknown_export(void) {{ return private_dependency(); }}
        int OSSL_provider_init(void) {{ return 1; }}
    "#,
        marker.display()
    );
    let object = f.build(
        "PRIVATE_CANARY_filename",
        &source,
        &[dependency.to_str().unwrap()],
    );
    let metadata = inspect_module(&object, LIMIT).unwrap();
    assert!(!marker.exists());
    assert_eq!(metadata.kind, ObjectKind::ProviderModule);
    let json = serde_json::to_string(&metadata).unwrap();
    assert!(!json.contains("PRIVATE_CANARY"));
    assert!(!json.contains("private_dependency"));
    assert!(!json.contains(f.0.to_str().unwrap()));
    assert!(!metadata.depends_on_libcrypto && !metadata.depends_on_libssl);
}

// Catches treating data, hidden symbols or undefined imports as exports.
#[test]
fn imports_are_consumer_evidence_and_data_is_not_code() {
    let f = Fixture::new();
    let object = f.build(
        "data",
        r#"
        int OSSL_provider_init = 1;
        __attribute__((visibility("hidden"))) int OSSL_PROVIDER_unload(void) { return 1; }
        extern int EVP_MD_fetch(void);
        int unrelated(void) { return EVP_MD_fetch(); }
    "#,
        &[],
    );
    let metadata = inspect_module(&object, LIMIT).unwrap();
    assert!(metadata.exports.is_empty());
    assert_eq!(metadata.kind, ObjectKind::OpenSslConsumer);
    let other = f.build("other", "int OSSL_provider_init = 1;", &[]);
    assert_eq!(
        inspect_module(&other, LIMIT).unwrap().kind,
        ObjectKind::Other
    );
}

// Catches missing API families, duplicate labels and discovery-order output.
#[test]
fn public_api_allowlist_is_finite_and_complete() {
    let f = Fixture::new();
    let object = f.build(
        "interfaces",
        r#"
        int OSSL_PROVIDER_load(void) { return 1; }
        int OSSL_PROVIDER_try_load(void) { return 1; }
        int OSSL_PROVIDER_unload(void) { return 1; }
        int OSSL_PROVIDER_load_ex(void) { return 1; }
        int OSSL_PROVIDER_try_load_ex(void) { return 1; }
        int OSSL_PROVIDER_add_builtin(void) { return 1; }
        int OSSL_PROVIDER_get0_dispatch(void) { return 1; }
        int OSSL_PROVIDER_query_operation(void) { return 1; }
        int OPENSSL_init_crypto(void) { return 1; }
        int OPENSSL_version_major(void) { return 1; }
        int EVP_MD_fetch(void) { return 1; }
        int EVP_CIPHER_fetch(void) { return 1; }
        int EVP_MAC_fetch(void) { return 1; }
        int EVP_KDF_fetch(void) { return 1; }
        int EVP_SIGNATURE_fetch(void) { return 1; }
        int EVP_KEM_fetch(void) { return 1; }
        int unknown(void) { return 1; }
    "#,
        &[],
    );
    let metadata = inspect_module(&object, LIMIT).unwrap();
    assert_eq!(metadata.kind, ObjectKind::OpenSslCompatible);
    assert_eq!(
        metadata.exports,
        vec![
            Api::OsslProviderLoad,
            Api::OsslProviderTryLoad,
            Api::OsslProviderUnload,
            Api::OsslProviderLoadEx,
            Api::OsslProviderTryLoadEx,
            Api::OsslProviderAddBuiltin,
            Api::OsslProviderGet0Dispatch,
            Api::OsslProviderQueryOperation,
            Api::OpenSslInitCrypto,
            Api::OpenSslVersionMajor,
            Api::EvpMdFetch,
            Api::EvpCipherFetch,
            Api::EvpMacFetch,
            Api::EvpKdfFetch,
            Api::EvpSignatureFetch,
            Api::EvpKemFetch,
        ]
    );
}

// Catches unbounded FIFO open/read and acceptance of malformed/over-limit data.
#[test]
fn nonregular_oversize_and_malformed_are_bounded() {
    let f = Fixture::new();
    assert_eq!(
        inspect_module(Path::new("/dev/null"), LIMIT),
        Err(GapReason::NonRegular)
    );
    assert_eq!(inspect_module(&f.0, LIMIT), Err(GapReason::NonRegular));
    assert_eq!(
        inspect_module(&f.0.join("missing"), LIMIT),
        Err(GapReason::Unavailable)
    );
    let plain = f.0.join("plain");
    fs::write(&plain, b"plain text").unwrap();
    assert_eq!(inspect_module(&plain, LIMIT), Err(GapReason::NotElf));
    assert_eq!(inspect_module(&plain, 3), Err(GapReason::TooLarge));
    fs::write(&plain, b"\x7fELF\x02\x01").unwrap();
    assert_eq!(inspect_module(&plain, LIMIT), Err(GapReason::MalformedElf));
    let fifo = f.0.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(inspect_module(&fifo, LIMIT)).unwrap();
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .expect("FIFO must not block"),
        Err(GapReason::NonRegular)
    );
}

// Catches reopening an attacker-replaced pathname or reading at the FD cursor.
#[test]
fn borrowed_descriptor_retains_identity_and_cursor_after_path_replacement() {
    let f = Fixture::new();
    let path = f.build("bound", "int OSSL_provider_init(void) { return 1; }", &[]);
    let expected = inspect_module(&path, LIMIT).unwrap();
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::Start(9)).unwrap();
    fs::rename(&path, f.0.join("renamed")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert_eq!(inspect_file(&mut file, LIMIT).unwrap(), expected);
    assert_eq!(file.stream_position().unwrap(), 9);
}

// Catches rejecting foreign inventory objects as a tracing-policy decision.
#[test]
fn architecture_is_descriptive() {
    let f = Fixture::new();
    let path = f.build("foreign", "int OSSL_provider_init(void) { return 1; }", &[]);
    let mut bytes = fs::read(&path).unwrap();
    // e_machine in these compiler-built ELF64 little-endian fixtures.
    for (machine, expected) in [(183_u16, Architecture::Aarch64), (243, Architecture::Other)] {
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert_eq!(inspect_module(&path, LIMIT).unwrap().architecture, expected);
    }
}

// Catches dependency filename guessing and dependencies promoted to providers.
#[test]
fn dependency_evidence_is_consumer_only() {
    let f = Fixture::new();
    for (name, crypto, ssl) in [
        ("libcrypto.so.3", true, false),
        ("libcrypto.so.4", true, false),
        ("libssl.so.3", false, true),
        ("libssl.so.4", false, true),
        ("libcrypto.so.PRIVATE_CANARY", false, false),
    ] {
        let dependency = f.build(
            name,
            "int dependency(void) { return 1; }",
            &[&format!("-Wl,-soname,{name}")],
        );
        let object = f.build(
            "consumer",
            "extern int dependency(void); int use_dependency(void) { return dependency(); }",
            &[dependency.to_str().unwrap()],
        );
        let metadata = inspect_module(&object, LIMIT).unwrap();
        assert_eq!(
            (metadata.depends_on_libcrypto, metadata.depends_on_libssl),
            (crypto, ssl)
        );
        assert_eq!(
            metadata.kind,
            if crypto || ssl {
                ObjectKind::OpenSslConsumer
            } else {
                ObjectKind::Other
            }
        );
        assert!(metadata.exports.is_empty());
    }
}

// Catches accepting a claimed function whose section definition is invalid.
#[test]
fn invalid_symbol_section_cannot_establish_an_interface() {
    let f = Fixture::new();
    let path = f.build(
        "bad-section",
        "int OSSL_provider_init(void) { return 1; }",
        &[],
    );
    let mut bytes = fs::read(&path).unwrap();
    let section_index_field = {
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let symbols = elf
            .section_headers
            .iter()
            .find(|section| section.sh_type == goblin::elf::section_header::SHT_DYNSYM)
            .unwrap();
        let index = elf
            .dynsyms
            .iter()
            .position(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some("OSSL_provider_init"))
            .unwrap();
        symbols.sh_offset as usize + index * 24 + 6
    };
    // ELF64 st_shndx: a nonreserved but nonexistent section index.
    bytes[section_index_field..section_index_field + 2].copy_from_slice(&0x1234_u16.to_le_bytes());
    fs::write(&path, bytes).unwrap();
    let metadata = inspect_module(&path, LIMIT).unwrap();
    assert!(metadata.exports.is_empty());
    assert_eq!(metadata.kind, ObjectKind::Other);
}

// Minimal ELF64 with a section-name table, optionally reused as the ordinary
// symbol-name table. Thousands of empty entries amplify Goblin's eager index.
fn string_table_elf(size: usize, ordinary_symbols: bool) -> Vec<u8> {
    let mut bytes = vec![0; 256 + size];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
    bytes[132..136].copy_from_slice(&3_u32.to_le_bytes()); // SHT_STRTAB
    bytes[152..160].copy_from_slice(&256_u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&(size as u64).to_le_bytes());
    if ordinary_symbols {
        bytes[196..200].copy_from_slice(&2_u32.to_le_bytes()); // SHT_SYMTAB
        bytes[232..236].copy_from_slice(&1_u32.to_le_bytes()); // sh_link
        bytes[248..256].copy_from_slice(&24_u64.to_le_bytes());
    }
    bytes
}

// Catches file-byte admission permitting an unbounded eager string index.
#[test]
fn metadata_string_rows_are_bounded_before_eager_parsing() {
    let f = Fixture::new();
    let path = f.0.join("many-strings");
    fs::write(&path, string_table_elf(65_537, false)).unwrap();
    assert_eq!(inspect_module(&path, LIMIT), Err(GapReason::ReadLimit));
    // The same bytes with one long string do not expand into thousands of rows.
    let mut control = string_table_elf(65_537, false);
    control[257..].fill(b'x');
    *control.last_mut().unwrap() = 0;
    fs::write(&path, control).unwrap();
    assert_eq!(
        inspect_module(&path, LIMIT).unwrap().kind,
        ObjectKind::Other
    );
}

// Catches per-table limits missing aggregate expansion, including aliased data.
#[test]
fn metadata_string_rows_are_aggregated_across_selected_tables() {
    let f = Fixture::new();
    let path = f.0.join("reused-strings");
    fs::write(&path, string_table_elf(40_000, true)).unwrap();
    assert_eq!(inspect_module(&path, LIMIT), Err(GapReason::ReadLimit));
}

// Catches Dynamic::parse reserving a huge vector despite an early DT_NULL.
#[test]
fn metadata_dynamic_capacity_is_bounded_before_eager_parsing() {
    let f = Fixture::new();
    let path = f.build("many-dynamic", "int unrelated(void) { return 1; }", &[]);
    let mut bytes = fs::read(&path).unwrap();
    let dynamic_header = {
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let index = elf
            .program_headers
            .iter()
            .position(|header| header.p_type == goblin::elf::program_header::PT_DYNAMIC)
            .unwrap();
        elf.header.e_phoff as usize + index * 56
    };
    let offset = bytes.len() as u64;
    let size = 16_385_u64 * 16;
    bytes.resize(bytes.len() + size as usize, 0);
    bytes[dynamic_header + 8..dynamic_header + 16].copy_from_slice(&offset.to_le_bytes());
    bytes[dynamic_header + 32..dynamic_header + 40].copy_from_slice(&size.to_le_bytes());
    fs::write(&path, bytes).unwrap();
    assert_eq!(inspect_module(&path, LIMIT), Err(GapReason::ReadLimit));
}

// Prevents addressing metadata amplification by reducing the file byte limit.
#[test]
fn metadata_bounds_preserve_128_mib_file_admission() {
    let f = Fixture::new();
    let path = f.0.join("large-object");
    fs::write(&path, string_table_elf(1, false)).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(LIMIT)
        .unwrap();
    assert_eq!(inspect_module(&path, LIMIT).unwrap().size_bytes, LIMIT);
}

// A procfs pseudofile can report S_IFREG/size0 while exposing process data.
// Exercise only harmless stat metadata in RED, never memory/environment/argv.
#[test]
fn procfs_pseudofiles_and_descriptor_aliases_are_refused_before_reading() {
    use std::os::fd::AsRawFd as _;
    let mut file = File::open("/proc/self/stat").unwrap();
    assert_eq!(inspect_file(&mut file, LIMIT), Err(GapReason::Unavailable));
    assert_eq!(
        inspect_module(Path::new("/proc/self/stat"), LIMIT),
        Err(GapReason::Unavailable)
    );
    let alias = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    assert_eq!(inspect_module(&alias, LIMIT), Err(GapReason::Unavailable));
}

#[test]
fn procfs_links_to_native_elf_backing_remain_supported() {
    use std::os::fd::AsRawFd as _;
    let f = Fixture::new();
    let module = f.build("native", "int OSSL_provider_init(void) { return 1; }", &[]);
    let expected = inspect_module(&module, LIMIT).unwrap();
    let file = File::open(&module).unwrap();
    let alias = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    assert_eq!(inspect_module(&alias, LIMIT).unwrap(), expected);
    // /proc/self/exe resolves to native backing even when this test harness is
    // intentionally larger than the normal module cap: it reaches TooLarge,
    // never the procfs refusal.
    assert_eq!(
        inspect_module(Path::new("/proc/self/exe"), 0),
        Err(GapReason::TooLarge)
    );
}

// IN_ACCESS is an independent Linux read oracle. Even the old EOF probe on
// an empty regular file generated it; a length guard must issue no read.
#[test]
fn files_shorter_than_elf_magic_are_rejected_without_a_read() {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    let f = Fixture::new();
    for size in 0..4 {
        let path = f.0.join(format!("short-{size}"));
        fs::write(&path, vec![b'x'; size]).unwrap();
        // SAFETY: returns a fresh descriptor, transferred once to OwnedFd.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0);
        let notifications = unsafe { OwnedFd::from_raw_fd(raw) };
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: owned FD and NUL-terminated path remain live.
        assert!(
            unsafe {
                libc::inotify_add_watch(notifications.as_raw_fd(), c_path.as_ptr(), libc::IN_ACCESS)
            } >= 0
        );
        assert_eq!(inspect_module(&path, LIMIT), Err(GapReason::NotElf));
        let mut events = [0u8; 4096];
        // SAFETY: destination buffer is valid for its full supplied size.
        let bytes = unsafe {
            libc::read(
                notifications.as_raw_fd(),
                events.as_mut_ptr().cast(),
                events.len(),
            )
        };
        assert_eq!(bytes, -1, "short file contents were read");
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn operational_only_public_exports_are_inventory_sources() {
    let f = Fixture::new();
    let object = f.build("operational.so", "int EVP_DigestSign(void) { return 1; } int EVP_RAND_generate(void) { return 1; } int EVP_MAC_final;", &[]);
    let metadata = inspect_module(&object, LIMIT).unwrap();
    assert_eq!(metadata.kind, ObjectKind::OpenSslCompatible);
    assert_eq!(metadata.exports.len(), 2);
}
