// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::inventory::{self, Api};
use osslscope::provider_observation::{self as observation, *};
use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.c");
        fs::write(&source, "int OSSL_PROVIDER_load(void){return 1;} void OSSL_PROVIDER_unquery_operation(void){} int EVP_MD_fetch=1; __attribute__((section(\".bss\"))) int EVP_CIPHER_fetch;").unwrap();
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,--strip-all", "-o"])
                .arg(dir.join("renamed.so"))
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        Self(dir)
    }
    fn file(&self) -> File {
        File::open(self.0.join("renamed.so")).unwrap()
    }
}
struct OwnedChild(Child);
impl OwnedChild {
    fn spawn(fixture: &Fixture, paths: &[std::path::PathBuf]) -> Self {
        let source = fixture.0.join("mmap.c");
        let binary = fixture.0.join("mmap");
        fs::write(&source,r#"#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv){for(int i=1;i<argc;i++){int fd=open(argv[i],O_RDONLY);struct stat st;if(fd<0||fstat(fd,&st))return 2;if(mmap(0,st.st_size,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0)==MAP_FAILED)return 3;close(fd);}puts("ready");fflush(stdout);int command=getchar();if(command==101){execl("/bin/cat","cat",(char*)0);return 4;}return 0;}
"#).unwrap();
        assert!(
            Command::new("cc")
                .arg("-o")
                .arg(&binary)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        let mut child = Command::new(binary)
            .args(paths)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        Self(child)
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        assert!(self.0.wait().unwrap().success());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn renamed_stripped_exports_resolve() {
    let f = Fixture::new();
    let mut budget = ObservationBudget::default();
    assert_eq!(
        observation::inspect_exports(&mut f.file(), &mut budget).unwrap(),
        vec![
            ObservationApi::Inventoried(Api::OsslProviderLoad),
            ObservationApi::OsslProviderUnqueryOperation
        ]
    );
    assert_eq!(
        ObservationApi::OsslProviderUnqueryOperation.export_name(),
        Some("OSSL_PROVIDER_unquery_operation")
    );
    assert_eq!(
        ObservationApi::Inventoried(Api::OpenSslInitCrypto).export_name(),
        None
    );
    assert_eq!(
        ObservationApi::Inventoried(Api::OpenSslVersionMajor).export_name(),
        None
    );
}
#[test]
fn nonexec_or_bss_symbol_refuses() {
    let f = Fixture::new();
    let exports =
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default()).unwrap();
    assert!(!exports.contains(&ObservationApi::Inventoried(Api::EvpMdFetch)));
    assert!(!exports.contains(&ObservationApi::Inventoried(Api::EvpCipherFetch)));
}
#[test]
fn budget_charged_before_read() {
    let f = Fixture::new();
    let mut limits = ObservationLimits::default();
    limits.max_elf_read_bytes = 0;
    let mut budget = ObservationBudget::new(limits);
    assert_eq!(
        observation::inspect_exports(&mut f.file(), &mut budget),
        Err(ObservationGap::ReadLimit)
    );
    assert_eq!(budget.elf_read_bytes(), 0);
}
#[test]
fn schema_rejects_raw_fields() {
    let fact = ObservationFact {
        pid: 1,
        starttime: 2,
        object_sha256: "00".repeat(32).try_into().unwrap(),
        generation: 1,
        context: ContextIdentity::Unknown {},
        source: ObservationSource::PublicApi,
        api: ObservationApi::OsslProviderUnqueryOperation,
        operation: Operation::Digest,
        class: AlgorithmClass::Other,
        monotonic_ns: 3,
        confidence: ScopeConfidence::Observed,
    };
    let value = serde_json::to_value(&fact).unwrap();
    assert_eq!(
        serde_json::from_value::<ObservationFact>(value.clone()).unwrap(),
        fact
    );
    for raw in ["address", "path", "raw_name", "parameters", "description"] {
        let mut invalid = value.clone();
        invalid[raw] = serde_json::json!("PRIVATE_CANARY");
        assert!(serde_json::from_value::<ObservationFact>(invalid).is_err());
    }
    let mut invalid = value.clone();
    invalid["context"]["pointer"] = serde_json::json!(42);
    assert!(serde_json::from_value::<ObservationFact>(invalid).is_err());
    let mut invalid = value.clone();
    invalid["object_sha256"] = serde_json::json!("/PRIVATE_CANARY");
    assert!(serde_json::from_value::<ObservationFact>(invalid).is_err());
    let encoded = serde_json::to_string(&fact).unwrap();
    assert!(!encoded.contains("PRIVATE_CANARY"));
    assert!(!encoded.contains("address"));
    assert!(!encoded.contains("path"));
    assert_eq!(
        serde_json::to_string(&ObservationGap::IdentityUnverified).unwrap(),
        "\"identity_unverified\""
    );
}
fn record() -> inventory::ProcessRecord {
    inventory::snapshot(&inventory::SnapshotOptions {
        pids: vec![std::process::id()],
        ..Default::default()
    })
    .processes
    .remove(0)
}
#[test]
fn pid_exec_namespace_change_retires() {
    let mut r = record();
    r.starttime = r.starttime.saturating_add(1);
    assert!(matches!(
        acquire(&r, &mut ObservationBudget::default()),
        Err(ObservationGap::ProcessChanged)
    ));
    let mut r = record();
    r.namespaces.mount = None;
    assert!(matches!(
        acquire(&r, &mut ObservationBudget::default()),
        Err(ObservationGap::NamespaceChanged)
    ));
}
#[test]
fn overlay_locator_refuses_attachment() {
    let mut r = record();
    for module in &mut r.modules {
        module.identity_status = inventory::IdentityStatus::LocatorCandidate;
    }
    match acquire(&r, &mut ObservationBudget::default()) {
        Ok(process) => assert!(
            process
                .resolve_api(ObservationApi::Inventoried(Api::OsslProviderLoad))
                .is_empty()
        ),
        Err(gap) => assert!(matches!(
            gap,
            ObservationGap::BackingUnavailable
                | ObservationGap::IdentityUnverified
                | ObservationGap::ProcessChanged
        )),
    }
}
#[test]
fn replaced_inode_or_same_inode_content_refuses() {
    let f = Fixture::new();
    let mut file = f.file();
    let expected = inventory::elf::inspect_file(&mut file, u64::MAX).unwrap();
    let path = f.0.join("renamed.so");
    let mut changed = fs::read(&path).unwrap();
    let last = changed.last_mut().unwrap();
    *last ^= 1;
    fs::write(&path, changed).unwrap();
    assert_eq!(
        observation::inspect_expected_exports(
            &mut file,
            &expected,
            &mut ObservationBudget::default()
        ),
        Err(ObservationGap::ObjectChanged)
    );
    let fresh = Fixture::new();
    let mut other = fresh.file();
    assert_eq!(
        observation::inspect_expected_exports(
            &mut other,
            &expected,
            &mut ObservationBudget::default()
        ),
        Err(ObservationGap::ObjectChanged)
    );
}
#[test]
fn btrfs_map_device_differs_native_identity_verifies() {
    // Default control exercises actual procfs with no privilege-dependent positive claim.
    let r = record();
    match acquire(&r, &mut ObservationBudget::default()) {
        Ok(process) => {
            process.revalidate().unwrap();
        }
        Err(gap) => assert!(matches!(
            gap,
            ObservationGap::BackingUnavailable
                | ObservationGap::IdentityUnverified
                | ObservationGap::ProcessChanged
        )),
    }
}
#[test]
#[ignore = "requires reviewed native map_files privileges and owned mapped fixtures"]
fn native_verified_objects() {
    let paths = ["OSSL_INVENTORY_BTRFS_FIRST", "OSSL_INVENTORY_BTRFS_SECOND"].map(|key| {
        std::path::PathBuf::from(
            std::env::var_os(key).expect("prepared native Btrfs input required"),
        )
    });
    let metadata = paths.each_ref().map(|path| fs::metadata(path).unwrap());
    assert_eq!(metadata[0].ino(), metadata[1].ino());
    assert_ne!(metadata[0].dev(), metadata[1].dev());
    let fixture = Fixture::new();
    let child = OwnedChild::spawn(&fixture, &paths);
    let maps = fs::read_to_string(format!("/proc/{}/maps", child.pid())).unwrap();
    let mapped = paths.each_ref().map(|path| {
        let line = maps
            .lines()
            .find(|line| line.ends_with(path.to_str().unwrap()))
            .unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        let start = u64::from_str_radix(fields[0].split('-').next().unwrap(), 16).unwrap();
        (fields[3].to_owned(), fields[4].to_owned(), start)
    });
    assert_eq!((&mapped[0].0, &mapped[0].1), (&mapped[1].0, &mapped[1].1));
    let mut snapshot = inventory::snapshot(&inventory::SnapshotOptions {
        pids: vec![child.pid()],
        ..Default::default()
    });
    let r = snapshot.processes.remove(0);
    let process = acquire(&r, &mut ObservationBudget::default()).unwrap();
    assert!(process.retained_objects() >= 2);
    process.revalidate().unwrap();
    let mut hashes = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let info = inventory::elf::inspect_file(&mut File::open(path).unwrap(), u64::MAX).unwrap();
        hashes.push(info.sha256.clone());
        let mut found = false;
        for api in info.exports {
            for entry in process.resolve_api(ObservationApi::Inventoried(api)) {
                if entry.site.native_device() != metadata[i].dev()
                    || entry.site.inode() != metadata[i].ino()
                {
                    continue;
                }
                let learned = process
                    .relocate(TransientCodeAddress::from_kernel_event(
                        mapped[i].2 + entry.site.file_offset(),
                    ))
                    .unwrap();
                assert_eq!(learned.native_device(), metadata[i].dev());
                assert_eq!(learned.file_offset(), entry.site.file_offset());
                assert_eq!(
                    serde_json::to_value(learned.object_hash()).unwrap(),
                    info.sha256
                );
                found = true;
            }
        }
        assert!(found, "expected native object API sites missing");
    }
    assert_ne!(hashes[0], hashes[1]);
    // Lazy objects must also relocate independently when D2 carries no module.
    let mut lazy_record = r.clone();
    lazy_record.modules.clear();
    let lazy = acquire(&lazy_record, &mut ObservationBudget::default()).unwrap();
    assert!(
        lazy.resolve_api(ObservationApi::Inventoried(Api::OsslProviderInit))
            .is_empty()
    );
    for (i, path) in paths.iter().enumerate() {
        let info = inventory::elf::inspect_file(&mut File::open(path).unwrap(), u64::MAX).unwrap();
        let api = info.exports[0];
        let sites = process.resolve_api(ObservationApi::Inventoried(api));
        let site = sites
            .iter()
            .find(|entry| entry.site.native_device() == metadata[i].dev())
            .unwrap();
        let learned = lazy
            .relocate(TransientCodeAddress::from_kernel_event(
                mapped[i].2 + site.site.file_offset(),
            ))
            .unwrap();
        assert_eq!(learned.native_device(), metadata[i].dev());
    }
    // Exec preserves PID/starttime but must retire the old attachment inputs.
    let before = fs::metadata(format!("/proc/{}/exe", child.pid())).unwrap();
    let mut child = child;
    child.0.stdin.as_mut().unwrap().write_all(b"e").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while fs::metadata(format!("/proc/{}/exe", child.pid()))
        .is_ok_and(|now| now.dev() == before.dev() && now.ino() == before.ino())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "owned exec did not complete"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(matches!(
        process.revalidate(),
        Err(ObservationGap::ProcessChanged)
    ));
    drop(child);
    assert!(matches!(
        process.revalidate(),
        Err(ObservationGap::ProcessUnavailable)
    ));
}

#[test]
fn sectionless_dynamic_exports_resolve() {
    let f = Fixture::new();
    let path = f.0.join("renamed.so");
    let mut bytes = fs::read(&path).unwrap();
    bytes[40..48].fill(0);
    bytes[58..64].fill(0);
    fs::write(path, bytes).unwrap();
    assert_eq!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default()).unwrap(),
        vec![
            ObservationApi::Inventoried(Api::OsslProviderLoad),
            ObservationApi::OsslProviderUnqueryOperation
        ]
    );
}

#[test]
fn bounded_segments_and_function_types_refuse_ambiguous_code() {
    let f = Fixture::new();
    let path = f.0.join("renamed.so");
    let original = fs::read(&path).unwrap();
    let u64at = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let phoff = u64at(&original, 32) as usize;
    let count = u16::from_le_bytes(original[56..58].try_into().unwrap()) as usize;
    let executable = (0..count)
        .map(|i| phoff + i * 56)
        .find(|at| {
            u32::from_le_bytes(original[*at..*at + 4].try_into().unwrap()) == 1
                && original[*at + 4] & 1 != 0
        })
        .unwrap();
    let mut overflow = original.clone();
    overflow[executable + 16..executable + 24].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&path, &overflow).unwrap();
    assert!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default()).is_err()
    );
    let mut nonexec = original.clone();
    nonexec[executable + 4] &= !1;
    fs::write(&path, nonexec).unwrap();
    assert!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default())
            .unwrap()
            .is_empty()
    );
    let shoff = u64at(&original, 40) as usize;
    let count = u16::from_le_bytes(original[60..62].try_into().unwrap()) as usize;
    let dynsym = (0..count)
        .map(|i| shoff + i * 64)
        .find(|at| u32::from_le_bytes(original[*at + 4..*at + 8].try_into().unwrap()) == 11)
        .unwrap();
    let offset = u64at(&original, dynsym + 24) as usize;
    let size = u64at(&original, dynsym + 32) as usize;
    let mut ifunc = original.clone();
    for symbol in ifunc[offset..offset + size].chunks_exact_mut(24) {
        if symbol[4] & 15 == 2 {
            symbol[4] = (symbol[4] & !15) | 10;
        }
    }
    fs::write(&path, ifunc).unwrap();
    assert!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default())
            .unwrap()
            .is_empty()
    );
    // A data or BSS declaration relabeled FUNC must still fail the executable
    // file-backed segment test; knowing a finite name is insufficient.
    let mut invalid_section = original.clone();
    for symbol in invalid_section[offset..offset + size].chunks_exact_mut(24) {
        if symbol[4] & 15 == 2 {
            symbol[6..8].copy_from_slice(&(count as u16).to_le_bytes());
        }
    }
    fs::write(&path, invalid_section).unwrap();
    assert!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default())
            .unwrap()
            .is_empty()
    );
    let mut data = original;
    for symbol in data[offset..offset + size].chunks_exact_mut(24) {
        if symbol[4] & 15 == 1 {
            symbol[4] = (symbol[4] & !15) | 2;
        }
    }
    fs::write(&path, data).unwrap();
    assert_eq!(
        observation::inspect_exports(&mut f.file(), &mut ObservationBudget::default()).unwrap(),
        vec![
            ObservationApi::Inventoried(Api::OsslProviderLoad),
            ObservationApi::OsslProviderUnqueryOperation
        ]
    );
}

#[test]
fn exact_public_api_spellings_are_exhaustive() {
    let mappings = [
        (Api::OsslProviderInit, "OSSL_provider_init"),
        (Api::OsslProviderLoad, "OSSL_PROVIDER_load"),
        (Api::OsslProviderTryLoad, "OSSL_PROVIDER_try_load"),
        (Api::OsslProviderUnload, "OSSL_PROVIDER_unload"),
        (Api::OsslProviderLoadEx, "OSSL_PROVIDER_load_ex"),
        (Api::OsslProviderTryLoadEx, "OSSL_PROVIDER_try_load_ex"),
        (Api::OsslProviderAddBuiltin, "OSSL_PROVIDER_add_builtin"),
        (Api::OsslProviderGet0Dispatch, "OSSL_PROVIDER_get0_dispatch"),
        (
            Api::OsslProviderQueryOperation,
            "OSSL_PROVIDER_query_operation",
        ),
        (Api::EvpMdFetch, "EVP_MD_fetch"),
        (Api::EvpCipherFetch, "EVP_CIPHER_fetch"),
        (Api::EvpMacFetch, "EVP_MAC_fetch"),
        (Api::EvpKdfFetch, "EVP_KDF_fetch"),
        (Api::EvpSignatureFetch, "EVP_SIGNATURE_fetch"),
        (Api::EvpKemFetch, "EVP_KEM_fetch"),
    ];
    for (api, symbol) in mappings {
        assert_eq!(ObservationApi::Inventoried(api).export_name(), Some(symbol));
    }
    assert_eq!(
        ObservationApi::OsslProviderUnqueryOperation.export_name(),
        Some("OSSL_PROVIDER_unquery_operation")
    );
}

#[test]
fn retained_parser_state_is_admitted_before_elf_reads() {
    let fixture = Fixture::new();
    for available in [0, 4096] {
        let mut budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: available,
            ..Default::default()
        });
        assert_eq!(
            observation::inspect_exports(&mut fixture.file(), &mut budget),
            Err(ObservationGap::StateLimit)
        );
        assert_eq!(
            budget.elf_read_bytes(),
            0,
            "retained parser admission followed ELF work"
        );
    }
}

#[test]
fn sectionless_shared_long_unknown_names_remain_valid() {
    // One literal ELF fixture: 129 FUNC definitions share one 64 KiB name.
    // The private reader-count test independently bounds comparison work.
    const BASE: u64 = 0x400000;
    const COUNT: usize = 130;
    const STRINGS: usize = 0x2000;
    let mut names = b"\0OSSL_PROVIDER_unquery_operation".to_vec();
    names.resize(65536, b'x');
    names.push(0);
    let mut image = vec![0; STRINGS + names.len()];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put = |image: &mut [u8], at: usize, value: u64, size: usize| {
        image[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
    };
    put(&mut image, 16, 3, 2);
    put(
        &mut image,
        18,
        if cfg!(target_arch = "aarch64") {
            183
        } else {
            62
        },
        2,
    );
    put(&mut image, 20, 1, 4);
    put(&mut image, 32, 64, 8);
    put(&mut image, 52, 64, 2);
    put(&mut image, 54, 56, 2);
    put(&mut image, 56, 2, 2);
    // RX PT_LOAD for every file byte; PT_DYNAMIC has six entries plus NULL.
    let len = image.len() as u64;
    for (at, value, size) in [
        (64, 1, 4),
        (68, 5, 4),
        (80, BASE, 8),
        (96, len, 8),
        (104, len, 8),
        (112, 4096, 8),
        (120, 2, 4),
        (128, 0x100, 8),
        (136, BASE + 0x100, 8),
        (152, 112, 8),
        (160, 112, 8),
    ] {
        put(&mut image, at, value, size);
    }
    let dynamic = [
        (4, BASE + 0x200),
        (5, BASE + STRINGS as u64),
        (6, BASE + 0x600),
        (10, names.len() as u64),
        (11, 24),
        (0, 0),
    ];
    for (index, (tag, value)) in dynamic.into_iter().enumerate() {
        put(&mut image, 0x100 + index * 16, tag, 8);
        put(&mut image, 0x108 + index * 16, value, 8);
    }
    put(&mut image, 0x200, 1, 4);
    put(&mut image, 0x204, COUNT as u64, 4);
    put(&mut image, 0x208, 1, 4);
    for index in 1..COUNT {
        let at = 0x600 + index * 24;
        put(&mut image, at, 1, 4);
        image[at + 4] = 0x12;
        put(&mut image, at + 6, 1, 2);
        put(&mut image, at + 8, BASE + 0x80, 8);
        put(&mut image, at + 16, 1, 8);
    }
    image[STRINGS..].copy_from_slice(&names);
    let fixture = Fixture::new();
    fs::write(fixture.0.join("renamed.so"), &image).unwrap();
    assert!(inventory::elf::inspect_file(&mut fixture.file(), u64::MAX).is_ok());
    assert_eq!(
        observation::inspect_exports(&mut fixture.file(), &mut ObservationBudget::default()),
        Ok(vec![])
    );
    // A malformed table ending cannot become an exact known-name match.
    *image.last_mut().unwrap() = b'x';
    fs::write(fixture.0.join("renamed.so"), image).unwrap();
    assert!(
        observation::inspect_exports(&mut fixture.file(), &mut ObservationBudget::default())
            .is_err()
    );
}
