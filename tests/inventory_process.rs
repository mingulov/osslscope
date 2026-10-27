// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned mmap controls exercise the real procfs snapshot without loading code.
use osslscope::inventory::{
    GapReason, IdentityStatus, Limits, ObjectKind, ObservationState, Snapshot, SnapshotOptions,
    snapshot,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osslscope-process-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn build(&self, name: &str, source: &str, shared: bool) -> PathBuf {
        let src = self.0.join(format!("{name}.c"));
        let out = self.0.join(name);
        fs::write(&src, source).unwrap();
        let mut command = Command::new("cc");
        if shared {
            command.args(["-shared", "-fPIC"]);
        }
        let result = command
            .args(["-Wl,--build-id=none", "-o"])
            .arg(&out)
            .arg(src)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        out
    }
    fn modules(&self) -> [PathBuf; 2] {
        [
            self.build(
                "PRIVATE_CANARY_cloud",
                "int OSSL_provider_init(void) { return 11; }",
                true,
            ),
            self.build(
                "PRIVATE_CANARY_rain",
                "int EVP_MD_fetch(void) { return 17; }",
                true,
            ),
        ]
    }
    fn child(&self, paths: &[PathBuf]) -> OwnedChild {
        let executable = self.build(
            "mmap-child",
            r#"
            #include <sys/mman.h>
            #include <sys/stat.h>
            #include <fcntl.h>
            #include <stdio.h>
            #include <unistd.h>
            int main(int argc, char **argv) {
                for (int i = 1; i < argc; ++i) {
                    int fd = open(argv[i], O_RDONLY); struct stat st;
                    if (fd < 0 || fstat(fd, &st)) return 2;
                    if (mmap(0, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) == MAP_FAILED) return 3;
                    close(fd);
                }
                puts("ready"); fflush(stdout);
                while (getchar() != EOF) {}
                return 0;
            }
        "#,
            false,
        );
        let mut child = Command::new(executable)
            .args(paths)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        OwnedChild(child)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct OwnedChild(Child);
impl OwnedChild {
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
fn snap(pids: Vec<u32>, limits: Limits) -> Snapshot {
    snapshot(&SnapshotOptions { pids, limits })
}
fn digest(path: &Path) -> String {
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn has_gap(result: &Snapshot, reason: GapReason) -> bool {
    result.gaps.iter().any(|gap| gap.reason == reason)
}

// Catches filename/profile gating, missing second objects and invented activation.
#[test]
fn finds_renamed_multiple_mapped_modules_without_profiles() {
    let fixture = Fixture::new();
    let modules = fixture.modules();
    let child = fixture.child(&modules);
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    assert!(process.starttime > 0);
    eprintln!(
        "owned snapshot: relevant={} verified={} candidates={} exit={}",
        process.modules.len(),
        process
            .modules
            .iter()
            .filter(|m| m.identity_status == IdentityStatus::Verified)
            .count(),
        process
            .modules
            .iter()
            .filter(|m| m.identity_status == IdentityStatus::LocatorCandidate)
            .count(),
        result.exit_code()
    );
    assert_eq!(process.provider_activation, ObservationState::Unknown);
    assert_eq!(process.provider_interfaces, ObservationState::Unknown);
    assert_eq!(process.execution, ObservationState::NotObserved);
    for (index, path) in modules.iter().enumerate() {
        let metadata = fs::metadata(path).unwrap();
        let module = process
            .modules
            .iter()
            .find(|m| m.info.sha256 == digest(path))
            .expect("mapped fixture missing");
        assert_eq!(
            (module.info.device, module.info.inode),
            (metadata.dev(), metadata.ino())
        );
        assert_eq!(
            module.info.kind,
            if index == 0 {
                ObjectKind::ProviderModule
            } else {
                ObjectKind::OpenSslCompatible
            }
        );
        if module.identity_status == IdentityStatus::LocatorCandidate {
            assert!(has_gap(&result, GapReason::IdentityUnverified));
        }
    }
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("PRIVATE_CANARY"));
    assert!(!json.contains(fixture.0.to_str().unwrap()));
    assert!(!json.contains("ready"));
    assert!(matches!(result.exit_code(), 0 | 3));
}

// Catches pathname reopening that promotes replacement/foreign bytes as mapped.
#[test]
fn replacement_deleted_and_foreign_backing_are_not_silently_rebound() {
    let fixture = Fixture::new();
    let modules = fixture.modules();
    let identities: Vec<_> = modules
        .iter()
        .map(|p| (digest(p), fs::metadata(p).unwrap().ino()))
        .collect();
    let child = fixture.child(&modules);
    fs::remove_file(&modules[0]).unwrap();
    let replacement = fixture.build(
        "replacement",
        "int OSSL_provider_init(void) { return 99; }",
        true,
    );
    let replacement_hash = digest(&replacement);
    fs::rename(replacement, &modules[0]).unwrap();
    fs::remove_file(&modules[1]).unwrap();
    std::os::unix::fs::symlink(&modules[0], &modules[1]).unwrap();
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    assert!(
        process
            .modules
            .iter()
            .all(|m| m.info.sha256 != replacement_hash)
    );
    for (hash, inode) in identities {
        assert!(
            process.modules.iter().any(|m| m.info.sha256 == hash)
                || result.gaps.iter().any(|gap| gap.pid == Some(child.pid())
                    && gap.inode == Some(inode)
                    && gap.reason == GapReason::IdentityUnverified)
        );
    }
    assert!(
        process
            .modules
            .iter()
            .filter(|m| m.identity_status == IdentityStatus::Verified)
            .all(|m| m.info.sha256 != replacement_hash)
    );
}

// Catches aborting the whole selection when one process disappears.
#[test]
fn one_missing_pid_keeps_other_results() {
    let fixture = Fixture::new();
    let modules = fixture.modules();
    let child = fixture.child(&modules);
    let missing = fixture.child(&[]);
    let missing_pid = missing.pid();
    drop(missing);
    let result = snap(vec![missing_pid, child.pid()], Limits::default());
    assert!(
        result
            .processes
            .iter()
            .any(|p| p.pid == child.pid() && !p.modules.is_empty())
    );
    assert!(has_gap(&result, GapReason::ProcessUnavailable));
    assert_eq!(result.exit_code(), 3);
    assert_eq!(snap(vec![missing_pid], Limits::default()).exit_code(), 4);
}

// Catches independent-per-PID budgets, unrestricted reads, and false complete results.
#[test]
fn budgets_and_malformed_maps_produce_partial() {
    let fixture = Fixture::new();
    let modules = fixture.modules();
    let first = fixture.child(&modules);
    let second = fixture.child(&modules);
    let pids = vec![first.pid(), second.pid()];
    for (limits, reason) in [
        (
            Limits {
                max_pids: 1,
                ..Limits::default()
            },
            GapReason::ProcessLimit,
        ),
        (
            Limits {
                max_objects_per_process: 1,
                ..Limits::default()
            },
            GapReason::ObjectLimit,
        ),
        (
            Limits {
                max_objects: 1,
                ..Limits::default()
            },
            GapReason::ObjectLimit,
        ),
        (
            Limits {
                max_maps_bytes: 1,
                ..Limits::default()
            },
            GapReason::ReadLimit,
        ),
        (
            Limits {
                max_read_bytes: 1,
                ..Limits::default()
            },
            GapReason::ReadLimit,
        ),
        (
            Limits {
                timeout: Duration::ZERO,
                ..Limits::default()
            },
            GapReason::Deadline,
        ),
    ] {
        let result = snap(pids.clone(), limits.clone());
        assert!(has_gap(&result, reason), "{reason:?}: {result:?}");
        assert!(result.totals.read_bytes <= limits.max_read_bytes);
        assert!(result.totals.processes_attempted <= limits.max_pids);
        assert!(result.totals.objects_attempted <= limits.max_objects);
        assert_ne!(result.exit_code(), 0);
    }
}

// Catches bounding native dedup results instead of backing-open attempts.
// Equal-path VMAs must still consume finite attempts before resolution; a
// candidate association cannot prove that the other VMAs share its backing.
#[test]
fn repeated_locators_are_charged_before_backing_resolution() {
    let fixture = Fixture::new();
    let module = fixture.modules()[0].clone();
    let child = fixture.child(&vec![module.clone(); 8]);
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    let hash = digest(&module);
    let relevant: Vec<_> = process
        .modules
        .iter()
        .filter(|m| m.info.sha256 == hash)
        .collect();
    assert!(!relevant.is_empty());
    if relevant
        .iter()
        .all(|m| m.identity_status == IdentityStatus::LocatorCandidate)
    {
        assert_eq!(
            relevant.len(),
            8,
            "uncertain equal-path VMAs were collapsed"
        );
    } else {
        assert_eq!(
            relevant
                .iter()
                .filter(|m| m.identity_status == IdentityStatus::Verified)
                .count(),
            1
        );
    }
    for limits in [
        Limits {
            max_objects_per_process: 4,
            ..Limits::default()
        },
        Limits {
            max_objects: 4,
            ..Limits::default()
        },
    ] {
        let limited = snap(vec![child.pid()], limits);
        assert_eq!(limited.totals.objects_attempted, 4);
        assert!(has_gap(&limited, GapReason::ObjectLimit));
    }
}

// Catches interpreting PID 0 as self and losing read failures with an empty population.
#[test]
fn zero_pid_is_unavailable_and_empty_limits_do_not_panic() {
    assert_eq!(snap(vec![0], Limits::default()).exit_code(), 4);
    for limits in [
        Limits {
            max_pids: 0,
            ..Limits::default()
        },
        Limits {
            max_objects: 0,
            ..Limits::default()
        },
        Limits {
            max_module_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_maps_bytes: 0,
            ..Limits::default()
        },
    ] {
        let result = snap(vec![std::process::id()], limits);
        assert_ne!(result.exit_code(), 0);
    }
}

// Catches early maps-device/inode deduplication across Btrfs subvolumes.
// Prepare two different relevant ELF files externally in separate Btrfs
// subvolumes with equal inode numbers; this test never creates subvolumes.
#[test]
#[ignore = "requires externally prepared Btrfs collision paths in OSSL_INVENTORY_BTRFS_FIRST/SECOND"]
fn btrfs_equal_maps_identity_preserves_distinct_native_backings() {
    let paths = ["OSSL_INVENTORY_BTRFS_FIRST", "OSSL_INVENTORY_BTRFS_SECOND"]
        .map(|name| PathBuf::from(std::env::var_os(name).expect("Btrfs input path required")));
    let metadata = paths.each_ref().map(|path| fs::metadata(path).unwrap());
    assert_eq!(
        metadata[0].ino(),
        metadata[1].ino(),
        "fixture inode collision required"
    );
    assert_ne!(
        metadata[0].dev(),
        metadata[1].dev(),
        "distinct native devices required"
    );
    let hashes = paths.each_ref().map(|path| digest(path));
    assert_ne!(hashes[0], hashes[1], "different fixture bytes required");
    let fixture = Fixture::new();
    let child = fixture.child(&paths);
    // Inspect the owned child's maps independently of production parsing.
    let maps = fs::read_to_string(format!("/proc/{}/maps", child.pid())).unwrap();
    let pairs = paths.each_ref().map(|path| {
        let line = maps
            .lines()
            .find(|line| line.ends_with(path.to_str().unwrap()))
            .unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert!(fields[1].contains('x'));
        (fields[3].to_owned(), fields[4].to_owned())
    });
    assert_eq!(
        pairs[0], pairs[1],
        "maps superblock device/inode collision required"
    );
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    for (index, hash) in hashes.iter().enumerate() {
        assert!(
            process.modules.iter().any(|m| m.info.sha256 == *hash
                && m.info.device == metadata[index].dev()
                && m.info.inode == metadata[index].ino()),
            "distinct native backing missing: index={index}, result={result:?}"
        );
    }
    assert!(result.totals.objects_attempted <= result.limits.max_objects);
    assert!(result.totals.objects_attempted <= result.limits.max_objects_per_process);
}
