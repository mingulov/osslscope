// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned mmap controls exercise the real procfs snapshot without loading code.
use osslscope::inventory::{
    GapReason, IdentityStatus, Limits, ObjectKind, ObservationState, Snapshot, SnapshotOptions,
    snapshot,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::io::AsRawFd as _;
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
                    void *at = mmap(0, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
                    if (at == MAP_FAILED) return 3;
                    { volatile char touch = ((char *)at)[0]; (void)touch; }
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
                    && gap.reason == GapReason::BackingUnavailable)
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

// 5E RED: ordinary overlay lower backing must verify; after copy-up the
// overlay identity must stay unverified while the old lower mapping stays
// positively traced through its direct backing.
struct OverlayMount {
    base: PathBuf,
    merged: PathBuf,
}
impl OverlayMount {
    fn mount() -> Self {
        let base = std::env::temp_dir().join(format!(
            "osslscope-overlay-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        for name in ["lower", "upper", "work", "merged"] {
            fs::create_dir_all(base.join(name)).unwrap();
        }
        let status = Command::new("mount")
            .args([
                "-t",
                "overlay",
                "overlay",
                "-o",
                &format!(
                    "lowerdir={},upperdir={},workdir={}",
                    base.join("lower").display(),
                    base.join("upper").display(),
                    base.join("work").display()
                ),
            ])
            .arg(base.join("merged"))
            .status()
            .unwrap();
        assert!(status.success(), "overlay mount requires privilege");
        Self {
            merged: base.join("merged"),
            base,
        }
    }
}
impl Drop for OverlayMount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.merged).status();
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn build_so(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    fs::write(&src, source).unwrap();
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wl,--build-id=none", "-o"])
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
fn copy_up_same_bytes(path: &Path) {
    use std::os::unix::fs::FileExt as _;
    let bytes = fs::read(path).unwrap();
    let writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    writer.write_all_at(&bytes, 0).unwrap();
    writer.sync_all().unwrap();
}
#[test]
#[ignore = "requires privileged overlay mount + map_files/pagemap (5E)"]
fn overlay_lower_only_module_verifies() {
    let overlay = OverlayMount::mount();
    let fixture = Fixture::new();
    let lower = build_so(
        &overlay.base.join("lower"),
        "PRIVATE_CANARY_lower",
        "int OSSL_provider_init(void) { return 11; }",
    );
    let merged = overlay.merged.join("PRIVATE_CANARY_lower");
    let child = fixture.child(&[merged.clone()]);
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    let merged_meta = fs::metadata(&merged).unwrap();
    let module = process
        .modules
        .iter()
        .find(|m| m.info.sha256 == digest(&lower))
        .expect("overlay module missing");
    assert_eq!(
        (module.info.device, module.info.inode),
        (merged_meta.dev(), merged_meta.ino())
    );
    assert_eq!(module.identity_status, IdentityStatus::Verified);
}
#[test]
#[ignore = "requires privileged overlay mount + map_files/pagemap (5E)"]
fn overlay_copyup_old_mapping_verifies_via_direct_lower_not_overlay() {
    let overlay = OverlayMount::mount();
    let fixture = Fixture::new();
    let lower = build_so(
        &overlay.base.join("lower"),
        "PRIVATE_CANARY_lower",
        "int OSSL_provider_init(void) { return 11; }",
    );
    let merged = overlay.merged.join("PRIVATE_CANARY_lower");
    let child = fixture.child(&[merged.clone()]);
    copy_up_same_bytes(&merged);
    assert!(
        overlay
            .base
            .join("upper/PRIVATE_CANARY_lower")
            .metadata()
            .is_ok(),
        "copy-up proof: upper file must exist"
    );
    let result = snap(vec![child.pid()], Limits::default());
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap();
    let lower_meta = fs::metadata(&lower).unwrap();
    let merged_meta = fs::metadata(&merged).unwrap();
    assert!(
        process.modules.iter().all(|m| {
            (m.info.device, m.info.inode) != (merged_meta.dev(), merged_meta.ino())
                || m.identity_status != IdentityStatus::Verified
        }),
        "overlay identity must never verify the old lower mapping"
    );
    let direct = process
        .modules
        .iter()
        .find(|m| (m.info.device, m.info.inode) == (lower_meta.dev(), lower_meta.ino()))
        .expect("direct-lower module missing");
    assert_eq!(direct.identity_status, IdentityStatus::Verified);
    assert_eq!(direct.info.sha256, digest(&lower));
}

/// Self-provisioning Btrfs fixture (T4, integration-local mirror of the
/// backing unit fixture): subvolumes under a leased-TMPDIR base with
/// reverse-order reclamation. Root + `btrfs` CLI + TMPDIR-on-btrfs required.
struct BtrfsFixture(PathBuf, Vec<PathBuf>);
impl BtrfsFixture {
    fn create(names: &[&str]) -> Option<Self> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip: btrfs subvolume control requires root");
            return None;
        }
        if Command::new("btrfs").arg("--version").output().is_err() {
            eprintln!("skip: btrfs CLI absent");
            return None;
        }
        let probe = std::fs::File::open(std::env::temp_dir()).unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs initializes stat on success and borrows an open FD.
        let is_btrfs = unsafe { libc::fstatfs(probe.as_raw_fd(), stat.as_mut_ptr()) == 0 }
            && unsafe { stat.assume_init() }.f_type == 0x9123683e;
        if !is_btrfs {
            eprintln!("skip: TMPDIR is not on btrfs");
            return None;
        }
        let base = std::env::temp_dir().join(format!(
            "osslscope-process-t4btrfs-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let mut subvols = Vec::with_capacity(names.len());
        for name in names {
            let path = base.join(name);
            let created = Command::new("btrfs")
                .args(["subvolume", "create"])
                .arg(&path)
                .output();
            match created {
                Ok(out) if out.status.success() => subvols.push(path),
                _ => {
                    // Prerequisites passed, so this is an acquisition
                    // failure (ENOSPC, unexpected fs error) — fail the
                    // cell, never green-skip. Reclaim first, in reverse.
                    for done in subvols.iter().rev() {
                        let _ = Command::new("btrfs")
                            .args(["subvolume", "delete"])
                            .arg(done)
                            .status();
                    }
                    let _ = fs::remove_dir_all(&base);
                    let detail = created
                        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                        .unwrap_or_else(|e| e.to_string());
                    panic!(
                        "btrfs subvolume create failed for {}: {detail}",
                        path.display()
                    );
                }
            }
        }
        Some(Self(base, subvols))
    }
    /// Same-ino pair with distinct bytes across two subvolumes. Bases are
    /// valid ELFs; variant `i` flips the `e_ident` padding byte so every
    /// file stays parseable with a distinct digest.
    fn colliding_pair(&self, a: &str, b: &str, base_a: &[u8], base_b: &[u8]) -> (PathBuf, PathBuf) {
        let mut seen: Vec<(u64, PathBuf)> = Vec::new();
        for i in 0..16u8 {
            let mut bytes = base_a.to_vec();
            bytes[9] = i;
            let pa = self.0.join(a).join(format!("f{i}"));
            fs::write(&pa, &bytes).unwrap();
            let ino = pa.metadata().unwrap().ino();
            if let Some((_, pb)) = seen.iter().find(|(n, _)| *n == ino) {
                if pb.starts_with(self.0.join(b)) {
                    return (pb.clone(), pa);
                }
            }
            seen.push((ino, pa));
            let mut bytes = base_b.to_vec();
            bytes[9] = i.wrapping_add(0x80);
            let pb = self.0.join(b).join(format!("g{i}"));
            fs::write(&pb, &bytes).unwrap();
            let ino = pb.metadata().unwrap().ino();
            if let Some((_, pa)) = seen.iter().find(|(n, _)| *n == ino) {
                if pa.starts_with(self.0.join(a)) {
                    return (pa.clone(), pb);
                }
            }
            seen.push((ino, pb));
        }
        panic!("no same-ino pair across fresh subvolumes after 16 files each");
    }
}
impl Drop for BtrfsFixture {
    fn drop(&mut self) {
        // Loud, never panicking: a failed delete leaks a subvolume
        // and must show in logs, not vanish. Both spawn errors and
        // unsuccessful exit statuses count as failures.
        for subvol in self.1.iter().rev() {
            match Command::new("btrfs")
                .args(["subvolume", "delete"])
                .arg(subvol)
                .status()
            {
                Ok(status) if status.success() => {}
                other => eprintln!(
                    "BtrfsFixture: subvolume delete failed for {}: {other:?}",
                    subvol.display()
                ),
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("BtrfsFixture: base removal failed: {error}");
        }
    }
}

// Catches a maps change landing inside one snapshot: the re-read fence
// must record Changed and downgrade every module. Window test by nature:
// the churn signal fires mid-parse (300 modules keep the window wide);
// up to 3 attempts, pass on the first observed fence trip. A 3/3 miss is
// a failure (window too narrow), never a skip.
#[test]
#[ignore = "requires root map_files (T4)"]
fn maps_churn_during_snapshot_downgrades_to_locator() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skip: root map_files required");
        return;
    }
    let fixture = Fixture::new();
    let base = fixture.build(
        "PRIVATE_CANARY_churn",
        "int OSSL_provider_init(void) { return 11; }",
        true,
    );
    let base_bytes = fs::read(&base).unwrap();
    // 300 distinct ELFs: e_ident padding flips keep every variant parseable.
    let mut paths = Vec::with_capacity(301);
    for i in 0..300u16 {
        let mut bytes = base_bytes.clone();
        bytes[9] = (i & 0xff) as u8;
        bytes[10] = (i >> 8) as u8;
        let path = fixture.0.join(format!("m{i}"));
        fs::write(&path, &bytes).unwrap();
        paths.push(path);
    }
    let mut churn_bytes = base_bytes.clone();
    churn_bytes[9] = 0xcc;
    churn_bytes[10] = 0xcc;
    let churn_path = fixture.0.join("churn_extra");
    fs::write(&churn_path, &churn_bytes).unwrap();
    let executable = fixture.build(
        "churn-child",
        r#"
            #include <sys/mman.h>
            #include <sys/stat.h>
            #include <fcntl.h>
            #include <stdio.h>
            #include <string.h>
            #include <unistd.h>
            static int mapone(const char *p) {
                int fd = open(p, O_RDONLY); struct stat st;
                if (fd < 0 || fstat(fd, &st)) return -1;
                void *at = mmap(0, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
                if (at == MAP_FAILED) return -1;
                { volatile char t = ((char *)at)[0]; (void)t; }
                close(fd); return 0;
            }
            int main(int argc, char **argv) {
                for (int i = 1; i < argc - 1; ++i) if (mapone(argv[i])) return 2;
                puts("ready"); fflush(stdout);
                char line[16];
                if (!fgets(line, sizeof line, stdin)) return 0;
                if (!strncmp(line, "churn", 5)) {
                    if (mapone(argv[argc-1])) return 3;
                    puts("churned"); fflush(stdout);
                }
                while (getchar() != EOF) {}
                return 0;
            }
        "#,
        false,
    );
    // Calm control: without churn the corpus verifies (root map_files).
    {
        let mut child = Command::new(&executable)
            .args(&paths)
            .arg(&churn_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        let calm = snap(vec![child.id()], Limits::default());
        let process = calm.processes.iter().find(|p| p.pid == child.id()).unwrap();
        assert!(
            process
                .modules
                .iter()
                .any(|m| m.identity_status == IdentityStatus::Verified),
            "calm control must verify: {calm:?}"
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }
    // Churned attempts: pass on the first fence trip.
    for attempt in 0..3 {
        let mut child = Command::new(&executable)
            .args(&paths)
            .arg(&churn_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let mut stdin = child.stdin.take().unwrap();
        let churned = std::thread::scope(|s| {
            let probe = s.spawn(|| snap(vec![pid], Limits::default()));
            std::thread::sleep(Duration::from_millis(200));
            stdin.write_all(b"churn\n").unwrap();
            stdin.flush().unwrap();
            let mut ack = String::new();
            stdout.read_line(&mut ack).unwrap();
            assert_eq!(ack, "churned\n");
            probe.join().unwrap()
        });
        drop(stdin);
        assert!(child.wait().unwrap().success());
        let process = churned.processes.iter().find(|p| p.pid == pid);
        let tripped = churned.gaps.iter().any(|g| g.reason == GapReason::Changed)
            && process.is_some_and(|p| {
                p.modules
                    .iter()
                    .all(|m| m.identity_status != IdentityStatus::Verified)
            });
        if tripped {
            return;
        }
        eprintln!("attempt {attempt}: churn missed the snapshot window, retrying");
    }
    panic!("maps churn missed the snapshot window 3/3: widen the corpus or the delay");
}

// Catches early maps-device/inode deduplication across Btrfs subvolumes.
// Self-provisioned: two subvolumes with a same-ino, distinct-bytes pair
// (operator may still pin paths via OSSL_INVENTORY_BTRFS_FIRST/SECOND).
#[test]
#[ignore = "requires root + btrfs subvolume control (T4; OSSL_INVENTORY_BTRFS_FIRST/SECOND override)"]
fn btrfs_equal_maps_identity_preserves_distinct_native_backings() {
    // Self-provisioned unless the operator pins paths explicitly. Bases are
    // compiled first so the pair files are valid ELFs with distinct bytes.
    let mut _held = None;
    let base_fixture = Fixture::new();
    let paths = match (
        std::env::var_os("OSSL_INVENTORY_BTRFS_FIRST"),
        std::env::var_os("OSSL_INVENTORY_BTRFS_SECOND"),
    ) {
        (Some(a), Some(b)) => [PathBuf::from(a), PathBuf::from(b)],
        _ => {
            let fx = match BtrfsFixture::create(&["a", "b"]) {
                Some(fx) => fx,
                None => return,
            };
            let cloud = base_fixture.build(
                "PRIVATE_CANARY_cloud",
                "int OSSL_provider_init(void) { return 11; }",
                true,
            );
            let rain = base_fixture.build(
                "PRIVATE_CANARY_rain",
                "int EVP_MD_fetch(void) { return 17; }",
                true,
            );
            let base_a = fs::read(&cloud).unwrap();
            let base_b = fs::read(&rain).unwrap();
            let (p0, p1) = fx.colliding_pair("a", "b", &base_a, &base_b);
            _held = Some(fx);
            [p0, p1]
        }
    };
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

// Catches backing IO operating outside the inventory read budget. The budget
// admits every procfs-owned read plus half of backing's duplicate reads
// (all sizes measured independently below, never from production
// accounting): GREEN refuses with ReadLimit before exceeding it, RED
// (uncharged backing) fits and reports no ReadLimit.
#[test]
fn backing_reads_are_charged_to_the_inventory_budget() {
    let fixture = Fixture::new();
    let modules = fixture.modules();
    let child = fixture.child(&modules);
    let pid = child.pid();
    let generous = snap(vec![pid], Limits::default());
    assert!(
        !has_gap(&generous, GapReason::ReadLimit),
        "sanity: generous snapshot must not hit ReadLimit: {generous:?}"
    );
    // Independent measurements (not production accounting).
    let stat_len = fs::read(format!("/proc/{pid}/stat")).unwrap().len() as u64;
    let maps_bytes = fs::read(format!("/proc/{pid}/maps")).unwrap();
    let maps_len = maps_bytes.len() as u64;
    let mountinfo_len = fs::read(format!("/proc/{pid}/mountinfo")).unwrap().len() as u64;
    // Every executable file-backed row is inspected (module_len + 1) and
    // triggers one layer-discovery mountinfo read.
    let mut inspected: u64 = 0;
    let mut rows: u64 = 0;
    for line in maps_bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let text = String::from_utf8_lossy(line);
        let mut fields = text.split_whitespace();
        let (Some(_range), Some(perms), Some(_offset), Some(_dev), Some(ino)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if perms.len() != 4 || perms.as_bytes()[2] != b'x' || ino == "0" {
            continue;
        }
        let path = fields.next().unwrap_or("");
        if path.is_empty() || path.starts_with('[') {
            continue;
        }
        inspected += fs::metadata(path).unwrap().len() + 1;
        rows += 1;
    }
    assert!(rows > 0, "fixture child must map executables");
    // Procfs-owned reads: open-stat + maps + inspections + final maps +
    // validation stat. Backing duplicates: capture stat + maps plus one
    // mountinfo read per mapping.
    let owned = 2 * stat_len + 2 * maps_len + inspected;
    let backing = stat_len + maps_len + rows * mountinfo_len;
    let max = owned + backing / 2;
    let result = snap(
        vec![pid],
        Limits {
            max_read_bytes: max,
            ..Limits::default()
        },
    );
    assert!(
        has_gap(&result, GapReason::ReadLimit),
        "backing reads must be charged (owned={owned} backing={backing} max={max}): {result:?}"
    );
    assert!(result.totals.read_bytes <= max);
}
