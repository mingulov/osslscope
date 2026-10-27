// SPDX-License-Identifier: GPL-3.0-or-later
//! Real owned processes, descriptors and current host cgroup; no fake isolation.
use osslscope::inventory::{
    GapReason, Limits, NamespaceId, Scope,
    scope::{ScopedScanner, Selection},
};
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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

fn current_cgroup() -> PathBuf {
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let path = text.lines().find_map(|s| s.strip_prefix("0::")).unwrap();
    PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/'))
}
#[test]
fn current_real_cgroup_selects_owned_child_and_reports_provenance() {
    let f = Fixture::new();
    let modules = f.modules();
    let child = f.child(&modules);
    let cgroup = current_cgroup();
    let metadata = fs::metadata(&cgroup).unwrap();
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid()],
            cgroup: Some(cgroup),
            modules: vec![],
        },
        Limits::default(),
    )
    .unwrap();
    let result = scanner.snapshot();
    let process = result
        .processes
        .iter()
        .find(|p| p.pid == child.pid())
        .unwrap_or_else(|| panic!("owned process missing: {result:?}"));
    assert_eq!(
        result.scope_record.cgroup,
        Some(NamespaceId {
            device: metadata.dev(),
            inode: metadata.ino()
        })
    );
    for (name, actual) in [
        ("pid", process.namespaces.pid),
        ("mnt", process.namespaces.mount),
    ] {
        let m = fs::metadata(format!("/proc/{}/ns/{name}", child.pid())).unwrap();
        assert_eq!(
            actual,
            Some(NamespaceId {
                device: m.dev(),
                inode: m.ino()
            })
        );
    }
    assert!(process.interval.elapsed_ns > 0);
    assert!(result.interval.elapsed_ns >= process.interval.elapsed_ns);
    assert!(process.interval.started_unix_ms.is_some());
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("PRIVATE_CANARY"));
    assert!(!json.contains("/sys/"));
    assert!(!json.contains(f.0.to_str().unwrap()));
}
#[test]
fn unavailable_and_non_cgroup_selection_refuse_before_sampling() {
    for path in [
        PathBuf::from("/PRIVATE_CANARY_absent"),
        std::env::temp_dir(),
    ] {
        assert!(
            ScopedScanner::new(
                Selection {
                    cgroup: Some(path),
                    ..Default::default()
                },
                Limits::default()
            )
            .is_err()
        );
    }
    assert!(
        ScopedScanner::new(
            Selection {
                modules: vec![PathBuf::from("/PRIVATE_CANARY_absent")],
                ..Default::default()
            },
            Limits::default()
        )
        .is_err()
    );
    assert!(matches!(
        ScopedScanner::new(
            Selection {
                modules: vec![PathBuf::from("/dev/null")],
                ..Default::default()
            },
            Limits::default()
        ),
        Err(GapReason::NonRegular)
    ));
}
#[test]
fn explicit_empty_cgroup_pid_intersection_never_scans_system() {
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![i32::MAX as u32],
            cgroup: Some(current_cgroup()),
            modules: vec![],
        },
        Limits::default(),
    )
    .unwrap();
    let result = scanner.snapshot();
    assert_ne!(result.scope, Scope::System);
    assert!(result.processes.is_empty());
    assert!(result.selected_pids.is_empty());
    assert_eq!(result.totals.processes_attempted, 0);
}
#[test]
fn supplied_module_sha_matches_copies_without_merging_native_identities() {
    let f = Fixture::new();
    let modules = f.modules();
    let copy = f.0.join("PRIVATE_CANARY_copy");
    fs::copy(&modules[0], &copy).unwrap();
    let child = f.child(&[modules[0].clone(), copy.clone(), modules[1].clone()]);
    let sibling = f.child(&[modules[1].clone()]);
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid(), sibling.pid()],
            modules: vec![modules[0].clone()],
            cgroup: None,
        },
        Limits::default(),
    )
    .unwrap();
    let result = scanner.snapshot();
    assert_eq!(result.processes.len(), 1);
    assert_eq!(result.processes[0].pid, child.pid());
    let found = &result.processes[0].modules;
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].info.sha256, found[1].info.sha256);
    assert_ne!(
        (found[0].info.device, found[0].info.inode),
        (found[1].info.device, found[1].info.inode)
    );
    assert_eq!(
        result.scope_record.modules,
        vec![found[0].info.sha256.clone()]
    );
    assert_eq!(result.selected_pids, vec![child.pid()]);
    let mut empty = ScopedScanner::new(
        Selection {
            pids: vec![sibling.pid()],
            modules: vec![modules[0].clone()],
            cgroup: None,
        },
        Limits::default(),
    )
    .unwrap();
    assert!(empty.snapshot().processes.is_empty());
    // Descriptor fingerprint invalidation refuses a stale selector instead of broadening.
    fs::write(&modules[0], b"invalidated").unwrap();
    let stale = scanner.snapshot();
    assert!(stale.processes.is_empty());
    assert!(stale.gaps.iter().any(|g| g.reason == GapReason::Changed));
}
#[test]
fn scan_cli_intersects_scope_and_preserves_inspect_grammar() {
    let f = Fixture::new();
    let modules = f.modules();
    let child = f.child(&modules);
    let cgroup = current_cgroup();
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--pid",
            &child.pid().to_string(),
            "--cgroup",
            cgroup.to_str().unwrap(),
            "--module",
            modules[0].to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{:?}",
        output.status
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["processes"][0]["modules"].as_array().unwrap().len(),
        1
    );
    for args in [
        vec!["scan", "--cgroup", "/PRIVATE_CANARY_missing"],
        vec!["scan", "--module", "/PRIVATE_CANARY_missing"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_CANARY"));
    }
}

#[test]
fn default_selection_remains_visible_system_and_scopes_keep_existing_limits() {
    let mut scanner = ScopedScanner::new(
        Selection::default(),
        Limits {
            max_pids: 0,
            ..Limits::default()
        },
    )
    .unwrap();
    let result = scanner.snapshot();
    assert_eq!(result.scope, Scope::System);
    assert!(result.processes.is_empty());
    assert!(
        result
            .gaps
            .iter()
            .any(|g| g.reason == GapReason::ProcessLimit)
    );
    let f = Fixture::new();
    let modules = f.modules();
    assert!(matches!(
        ScopedScanner::new(
            Selection {
                modules: vec![modules[0].clone()],
                ..Default::default()
            },
            Limits {
                max_objects: 0,
                ..Limits::default()
            }
        ),
        Err(GapReason::ObjectLimit)
    ));
    let charge = fs::metadata(&modules[0]).unwrap().len() + 1;
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![i32::MAX as u32],
            modules: vec![modules[0].clone(), modules[0].clone()],
            cgroup: None,
        },
        Limits {
            max_read_bytes: charge,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(scanner.snapshot().processes.is_empty());
}
#[test]
fn module_or_filters_and_explicit_elf_without_openssl_exports_work() {
    let f = Fixture::new();
    let modules = f.modules();
    let ordinary = f.build(
        "PRIVATE_CANARY_ordinary",
        "int ordinary(void) { return 31; }",
        true,
    );
    let child = f.child(&[modules[0].clone(), modules[1].clone(), ordinary.clone()]);
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid()],
            modules: modules.to_vec(),
            cgroup: None,
        },
        Limits::default(),
    )
    .unwrap();
    assert_eq!(scanner.snapshot().processes[0].modules.len(), 2);
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid()],
            modules: vec![ordinary],
            cgroup: None,
        },
        Limits::default(),
    )
    .unwrap();
    let result = scanner.snapshot();
    assert_eq!(result.processes[0].modules.len(), 1);
    assert_eq!(
        result.processes[0].modules[0].info.kind,
        osslscope::inventory::ObjectKind::Other
    );
}
