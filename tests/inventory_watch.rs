// SPDX-License-Identifier: GPL-3.0-or-later
//! Real passive mmap workloads; commands are acknowledged before the next poll.
use osslscope::inventory::{
    Limits,
    scope::{ScopedScanner, Selection},
    watch::{self, WatchOptions},
};
use serde_json::Value;
use std::{
    fs,
    io::{self, BufRead as _, BufReader, Read as _, Write},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "osslscope-watch-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn build(&self, name: &str, source: &str, shared: bool) -> PathBuf {
        let src = self.0.join(format!("{name}.c"));
        let out = self.0.join(name);
        fs::write(&src, source).unwrap();
        let mut cc = Command::new("cc");
        if shared {
            cc.args(["-shared", "-fPIC"]);
        }
        let result = cc.arg("-o").arg(&out).arg(src).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        out
    }
    fn module(&self) -> PathBuf {
        self.build(
            "PRIVATE_CANARY_module",
            "int OSSL_provider_init(void) { return 31; }",
            true,
        )
    }
    fn child(&self, module: &PathBuf) -> Owned {
        let exe = self.build(
            "child",
            r#"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc; void *p = 0; size_t len = 0;
    puts("ready"); fflush(stdout);
    int c;
    while ((c=getchar()) != EOF) {
        if (c=='m') { int fd=open(argv[1],O_RDONLY); struct stat st;
            if(fd<0 || fstat(fd,&st)) return 2; len=st.st_size;
            p=mmap(0,len,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0); close(fd);
            if(p==MAP_FAILED) return 3;
        } else if(c=='u') { if(munmap(p,len)) return 4; p=0; }
        else if(c=='d') { if(prctl(PR_SET_DUMPABLE,0)) return 5; }
        else if(c=='e') { if(prctl(PR_SET_DUMPABLE,1)) return 7; }
        else if(c=='n') { if(prctl(PR_SET_NAME,"renamed",0,0,0)) return 8; }
        else return 6;
        puts("ready"); fflush(stdout);
    }
    return 0;
}"#,
            false,
        );
        let mut child = Command::new(exe)
            .arg(module)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut owned = Owned { child, stdout };
        owned.ready();
        owned
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Owned {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}
impl Owned {
    fn ready(&mut self) {
        let mut s = String::new();
        self.stdout.read_line(&mut s).unwrap();
        assert_eq!(s, "ready\n");
    }
    fn command(&mut self, c: u8) {
        self.child.stdin.as_mut().unwrap().write_all(&[c]).unwrap();
        self.ready();
    }
    fn pid(&self) -> u32 {
        self.child.id()
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().unwrap().success());
    }
}
/// Observer child that is always reaped, even when an assertion
/// fails mid-stream (keeps the child-reaper lint quiet).
struct ReapedObserver(Child);
impl Drop for ReapedObserver {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn options(pid: u32) -> WatchOptions {
    WatchOptions {
        selection: Selection {
            pids: vec![pid],
            ..Default::default()
        },
        limits: Limits::default(),
        interval: Duration::from_millis(50),
        duration: Some(Duration::from_secs(5)),
        ..Default::default()
    }
}
struct Records<F: FnMut(&Value)> {
    pending: Vec<u8>,
    values: Vec<Value>,
    after: F,
}
impl<F: FnMut(&Value)> Write for Records<F> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        for &c in b {
            self.pending.push(c);
            if c == b'\n' {
                let value: Value = serde_json::from_slice(&self.pending).unwrap();
                (self.after)(&value);
                self.values.push(value);
                self.pending.clear();
            }
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn changes(v: &Value, kind: &str) -> bool {
    v["changes"]
        .as_array()
        .is_some_and(|a| a.iter().any(|c| c["kind"] == kind))
}
// Catches rebuilding the cache each tick and attributing an inaccessible PID to exit.
#[test]
fn sampled_arrival_removal_visibility_and_direct_cancellation() {
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    let pid = child.pid();
    let cancel = AtomicBool::new(false);
    let mut count = 0;
    let mut writer = Records {
        pending: vec![],
        values: vec![],
        after: |v: &Value| {
            if v["record"] != "snapshot" {
                return;
            }
            count += 1;
            match count {
                1 => child.command(b'm'),
                2 => child.command(b'u'),
                3 => child.command(b'd'),
                4 => cancel.store(true, Ordering::Relaxed),
                _ => panic!("unexpected poll"),
            }
        },
    };
    let outcome = watch::run(&options(pid), &mut writer, &cancel).unwrap();
    assert_eq!(outcome.exit_code(), 3);
    assert_eq!(writer.values.len(), 5);
    assert!(changes(&writer.values[0], "process_seen"));
    assert!(changes(&writer.values[1], "module_seen"));
    assert!(
        changes(&writer.values[2], "module_not_seen"),
        "{:?}",
        writer.values[2]
    );
    assert!(changes(&writer.values[3], "visibility_lost"));
    assert!(!changes(&writer.values[3], "process_not_seen"));
    assert!(!changes(&writer.values[3], "module_not_seen"));
    assert_eq!(writer.values[4]["reason"], "interrupted");
    let text = serde_json::to_string(&writer.values).unwrap();
    // v0.6.0 F7 (R6 carry): `watch::run` now acquires path
    // evidence like the CLI `--json` path, so the fixture module
    // filename LEGITIMATELY appears in machine records — but ONLY
    // under the D1 path-evidence keys (`verified_path.path` and
    // `maps_spelling.spelling`). Anywhere else is a leak.
    // Deferral pointer: the never-acquire carve-out lived in
    // `watch::run` from machine T2 until human-surface Task 3
    // flipped it; the acquisition rules themselves are D1's (see
    // `procfs.rs` D1 publish block + `resolve.rs` custody).
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    fn walk(value: &serde_json::Value, parent: &str, dir: &str) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, child) in object {
                    walk(child, key, dir);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, parent, dir);
                }
            }
            serde_json::Value::String(text) => {
                if text.contains("PRIVATE_CANARY") {
                    assert!(
                        parent == "path" || parent == "spelling",
                        "canary filename outside D1 path-evidence keys (key {parent:?}): {text}"
                    );
                }
                // v0.6.0 D2: the fixture dir LEGITIMATELY appears
                // in the allowlisted per-process `exe` identity
                // value (watch records embed the full snapshot;
                // the fixture child binary lives under the canary
                // dir), and — since F7 — under the D1 keys above.
                if text.contains(dir) {
                    assert!(
                        parent == "path" || parent == "spelling" || parent == "exe",
                        "canary path outside allowlisted values (key {parent:?}): {text}"
                    );
                }
            }
            _ => {}
        }
    }
    walk(&doc, "", f.0.to_str().unwrap());
    // F7 fix evidence: with acquisition on, every module record
    // carries either proven path evidence or null plus a finite
    // D1 reason — never the bare null pair of the off shape —
    // and at least one row carries D1 evidence (the flip proof).
    let mut modules = 0;
    let mut evidenced = 0;
    for record in &writer.values {
        let processes = record["snapshot"]["processes"].as_array();
        for module in processes
            .into_iter()
            .flatten()
            .flat_map(|p| p["modules"].as_array().into_iter().flatten())
        {
            modules += 1;
            assert!(
                module["verified_path"].is_null() != module["verified_path_unavailable"].is_null(),
                "bare null pair without a D1 reason: {module}"
            );
            if !module["maps_spelling"].is_null() {
                evidenced += 1;
            }
        }
    }
    assert!(
        modules > 0 && evidenced > 0,
        "acquisition off: no D1 evidence in {modules} module records"
    );
    assert!(child.child.try_wait().unwrap().is_none());
}
// Catches rehashing stable files, stale fingerprint reuse, and unbounded retained descriptors.
#[test]
fn persistent_cache_reuses_revalidates_and_evicts_unseen_files() {
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    child.command(b'm');
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid()],
            ..Default::default()
        },
        Limits::default(),
    )
    .unwrap();
    let cold = scanner.snapshot();
    // Independent kernel oracle: a stable warm sample must not read the ELF,
    // even if its self-reported objects_inspected counter were incorrect.
    let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(raw >= 0);
    let mut access = unsafe { fs::File::from_raw_fd(raw) };
    let path = std::ffi::CString::new(module.as_os_str().as_bytes()).unwrap();
    assert!(
        unsafe { libc::inotify_add_watch(access.as_raw_fd(), path.as_ptr(), libc::IN_ACCESS) } >= 0
    );
    let warm = scanner.snapshot();
    assert!(cold.totals.objects_inspected > 0);
    assert_eq!(warm.totals.objects_inspected, 0);
    assert!(warm.totals.read_bytes < cold.totals.read_bytes);
    let mut events = [0; 4096];
    assert!(matches!(access.read(&mut events),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
    let mut byte = [0];
    fs::File::open(&module)
        .unwrap()
        .read_exact(&mut byte)
        .unwrap();
    assert!(
        access.read(&mut events).unwrap() > 0,
        "IN_ACCESS positive control failed"
    );
    // Appending a harmless ELF tail changes a live fingerprint without changing its interface.
    fs::OpenOptions::new()
        .append(true)
        .open(&module)
        .unwrap()
        .write_all(b"tail")
        .unwrap();
    let changed = scanner.snapshot();
    assert!(changed.totals.objects_inspected > 0);
    use sha2::Digest as _;
    let expected: String = sha2::Sha256::digest(fs::read(&module).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        changed
            .processes
            .iter()
            .flat_map(|p| &p.modules)
            .any(|m| m.info.sha256 == expected)
    );
    assert!(
        !cold
            .processes
            .iter()
            .flat_map(|p| &p.modules)
            .any(|m| m.info.sha256 == expected)
    );
    child.command(b'u');
    scanner.snapshot();
    child.command(b'm');
    assert!(scanner.snapshot().totals.objects_inspected > 0);
    let metadata = fs::metadata(&module).unwrap();
    let descriptors = || {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::metadata(entry.path()).ok())
            .filter(|m| (m.dev(), m.ino()) == (metadata.dev(), metadata.ino()))
            .count()
    };
    assert_eq!(descriptors(), 1);
    for _ in 0..20 {
        child.command(b'u');
        scanner.snapshot();
        child.command(b'm');
        scanner.snapshot();
    }
    assert_eq!(descriptors(), 1);
}
// Catches permanently admitting the low PID prefix under process/object limits.
#[test]
fn repeated_caps_progress_to_every_controlled_pid() {
    let f = Fixture::new();
    let module = f.module();
    let mut children: Vec<_> = (0..4).map(|_| f.child(&module)).collect();
    for child in &mut children {
        child.command(b'm');
    }
    let pids: Vec<_> = children.iter().map(Owned::pid).collect();
    for limits in [
        Limits {
            max_pids: 1,
            ..Default::default()
        },
        Limits {
            max_objects: 1,
            ..Default::default()
        },
    ] {
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: pids.clone(),
                ..Default::default()
            },
            limits,
        )
        .unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let s = scanner.snapshot();
            for p in s.processes {
                seen.insert(p.pid);
            }
        }
        assert!(
            pids.iter().all(|p| seen.contains(p)),
            "starved: {seen:?} wanted {pids:?}"
        );
    }
}
#[test]
fn duration_end_and_output_failure_are_bounded() {
    let mut o = options(std::process::id());
    o.duration = Some(Duration::from_millis(110));
    let mut output = vec![];
    let outcome = watch::run(&o, &mut output, &AtomicBool::new(false)).unwrap();
    assert!(matches!(outcome.exit_code(), 0 | 3 | 4));
    let records: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!((2..=4).contains(&records.len()));
    assert_eq!(records.last().unwrap()["reason"], "duration");
    assert!(
        records
            .iter()
            .all(|v| v["schema_version"] == "osslscope.discovery.v1")
    );
    let mut full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    assert!(watch::run(&o, &mut full, &AtomicBool::new(false)).is_err());
}
#[test]
fn invalid_timing_is_usage_before_scope_acquisition() {
    for tail in [
        vec!["--interval", "0.05"],
        vec!["--duration", "1"],
        vec!["--watch", "--interval", "NaN"],
        vec!["--watch", "--interval", "0.049"],
        vec!["--watch", "--duration", "1e-99"],
        vec!["--watch", "--duration", "3601"],
        vec!["--watch", "--watch"],
        vec!["--watch", "--interval", "1", "--interval", "2"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args(["scan", "--module", "/PRIVATE_CANARY_missing"])
            .args(&tail)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{tail:?}");
        assert!(output.stdout.is_empty());
    }
}
#[test]
fn cli_observer_signals_end_stream_and_leave_workload_alive() {
    let f = Fixture::new();
    let module = f.module();
    let mut workload = f.child(&module);
    workload.command(b'm');
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let mut observer = Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args([
                "scan",
                "--watch",
                "--pid",
                &workload.pid().to_string(),
                "--interval",
                "0.05",
                "--json",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(observer.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let first: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(first["record"], "snapshot");
        // Only signal the observer process created by this test.
        assert_eq!(unsafe { libc::kill(observer.id() as i32, signal) }, 0);
        let mut lines = vec![];
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            lines.push(serde_json::from_str::<Value>(&line).unwrap());
        }
        assert_eq!(observer.wait().unwrap().code(), Some(3));
        assert_eq!(lines.last().unwrap()["reason"], "interrupted");
        assert!(workload.child.try_wait().unwrap().is_none());
    }
}

// Catches acquiring unavailable selectors despite cancellation already being requested.
#[test]
fn already_cancelled_library_watch_does_not_acquire_scope() {
    let mut options = WatchOptions::default();
    options
        .selection
        .modules
        .push(PathBuf::from("/PRIVATE_CANARY_missing"));
    let mut output = vec![];
    let outcome = watch::run(&options, &mut output, &AtomicBool::new(true)).unwrap();
    assert_eq!(outcome.exit_code(), 3);
    let end: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(end["reason"], "interrupted");
    assert_eq!(end["sequence"], 0);
    options.interval = Duration::ZERO;
    output.clear();
    assert_eq!(
        watch::run(&options, &mut output, &AtomicBool::new(true))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(output.is_empty());
}

#[test]
fn cli_watch_human_refusal_and_output_delivery() {
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    child.command(b'm');
    let human = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            &child.pid().to_string(),
            "--duration",
            "0.2",
        ])
        .output()
        .unwrap();
    assert!(matches!(human.status.code(), Some(0 | 3)));
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("process_seen"));
    assert!(text.contains("module_seen"));
    assert!(text.contains("unknown"));
    assert!(text.contains("not_observed"));
    assert!(text.contains("incomplete"));
    assert!(!text.contains("PRIVATE_CANARY"));
    let unavailable = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--module",
            "/PRIVATE_CANARY_missing",
            "--duration",
            "0.1",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(unavailable.status.code(), Some(4));
    let end: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(end["reason"], "scope_unavailable");
    assert_eq!(end["sequence"], 0);
    let full = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            &child.pid().to_string(),
            "--duration",
            "0.1",
            "--json",
        ])
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(full.status.code(), Some(1));
    assert!(child.child.try_wait().unwrap().is_none());
}

// Catches retaining obsolete sampled descriptors after pinned selection failure.
#[test]
fn failed_scope_drops_sample_cache_but_keeps_pinned_selector() {
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    child.command(b'm');
    let metadata = fs::metadata(&module).unwrap();
    let descriptors = || {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| fs::metadata(e.path()).ok())
            .filter(|m| (m.dev(), m.ino()) == (metadata.dev(), metadata.ino()))
            .count()
    };
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.pid()],
            modules: vec![module.clone()],
            cgroup: None,
            resolve_paths: false,
        },
        Limits::default(),
    )
    .unwrap();
    scanner.snapshot();
    assert_eq!(descriptors(), 2);
    fs::OpenOptions::new()
        .append(true)
        .open(&module)
        .unwrap()
        .write_all(b"tail")
        .unwrap();
    let failed = scanner.snapshot();
    assert!(failed.processes.is_empty());
    assert_eq!(descriptors(), 1);
}

// Independent procfs oracle for the test-owned mapping; no target bytes are read.
fn assert_executable_mapping(pid: u32, inode: u64) {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    assert!(
        maps.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields
                .get(1)
                .is_some_and(|p| p.as_bytes().get(2) == Some(&b'x'))
                && fields.get(4).and_then(|s| s.parse::<u64>().ok()) == Some(inode)
        }),
        "owned executable mmap must remain present"
    );
}
fn unresolved_backing_watch(module_scope: bool) {
    let f = Fixture::new();
    let module = f.module();
    // A separate native inode with identical content pins the selector. Its
    // fingerprint cannot be invalidated by unlinking the actual mapped file.
    let selector = f.0.join("PRIVATE_CANARY_selector_copy");
    fs::copy(&module, &selector).unwrap();
    let inode = fs::metadata(&module).unwrap().ino();
    let mut child = f.child(&module);
    child.command(b'm');
    let pid = child.pid();
    assert_executable_mapping(pid, inode);
    let mut options = options(pid);
    if module_scope {
        options.selection.modules.push(selector);
    }
    let cancel = AtomicBool::new(false);
    let mut count = 0;
    let mut writer = Records {
        pending: vec![],
        values: vec![],
        after: |record: &Value| {
            if record["record"] != "snapshot" {
                return;
            }
            count += 1;
            if count == 1 {
                fs::remove_file(&module).unwrap();
            } else {
                assert_eq!(count, 2);
                cancel.store(true, Ordering::Relaxed);
            }
            assert_executable_mapping(pid, inode);
            assert!(child.child.try_wait().unwrap().is_none());
        },
    };
    watch::run(&options, &mut writer, &cancel).unwrap();
    assert!(changes(&writer.values[0], "module_seen"));
    let second = &writer.values[1];
    assert!(
        changes(second, "visibility_lost"),
        "expected visibility_lost; changes={}",
        second["changes"]
    );
    assert!(!changes(second, "module_not_seen"));
    assert!(!changes(second, "process_not_seen"));
    assert!(
        second["snapshot"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["reason"] == "backing_unavailable")
    );
    assert_eq!(
        second["snapshot"]["scope_record"],
        writer.values[0]["snapshot"]["scope_record"]
    );
    assert_executable_mapping(pid, inode);
    assert!(child.child.try_wait().unwrap().is_none());
}
// Catches conflating a deleted/unresolvable executable backing with real unmapping.
#[test]
fn unresolved_backing_loses_visibility_without_asserting_module_absence() {
    unresolved_backing_watch(false);
}
// Catches selector filtering promoting that same backing failure to process absence.
#[test]
fn unresolved_backing_with_independent_selector_cannot_assert_process_absence() {
    unresolved_backing_watch(true);
}

#[test]
fn scope_unavailable_watch_exit4_names_reason_on_stderr() {
    // Deterministic exit 4: unresolvable module selector, end record intact.
    let unavailable = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--module",
            "/PRIVATE_CANARY_missing",
            "--duration",
            "0.1",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(unavailable.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&unavailable.stderr);
    let reasons: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("osslscope discovery:"))
        .collect();
    assert_eq!(reasons.len(), 1, "exactly one stderr reason, got: {stderr}");
    assert!(
        reasons[0].contains("scope unavailable"),
        "reason names the scope failure, got: {stderr}"
    );
    let end: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(end["reason"], "scope_unavailable");
}

#[test]
fn human_watch_snapshot_prints_identity_totals() {
    // Own-pid watch: human snapshots carry the identity totals line.
    let pid = std::process::id().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["scan", "--watch", "--pid", &pid, "--duration", "0.3"])
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(0 | 3 | 4)));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("tick 1:"), "sampled, got: {text}");
    assert!(
        text.contains("identity: ")
            && (text.contains("verified") || text.contains("no modules inventoried")),
        "identity totals on human snapshots, got: {text}"
    );
}

#[test]
fn human_watch_with_gaps_never_claims_blindness() {
    // Unprivileged snapshots carry gaps: the boundary stays silent
    // across every sample (fail closed). Under root the presence
    // test owns the assertion instead.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: absence needs an unprivileged gap fixture");
        return;
    }
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let pid = child.id().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            &pid,
            "--interval",
            "0.2",
            "--duration",
            "0.6",
        ])
        .output()
        .unwrap();
    child.kill().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("tick 2:"), "sampled twice, got: {text}");
    assert!(
        !text.contains("blindness:"),
        "no absence claim under gaps, got: {text}"
    );
}

#[test]
fn human_watch_states_blindness_exactly_once_when_verified() {
    // Root-only presence: verified gap-free snapshots state the
    // boundary exactly once per run.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP: verified scan needs root");
        return;
    }
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let pid = child.id().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            &pid,
            "--interval",
            "0.2",
            "--duration",
            "0.6",
        ])
        .output()
        .unwrap();
    child.kill().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("tick 2:"), "sampled twice, got: {text}");
    assert_eq!(
        text.matches("blindness: no-mapped-openssl").count(),
        1,
        "boundary printed once, got: {text}"
    );
}

#[test]
fn v060_watch_delta_heartbeat_and_cumulative_uncertainty() {
    use std::io::Read;
    let me = std::process::id().to_string();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--pid",
            &me,
            "--watch",
            "--interval",
            "1",
            "--duration",
            "3",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success() || status.code() == Some(3));
    let ticks = out.matches("tick ").count();
    assert!(ticks >= 2, "no heartbeats: {out}");
    let full_lists = out.matches("modules=").count();
    assert!(full_lists <= 2, "full state re-dumped every tick: {out}");
    assert!(out.contains("Watch ended:"), "no end record");
}

// F8/H2: partial-then-complete must end non-complete — a later
// complete sample never erases earlier uncertainty. The
// dumpable dance below needs an environment that yields
// complete samples; elsewhere it SKIPs (the
// `cumulative_end_status_*` unit tests pin the rule itself).
#[test]
fn watch_end_status_preserves_partial_history() {
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    child.command(b'm');
    let pid = child.pid();
    let mut opts = options(pid);
    opts.interval = Duration::from_millis(50);
    opts.duration = Some(Duration::from_millis(400));
    let mut count = 0;
    let mut writer = Records {
        pending: vec![],
        values: vec![],
        after: |record: &Value| {
            if record["record"] != "snapshot" {
                return;
            }
            count += 1;
            match count {
                1 => child.command(b'd'),
                2 => child.command(b'e'),
                _ => {}
            }
        },
    };
    let outcome = watch::run(&opts, &mut writer, &AtomicBool::new(false)).unwrap();
    let snapshots: Vec<&Value> = writer
        .values
        .iter()
        .filter(|v| v["record"] == "snapshot")
        .collect();
    assert!(snapshots.len() >= 3, "too few samples");
    let exit = |v: &Value| match v["snapshot"]["capabilities"]["inventory"].as_str() {
        Some("complete") => 0,
        Some("partial") => 3,
        Some("unavailable") => 4,
        other => panic!("unknown inventory state: {other:?}"),
    };
    if exit(snapshots[0]) != 0 {
        eprintln!("SKIP: environment yields no complete baseline");
        return;
    }
    if exit(snapshots[1]) == 0 {
        eprintln!("SKIP: dumpable dance inert here (e.g. root)");
        return;
    }
    if snapshots[2..].iter().any(|s| exit(s) != 0) {
        eprintln!("SKIP: re-enable did not restore complete samples");
        return;
    }
    assert_eq!(writer.values.last().unwrap()["reason"], "duration");
    assert_eq!(
        outcome.exit_code(),
        3,
        "later complete erased partial history: {:?}",
        snapshots.iter().map(|s| exit(s)).collect::<Vec<_>>()
    );
    assert_eq!(writer.values.last().unwrap()["status"], 3);
}

// F8/H2 dual (runs everywhere): usable-then-unavailable must
// end partial (3), not unavailable (4) — exit 4 means zero
// usable samples, and the first sample here was usable. A
// last-sample-only end status would report 4.
#[test]
fn watch_end_status_preserves_usable_history() {
    let mut workload = ReapedObserver(Command::new("sleep").arg("30").spawn().unwrap());
    std::thread::sleep(Duration::from_millis(200));
    let pid = workload.0.id();
    let mut opts = options(pid);
    opts.interval = Duration::from_millis(50);
    opts.duration = Some(Duration::from_millis(400));
    let mut count = 0;
    let mut writer = Records {
        pending: vec![],
        values: vec![],
        after: |record: &Value| {
            if record["record"] != "snapshot" {
                return;
            }
            count += 1;
            if count == 1 {
                // Reaped before the next sample: later samples
                // observe a dead pid (unavailable).
                workload.0.kill().unwrap();
                workload.0.wait().unwrap();
            }
        },
    };
    let outcome = watch::run(&opts, &mut writer, &AtomicBool::new(false)).unwrap();
    let snapshots: Vec<&Value> = writer
        .values
        .iter()
        .filter(|v| v["record"] == "snapshot")
        .collect();
    assert!(snapshots.len() >= 2, "too few samples");
    let exit = |v: &Value| match v["snapshot"]["capabilities"]["inventory"].as_str() {
        Some("complete") => 0,
        Some("partial") => 3,
        Some("unavailable") => 4,
        other => panic!("unknown inventory state: {other:?}"),
    };
    if exit(snapshots[0]) == 4 {
        eprintln!("SKIP: live baseline unusable here");
        return;
    }
    if exit(snapshots[snapshots.len() - 1]) != 4 {
        eprintln!("SKIP: pid reused or still observable after kill");
        return;
    }
    assert_eq!(writer.values.last().unwrap()["reason"], "duration");
    assert_eq!(
        outcome.exit_code(),
        3,
        "later unavailable erased usable history: {:?}",
        snapshots.iter().map(|s| exit(s)).collect::<Vec<_>>()
    );
    assert_eq!(writer.values.last().unwrap()["status"], 3);
}

// W1 names: a mid-watch rename (same pid+starttime, same
// modules) is a meaningful human change — full state, not a
// heartbeat — while machine changes[] stays empty (the Change
// vocabulary is schema-pinned; machines diff full records).
#[test]
fn watch_human_reports_rename_without_machine_changes() {
    // Machine leg (library): rename between samples, changes empty.
    {
        let f = Fixture::new();
        let module = f.module();
        let mut child = f.child(&module);
        child.command(b'm');
        let pid = child.pid();
        let cancel = AtomicBool::new(false);
        let mut count = 0;
        let mut writer = Records {
            pending: vec![],
            values: vec![],
            after: |record: &Value| {
                if record["record"] != "snapshot" {
                    return;
                }
                count += 1;
                match count {
                    1 => child.command(b'n'),
                    2 => cancel.store(true, Ordering::Relaxed),
                    _ => panic!("unexpected poll"),
                }
            },
        };
        watch::run(&options(pid), &mut writer, &cancel).unwrap();
        assert_eq!(writer.values.len(), 3);
        assert!(
            writer.values[1]["changes"].as_array().unwrap().is_empty(),
            "machine vocabulary grew: {}",
            writer.values[1]["changes"]
        );
        assert_ne!(
            writer.values[0]["snapshot"]["processes"][0]["comm"],
            writer.values[1]["snapshot"]["processes"][0]["comm"],
            "rename did not land"
        );
    }
    // Human leg (CLI): tick 2 (still idle) heartbeats — the
    // control — then the rename breaks the heartbeat at tick 3.
    let f = Fixture::new();
    let module = f.module();
    let mut child = f.child(&module);
    child.command(b'm');
    let mut observer = ReapedObserver(
        Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args([
                "scan",
                "--watch",
                "--pid",
                &child.pid().to_string(),
                "--interval",
                "0.2",
                "--duration",
                "5",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(observer.0.stdout.take().unwrap());
    let mut line = String::new();
    // EOF (duration end without the wanted line) returns empty so
    // the assertions below fail instead of blocking forever.
    let tick_line =
        |reader: &mut BufReader<std::process::ChildStdout>, line: &mut String, want: &str| {
            loop {
                line.clear();
                if reader.read_line(line).unwrap() == 0 {
                    return String::new();
                }
                if line.starts_with(want) {
                    return line.clone();
                }
            }
        };
    tick_line(&mut reader, &mut line, "tick 1:");
    let tick2 = tick_line(&mut reader, &mut line, "tick 2:");
    child.command(b'n');
    let tick3 = tick_line(&mut reader, &mut line, "tick 3:");
    // Only signal the observer process created by this test.
    assert_eq!(
        unsafe { libc::kill(observer.0.id() as i32, libc::SIGINT) },
        0
    );
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    let code = observer.0.wait().unwrap().code();
    // Assertions after the reaped wait (also keeps the
    // child-reaper lint quiet on every path).
    assert!(
        tick2.contains("no changes"),
        "control failed: idle tick not quiet: {tick2}"
    );
    assert!(
        !tick3.contains("no changes"),
        "rename swallowed by heartbeat: {tick3}"
    );
    assert!(
        tick3.contains("state changed"),
        "rename tick mislabeled: {tick3}"
    );
    assert_eq!(code, Some(3));
    assert!(rest.contains("Watch ended:"), "no end record: {rest}");
    assert!(child.child.try_wait().unwrap().is_none());
}

#[test]
fn human_watch_end_reports_cumulative_uncertainty() {
    // Dead pid: every sample uncertain — the end record names
    // the cumulative history and the first uncertain sample.
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "scan",
            "--watch",
            "--pid",
            "2147483647",
            "--interval",
            "0.05",
            "--duration",
            "0.3",
        ])
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(3 | 4)));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Watch ended:"), "no end record: {text}");
    assert!(
        text.contains("cumulative: partial-seen") || text.contains("cumulative: unavailable-seen"),
        "no cumulative word: {text}"
    );
    assert!(
        text.contains("note: sample 1 was ") && text.contains("history remains uncertain"),
        "no uncertainty note: {text}"
    );
}

#[test]
fn human_watch_coalesces_snapshot_gaps() {
    // Dead pid (deterministic in any privilege lane): level 0
    // shows the exact per-reason counts line, -v the coalesced
    // grouped block — never one line per gap.
    let run = |extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--watch",
            "--pid",
            "2147483647",
            "--duration",
            "0.3",
        ];
        args.extend(extra.iter().copied());
        Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args(&args)
            .output()
            .unwrap()
    };
    let quiet = String::from_utf8_lossy(&run(&[]).stdout).into_owned();
    assert!(
        quiet.contains("gaps: ") && !quiet.contains("total in"),
        "counts line at level 0, got: {quiet}"
    );
    let verbose = String::from_utf8_lossy(&run(&["-v"]).stdout).into_owned();
    assert!(
        verbose.contains("gaps (") && verbose.contains("total in"),
        "coalesced gap block at -v, got: {verbose}"
    );
    for (level, text) in [("0", &quiet), ("1", &verbose)] {
        assert!(
            !text.contains("  gap=\""),
            "no per-gap lines remain at level {level}, got: {text}"
        );
    }
}
