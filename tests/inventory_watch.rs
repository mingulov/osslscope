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
fn options(pid: u32) -> WatchOptions {
    WatchOptions {
        selection: Selection {
            pids: vec![pid],
            ..Default::default()
        },
        limits: Limits::default(),
        interval: Duration::from_millis(50),
        duration: Some(Duration::from_secs(5)),
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
    assert!(!text.contains("PRIVATE_CANARY"));
    assert!(!text.contains(f.0.to_str().unwrap()));
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
