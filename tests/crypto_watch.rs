// SPDX-License-Identifier: GPL-3.0-or-later
//! Operator-facing watch command. Native positive attachment is tested separately.
use std::process::{Command, Output};
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(args)
        .output()
        .unwrap()
}
fn records(output: &Output) -> Vec<serde_json::Value> {
    assert!(
        matches!(output.status.code(), Some(0 | 3 | 4)),
        "{:?}",
        output
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
#[test]
fn crypto_watch_rejects_incompatible_grammar_before_scope_access() {
    for args in [
        vec!["scan", "--observe-crypto", "--cgroup", "/PRIVATE_CANARY"],
        vec!["scan", "--watch", "--observe-crypto", "--observe-providers"],
        vec!["inspect", "--watch", "--observe-crypto"],
        vec![
            "scan",
            "--watch",
            "--module",
            "--observe-crypto",
            "/PRIVATE_CANARY",
        ],
        vec!["scan", "--watch", "--observe-crypto", "--duration", "NaN"],
    ] {
        let out = command(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE_CANARY"));
    }
}
#[test]
fn one_command_discovers_two_real_incarnations_without_trusted_companions() {
    let mut a = Command::new("openssl")
        .args([
            "speed", "-elapsed", "-seconds", "20", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut b = Command::new("openssl")
        .args([
            "speed", "-elapsed", "-seconds", "20", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let dir = std::env::temp_dir().join(format!(
        "osslscope-watch-no-companions-{}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).unwrap();
    let binary = dir.join("osslscope");
    std::fs::copy(env!("CARGO_BIN_EXE_osslscope"), &binary).unwrap();
    let out = Command::new(&binary)
        .args([
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &a.id().to_string(),
            "--pid",
            &b.id().to_string(),
            "--duration",
            "3",
            "--interval",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let alive = a.try_wait().unwrap().is_none() && b.try_wait().unwrap().is_none();
    a.kill().unwrap();
    b.kill().unwrap();
    a.wait().unwrap();
    b.wait().unwrap();
    assert!(alive);
    let rows = records(&out);
    assert!(
        rows.iter()
            .all(|r| r["schema_version"] == "crypto-watch-v1")
    );
    for pid in [a.id(), b.id()] {
        let row = rows
            .iter()
            .find(|r| r["kind"] == "discovery" && r["process"]["pid"] == pid)
            .expect("separate passive process inventory");
        assert!(
            row["process"]["modules"]
                .as_array()
                .is_some_and(|m| !m.is_empty())
        );
        assert!(row["process"]["starttime"].as_u64().unwrap() > 0);
    }
    assert!(
        rows.iter()
            .any(|r| r["kind"] == "tracing_gap" && r["reason"] == "companions_unavailable")
    );
    assert!(!rows.iter().any(|r| r["kind"] == "process_observation"));
    assert_eq!(rows.last().unwrap()["kind"], "end");
}
#[test]
fn missing_selected_process_is_an_explicit_gap_not_an_inactive_observation() {
    let out = command(&[
        "scan",
        "--watch",
        "--observe-crypto",
        "--pid",
        "2147483647",
        "--duration",
        "0.1",
        "--json",
    ]);
    let rows = records(&out);
    assert!(
        rows.iter()
            .any(|r| r["kind"] == "gap" && r["gap"]["pid"] == 2147483647u32)
    );
    assert!(!rows.iter().any(|r| r["kind"] == "process_observation"));
}

fn physical(doc: &serde_json::Value) -> u64 {
    doc["sites"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            doc["fenced"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|f| f["sites"].as_array().unwrap()),
        )
        .map(|s| s["calls"].as_u64().unwrap())
        .sum()
}
#[test]
#[ignore = "requires a privileged installed CLI and stock OpenSSL"]
fn installed_two_process_crypto_and_global_cap_preserve_foreign_workloads() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let mut children: Vec<_> = (0..3)
        .map(|_| {
            Command::new("openssl")
                .args([
                    "speed", "-elapsed", "-seconds", "30", "-evp", "SHA512", "-bytes", "64",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut command = Command::new(binary);
    command.args([
        "scan",
        "--watch",
        "--observe-crypto",
        "--duration",
        "10",
        "--json",
    ]);
    for child in &children {
        command.args(["--pid", &child.id().to_string()]);
    }
    let output = command.output().unwrap();
    let alive = children.iter_mut().all(|p| p.try_wait().unwrap().is_none());
    for child in &mut children {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert!(alive, "observer stop must not signal foreign applications");
    let rows = records(&output);
    let docs: Vec<_> = rows
        .iter()
        .filter(|r| r["kind"] == "process_observation")
        .collect();
    assert_eq!(
        docs.len(),
        2,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for row in docs {
        let doc = &row["document"];
        osslscope::schema::validate_v2(doc).unwrap();
        let calls = physical(doc);
        assert!(
            calls > 0,
            "no physical activity: end={} counters={} stderr={}",
            rows.last().unwrap(),
            doc["completeness"]["counters"],
            String::from_utf8_lossy(&output.stderr)
        );
        let api: u64 = doc["api_activity"]
            .as_array()
            .expect("separate public API ledger")
            .iter()
            .map(|r| r["entries"].as_u64().unwrap())
            .sum();
        assert!(api > 0, "no API activity: {row}");
        println!(
            "PID {}: {calls} physical entries, {api} separate API entries",
            row["incarnation"]["pid"]
        );
    }
    assert!(
        rows.iter()
            .any(|r| r["kind"] == "limit" && r["reason"] == "global_state_limit")
    );
    let rejected = rows
        .iter()
        .find(|r| r["kind"] == "limit" && r["reason"] == "global_state_limit")
        .unwrap();
    assert!(
        rows.iter().any(|r| r["kind"] == "discovery"
            && r["process"]["pid"] == rejected["incarnation"]["pid"]
            && r["process"]["modules"].as_array().is_some_and(|m| m
                .iter()
                .any(|m| m["info"]["kind"] == "openssl_compatible"
                    && !m["info"]["exports"].as_array().unwrap().is_empty()))),
        "cap refusal must retain passive interface evidence"
    );
    let peak = rows.last().unwrap()["peak_accounted_bytes"]
        .as_u64()
        .unwrap();
    assert!(peak <= 256 << 20);
    println!(
        "peak declared observer state: {peak} bytes; next member explicitly uncovered; foreign processes survived"
    );
}

#[test]
#[ignore = "requires privileged installed CLI and writable cgroup v2"]
fn installed_late_cgroup_member_removal_reentry_cancel_and_unrelated_exclusion() {
    use std::{
        io::BufRead,
        sync::mpsc,
        time::{Duration, Instant},
    };
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let current = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let relative = current.lines().find_map(|s| s.strip_prefix("0::")).unwrap();
    let parent = std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let scope = parent.join(format!("osslscope-watch-test-{}", std::process::id()));
    std::fs::create_dir(&scope).unwrap();
    struct Cleanup {
        children: Vec<std::process::Child>,
        scope: std::path::PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_dir(&self.scope);
        }
    }
    let mut cleanup = Cleanup {
        children: vec![],
        scope: scope.clone(),
    };
    let spawn = || {
        Command::new("openssl")
            .args([
                "speed", "-elapsed", "-seconds", "60", "-evp", "SHA512", "-bytes", "64",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    cleanup.children.push(spawn());
    cleanup.children.push(spawn());
    let a = cleanup.children[0].id();
    let unrelated = cleanup.children[1].id();
    std::fs::write(scope.join("cgroup.procs"), a.to_string()).unwrap();
    let mut observer = Command::new(binary)
        .args([
            "scan",
            "--watch",
            "--observe-crypto",
            "--cgroup",
            scope.to_str().unwrap(),
            "--duration",
            "40",
            "--json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = observer.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
            if tx.send(row).is_err() {
                break;
            }
        }
    });
    let mut rows = Vec::new();
    let wait = |rows: &mut Vec<serde_json::Value>, pid: u32, state: &str| {
        let deadline = Instant::now() + Duration::from_secs(14);
        loop {
            let row = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("membership event within bounded native setup");
            let found = row["kind"] == "membership"
                && row["incarnation"]["pid"] == pid
                && row["state"] == state;
            rows.push(row);
            if found {
                break;
            }
        }
    };
    wait(&mut rows, a, "observing");
    cleanup.children.push(spawn());
    let b = cleanup.children[2].id();
    std::fs::write(scope.join("cgroup.procs"), b.to_string()).unwrap();
    wait(&mut rows, b, "observing");
    std::thread::sleep(Duration::from_secs(3));
    std::fs::write(parent.join("cgroup.procs"), a.to_string()).unwrap();
    wait(&mut rows, a, "retired");
    std::fs::write(scope.join("cgroup.procs"), a.to_string()).unwrap();
    wait(&mut rows, a, "observing");
    std::thread::sleep(Duration::from_secs(3));
    // Signal only the observer process created by this test.
    assert_eq!(
        unsafe { libc::kill(observer.id() as i32, libc::SIGTERM) },
        0
    );
    while let Ok(row) = rx.recv_timeout(Duration::from_secs(8)) {
        let end = row["kind"] == "end";
        rows.push(row);
        if end {
            break;
        }
    }
    assert_eq!(observer.wait().unwrap().code(), Some(3));
    reader.join().unwrap();
    assert!(
        cleanup
            .children
            .iter_mut()
            .all(|p| p.try_wait().unwrap().is_none())
    );
    assert!(!rows.iter().any(|r| r["incarnation"]["pid"] == unrelated));
    let a_docs: Vec<_> = rows
        .iter()
        .filter(|r| r["kind"] == "process_observation" && r["incarnation"]["pid"] == a)
        .collect();
    assert_eq!(
        a_docs.len(),
        2,
        "removal/reentry preserves distinct segments"
    );
    assert_ne!(a_docs[0]["segment"], a_docs[1]["segment"]);
    assert_eq!(a_docs[0]["retirement"], "sampled_removal");
    assert_eq!(a_docs[0]["incarnation"], a_docs[1]["incarnation"]);
    for row in rows.iter().filter(|r| r["kind"] == "process_observation") {
        osslscope::schema::validate_v2(&row["document"]).unwrap();
        assert!(physical(&row["document"]) > 0);
        if row["retirement"] == "cancelled" {
            assert_eq!(row["document"]["window"]["signal_cut"], true);
        }
    }
    assert_eq!(rows.last().unwrap()["reason"], "cancelled");
    println!(
        "late cgroup member observed; removal/reentry produced separate positive segments; unrelated PID {unrelated} excluded; cancellation preserved all foreign workloads; {}",
        rows.last().unwrap()
    );
}

#[test]
fn denied_process_access_is_pid_specific_and_never_an_inactive_document() {
    use std::{io::BufRead, os::unix::process::CommandExt};
    let mut child_command = Command::new("python3");
    child_command.args(["-c", "import ctypes,time; assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0; print('ready',flush=True); time.sleep(20)"]).stdout(std::process::Stdio::piped());
    // Always run the observer without ptrace authority, including root suites.
    if unsafe { libc::geteuid() } == 0 {
        child_command.uid(65534).gid(65534);
    }
    let mut child = child_command.spawn().unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_osslscope").into());
    let mut observer = Command::new(binary);
    observer.args([
        "scan",
        "--watch",
        "--observe-crypto",
        "--pid",
        &child.id().to_string(),
        "--duration",
        "0.3",
        "--json",
    ]);
    if unsafe { libc::geteuid() } == 0 {
        observer.uid(65534).gid(65534);
    }
    let out = observer.output().unwrap();
    let alive = child.try_wait().unwrap().is_none();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(alive);
    let rows = records(&out);
    assert!(rows.iter().any(|r| r["kind"] == "gap"
        && r["gap"]["pid"] == child.id()
        && r["gap"]["reason"] == "process_unavailable"));
    assert!(!rows.iter().any(|r| r["kind"] == "process_observation"));
}

#[test]
#[ignore = "requires a privileged installed CLI and stock OpenSSL"]
fn installed_module_selector_observes_full_selected_process_inventory() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    let mut child = Command::new("/usr/bin/openssl")
        .args([
            "speed", "-elapsed", "-seconds", "30", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut other = Command::new("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let output = Command::new(binary)
        .args([
            "scan",
            "--watch",
            "--observe-crypto",
            "--module",
            "/usr/bin/openssl",
            "--pid",
            &child.id().to_string(),
            "--pid",
            &other.id().to_string(),
            "--duration",
            "7",
            "--json",
        ])
        .output()
        .unwrap();
    let alive = child.try_wait().unwrap().is_none() && other.try_wait().unwrap().is_none();
    child.kill().unwrap();
    other.kill().unwrap();
    child.wait().unwrap();
    other.wait().unwrap();
    assert!(alive);
    let rows = records(&output);
    assert!(
        !rows
            .iter()
            .any(|r| r["process"]["pid"] == other.id() || r["incarnation"]["pid"] == other.id())
    );
    assert!(rows.iter().any(|r| {
        r["kind"] == "discovery"
            && r["process"]["modules"]
                .as_array()
                .is_some_and(|m| m.iter().any(|m| m["info"]["kind"] == "openssl_compatible"))
    }));
    let row = rows
        .iter()
        .find(|r| r["kind"] == "process_observation")
        .expect("selected process observation");
    osslscope::schema::validate_v2(&row["document"]).unwrap();
    assert!(
        physical(&row["document"]) > 0,
        "selected executable must not strip libcrypto from the observation inventory"
    );
    assert!(
        row["document"]["api_activity"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["entries"].as_u64().unwrap() > 0)),
        "selected process needs independent public API evidence"
    );
    println!(
        "module-selected process: {} physical entries from full inventory; unrelated sleeper excluded",
        physical(&row["document"])
    );
}

#[test]
#[ignore = "requires privileged installed CLI, unshare and stock OpenSSL"]
fn installed_visible_host_discovers_two_workloads_in_observer_proc_view() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    // Restrict the observer's visible host population to these owned workloads.
    // The application command receives no selector or provider/query driver.
    let script = r#"
openssl speed -elapsed -seconds 30 -evp SHA512 -bytes 64 >/dev/null 2>/dev/null & a=$!
openssl speed -elapsed -seconds 30 -evp SHA512 -bytes 64 >/dev/null 2>/dev/null & b=$!
trap 'kill "$a" "$b" 2>/dev/null; wait' EXIT
"$1" scan --watch --observe-crypto --duration 10 --json
result=$?
kill -0 "$a" && kill -0 "$b" || exit 99
exit "$result"
"#;
    let output = Command::new("unshare")
        .args([
            "--fork",
            "--pid",
            "--mount-proc",
            "/bin/sh",
            "-c",
            script,
            "sh",
        ])
        .arg(binary)
        .output()
        .unwrap();
    let rows = records(&output);
    let docs: Vec<_> = rows
        .iter()
        .filter(|r| r["kind"] == "process_observation")
        .collect();
    assert_eq!(
        docs.len(),
        2,
        "no-selector visible-host discovery: end={} stderr={}",
        rows.last().unwrap(),
        String::from_utf8_lossy(&output.stderr)
    );
    for row in docs {
        osslscope::schema::validate_v2(&row["document"]).unwrap();
        assert!(
            physical(&row["document"]) > 0,
            "{}",
            row["document"]["completeness"]
        );
    }
    println!(
        "no-selector discovery observed two stock processes in its isolated proc view; both survived observer stop; {}",
        rows.last().unwrap()
    );
}

#[test]
#[ignore = "requires privileged installed CLI and isolated PID namespace reuse control"]
fn installed_reused_pid_keeps_distinct_incarnations_and_never_redirects_old_links() {
    let binary = std::env::var_os("OSSLSCOPE_TEST_INSTALLED_CLI").expect("installed CLI");
    // ns_last_pid is changed only in this fresh PID namespace, after the owned
    // old workload is reaped. The observer itself is never recycled.
    let script = r#"
import json, pathlib, subprocess, sys, time, threading, queue
ready=queue.Queue(); events=queue.Queue()
args=['openssl','speed','-elapsed','-seconds','60','-evp','SHA512','-bytes','64']
def workload(): return subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
old=workload(); replacement=None; observer=None; rows=[]
try:
    observer=subprocess.Popen([sys.argv[1],'scan','--watch','--observe-crypto','--pid',str(old.pid),'--duration','35','--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def read_ready():
        for line in observer.stderr:
            if 'focused callbacks attached' in line: ready.put(line)
    threading.Thread(target=read_ready,daemon=True).start()
    def read_rows():
        for line in observer.stdout:
            row=json.loads(line); rows.append(row); events.put(row)
        events.put(None)
    reader=threading.Thread(target=read_rows); reader.start()
    def admitted():
        while True:
            row=events.get(timeout=12)
            assert row is not None, 'observer ended before admission'
            if row['kind']=='membership' and row['state']=='observing': return
    admitted(); ready.get(timeout=12); time.sleep(2)
    pid=old.pid; old.terminate(); old.wait()
    pathlib.Path('/proc/sys/kernel/ns_last_pid').write_text(str(pid-1))
    replacement=workload(); assert replacement.pid==pid
    admitted(); ready.get(timeout=12); time.sleep(2); observer.terminate()
    reader.join(timeout=12); assert not reader.is_alive()
    assert observer.wait()==3
    assert replacement.poll() is None, 'foreign replacement was signalled'
    for row in rows: print(json.dumps(row,separators=(',',':')))
finally:
    for p in [observer,old,replacement]:
        if p is not None and p.poll() is None: p.kill(); p.wait()
"#;
    let output = Command::new("unshare")
        .args(["--fork", "--pid", "--mount-proc", "python3", "-c", script])
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = records(&output);
    let docs: Vec<_> = rows
        .iter()
        .filter(|r| r["kind"] == "process_observation")
        .collect();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0]["incarnation"]["pid"], docs[1]["incarnation"]["pid"]);
    assert_ne!(
        docs[0]["incarnation"]["starttime"],
        docs[1]["incarnation"]["starttime"]
    );
    assert_ne!(docs[0]["segment"], docs[1]["segment"]);
    assert!(matches!(
        docs[0]["retirement"].as_str(),
        Some("incarnation_changed" | "visibility_lost")
    ));
    for row in docs {
        osslscope::schema::validate_v2(&row["document"]).unwrap();
        assert!(physical(&row["document"]) > 0);
    }
    println!(
        "actual numeric PID reuse preserved two independently acquired positive segments; replacement survived observer stop"
    );
}
