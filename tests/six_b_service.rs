//! SPDX-License-Identifier: GPL-3.0-or-later
//! 6B bounded-service controls (§9 executable specifications).
//!
//! Admission legs call the library entry in-process; lifecycle legs
//! spawn the real binary. RED-before-GREEN: behavioral legs fail
//! until the service implements the frozen D-record.

use std::process::Command;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

fn run_service(words: &[&str]) -> u8 {
    let code = osslscope::service::run(&argv(words));
    // ExitCode has no stable value reader; map the known constants.
    if code == std::process::ExitCode::SUCCESS {
        0
    } else if code == std::process::ExitCode::from(2) {
        2
    } else if code == std::process::ExitCode::from(3) {
        3
    } else if code == std::process::ExitCode::from(4) {
        4
    } else if code == std::process::ExitCode::from(10) {
        10
    } else if code == std::process::ExitCode::from(11) {
        11
    } else {
        1
    }
}

fn bin() -> Command {
    let exe = env!("CARGO_BIN_EXE_osslscope");
    let mut c = Command::new(exe);
    c.arg("service");
    c
}

fn fresh_dir(name: &str) -> std::path::PathBuf {
    let root = std::env::var("OSSL_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = root.join(format!(
        "sixb-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- §1 admission (exit 2, pre-side-effect) ---

#[test]
fn sixb_flag_equals_rejected() {
    assert_eq!(run_service(&["--out=/tmp/x", "--pid", "1"]), 2);
}

#[test]
fn sixb_second_cgroup_rejected() {
    assert_eq!(
        run_service(&["--out", "/tmp/x", "--cgroup", "/a", "--cgroup", "/b"]),
        2
    );
}

#[test]
fn sixb_missing_selector_rejected() {
    let dir = fresh_dir("no-selector");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--module", "/x.so"]),
        2
    );
}

#[test]
fn sixb_missing_out_rejected() {
    assert_eq!(run_service(&["--pid", "1"]), 2);
}

#[test]
fn sixb_zero_timeout_rejected_by_positivity() {
    let dir = fresh_dir("zero-timeout");
    assert_eq!(
        run_service(&[
            "--out",
            dir.to_str().unwrap(),
            "--pid",
            "1",
            "--timeout",
            "0"
        ]),
        2
    );
}

#[test]
fn sixb_zero_grace_rejected_by_positivity() {
    let dir = fresh_dir("zero-grace");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "1", "--grace", "0"]),
        2
    );
}

#[test]
fn sixb_bad_format_rejected() {
    let dir = fresh_dir("bad-format");
    assert_eq!(
        run_service(&[
            "--out",
            dir.to_str().unwrap(),
            "--pid",
            "1",
            "--format",
            "yaml"
        ]),
        2
    );
}

#[test]
fn sixb_unknown_flag_rejected() {
    let dir = fresh_dir("unknown-flag");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "1", "--forever"]),
        2
    );
}

#[test]
fn sixb_no_spawn_mode() {
    let dir = fresh_dir("no-spawn");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "run", "--", "true"]),
        2
    );
}

#[test]
fn sixb_bad_pid_rejected() {
    let dir = fresh_dir("bad-pid");
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "0"]),
        2
    );
    assert_eq!(
        run_service(&["--out", dir.to_str().unwrap(), "--pid", "abc"]),
        2
    );
}

#[test]
fn sixb_bad_counts_rejected() {
    let dir = fresh_dir("bad-counts");
    let d = dir.to_str().unwrap();
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-bytes", "x"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-bytes", "1"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--queue-events", "63"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--retain-windows", "0"]),
        2
    );
    assert_eq!(run_service(&["--out", d, "--pid", "1", "--window", "0"]), 2);
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--window", "3601"]),
        2
    );
    assert_eq!(
        run_service(&["--out", d, "--pid", "1", "--interval", "0.04"]),
        2
    );
}

#[test]
fn sixb_help_exits_zero() {
    assert_eq!(run_service(&["--help"]), 0);
}

// --- Behavioral REDs (need the implemented service) ---

/// One window against a live sleeper target: the DIR must hold a
/// `service-window-v1` envelope plus sequence state after SIGTERM.
#[test]
fn sixb_one_window_finalizes() {
    let dir = fresh_dir("one-window");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        status.code() == Some(3),
        "cancel-after-windows exits 3, got {status:?}"
    );
    let win = dir.join("window-0000000000.json");
    assert!(win.is_file(), "window 0 published, dir: {dir:?}");
    let body = std::fs::read_to_string(&win).unwrap();
    // Strict structural parse (regression pin for the splice: the
    // file MUST be valid JSON with the `crypto_watch` key present —
    // substring checks pass on malformed files).
    let doc: serde_json::Value = serde_json::from_str(&body).expect("window 0 is valid JSON");
    assert_eq!(doc["schema"], "service-window-v1", "envelope schema");
    assert_eq!(doc["seq"], 0, "window seq");
    assert!(doc["crypto_watch"].is_array(), "crypto_watch array present");
    assert!(doc["window"].is_object(), "window span present");
    assert!(doc["document"].is_object(), "snapshot document present");
    assert!(dir.join("sequence.json").is_file(), "sequence state");
    let seq_body = std::fs::read_to_string(dir.join("sequence.json")).unwrap();
    let _: serde_json::Value = serde_json::from_str(&seq_body).expect("sequence is valid JSON");
    assert!(dir.join("run-summary.json").is_file(), "run summary");
    let sum_body = std::fs::read_to_string(dir.join("run-summary.json")).unwrap();
    let sum: serde_json::Value = serde_json::from_str(&sum_body).expect("summary is valid JSON");
    assert_eq!(sum["schema"], "service-run-v1", "summary schema");
    // Clean close drops no diagnostics (the abandonment wake is not
    // a diagnostic — regression pin).
    assert_eq!(sum["diagnostics_dropped"], 0, "no drops on clean close");
}

/// Second coordinator on a live out-DIR refuses pre-start (exit 2).
#[test]
fn sixb_double_coordinator_refused() {
    let dir = fresh_dir("double-coord");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_millis(800));
    let probe = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .status()
        .expect("spawn probe");
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let _ = svc.wait();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(probe.code(), Some(2), "out-DIR locked refuses exit 2");
}

/// Mixed double-signal (SIGINT + SIGTERM) stages two `Term`s in one
/// drain batch: immediate stop — the in-flight window is abandoned
/// (never published), the reservation is marked `double_signal`, and
/// the run exits 3 with the abandonment in the summary.
///
/// Determinism: SIGSTOP freezes the service first (polled `T` state
/// via /proc), so both signals are pending before any consume —
/// no iteration-boundary race. Same-signo rapid pairs coalesce in
/// the kernel and are observed once (single stop); mixed pairs do
/// not merge. STOP/CONT are test staging, unobserved by the service.
#[test]
fn sixb_mixed_double_signal_abandons_immediately() {
    let dir = fresh_dir("double-signal");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let svc_pid = svc.id() as i32;
    unsafe { libc::kill(svc_pid, libc::SIGSTOP) };
    // Poll until stopped (T state) — bounded, fail-loud on timeout.
    let state_path = format!("/proc/{svc_pid}/stat");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let stat = std::fs::read_to_string(&state_path).unwrap_or_default();
        let stopped = stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.split_whitespace().next() == Some("T"));
        if stopped || std::time::Instant::now() >= deadline {
            assert!(stopped, "service did not stop for staging");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unsafe {
        libc::kill(svc_pid, libc::SIGINT);
        libc::kill(svc_pid, libc::SIGTERM);
        libc::kill(svc_pid, libc::SIGCONT);
    }
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    // Zero finalized + interrupted → 4 (§7.3: "double-signal with
    // zero finalized windows exits 4" — priority 3 beats 6).
    assert_eq!(
        status.code(),
        Some(4),
        "double-signal zero-finalized exits 4"
    );
    assert!(
        !dir.join("window-0000000000.json").exists(),
        "in-flight window abandoned, never published"
    );
    let seq = std::fs::read_to_string(dir.join("sequence.json")).expect("sequence");
    assert!(seq.contains("\"double_signal\""), "mark reason: {seq}");
    let summary = std::fs::read_to_string(dir.join("run-summary.json")).expect("summary");
    assert!(
        summary.contains("\"double_signal\""),
        "abandoned note: {summary}"
    );
}

/// Latch hold (§6.2 MUST): a restart into a latched out-DIR exits 4
/// with a byte-identical DIR (the refused start restores even the
/// lock bytes).
///
/// Honest hostile environment, no forged state: run 1 fills the DIR
/// (retain 1); the oldest window file becomes an undeletable
/// directory (external fs condition — unlink fails); run 2 hits
/// deletion-failure → quota-stop latch → exit 1; the DIR goes
/// read-only (deletion provably impossible); legs A and B refuse
/// with 4 and leave every byte identical.
#[test]
fn sixb_latch_hold_exits_4_byte_identical() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = fresh_dir("latch-hold");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let flags = |cmd: &mut Command| {
        cmd.arg("--out")
            .arg(&dir)
            .arg("--pid")
            .arg(&pid)
            .arg("--window")
            .arg("1")
            .arg("--interval")
            .arg("0.2")
            .arg("--retain-windows")
            .arg("1");
    };
    // Run 1: fill + graceful cut.
    let mut run1 = bin();
    flags(&mut run1);
    let mut run1 = run1.spawn().expect("spawn run 1");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run1.id() as i32, libc::SIGTERM) };
    let st1 = run1.wait().expect("wait run 1");
    assert_eq!(st1.code(), Some(3), "run 1 cuts gracefully");
    // Surgery: the oldest window file becomes a non-empty directory.
    let mut wins: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("window-"))
        .collect();
    wins.sort();
    assert!(!wins.is_empty(), "run 1 published windows");
    let victim = dir.join(&wins[0]);
    std::fs::remove_file(&victim).unwrap();
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("junk"), b"undeletable-by-unlink").unwrap();
    // Run 2: eviction fails → deletion-failure latch → exit 1 (self).
    let mut run2 = bin();
    flags(&mut run2);
    let mut run2 = run2.spawn().expect("spawn run 2");
    let st2 = wait_bounded(&mut run2, 30).expect("run 2 exits itself");
    assert_eq!(st2.code(), Some(1), "run 2 quota-stops with 1");
    assert!(dir.join("quota-stop.json").is_file(), "latch written");
    // Read-only: deletion provably impossible from here on.
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&dir, perms).unwrap();
    let snap0 = dir_snapshot(&dir);
    // Legs A and B: refuse 4, byte-identical (including service.lock).
    for leg in ["A", "B"] {
        let mut cmd = bin();
        flags(&mut cmd);
        let mut proc = cmd.spawn().expect("spawn latch leg");
        let st = wait_bounded(&mut proc, 30).expect("latch leg exits");
        assert_eq!(st.code(), Some(4), "leg {leg} refuses with 4");
        assert_eq!(dir_snapshot(&dir), snap0, "leg {leg} byte-identical");
    }
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&dir, perms).unwrap();
    let _ = child.kill();
    let _ = child.wait();
}

/// Resident-stream restart admits (R1 finding 5a): `--stream` given
/// as the out-DIR resolves to the resident `stream.jsonl`, which is
/// the tap's own file — never evidence. A restart with the tap
/// resident must NOT refuse exit 2 (the alias check covers RESERVED
/// artifacts only).
#[test]
fn sixb_resident_stream_restart_admits() {
    let dir = fresh_dir("resident-restart");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let flags = |cmd: &mut Command| {
        cmd.arg("--out")
            .arg(&dir)
            .arg("--pid")
            .arg(&pid)
            .arg("--window")
            .arg("1")
            .arg("--interval")
            .arg("0.2")
            .arg("--stream")
            .arg(&dir);
    };
    // Run 1: publish + cut; the resident tap now exists.
    let mut run1 = bin();
    flags(&mut run1);
    let mut run1 = run1.spawn().expect("spawn run 1");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run1.id() as i32, libc::SIGTERM) };
    let st1 = run1.wait().expect("wait run 1");
    assert_eq!(st1.code(), Some(3), "run 1 cuts gracefully");
    assert!(
        dir.join("stream.jsonl").is_file(),
        "resident tap exists after run 1"
    );
    // Run 2 (restart): the resident tap must admit.
    let mut run2 = bin();
    flags(&mut run2);
    let mut run2 = run2.spawn().expect("spawn run 2");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(run2.id() as i32, libc::SIGTERM) };
    let st2 = run2.wait().expect("wait run 2");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(st2.code(), Some(3), "resident restart admits (cuts 3)");
}

/// Reserved-alias taps refuse pre-open (R1 finding 5 guard): a
/// non-reserved FILENAME hard-linked to a RESERVED identity
/// (sequence.json) still refuses exit 2 — the identity half of the
/// §4.1 rule survives the F5a restriction to reserved artifacts.
#[test]
fn sixb_reserved_alias_tap_refused_preopen() {
    let dir = fresh_dir("reserved-alias");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    // Seed run: create sequence.json (state).
    let mut seed = bin();
    seed.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2");
    let mut seed = seed.spawn().expect("spawn seed");
    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe { libc::kill(seed.id() as i32, libc::SIGTERM) };
    let st = seed.wait().expect("wait seed");
    assert_eq!(st.code(), Some(3), "seed cuts gracefully");
    assert!(dir.join("sequence.json").is_file(), "seed wrote state");
    // Non-reserved name, reserved identity.
    let evil = dir.join("evil-tap.jsonl");
    std::fs::hard_link(dir.join("sequence.json"), &evil).unwrap();
    let probe = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--stream")
        .arg(&evil)
        .status()
        .expect("spawn probe");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(probe.code(), Some(2), "reserved-alias tap refuses exit 2");
}

/// Post-open hard-link swap fails the run as a tool failure (R1
/// finding 5b): the tap admits clean, then the PATH is swapped to a
/// hard link of a RESERVED window file before the first tap open.
/// The post-open fstat check must catch it: fd closed before any
/// write (the window stays byte-identical — an unchecked open would
/// splice stream bytes into published evidence), run-level tool
/// failure (exit 1 — windows finalized).
#[test]
fn sixb_postopen_reserved_swap_fails_tool_failure() {
    let dir = fresh_dir("postopen-swap");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    // Seed run: publish window 0 (the reserved swap target).
    let mut seed = bin();
    seed.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2");
    let mut seed = seed.spawn().expect("spawn seed");
    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe { libc::kill(seed.id() as i32, libc::SIGTERM) };
    let st = seed.wait().expect("wait seed");
    assert_eq!(st.code(), Some(3), "seed cuts gracefully");
    let win0 = dir.join("window-0000000000.json");
    assert!(win0.is_file(), "seed published window 0");
    let win0_bytes = std::fs::read(&win0).unwrap();
    // Run 2: tap ABSENT at admission (clean admit), swapped to
    // the reserved window before the first tap open (the final
    // close drives the tap). Pre-creating it would trip the F5a
    // self-refusal instead of the post-open path.
    let tap = dir.join("stream.jsonl");
    let mut svc = bin();
    svc.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .arg("--interval")
        .arg("0.2")
        .arg("--stream")
        .arg(&tap);
    let mut svc = svc.spawn().expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(dir.join("sequence.json").is_file(), "admission wrote state");
    std::fs::hard_link(&win0, &tap).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let st = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        st.code(),
        Some(1),
        "post-open reserved swap fails as tool failure (exit 1), got {st:?}"
    );
    assert_eq!(
        std::fs::read(&win0).unwrap(),
        win0_bytes,
        "window 0 byte-identical (fd closed pre-write)"
    );
}

/// Ptrace fsync delayer (R1 finding 3 — hostile stalled-I/O
/// through the real coordinator): seizes `pid` (own child — no
/// caps), follows clones, and holds every fsync/fdatasync ENTER
/// for `delay` before resuming it. Never injects signals (resume
/// signo is always 0 on stops; only a real delivered-signal stop
/// is re-injected, and the service blocks its signals so those
/// never occur). Returns the tracee's `(exit_code, term_signal)`.
///
/// Stall discipline (stash-and-defer): a stalled thread's stop is
/// CONSUMED but its resume is deferred to `now + delay` while the
/// tracer keeps serving other threads' stops — detached
/// background workers' stalls must never serialize onto the
/// coordinator's own stops (that would inflate every wait
/// iteration and fake a deadline overrun). The wait stays
/// BLOCKING (a `WNOHANG`+sleep poll adds millisecond latency per
/// stop whenever the queue momentarily drains — measured 500x
/// collapse on syscall-dense phases); the due-resume runs before
/// every wait, and the tracee's own wait/pump quanta (5–25 ms of
/// stops) bound any overstay. A stalled tid can only outlive its
/// resume while the whole process is otherwise idle — in which
/// case nothing waits on it (the coordinator never fsyncs, so it
/// is never the stalled one).
/// Reaping discipline: this thread OWNS all `waitpid(-1)` reaping
/// for the tracee (cloned worker threads included) — the caller
/// must NOT `wait`/`try_wait` the child (that races the tracer).
/// Termination is by the LEADER's exit status (traced non-leader
/// threads vanish after their EXIT event-stop without a waitable
/// status, so thread-set emptiness is never the rule).
#[allow(non_upper_case_globals)]
fn delay_tracee_syncs(pid: u32, delay: std::time::Duration) -> (Option<i32>, Option<i32>) {
    use std::collections::{HashMap, HashSet};
    const SYS_FSYNC: u64 = 74;
    const SYS_FDATASYNC: u64 = 75;
    const WAIT_FLAGS: libc::c_int = libc::__WALL | libc::WUNTRACED;
    let leader = pid as libc::pid_t;
    unsafe {
        let opts = (libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXIT) as u64;
        if libc::ptrace(
            libc::PTRACE_SEIZE,
            leader,
            std::ptr::null_mut::<libc::c_void>(),
            opts as *mut libc::c_void,
        ) != 0
        {
            return (None, None); // Already gone — nothing to stall.
        }
        // Stop it once so syscall-tracing can start (no signal).
        libc::ptrace(
            libc::PTRACE_INTERRUPT,
            leader,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }
    let cont = |tid: libc::pid_t, sig: i32| unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as *mut libc::c_void,
        );
    };
    let mut tids: HashSet<libc::pid_t> = HashSet::new();
    let mut entering: HashMap<libc::pid_t, bool> = HashMap::new();
    // Stalled fsync ENTERs: tid → resume instant (the stop is
    // consumed; the resume is deferred — other tids' stops keep
    // flowing meanwhile).
    let mut stashed: HashMap<libc::pid_t, std::time::Instant> = HashMap::new();
    tids.insert(leader);
    loop {
        // Resume due stashed tids first (their syscalls execute;
        // their exit-stops arrive later like any other stop).
        let now = std::time::Instant::now();
        let due: Vec<libc::pid_t> = stashed
            .iter()
            .filter(|(_, at)| now >= **at)
            .map(|(tid, _)| *tid)
            .collect();
        for tid in due {
            stashed.remove(&tid);
            cont(tid, 0);
        }
        let mut status = 0;
        let got = unsafe { libc::waitpid(-1, &mut status, WAIT_FLAGS) };
        if got < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD backstop (unreachable — the leader's exit below
            // always terminates first): status unknown, fail loud.
            return (None, None);
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            tids.remove(&got);
            entering.remove(&got);
            if got == leader {
                let code = if libc::WIFEXITED(status) {
                    Some(libc::WEXITSTATUS(status))
                } else {
                    None
                };
                let sig = if libc::WIFSIGNALED(status) {
                    Some(libc::WTERMSIG(status))
                } else {
                    None
                };
                // Drain stragglers once (non-blocking), then done.
                let mut extra = 0;
                let mut st = 0;
                while unsafe { libc::waitpid(-1, &mut st, WAIT_FLAGS | libc::WNOHANG) } > 0 {
                    extra += 1;
                    if extra > 64 {
                        break;
                    }
                }
                return (code, sig);
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        tids.insert(got);
        let event = (status >> 16) as i32;
        if event == libc::PTRACE_EVENT_CLONE {
            let mut new_tid: libc::c_ulong = 0;
            unsafe {
                libc::ptrace(
                    libc::PTRACE_GETEVENTMSG,
                    got,
                    std::ptr::null_mut::<libc::c_void>(),
                    &mut new_tid as *mut _ as *mut libc::c_void,
                );
            }
            tids.insert(new_tid as libc::pid_t);
            cont(got, 0);
            continue;
        }
        if event == libc::PTRACE_EVENT_EXIT {
            // A dying thread vanishes after this stop with NO
            // waitable status — drop it now (never the rule).
            tids.remove(&got);
            entering.remove(&got);
            cont(got, 0);
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        if sig == (libc::SIGTRAP | 0x80) {
            let is_enter = entering.get(&got).copied().unwrap_or(true);
            if is_enter {
                let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                let ok = unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETREGS,
                        got,
                        std::ptr::null_mut::<libc::c_void>(),
                        &mut regs as *mut _ as *mut libc::c_void,
                    )
                };
                if ok == 0 && (regs.orig_rax == SYS_FSYNC || regs.orig_rax == SYS_FDATASYNC) {
                    // Stash (defer the resume — never sleep inline).
                    entering.insert(got, false);
                    stashed.insert(got, std::time::Instant::now() + delay);
                    continue;
                }
            }
            entering.insert(got, !is_enter);
            cont(got, 0);
        } else {
            // Group/event stop (SIGTRAP — resume clean, never
            // re-inject: an injected SIGTRAP would kill) or a real
            // delivered-signal stop (re-inject — swallow nothing;
            // the service blocks TERM/INT/HUP so those never stop
            // here).
            entering.insert(got, true);
            let reinject = if sig == libc::SIGTRAP { 0 } else { sig };
            cont(got, reinject);
        }
    }
}

/// Single-deadline shutdown + double-signal expedition (R1 finding
/// 3): with every fsync stalled 1.5 s, the close from the first
/// TERM must still meet ONE `--grace` (3 s here — stale per-stage
/// budgets would stack ~10 s), and a second TERM mid-close must
/// expedite via Cancelled waits (not blind expiry). Zero finalized
/// + double-signal exits 4 (§7.3 priority 3 beats 6).
#[test]
fn sixb_shutdown_meets_single_deadline_and_double_expedites() {
    let dir = fresh_dir("shutdown-deadline");
    let mut child = Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin();
    svc.arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("30")
        .arg("--interval")
        .arg("0.2")
        .arg("--grace")
        .arg("3")
        .arg("--timeout")
        .arg("30");
    let mut svc = svc.spawn().expect("spawn service");
    // Settle WITHOUT stalls (fast startup): window 0 reserved.
    let seq_path = dir.join("sequence.json");
    let mut settled = false;
    for _ in 0..300 {
        if let Ok(body) = std::fs::read_to_string(&seq_path) {
            if body.contains("\"started\":true") {
                settled = true;
                break;
            }
        }
        if let Ok(Some(st)) = svc.try_wait() {
            panic!("service exited during settle: {st:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(settled, "window 0 reserved (settle)");
    // Stall every fsync from here (the close path only). From this
    // point the tracer OWNS reaping — never wait the child here.
    let svc_id = svc.id();
    let tracer = std::thread::spawn(move || {
        delay_tracee_syncs(svc_id, std::time::Duration::from_millis(1500))
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    let t0 = std::time::Instant::now();
    unsafe { libc::kill(svc_id as i32, libc::SIGTERM) };
    std::thread::sleep(std::time::Duration::from_secs(1));
    unsafe { libc::kill(svc_id as i32, libc::SIGTERM) };
    std::thread::sleep(std::time::Duration::from_millis(500));
    unsafe { libc::kill(svc_id as i32, libc::SIGTERM) };
    // The clock stops when the tracer reaps the leader (fail-loud
    // 60 s on the tracer, never on the child handle).
    let mut done = false;
    for _ in 0..600 {
        if tracer.is_finished() {
            done = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(done, "close finishes (60 s fail-loud)");
    let dt = t0.elapsed();
    let (code, sig) = tracer.join().expect("tracer thread");
    drop(svc);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(sig, None, "service not killed by a signal");
    assert_eq!(code, Some(4), "double-signal zero-finalized exits 4");
    assert!(
        dt <= std::time::Duration::from_secs(6),
        "one grace (3 s) bounds the stalled close — took {dt:?}"
    );
    // Expedition proof: a cancelled op (signal-consumed wait —
    // `OpOutcome` serializes snake_case), not blind expiry alone.
    let summary =
        std::fs::read_to_string(dir.join("run-summary.json")).expect("run summary written");
    assert!(
        summary.contains("\"cancelled\""),
        "a close wait cancelled on the second signal"
    );
}

/// Bounded wait for a self-exiting child (poll — fail-loud timeout).
fn wait_bounded(child: &mut std::process::Child, secs: u64) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return Some(st);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Full-DIR content snapshot (every regular file incl. service.lock).
fn dir_snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// FIFO at `service.lock` fails fast (RANK-1 startup admission
/// hang): startup admission never blocks in lockfile open/read,
/// so the run refuses (exit 2) on a `--timeout` scale even with
/// pending TERM+INT — the reviewer's probe shape (FIFO lock +
/// `--timeout 0.1` + TERM+INT, blocked >400 ms pre-fix).
#[test]
fn sixb_fifo_lock_admission_fails_fast() {
    let dir = fresh_dir("fifo-lock");
    let lock = dir.join("service.lock");
    let c = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .arg("--timeout")
        .arg("0.1")
        .arg("--grace")
        .arg("0.05")
        .spawn()
        .expect("spawn service");
    // Reviewer shape: let admission settle, then TERM+INT.
    std::thread::sleep(std::time::Duration::from_millis(400));
    if svc.try_wait().expect("try_wait").is_none() {
        unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
        unsafe { libc::kill(svc.id() as i32, libc::SIGINT) };
    }
    let status = wait_bounded(&mut svc, 10);
    if status.is_none() {
        let _ = svc.kill();
        let _ = svc.wait();
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        status.is_some(),
        "FIFO lock admission hung >10s despite TERM+INT"
    );
    assert_eq!(
        status.unwrap().code(),
        Some(2),
        "FIFO lock refuses pre-start (exit 2)"
    );
}

/// Compute a live service run's spill-tag (`pid-starttime-boot8`,
/// mirroring `RunId::tag`) from outside the process.
fn run_tag(pid: u32) -> String {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat readable");
    let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let starttime = after
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let boot8: String = boot_id.chars().take(8).collect();
    format!("{pid}-{starttime}-{boot8}")
}

/// Leaked spill tmps are retried in-run (RANK-4): files matching
/// this run's spill prefix but holding no live identity (seeded
/// here — the relisted-leak shape) are unlinked by a later
/// boundary's absorb retry, NOT left for the next start. No next
/// start runs here, so absence at exit proves the in-run unlink
/// (pre-fix the seeds survive — the queue had no consumer).
/// Live-identity exclusion is pinned hermetically by the
/// coordinator `spill_retry_*` unit legs; the run finalizing
/// normally (exit 3 + windows + summary) proves no live spill
/// was eaten on the way.
#[test]
fn sixb_leaked_spills_retry_in_run() {
    let dir = fresh_dir("spill-retry");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = bin()
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    // Seed AFTER the run owns the out-DIR (startup `clean_tmps`
    // runs before this — the seeds below are genuinely leaked
    // mid-run identities, not startup leftovers).
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(
        svc.try_wait().expect("try_wait").is_none(),
        "service alive at seed time"
    );
    let tag = run_tag(svc.id());
    let seed1 = dir.join(format!(".{tag}.tmp.spill.999999.0"));
    let seed2 = dir.join(format!(".{tag}.tmp.spill.999999.1"));
    std::fs::write(&seed1, b"{\"leaked\":true}\n").unwrap();
    std::fs::write(&seed2, b"{\"leaked\":true}\n").unwrap();
    // Two mid-run boundaries (1 s windows) + the final close:
    // boundary N re-lists the leaks into the retry queue,
    // boundary N+1's absorb unlinks them.
    std::thread::sleep(std::time::Duration::from_millis(2500));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let status = wait_bounded(&mut svc, 30).expect("service exits after TERM");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        status.code(),
        Some(3),
        "cancel-after-windows exits 3, got {status:?}"
    );
    assert!(
        !seed1.exists() && !seed2.exists(),
        "leaked spill tmps unlinked in-run (no next start ran)"
    );
    assert!(
        dir.join("window-0000000000.json").is_file(),
        "window 0 published, dir: {dir:?}"
    );
    assert!(
        dir.join("run-summary.json").is_file(),
        "run summary written, dir: {dir:?}"
    );
}
